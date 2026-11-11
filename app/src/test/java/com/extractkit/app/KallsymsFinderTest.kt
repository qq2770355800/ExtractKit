package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * KallsymsFinder 自测：在内存里造一张只有 kallsyms 段的假 Image（布局照抄真实内核：
 * num_syms / names / markers / token_table / token_index / offsets / relative_base），
 * 断言能把这些符号原样解出来。
 *
 * 同一张 fixture 也用 tools/find-kallsyms.py 跑过（那边已验证 40009 个符号、地址全对），
 * 两边算法必须一致。
 */
class KallsymsFinderTest {

    private val named = listOf(
        "_text" to 0x0L,
        "do_timer_create" to 0x3AFC58L,
        "prepare_creds" to 0x238438L,
        "copy_process" to 0x1CB0FCL,
        "selinux_state" to 0x23BA418L,
        "root_user" to 0x218F228L,
        "init_user_ns" to 0x218EF98L,
        "init_ucounts" to 0x2190CF8L,
        "init_groups" to 0x2190788L,
    )
    private val filler = (0 until 40000).map { "sym_$it" to (0x100000L + it * 0x10L) }
    private val symbols = named + filler
    private val base = 0xFFFFFFC080000000uL

    private fun buildImage(): ByteArray {
        val count = symbols.size
        val b = ByteArray(8 * 1024 * 1024)
        val buf = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)

        // ---- token 表：ASCII 字母数字/._ 映射到自身，其余给空串（与真实布局兼容）
        val tableStart = 0x100000
        var p = tableStart
        val tokenOffsets = IntArray(256)
        for (i in 0 until 256) {
            val ch = i.toChar()
            val tok = if (ch in '0'..'9' || ch in 'a'..'z' || ch in 'A'..'Z' || ch == '_' || ch == '.') {
                ch.toString()
            } else {
                ""
            }
            tokenOffsets[i] = p - tableStart
            val bytes = tok.toByteArray(Charsets.US_ASCII)
            System.arraycopy(bytes, 0, b, p, bytes.size)
            p += bytes.size
            b[p] = 0
            p += 1
        }

        // ---- token_index
        val tiStart = (p + 1) and 1.inv()
        for (i in 0 until 256) buf.putShort(tiStart + 2 * i, tokenOffsets[i].toShort())

        // ---- offsets（相对 base）+ relative_base
        val offsetsStart = (tiStart + 512 + 3) and 3.inv()
        symbols.forEachIndexed { i, (_, addr) -> buf.putInt(offsetsStart + 4 * i, addr.toInt()) }
        val basePos = (offsetsStart + 4 * count + 7) and 7.inv()
        buf.putLong(basePos, base.toLong())

        // ---- names 与 markers（markers 在 names 之后，指向每第 256 条记录的起点）
        val markersCount = (count + 255) / 256
        val markersStart = tableStart - 4 * markersCount
        val records = symbols.map { (name, _) ->
            val raw = name.toByteArray(Charsets.US_ASCII)
            ByteArray(raw.size + 2).also { rec ->
                rec[0] = (raw.size + 1).toByte()   // 长度 = 类型字符 + 名字
                rec[1] = 'T'.code.toByte()         // kallsyms 把类型字符也编进名字里
                System.arraycopy(raw, 0, rec, 2, raw.size)
            }
        }
        val namesStart = markersStart - records.sumOf { it.size }
        var w = namesStart
        var idx = 0
        records.forEachIndexed { i, rec ->
            if (i % 256 == 0) {
                buf.putInt(markersStart + 4 * idx, w - namesStart)
                idx++
            }
            System.arraycopy(rec, 0, b, w, rec.size)
            w += rec.size
        }
        // num_syms（解析器不依赖它，这里只是让布局更真实）
        buf.putInt((namesStart - 8) and 7.inv(), count)
        return b
    }

    @Test
    fun decodesSymbolsFromSyntheticImage() {
        val image = buildImage()
        val result = KallsymsFinder.find(image)
        assertNotNull("没解析出 kallsyms", result)
        val syms = result!!.symbols
        assertEquals(symbols.size, result.numSyms)
        assertEquals(base.toLong(), result.relativeBase)

        named.forEach { (name, off) ->
            assertEquals(name, base.toLong() + off, syms[name])
        }
        assertTrue(syms.containsKey("sym_39999"))
    }

    @Test
    fun returnsNullOnGarbage() {
        assertEquals(null, KallsymsFinder.find(ByteArray(4096)))
    }
}
