package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * 用真实镜像校验解析器（本机有固件时才跑，CI 上自动跳过）。
 *
 * 6.1.157（MTN-AN80）：旧布局（offsets 在 names 前 + token 表不相邻 + KCFI thunk）
 * 6.6.118（PPG-AN00）：新布局，回归用
 */
class RealImageTest {

    private fun loadRawImage(path: String): ByteArray? = runCatching {
        val f = File(path)
        if (!f.isFile) return null
        val head = f.inputStream().use { it.readNBytes(8192) }
        // boot.img → 切出 kernel 段；裸 Image 直接整份读
        if (head.size >= 64 && String(head, 0, 8, Charsets.US_ASCII) == "ANDROID!") {
            val size = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN).getInt(8)
            java.io.RandomAccessFile(f, "r").use { raf ->
                raf.seek(4096)
                val out = ByteArray(size)
                raf.readFully(out)
                out
            }
        } else {
            f.readBytes()
        }
    }.getOrNull()

    /**
     * 5.10 那颗（ALT-AN00 / `5.10.252-android12-9-g839eb53a56c3`）没有 BTF，
     * 只能靠指令挖：`init_posix_timers`/`cred_init`/`fork_init` 的 sizeof 参数
     * 与 `exit_creds` 清 cred 的 STR XZR。
     */
    @Test
    fun codeOffsetsWithoutBtfOn510() {
        val img = loadRawImage("E:/alt_an00/Image")
        assumeTrue("本机没有 E:/alt_an00/Image", img != null)
        val image = img!!

        val found = KallsymsFinder.find(image)
        assertNotNull("5.10 的 kallsyms 也要能扫开", found)

        val syms = found!!.symbols
        println("[dbg] symbols=${syms.size} base=0x${java.lang.Long.toHexString(found.relativeBase)}")
        listOf("init_posix_timers", "cred_init", "fork_init", "exit_creds", "prepare_creds").forEach { n ->
            val a = syms[n]
            val fo = if (a == null) null else (a - found.relativeBase)
            println("[dbg] $n addr=${a?.let { "0x" + java.lang.Long.toHexString(it) }} fileOff=${fo?.let { "0x" + java.lang.Long.toHexString(it) }}")
            if (fo != null && fo > 0 && fo < image.size - 64) {
                val w = (0 until 6).joinToString(" ") { i ->
                    val o = fo.toInt() + i * 4
                    val v = (image[o].toLong() and 0xFF) or ((image[o + 1].toLong() and 0xFF) shl 8) or
                        ((image[o + 2].toLong() and 0xFF) shl 16) or ((image[o + 3].toLong() and 0xFF) shl 24)
                    java.lang.Long.toHexString(v)
                }
                println("[dbg]   words: $w")
            }
        }
        println("[dbg] posix keys=" + syms.keys.filter { it.contains("posix") }.joinToString())
        println("[dbg] timer keys=" + syms.keys.filter { it.contains("timer") && it.contains("init") }.joinToString())
        println("[dbg] numSyms=${found.numSyms} mapSize=${syms.size}")
        val off = ConfigGen.offsetsFromCode(image, syms, found.relativeBase)
        assertNotNull("指令里应该能挖出偏移", off)
        val o = off!!

        // 这颗 5.10 缺 `init_posix_timers` 符号 → 尺寸允许为 0（payload 会退回按 call site 匹配）
        assertTrue("k_itimer 尺寸异常: ${o.itimerSize}", o.itimerSize == 0 || o.itimerSize in 0x100..0x180)
        assertTrue("cred 尺寸异常: ${o.credSize}", o.credSize in 0xA0..0xC8)
        assertTrue("task->cred 偏移异常: ${o.taskCred}", o.taskCred in 0x400..0x900)
        assertEquals("task->comm 应紧跟 cred", o.taskCred + 0x10, o.taskComm)

        if (o.credSize == 0xA8) {
            // 5.10 的布局是固定的，与服务器 25 条档案逐个对得上
            assertEquals(4, o.credUid)
            assertEquals(0x78, o.credSecurity)
            assertEquals(0x80, o.credUser)
            assertEquals(0x88, o.credUserNs)
            assertEquals(0x90, o.credGroups)
            assertEquals("5.10 没有 ucounts，应与 groups 同值", o.credGroups, o.credUcounts)
        }
    }

    @Test
    fun legacyLayoutOnAndroid13Gki() {
        val img = loadRawImage("F:/MTN-AN80-firmware/work/Image")
        assumeTrue("没有 6.1 镜像，跳过", img != null && img.size > 10_000_000)

        val r = KallsymsFinder.find(img!!) { println("  [$it]") }
        assertNotNull("旧布局应能解出 kallsyms", r)
        r!!
        assertTrue("符号数应在 8 万以上，实际 ${r.numSyms}", r.numSyms > 80_000)

        val base = r.relativeBase
        assertEquals("0xffffffc008000000", "0x" + java.lang.Long.toHexString(base))
        assertEquals("_text 应等于 base", base, r.symbols["_text"])

        // 与固件里 mtn_vuln.json 的已知值对照
        val dell = r.symbols["posix_cpu_timer_del"]
        assertNotNull("应有 posix_cpu_timer_del", dell)
        assertEquals("0xffffffc00888c948", "0x" + java.lang.Long.toHexString(dell!!))
    }

    @Test
    fun callSitesResolveThroughCfiThunks() {
        val img = loadRawImage("F:/MTN-AN80-firmware/work/Image")
        assumeTrue("没有 6.1 镜像，跳过", img != null && img.size > 10_000_000)

        val r = KallsymsFinder.find(img!!) { println("  [$it]") }
        assertNotNull(r)
        val cs = CallSiteFinder.find(img, r!!.symbols, r.relativeBase)
        assertNotNull("KCFI thunk 也要能解析出三处 call site", cs)
        cs!!
        assertTrue("timer 偏移应在函数前 4 KiB 内: 0x${cs.timerOffset.toString(16)}", cs.timerOffset in 1..0x1000)
        assertTrue("cred low21 应非 0", cs.credLow21 != 0)
        assertTrue("task low21 应非 0", cs.taskLow21 != 0)
    }

    @Test
    fun modernLayoutStillWorksOnAndroid15Kernel() {
        val img = loadRawImage("E:/ppf/boot.img")
        assumeTrue("没有 6.6 镜像，跳过", img != null && img.size > 10_000_000)

        val r = KallsymsFinder.find(img!!) { println("  [$it]") }
        assertNotNull("新布局（6.6）回归失败", r)
        r!!
        assertEquals("0xffffffc080000000", "0x" + java.lang.Long.toHexString(r.relativeBase))
        assertEquals(
            "0xffffffc0803afc58",
            "0x" + java.lang.Long.toHexString(r.symbols["do_timer_create"] ?: 0L),
        )
        val cs = CallSiteFinder.find(img, r.symbols, r.relativeBase)
        assertNotNull(cs)
        assertEquals(0x94, cs!!.timerOffset)
        assertEquals(0x38458, cs.credLow21)
        assertEquals(0x1CB240, cs.taskLow21)
    }
}
