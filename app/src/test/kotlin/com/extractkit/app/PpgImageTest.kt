package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * 第二个 6.6 内核（6.6.89-android15-8-g660f666ec112）的校验。
 * 固件目录里有官方导出的 kallsyms_6689.json，可以逐符号对照。
 */
class PpgImageTest {

    private val dir = "E:/ppg_fw"

    private fun loadImage(): ByteArray? = runCatching {
        val f = File("$dir/Image")
        if (f.isFile) f.readBytes() else {
            val b = File("$dir/boot.img")
            if (!b.isFile) return null
            val head = b.inputStream().use { it.readNBytes(8192) }
            val size = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN).getInt(8)
            RandomAccessFile(b, "r").use { raf ->
                raf.seek(4096)
                ByteArray(size).also { raf.readFully(it) }
            }
        }
    }.getOrNull()

    @Test
    fun kallsymsMatchesVendorExport() {
        val img = loadImage() ?: return
        val json = File("$dir/kallsyms_6689.json")
        assumeTrue("没有官方导出，跳过", json.isFile)

        val r = KallsymsFinder.find(img) { println("  [$it]") }
        assertNotNull("应从 6.6.89 镜像解出 kallsyms", r)
        r!!
        println("  符号 ${r.numSyms} 个，base=${java.lang.Long.toHexString(r.relativeBase)}")
        assertEquals(0xFFFFFFC080000000uL.toLong(), r.relativeBase)

        // 和官方 JSON 对照：抽 3 个符号
        val text = json.readText()
        val need = listOf(
            "_text", "do_timer_create", "selinux_state", "panic_on_warn", "root_user",
            "init_user_ns", "init_ucounts", "init_groups", "posix_timers_cache",
        )
        for (name in need) {
            val m = Regex("\"name\": \"$name\", \"address\": \"(0x[0-9a-f]+)\"").find(text) ?: continue
            val want = m.groupValues[1].removePrefix("0x").toULong(16).toLong()
            val got = r.symbols[name]
            assertNotNull("缺少符号 $name", got)
            assertEquals("$name 与官方导出不一致", want, got)
        }
        println("  ✅ 与 kallsyms_6689.json 一致")
    }

    @Test
    fun callSitesCanBeDerived() {
        val img = loadImage() ?: return
        val r = KallsymsFinder.find(img) { } ?: return
        val cs = CallSiteFinder.find(img, r.symbols, r.relativeBase)
        assertNotNull("call site 应能解析", cs)
        cs!!
        println(
            "  call site: timer=+0x${cs.timerOffset.toString(16)} " +
                "cred=0x${cs.credLow21.toString(16)} task=0x${cs.taskLow21.toString(16)}",
        )
        cs.detail.forEach { println("    $it") }
        assertTrue(cs.timerOffset in 0x10..0x1000)
    }
}
