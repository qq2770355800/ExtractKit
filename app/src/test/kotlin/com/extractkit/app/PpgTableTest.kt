package com.extractkit.app

import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** 从 E:/ppf/boot.img 解出我们这台（6.6.118）的 98937 内核表所需绝对地址。 */
class PpgTableTest {

    private fun kernel(path: String): ByteArray {
        val f = File(path)
        val head = f.inputStream().use { it.readNBytes(8192) }
        val size = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN).getInt(8)
        java.io.RandomAccessFile(f, "r").use { raf ->
            raf.seek(4096)
            val out = ByteArray(size)
            raf.readFully(out)
            return out
        }
    }

    @Test
    fun emit() {
        val img = kernel("E:/ppf/boot.img")
        val r = KallsymsFinder.find(img) { } ?: error("kallsyms failed")
        println("BASE=" + java.lang.Long.toHexString(r.relativeBase) + " COUNT=" + r.symbols.size)
        for (n in listOf("do_timer_create", "prepare_creds", "copy_process", "selinux_state",
                         "panic_on_warn", "root_user", "init_user_ns", "init_ucounts", "init_groups")) {
            r.symbols[n]?.let { println("SYM $n " + java.lang.Long.toHexString(it)) }
        }
        val cs = CallSiteFinder.find(img, r.symbols, r.relativeBase)
        println("CS timer=" + java.lang.Long.toHexString((r.symbols.getValue("do_timer_create") + (cs?.timerOffset ?: 0))))
        println("CS credLow21=" + cs?.credLow21?.toString(16) + " taskLow21=" + cs?.taskLow21?.toString(16))
        cs?.detail?.forEach { println("DET " + it) }
    }
}
