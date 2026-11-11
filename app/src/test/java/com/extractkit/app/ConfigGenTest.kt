package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** kallsyms 解析 + device_config.h 生成的回归测试。 */
class ConfigGenTest {

    private fun resource(name: String): ByteArray =
        javaClass.classLoader!!.getResourceAsStream(name)!!.readBytes()

    @Test
    fun parsesBothKallsymsFormats() {
        val m = Kallsyms.parse(
            """
            # 注释行
            ffffffc0803afc58 do_timer_create
            ffffffc0823ba418 T selinux_state
            """
        )
        assertEquals(0xFFFFFFC0803AFC58uL.toLong(), m["do_timer_create"])
        assertEquals(0xFFFFFFC0823BA418uL.toLong(), m["selinux_state"])
    }

    @Test
    fun emitsBaselineHeader() {
        val btf = Btf.parse(resource("vmlinux.btf"))
        val off = ConfigGen.offsetsFromBtf(btf)
        val syms = Kallsyms.parse(resource("kallsyms.txt").toString(Charsets.UTF_8))

        val header = ConfigGen.emitHeader(
            kernelRelease = "test-kernel",
            syms = syms,
            off = off,
            m = ConfigGen.Measured(),
            btfSha256 = "-",
            kallsymsSha256 = "-",
        )

        // do_timer_create 0xffffffc0803afc58 + 0x94
        assertTrue(header.contains("#define STATIC_TIMER_SITE 0xffffffc0803afcecULL"))
        assertTrue(header.contains("#define TIMER_SITE_LOW21 0x1afcecUL"))
        assertTrue(header.contains("#define SELINUX_STATE_STATIC 0xffffffc0823ba418ULL"))
        assertTrue(header.contains("#define CRED_OFF_SECURITY 0x80ULL"))
        assertTrue(header.contains("#define PADDING_TIMERS (150 * 31)"))
        assertTrue(header.contains("#define ITIMER_NODE 0x78"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun refusesMissingSymbols() {
        val btf = Btf.parse(resource("vmlinux.btf"))
        val off = ConfigGen.offsetsFromBtf(btf)
        ConfigGen.emitHeader("k", mapOf("do_timer_create" to 1L), off, ConfigGen.Measured(), "-", "-")
    }
}
