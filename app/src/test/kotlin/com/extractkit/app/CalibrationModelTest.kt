package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * 标定页搬进 Compose 后，逻辑里最容易回归的三块：十六进制输入、日志环形缓冲、profile 组装。
 * 三者都已抽成纯函数，这里不依赖 Android 运行时。
 */
class CalibrationModelTest {

    /** 内核地址超过 Long.MAX，必须按无符号解析（0xffffff... 直接写字面量在 Kotlin 里会 Value out of range）。 */
    private fun u(hex: String): Long = java.lang.Long.parseUnsignedLong(hex, 16)

    private val off = Offsets(
        itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x0, itimerElist = 0x10,
        itimerFiring = 0x20, itimerHandling = 0x28, taskCred = 0x820, taskComm = 0x830,
        credSize = 0xb8, credUid = 0x8, credSecurity = 0x78, credUser = 0x80,
        credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
    )

    private val syms: Map<String, Long> = java.util.LinkedHashMap<String, Long>().apply {
        put("do_timer_create", u("ffffffc0803afc58"))
        put("kmem_cache_alloc_node", u("ffffffc080112233"))
        put("root_user", u("ffffffc0826c1f00"))
        put("init_ucounts", u("ffffffc0826c2000"))
        put("init_groups", u("ffffffc0826c2100"))
        put("panic_on_warn", u("ffffffc08216ae0c"))
        put("selinux_state", u("ffffffc0823ba418"))
        put("init_user_ns", u("ffffffc0826c1f40"))
    }

    @Test
    fun parseHexHandlesPrefixAndJunk() {
        assertEquals(0x94, parseHex("0x94", 0))
        assertEquals(0x94, parseHex("94", 0))
        assertEquals(0x94, parseHex(" 0X94 ", 0))
    }

    @Test
    fun parseHexFallsBackOnEmptyOrInvalid() {
        assertEquals(7, parseHex(null, 7))
        assertEquals(7, parseHex("   ", 7))
        assertEquals(7, parseHex("zz", 7))
    }

    @Test
    fun ringAppendKeepsLastN() {
        val lines = mutableListOf<String>()
        repeat(1000) { ringAppend(lines, "line$it", 600) }
        assertEquals(600, lines.size)
        assertEquals("line400", lines.first())
        assertEquals("line999", lines.last())
    }

    @Test
    fun assembleProfileKeepsOnlyRequiredSymbols() {
        val p = assembleProfile(
            release = "6.6.118-android15-8",
            syms = syms,
            off = off,
            measured = ConfigGen.Measured(
                timerSiteOffset = 0x94, credSiteLow21 = 0x38458, taskAllocLow21 = 0x1CB240,
                taskAllocBytes = 0x12C0,
            ),
            timerAbs = u("ffffffc0803afcec"),
            credAbs = u("ffffffc080238458"),
            timerFallback = 0x94,
        )
        assertEquals(ConfigGen.REQUIRED_SYMBOLS.size, p.symbols.size)
        assertEquals(u("ffffffc0803afcec"), p.timerLink)
        assertEquals(u("ffffffc080238458"), p.credLink)
        assertEquals("6.6.118-android15-8", p.release)
    }

    @Test
    fun assembleProfileFallsBackToSymbolPlusOffset() {
        val p = assembleProfile(
            release = "?",
            syms = syms,
            off = off,
            measured = ConfigGen.Measured(timerSiteOffset = 0x5c),
            timerAbs = null,
            credAbs = null,
            timerFallback = 0x5c,
        )
        assertEquals(u("ffffffc0803afc58") + 0x5c, p.timerLink)
        assertEquals(0L, p.credLink)
        assertEquals(ConfigGen.Baseline.release, p.release)
    }

    @Test
    fun assembleProfileWithEmptySymsProducesNoSymbolTable() {
        val p = assembleProfile(
            release = "x", syms = emptyMap(), off = off,
            measured = ConfigGen.Measured(), timerAbs = null, credAbs = null, timerFallback = 0x94,
        )
        assertEquals(0, p.symbols.size)
    }
}
