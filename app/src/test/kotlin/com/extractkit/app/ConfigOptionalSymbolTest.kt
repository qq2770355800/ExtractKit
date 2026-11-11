package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * 8.25：`panic_on_warn` 从「必需」降级为「条件必需」。
 *
 * 背景：服务器收录的 9 台机型（AAK-AN00 / APH-AN00 / BVL-AN00 / CGL-W60 /
 * ELP-AN00 / PTP-AN10 ×2 / ROD2-W09）的 symbols 里都没有 `panic_on_warn` —— 它走自己
 * 的 LKM，不需要抹这个符号。我们的 userspace 链只有在
 * `/proc/sys/kernel/panic_on_warn != 0` 时才需要它，所以缺符号时应当照样能出 cfg，
 * 只是该字段写 0 表示「未知」，由 payload 运行时决定跳过还是拒绝。
 */
private fun u(hex: String): Long = java.lang.Long.parseUnsignedLong(hex, 16)

class ConfigOptionalSymbolTest {

    private fun offsets() = Offsets(
        itimerSize = 0x108,
        itimerNode = 0x78,
        itimerHead = 0x98,
        itimerElist = 0xa8,
        itimerFiring = 0xb8,
        itimerHandling = 0xc0,
        taskCred = 0x838,
        taskComm = 0x848,
        credSize = 0xb0,
        credUid = 0x4,
        credSecurity = 0x80,
        credUser = 0x88,
        credUserNs = 0x90,
        credUcounts = 0x98,
        credGroups = 0xa0,
    )

    private fun syms(withPanic: Boolean): Map<String, Long> = buildMap {
        put("do_timer_create", u("ffffffc0083be82c"))
        put("selinux_state", u("ffffffc00a6fca40"))
        if (withPanic) put("panic_on_warn", u("ffffffc00a0aae08"))
        put("root_user", u("ffffffc00a0d09d8"))
        put("init_user_ns", u("ffffffc00a0d0748"))
        put("init_ucounts", u("ffffffc00a0d2268"))
        put("init_groups", u("ffffffc00a0d1cf8"))
    }

    private fun measured() = ConfigGen.Measured(
        timerSiteOffset = 0x94,
        credSiteLow21 = 0x10B7F8,
        taskAllocLow21 = 0x19ECC0,
        taskAllocBytes = 0x12c0,
        credReq = 0xb0,
        credAlloc = 0xb0,
    )

    private fun byteAt(blob: ByteArray, off: Int): Long =
        ByteBuffer.wrap(blob, off, 8).order(ByteOrder.LITTLE_ENDIAN).long

    @Test
    fun cfgStillBuildsWithoutPanicOnWarn() {
        val withIt = ConfigGen.emitCfgBlob(syms(true), offsets(), measured())
        val without = ConfigGen.emitCfgBlob(syms(false), offsets(), measured())

        // 结构不变，只有那一个字段从真实地址变成 0。blob 头部有 magic 与计数，u64 段未必
        // 从 8 字节边界开始，所以按字节滑窗找 panic_on_warn 的地址。
        assertTrue("长度应一致，实际 ${withIt.size} vs ${without.size}", withIt.size == without.size)
        val target = u("ffffffc00a0aae08")
        val at = (0..withIt.size - 8).firstOrNull { byteAt(withIt, it) == target }
        assertTrue("在 cfg 里找不到 panic_on_warn 地址", at != null)
        assertEquals("缺符号时 panic_on_warn 槽位应写 0（未知）", 0L, byteAt(without, at!!))
        for (off in 0 until withIt.size) {
            if (off in at!! until at + 8) continue
            assertEquals(
                "cfg 偏移 $off 的字节被意外改动",
                withIt[off].toInt() and 0xff,
                without[off].toInt() and 0xff,
            )
        }
    }

    @Test
    fun coreSymbolsStillRequired() {
        // 双模之后：内核 text 符号已变成可选（缺了就走 offsets-only），
        // 但 4 个 cred 锚点是硬需求——缺一个都必须拒绝出 cfg。
        val broken = syms(true).toMutableMap().apply { remove("root_user") }
        var threw = false
        try {
            ConfigGen.emitCfgBlob(broken, offsets(), measured())
        } catch (e: IllegalArgumentException) {
            threw = true
        }
        assertTrue("缺 cred 锚点（root_user）时必须拒绝出 cfg", threw)
    }

    @Test
    fun missingTextSymbolsFallBackToOffsetsOnly() {
        // 第三方二进制里那条链的做法：没有 do_timer_create / selinux_state，
        // 只留 4 个锚点 + 结构偏移。cfg 必须照样能出，且这两个字段写 0，
        // payload 见到 0 会自动切 offsets-only。
        val noText = syms(true).toMutableMap().apply {
            remove("do_timer_create")
            remove("selinux_state")
        }
        val blob = ConfigGen.emitCfgBlob(noText, offsets(), measured())
        assertEquals(336, blob.size)
        val buf = java.nio.ByteBuffer.wrap(blob).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        buf.position(12)
        val staticTimer = buf.long
        val low21 = buf.long
        assertEquals("缺 do_timer_create 时 staticTimer 必须为 0", 0L, staticTimer)
        assertEquals("缺 do_timer_create 时 low21 必须为 0", 0L, low21)
        val selinux = buf.long
        assertEquals("缺 selinux_state 时必须写 0", 0L, selinux)
    }

    @Test
    fun panicOnWarnStaysInRequiredListForDisplay() {
        // UI 依然按 7 个符号展示「是否齐全」，但闸门用的是 CORE_SYMBOLS
        assertEquals(7, ConfigGen.REQUIRED_SYMBOLS.size)
        assertEquals(6, ConfigGen.CORE_SYMBOLS.size)
        assertTrue(ConfigGen.CORE_SYMBOLS.none { it == "panic_on_warn" })
    }
}
