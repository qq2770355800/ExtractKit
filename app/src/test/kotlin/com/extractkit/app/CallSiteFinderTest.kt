package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * CallSiteFinder 的离线校验：用合成指令流构造 bl，检查解码/取址/低 21 位都对。
 * 真实镜像上的结果已在真机标定页验证过（0x1afcec / 0x38458 / 0x1cb240）。
 */
class CallSiteFinderTest {

    private fun putBl(buf: ByteArray, at: Long, from: Long, to: Long) {
        val imm = ((to - from) shr 2).toInt() and 0x03FFFFFF
        val insn = 0x94000000.toInt() or imm
        val o = at.toInt()
        buf[o] = insn.toByte()
        buf[o + 1] = (insn ushr 8).toByte()
        buf[o + 2] = (insn ushr 16).toByte()
        buf[o + 3] = (insn ushr 24).toByte()
    }

    @Test
    fun findsThreeSitesFromSyntheticImage() {
        val text = 0xFFFFFFC080000000uL.toLong()
        val img = ByteArray(0x4000)

        val doTimer = text + 0x1000
        val prepCreds = text + 0x1800
        val copyProc = text + 0x2000
        val kmemAlloc = text + 0x3000
        val kmemAllocNode = text + 0x3100
        val kmemFree = text + 0x3200

        // do_timer_create: +0x90 处 bl kmem_cache_alloc
        putBl(img, 0x1000 + 0x90, doTimer + 0x90, kmemAlloc)
        // prepare_creds: +0x1c 处 bl kmem_cache_alloc
        putBl(img, 0x1800 + 0x1c, prepCreds + 0x1c, kmemAlloc)
        // copy_process: +0x140 处 bl kmem_cache_alloc_node（更早处还有一条 kmem_cache_free 干扰）
        putBl(img, 0x2000 + 0x10, copyProc + 0x10, kmemFree)
        putBl(img, 0x2000 + 0x140, copyProc + 0x140, kmemAllocNode)

        val syms = mapOf(
            "do_timer_create" to doTimer,
            "prepare_creds" to prepCreds,
            "copy_process" to copyProc,
            "kmem_cache_alloc" to kmemAlloc,
            "kmem_cache_alloc_node" to kmemAllocNode,
            "kmem_cache_free" to kmemFree,
        )

        val r = CallSiteFinder.find(img, syms, text)
        requireNotNull(r)
        // 返址 = bl 地址 + 4
        assertEquals(0x90 + 4, r.timerOffset)
        assertEquals(((doTimer + 0x94) and 0x1FFFFF).toInt(), r.timerLow21)
        assertEquals(((prepCreds + 0x20) and 0x1FFFFF).toInt(), r.credLow21)
        assertEquals(((copyProc + 0x144) and 0x1FFFFF).toInt(), r.taskLow21)
        assertEquals(3, r.detail.size)
    }

    @Test
    fun returnsNullWhenSymbolMissing() {
        val text = 0xFFFFFFC080000000uL.toLong()
        assertNull(CallSiteFinder.find(ByteArray(0x1000), emptyMap(), text))
        assertNull(
            CallSiteFinder.find(
                ByteArray(0x1000),
                mapOf("do_timer_create" to text + 0x10, "prepare_creds" to text + 0x20),
                text,
            ),
        )
    }

    @Test
    fun returnsZeroSitesWhenNoCallInSpan() {
        val text = 0xFFFFFFC080000000uL.toLong()
        val img = ByteArray(0x4000)
        val syms = mapOf(
            "do_timer_create" to text + 0x1000,
            "prepare_creds" to text + 0x1800,
            "copy_process" to text + 0x2000,
            "kmem_cache_alloc" to text + 0x3000,
            "kmem_cache_alloc_node" to text + 0x3100,
        )
        // 现在允许"部分成功"：没有任何调用时返回全 0，而不是 null
        val r = CallSiteFinder.find(img, syms, text)
        requireNotNull(r)
        assertEquals(0, r.timerOffset)
        assertEquals(0, r.credLow21)
        assertEquals(0, r.taskLow21)
        assertTrue(r.detail.any { it.contains("✗") })
    }
}
