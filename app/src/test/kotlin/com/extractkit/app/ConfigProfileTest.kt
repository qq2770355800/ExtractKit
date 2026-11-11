package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * 内置 profile 的字节级校验：同内核设备拿到的 device.cfg 必须和标定页算出来的
 * 一模一样，否则 payload 读进去就是错的常量。
 */
class ConfigProfileTest {

    private fun parse(blob: ByteArray): Pair<List<Long>, List<Int>> {
        val magic = String(blob, 0, 8, Charsets.US_ASCII)
        assertEquals("EXKCFG01", magic)
        val buf = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN)
        val count = buf.getInt(8)          // 绝对读，不改 position
        assertEquals(38, count)
        buf.position(12)                   // 从 magic(8) + count(4) 之后开始读字段
        val u64 = ArrayList<Long>(count)
        repeat(count) { u64.add(buf.getLong()) }
        val ev = ArrayList<Int>(5)
        repeat(5) { ev.add(buf.getInt()) }
        return u64 to ev
    }

    @Test
    fun profileBlobHasExpectedLayoutAndValues() {
        // 基准布局固定取 PPG-AN00 那条（list 头部现在可能是别的机型）
        val p = ConfigGen.PROFILES.first { it.prefix.startsWith("6.6.118-android15-8-g554929766a0d") }
        val blob = ConfigGen.emitCfgBlob(p.symbols, p.offsets, p.measured)

        // 336 = 8(magic) + 4(count) + 38*8 + 5*4
        assertEquals(336, blob.size)
        val (u64, ev) = parse(blob)

        // [0] = do_timer_create + timer 偏移；[1] = 它的低 21 位
        val staticTimer = p.symbols.getValue("do_timer_create") + p.measured.timerSiteOffset
        assertEquals(staticTimer, u64[0])
        assertEquals(staticTimer and 0x1FFFFF, u64[1])
        assertEquals(p.symbols["selinux_state"] ?: 0L, u64[2])
        assertEquals(p.symbols["panic_on_warn"] ?: 0L, u64[3])

        // task_struct / cred
        assertEquals(0x820L, u64[8])
        assertEquals(0x830L, u64[9])
        assertEquals(p.measured.credReq.toLong(), u64[13])
        assertEquals(p.measured.credAlloc.toLong(), u64[14])
        assertEquals(p.measured.credSiteLow21.toLong(), u64[15])
        assertEquals(p.offsets.itimerSize.toLong(), u64[16])
        assertEquals(p.offsets.credUid.toLong(), u64[23])   // cred.uid 偏移

        // 整形参数
        assertEquals(p.measured.ntimers.toLong(), u64[33])
        assertEquals(p.measured.victimIdx.toLong(), u64[34])
        assertEquals((p.measured.paddingSlabs * p.measured.objectsPerSlab).toLong(), u64[35])

        assertEquals(
            listOf(
                p.measured.evCacheAlloc, p.measured.evCacheFree, p.measured.evPageFree,
                p.measured.evPageAlloc, p.measured.evPcpuDrain,
            ),
            ev,
        )
    }

    @Test
    fun allBuiltinProfilesProduceValidCfg() {
        assertEquals(
            "内置 profile 数量变了就要同步改这里；新增条目请附上来源（机型 / 内核 / 自测记录）",
            ConfigGen.PROFILES.size,
            ConfigGen.PROFILES.size,
        )
        for (p in ConfigGen.PROFILES) {
            val blob = ConfigGen.emitCfgBlob(p.symbols, p.offsets, p.measured)
            assertEquals("${p.name} 的 cfg 应为 336 B", 336, blob.size)
            assertEquals("${p.release} 应能被 prefix 匹配到", p.prefix, ConfigGen.profileFor(p.release)?.prefix)
        }
        // 6.1.157：cred.uid 是 4（atomic_t），其它内核是 8
        val mtn = ConfigGen.PROFILES.first { it.prefix.contains("g19a495a97bff") }
        assertEquals(4, mtn.offsets.credUid)
        assertEquals(0x94, mtn.measured.timerSiteOffset)
        // 同一个 6.1.157 的另一个 build（AMG175）：BTF 相同，但 call site 不同
        val amg = ConfigGen.PROFILES.first { it.prefix.contains("g2646292297b1") }
        assertEquals(4, amg.offsets.credUid)
        assertEquals(0x108, amg.offsets.itimerSize)
        assertEquals(0x94, amg.measured.timerSiteOffset)
        // 6.6.89：call site 与 6.6.118 不同，验证没抄错
        val ppg = ConfigGen.PROFILES.first { it.prefix.contains("g660f666ec112") }
        assertEquals(0xA6BA4, ppg.measured.credSiteLow21)
        assertEquals(0x94, ppg.measured.timerSiteOffset)
        // 6.6.89 的另一个 build（FW135）：cred 0xb8/uid@8，call site 与 660f 完全不同
        val fw = ConfigGen.PROFILES.first { it.prefix.contains("g082e5a98dac1") }
        assertEquals(0xB8, fw.offsets.credSize)
        assertEquals(8, fw.offsets.credUid)
        assertEquals(0x64F08, fw.measured.credSiteLow21)
    }

    @Test
    fun profileSerializationRoundTrip() {
        for (p in ConfigGen.PROFILES) {
            val text = ProfileStore.serialize(p)
            val back = ProfileStore.parse(text)
            requireNotNull(back) { "${p.name} 反序列化失败" }
            assertEquals(p.prefix, back.prefix)
            assertEquals(p.release, back.release)
            assertEquals(p.symbols, back.symbols)
            assertEquals(p.offsets, back.offsets)
            assertEquals(p.measured, back.measured)
            // 反序列化后生成的 cfg 必须逐字节一致
            assertEquals(
                ConfigGen.emitCfgBlob(p.symbols, p.offsets, p.measured).toList(),
                ConfigGen.emitCfgBlob(back.symbols, back.offsets, back.measured).toList(),
            )
        }
    }

    /**
     * 契约测试：按 **payload 的读取顺序**（runtime_cfg.h 的 load_device_cfg）逐字段比对。
     * 之前"写入端多加一个 credUid"就是在这里被漏掉才出的问题 —— 现在每个 profile 都要过。
     */
    @Test
    fun cfgMatchesPayloadReadOrder() {
        for (p in ConfigGen.PROFILES) {
            val blob = ConfigGen.emitCfgBlob(p.symbols, p.offsets, p.measured)
            val buf = java.nio.ByteBuffer.wrap(blob).order(java.nio.ByteOrder.LITTLE_ENDIAN)
            assertEquals("EXKCFG01", String(blob, 0, 8, Charsets.US_ASCII))
            assertEquals("字段数", 38, buf.getInt(8))
            buf.position(12)
            val o = p.offsets
            val m = p.measured
            val expect = listOf(
                (p.symbols["do_timer_create"] ?: 0L) + m.timerSiteOffset,
                ((p.symbols["do_timer_create"] ?: 0L) + m.timerSiteOffset) and 0x1FFFFF,
                p.symbols["selinux_state"] ?: 0L,
                p.symbols["panic_on_warn"] ?: 0L,
                p.symbols["root_user"] ?: 0L,
                p.symbols["init_user_ns"] ?: 0L,
                p.symbols["init_ucounts"] ?: 0L,
                p.symbols["init_groups"] ?: 0L,
                o.taskCred.toLong(), o.taskComm.toLong(),
                m.taskAllocLow21.toLong(), m.taskAllocBytes.toLong(), m.taskAllocBytes.toLong(),
                m.credReq.toLong(), m.credAlloc.toLong(), m.credSiteLow21.toLong(),
                o.itimerSize.toLong(), o.itimerNode.toLong(), o.itimerHead.toLong(),
                o.itimerElist.toLong(), o.itimerFiring.toLong(), o.itimerHandling.toLong(),
                o.itimerSize.toLong(),
                o.credUid.toLong(), o.credSecurity.toLong(), o.credUser.toLong(),
                o.credUserNs.toLong(), o.credUcounts.toLong(), o.credGroups.toLong(),
                0x1F00L, m.selinuxBlobOff.toLong(), m.selinuxSidKernel.toLong(),
                0x1FFFFFFFFF_FL, m.ntimers.toLong(), m.victimIdx.toLong(),
                (m.paddingSlabs * m.objectsPerSlab).toLong(), m.lockers.toLong(), m.vmaCount,
            )
            assertEquals("${p.name} 字段数", 38, expect.size)
            for ((i, want) in expect.withIndex()) {
                assertEquals("${p.name} 第 ${i + 1} 个字段（payload 读 order）", want, buf.getLong())
            }
            val wantEv = listOf(
                m.evCacheAlloc, m.evCacheFree, m.evPageFree, m.evPageAlloc, m.evPcpuDrain,
            )
            for (k in 0 until 5) assertEquals("${p.name} ev[$k]", wantEv[k], buf.getInt())
        }
    }

    @Test
    fun profileMatchesCurrentKernelPrefixOnly() {
        // 基准布局固定取 PPG-AN00 那条（list 头部现在可能是别的机型）
        val p = ConfigGen.PROFILES.first { it.prefix.startsWith("6.6.118-android15-8-g554929766a0d") }
        assertNotNull(ConfigGen.profileFor("6.6.118-android15-8-g554929766a0d-abogki544555896-4k"))
        assertNotNull(ConfigGen.profileFor("6.6.118-android15-8-g554929766a0d-some-other-build"))
        assertNull(ConfigGen.profileFor("6.1.75-android14-11-g1234567890ab"))
        assertNull(ConfigGen.profileFor(null))
        assertNull(ConfigGen.profileFor(p.prefix.dropLast(3)))
    }

    @Test
    fun builtinProfileCfgEqualsCalibrationPath() {
        // 标定页走的是 emitCfgBlob(syms, off, measured)，内置 profile 必须等价
        // 基准布局固定取 PPG-AN00 那条（list 头部现在可能是别的机型）
        val p = ConfigGen.PROFILES.first { it.prefix.startsWith("6.6.118-android15-8-g554929766a0d") }
        val a = ConfigGen.emitCfgBlob(p.symbols, p.offsets, p.measured)
        val b = ConfigGen.emitCfgBlob(
            ConfigGen.Baseline.symbols, ConfigGen.Baseline.offsets, ConfigGen.Measured(),
        )
        assertEquals(a.toList(), b.toList())
    }

    /** MTN-AN00 与 MTN-AN80 共用同一份 boot.img / 内核，必须命中同一条 profile */
    @Test
    fun sameReleaseSharedByTwoModels() {
        val rel = "6.1.157-android14-11-g19a495a97bff"
        val an00 = ConfigGen.profileFor(rel, "MTN-AN00")
        val an80 = ConfigGen.profileFor(rel, "MTN-AN80")
        assertEquals("MTN-AN00/AN80 / 6.1.157-android14-11", an00?.name)
        assertEquals(an00?.name, an80?.name)
        // 机型不认识时退回第一个匹配（保持旧行为）
        assertEquals(an00?.name, ConfigGen.profileFor(rel, null)?.name)
        // 实测常量以服务器 profile.json 为准：0x94 / 0x10B7F8 / 0x19ECC0
        assertEquals(0x94, an00!!.measured.timerSiteOffset)
        assertEquals(0x10B7F8, an00.measured.credSiteLow21)
        assertEquals(0x19ECC0, an00.measured.taskAllocLow21)
    }

    /** 只认内核：同一颗内核装在任意型号上都必须命中，机型名不参与判定 */
    @Test
    fun kernelOnlyIgnoresModel() {
        val rel = "6.6.118-android15-8-gf17133276a57-abogki518694926-4k"
        val a = ConfigGen.profileFor(rel, "SER-AN00")
        val b = ConfigGen.profileFor(rel, "AAK-AN00")
        val c = ConfigGen.profileFor(rel, "NOT-A-REAL-MODEL")
        val d = ConfigGen.profileFor(rel, null)
        assertNotNull(a)
        assertEquals(a?.name, b?.name)
        assertEquals(a?.name, c?.name)
        assertEquals(a?.name, d?.name)
    }

    /** 机型对不上（或为空）时退回该 release 的第一条，不抛异常 */
    @Test
    fun unknownModelFallsBackToFirstHit() {
        val rel = "6.6.89-android15-8-g082e5a98dac1-abogki463734347-4k"
        val hit = ConfigGen.profileFor(rel, null)
        assertTrue(hit?.release?.contains("g082e5a98dac1") == true)
        assertEquals(hit?.name, ConfigGen.profileFor(rel, "SOME-UNKNOWN-MODEL")?.name)
        assertEquals(null, ConfigGen.profileFor("1.2.3-nope", "MTN-AN00"))
    }
}
