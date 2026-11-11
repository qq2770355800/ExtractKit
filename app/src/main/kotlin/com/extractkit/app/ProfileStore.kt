package com.extractkit.app

import java.io.File

/**
 * 本机导入/自建的 profile 存取。
 *
 * 格式是行式的 `key=value`（不用 JSON：手写解析更稳、diff 友好、单元测试不依赖 org.json）。
 *
 * ```
 * # ExtractKit profile v1
 * name=MTN-AN80 / 6.1.157
 * prefix=6.1.157-android14-11-g19a495a97bff
 * release=6.1.157-android14-11-g19a495a97bff
 * sym.do_timer_create=0xffffffc0083be82c
 * off.itimerSize=0x108
 * meas.timerSiteOffset=0x5c
 * ev=269,272,273,275,277
 * ```
 *
 * 用途：标定页选一次 boot.img → 保存为 profile；同内核的其他设备导入后直接"已适配"，
 * 连 boot.img 都不用。
 */
object ProfileStore {

    private const val MAGIC = "# ExtractKit profile v1"

    fun dir(ctx: android.content.Context): File =
        File(ctx.filesDir, "profiles").apply { mkdirs() }

    fun listFiles(ctx: android.content.Context): List<File> =
        dir(ctx).listFiles { f -> f.isFile && f.name.endsWith(".profile") }?.sortedBy { it.name }
            ?: emptyList()

    fun loadAll(ctx: android.content.Context): List<ConfigGen.Profile> =
        listFiles(ctx).mapNotNull { runCatching { parse(it.readText()) }.getOrNull() }

    /** 前缀匹配（与内置 profile 同一套规则）。 */
    fun match(ctx: android.content.Context, release: String?): ConfigGen.Profile? {
        if (release.isNullOrBlank()) return null
        return loadAll(ctx).firstOrNull { release.startsWith(it.prefix) }
    }

    fun save(ctx: android.content.Context, p: ConfigGen.Profile): File {
        val safe = p.prefix.replace(Regex("[^A-Za-z0-9._-]"), "_").take(64)
        val f = File(dir(ctx), "$safe.profile")
        f.writeText(serialize(p))
        return f
    }

    fun serialize(p: ConfigGen.Profile): String = buildString {
        appendLine(MAGIC)
        appendLine("name=${p.name}")
        appendLine("prefix=${p.prefix}")
        appendLine("release=${p.release}")
        if (p.timerLink != 0L) appendLine("link.timer=" + hex(p.timerLink))
        if (p.credLink != 0L) appendLine("link.cred=" + hex(p.credLink))
        for ((k, v) in p.symbols) appendLine("sym.$k=${hex(v)}")
        val o = p.offsets
        appendLine("off.itimerSize=${hex(o.itimerSize.toLong())}")
        appendLine("off.itimerNode=${hex(o.itimerNode.toLong())}")
        appendLine("off.itimerHead=${hex(o.itimerHead.toLong())}")
        appendLine("off.itimerElist=${hex(o.itimerElist.toLong())}")
        appendLine("off.itimerFiring=${hex(o.itimerFiring.toLong())}")
        appendLine("off.itimerHandling=${hex(o.itimerHandling.toLong())}")
        appendLine("off.taskCred=${hex(o.taskCred.toLong())}")
        appendLine("off.taskComm=${hex(o.taskComm.toLong())}")
        appendLine("off.credSize=${hex(o.credSize.toLong())}")
        appendLine("off.credUid=${hex(o.credUid.toLong())}")
        appendLine("off.credSecurity=${hex(o.credSecurity.toLong())}")
        appendLine("off.credUser=${hex(o.credUser.toLong())}")
        appendLine("off.credUserNs=${hex(o.credUserNs.toLong())}")
        appendLine("off.credUcounts=${hex(o.credUcounts.toLong())}")
        appendLine("off.credGroups=${hex(o.credGroups.toLong())}")
        val m = p.measured
        appendLine("meas.timerSiteOffset=${hex(m.timerSiteOffset.toLong())}")
        appendLine("meas.credSiteLow21=${hex(m.credSiteLow21.toLong())}")
        appendLine("meas.taskAllocLow21=${hex(m.taskAllocLow21.toLong())}")
        appendLine("meas.taskAllocBytes=${hex(m.taskAllocBytes.toLong())}")
        appendLine("meas.credReq=${hex(m.credReq.toLong())}")
        appendLine("meas.credAlloc=${hex(m.credAlloc.toLong())}")
        appendLine("meas.ntimers=${m.ntimers}")
        appendLine("meas.victimIdx=${m.victimIdx}")
        appendLine("meas.objectsPerSlab=${m.objectsPerSlab}")
        appendLine("meas.paddingSlabs=${m.paddingSlabs}")
        appendLine("meas.lockers=${m.lockers}")
        appendLine("meas.vmaCount=${m.vmaCount}")
        appendLine("meas.selinuxBlobOff=${hex(m.selinuxBlobOff.toLong())}")
        appendLine("meas.selinuxSidKernel=${m.selinuxSidKernel}")
        appendLine("ev=${m.evCacheAlloc},${m.evCacheFree},${m.evPageFree},${m.evPageAlloc},${m.evPcpuDrain}")
    }

    fun parse(text: String): ConfigGen.Profile? {
        val kv = HashMap<String, String>()
        for (line in text.lineSequence()) {
            val t = line.trim()
            if (t.isEmpty() || t.startsWith("#")) continue
            val i = t.indexOf('=')
            if (i <= 0) continue
            kv[t.substring(0, i)] = t.substring(i + 1)
        }
        val prefix = kv["prefix"] ?: return null
        val release = kv["release"] ?: prefix
        val name = kv["name"] ?: prefix

        fun num(key: String, def: Int = 0): Int = kv[key]?.let { parseNum(it)?.toInt() } ?: def
        fun lng(key: String, def: Long = 0L): Long = kv[key]?.let { parseNum(it) } ?: def

        val syms = HashMap<String, Long>()
        for ((k, v) in kv) if (k.startsWith("sym.")) {
            parseNum(v)?.let { syms[k.removePrefix("sym.")] = it }
        }
        // offsets-only profile 只带 4 个 cred 锚点，没有 text 符号 —— 与 emitCfgBlob 的校验保持一致
        if (!ConfigGen.ANCHOR_SYMBOLS.all { it in syms }) return null

        val off = Offsets(
            itimerSize = num("off.itimerSize"),
            itimerNode = num("off.itimerNode"),
            itimerHead = num("off.itimerHead"),
            itimerElist = num("off.itimerElist"),
            itimerFiring = num("off.itimerFiring"),
            itimerHandling = num("off.itimerHandling"),
            taskCred = num("off.taskCred"),
            taskComm = num("off.taskComm"),
            credSize = num("off.credSize"),
            credUid = num("off.credUid", 8),
            credSecurity = num("off.credSecurity"),
            credUser = num("off.credUser"),
            credUserNs = num("off.credUserNs"),
            credUcounts = num("off.credUcounts"),
            credGroups = num("off.credGroups"),
        )
        val ev = (kv["ev"] ?: "269,272,273,275,277").split(',').mapNotNull { it.trim().toIntOrNull() }
        val m = ConfigGen.Measured(
            evCacheAlloc = ev.getOrElse(0) { 269 },
            evCacheFree = ev.getOrElse(1) { 272 },
            evPageFree = ev.getOrElse(2) { 273 },
            evPageAlloc = ev.getOrElse(3) { 275 },
            evPcpuDrain = ev.getOrElse(4) { 277 },
            timerSiteOffset = num("meas.timerSiteOffset"),
            credSiteLow21 = num("meas.credSiteLow21"),
            credReq = num("meas.credReq"),
            credAlloc = num("meas.credAlloc"),
            taskAllocLow21 = num("meas.taskAllocLow21"),
            taskAllocBytes = num("meas.taskAllocBytes"),
            objectsPerSlab = num("meas.objectsPerSlab", 31),
            paddingSlabs = num("meas.paddingSlabs", 150),
            ntimers = num("meas.ntimers", 4096),
            victimIdx = num("meas.victimIdx", 2048),
            lockers = num("meas.lockers", 3),
            vmaCount = lng("meas.vmaCount", 50000),
            selinuxBlobOff = num("meas.selinuxBlobOff", 8),
            selinuxSidKernel = num("meas.selinuxSidKernel", 1),
        )
        return ConfigGen.Profile(
            name, prefix, release, syms, off, m,
            timerLink = lng("link.timer"), credLink = lng("link.cred"),
        )
    }

    private fun parseNum(s: String): Long? {
        val t = s.trim()
        return when {
            t.startsWith("0x") || t.startsWith("0X") -> t.substring(2).toULongOrNull(16)?.toLong()
            else -> t.toLongOrNull()
        }
    }

    private fun hex(v: Long) = "0x" + java.lang.Long.toHexString(v)
}
