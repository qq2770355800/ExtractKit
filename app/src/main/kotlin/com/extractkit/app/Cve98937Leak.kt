package com.extractkit.app

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * CVE-2026-98937 泄露自检——**用我们自己的标定器**，不再带第三方 PoC。
 *
 * 漏洞本体：`perf_event_open` 只在 `!attr.exclude_kernel` 时才调
 * `perf_allow_kernel()`；设 `exclude_kernel=1` 同时保留
 * `PERF_SAMPLE_CALLCHAIN` + `exclude_callchain_kernel=0`，硬件 PMU 在 skid 时
 * 于内核上下文溢出，`perf_callchain_kernel()` 把内核栈帧写进 ring buffer。
 * 普通 shell 因此能拿到内核地址 → 反推 KASLR slide。
 *
 * 它**不是**提权原语；这里只用来回答「这台机器受不受影响、slide 是多少」。
 */
object Cve98937Leak {

    private const val WORK = "/data/local/tmp/extract-kit"
    private const val BIN = "$WORK/cve98937-calib"
    private const val ASSET = "payload/cve-2026-98937-calib"

    data class Result(
        val vulnerable: Boolean,
        val firstKernelIp: Long?,
        val frames: Int,
        val slide: Long?,
        val raw: String,
    )

    suspend fun deploy(ctx: Context): Boolean = withContext(Dispatchers.IO) {
        val bytes = runCatching { ctx.assets.open(ASSET).readBytes() }.getOrNull() ?: return@withContext false
        if (!Shell.connected() && !Shell.connect(ctx)) return@withContext false
        Shell.exec("mkdir -p $WORK")
        val (rc, _) = Shell.pushFile(BIN, bytes, executable = true)
        if (rc != 0) return@withContext false
        Shell.exec("chmod 755 $BIN")
        true
    }

    /** 跑一次标定器（约 1.5 秒），把泄露结果解析成结构。 */
    suspend fun run(ctx: Context, textSize: Long = 0x2A00000L): Result = withContext(Dispatchers.IO) {
        if (!Shell.connected() && !Shell.connect(ctx)) {
            return@withContext Result(false, null, 0, null, "shell 未就绪")
        }
        val (_, out) = Shell.exec("cd $WORK && CVE98937_HOME=/data/local/tmp ./cve98937-calib 2>&1")
        val frames = Regex("""\[perf\] leak=(\d+)""").find(out)?.groupValues?.get(1)?.toIntOrNull()
            ?: Regex("""frames=(\d+)""").find(out)?.groupValues?.get(1)?.toIntOrNull()
            ?: 0
        val slideHex = Regex("""SLIDE=(0x[0-9a-fA-F]+)""").find(out)?.groupValues?.get(1)
            ?: Regex("""\[perf\] slide=(0x[0-9a-fA-F]+)""").find(out)?.groupValues?.get(1)
            ?: Regex("""slide=(0x[0-9a-fA-F]+)""").find(out)?.groupValues?.get(1)
        val slide = slideHex?.removePrefix("0x")?.toLongOrNull(16)
        // 命中任何一帧内核地址就说明这台机器可泄露；有 slide 更加确定。
        val vulnerable = slide != null || frames > 0
        Result(vulnerable, null, frames, slide, out)
    }
}
