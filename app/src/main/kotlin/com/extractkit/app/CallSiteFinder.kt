package com.extractkit.app

/**
 * 从内核 Image 里反汇编出三处 call site。
 *
 * 背景：这三处是 `_RET_IP_ & 0x1fffff`，属于"代码布局"常量 —— BTF / kallsyms 都给不出来，
 * 所以以前只能手填，等于把 payload 钉死在某个内核 build 上。
 *
 * 但其实它们可以算：
 *
 *   do_timer_create  里  bl kmem_cache_alloc       的返址低 21 位  = timer site
 *   prepare_creds    里  bl kmem_cache_alloc       的返址低 21 位  = cred site
 *   copy_process     里  bl kmem_cache_alloc_node  的返址低 21 位  = task site
 *
 * 做法：kallsyms 给出函数与 callee 的链接期地址，Image 里 file_off = va - _text，
 * 逐条解码 4 字节指令，`(insn & 0xFC000000) == 0x94000000` 就是 BL，imm26 左移 2 得目标。
 *
 * 已用真机镜像验证：解出 0x1afcec / 0x38458 / 0x1cb240，与手工标定值逐位一致。
 */
object CallSiteFinder {

    data class Result(
        /** do_timer_create 入口到 bl 后一条指令的字节偏移，即 device_config.h 里的 TIMER_OFF */
        val timerOffset: Int,
        val timerLow21: Int,
        val credLow21: Int,
        val taskLow21: Int,
        /** 绝对地址（含 base），98937 后端的内核表要用 */
        val timerAbs: Long = 0,
        val credAbs: Long = 0,
        val taskAbs: Long = 0,
        /** 被调函数名、返址等，便于在标定页展示 */
        val detail: List<String>,
    )

    // 0xFC000000 / 0x94000000 超过 Int 范围，用等价的有符号常量
    private const val BL_MASK = -0x04000000
    private const val BL_OP = -0x6C000000
    private const val SPAN = 0x1200      // 函数体最多扫 4.5 KiB
    private const val THUNK_WINDOW = 0x80L   // CFI 存根一般紧贴目标函数之前

    /**
     * @param image   raw arm64 Image（从 boot.img 切出来的那段）
     * @param syms    kallsyms 结果（name → 链接期地址）
     * @param textVa  `_text` 的地址；Image 偏移 0 对应它
     */
    fun find(image: ByteArray, syms: Map<String, Long>, textVa: Long): Result? {
        // 只保留关心的 callee；名字归一化（CFI 内核里会有 kmem_cache_alloc.cfi_jt 桩）
        val wantedAt = ArrayList<Long>()
        val wantedName = ArrayList<String>()
        for ((rawName, a) in syms) {
            val n = rawName.substringBefore(".cfi_jt")
            if (n.startsWith("kmem_cache_alloc")) {
                wantedAt.add(a)
                wantedName.add(if (rawName.endsWith(".cfi_jt")) "$n@jt" else n)
            }
        }
        if (wantedAt.isEmpty()) return null
        val order = wantedAt.indices.sortedBy { wantedAt[it] }
        val allocAddrs = LongArray(order.size) { wantedAt[order[it]] }
        val allocNames = Array(order.size) { wantedName[order[it]] }

        val timer = syms["do_timer_create"] ?: return null
        val cred = syms["prepare_creds"] ?: return null
        val task = syms["copy_process"] ?: return null

        val detail = ArrayList<String>(3)

        // do_timer_create: 取第一条 bl kmem_cache_alloc（不带 _node）
        val timerHit = firstBl(image, timer, textVa, allocAddrs, allocNames, "kmem_cache_alloc")
        timerHit?.let { detail.add("do_timer_create +0x${(it.first - timer).toString(16)} → ${it.second}") }
            ?: detail.add("do_timer_create ✗ 没找到 kmem_cache_alloc 调用")

        val credHit = firstBl(image, cred, textVa, allocAddrs, allocNames, "kmem_cache_alloc")
        credHit?.let { detail.add("prepare_creds   +0x${(it.first - cred).toString(16)} → ${it.second}") }
            ?: detail.add("prepare_creds   ✗ 没找到 kmem_cache_alloc 调用")

        val hasNode = allocNames.any { it.startsWith("kmem_cache_alloc_node") }
        val taskCallee = if (hasNode) "kmem_cache_alloc_node" else "kmem_cache_alloc"
        val taskHit = firstBl(image, task, textVa, allocAddrs, allocNames, taskCallee)
        taskHit?.let { detail.add("copy_process    +0x${(it.first - task).toString(16)} → ${it.second}") }
            ?: detail.add("copy_process    ✗ 没找到 $taskCallee 调用")

        return Result(
            timerOffset = timerHit?.let { (it.first - timer).toInt() } ?: 0,
            timerLow21 = timerHit?.let { (it.first and 0x1FFFFF).toInt() } ?: 0,
            timerAbs = timerHit?.first ?: 0,
            credLow21 = credHit?.let { (it.first and 0x1FFFFF).toInt() } ?: 0,
            credAbs = credHit?.first ?: 0,
            taskLow21 = taskHit?.let { (it.first and 0x1FFFFF).toInt() } ?: 0,
            taskAbs = taskHit?.first ?: 0,
            detail = detail,
        )
    }

    /**
     * 返回 (返址, 被调符号名)；返址 = bl 的下一条指令地址。
     *
     * **thunk 感知**：开了 KCFI/CONFIG_CFI_CLANG 的内核里，`bl` 打到的是目标函数
     * 前面几十字节的校验存根（实测 6.1 上是 `kmem_cache_alloc - 0x38`），所以
     * 「目标落在某个 kmem_cache_alloc* 的 [addr-0x80, addr] 区间内」也算命中。
     */
    private fun firstBl(
        image: ByteArray,
        fnVa: Long,
        textVa: Long,
        allocAddrs: LongArray,
        allocNames: Array<String>,
        callee: String,
    ): Pair<Long, String>? {
        val start = fnVa - textVa
        if (start < 0 || start >= image.size) return null
        var off = start
        val end = minOf(start + SPAN, (image.size - 4).toLong())
        while (off <= end) {
            val insn = readU32(image, off.toInt())
            if ((insn and BL_MASK) == BL_OP) {
                var imm = insn and 0x03FFFFFF
                if ((imm and 0x02000000) != 0) imm -= 0x04000000     // 符号扩展 imm26
                val pcVa = fnVa + (off - start)
                val target = pcVa + (imm.toLong() shl 2)
                val name = resolveCallee(target, allocAddrs, allocNames, callee)
                if (name != null) return (pcVa + 4) to name
            }
            off += 4
        }
        return null
    }

    /** 精确命中，或目标落在目标函数前 0x80（CFI 存根）也算。 */
    private fun resolveCallee(
        target: Long,
        allocAddrs: LongArray,
        allocNames: Array<String>,
        callee: String,
    ): String? {
        var lo = 0
        var hi = allocAddrs.size - 1
        var pos = -1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            if (allocAddrs[mid] <= target + THUNK_WINDOW) { pos = mid; lo = mid + 1 } else hi = mid - 1
        }
        if (pos < 0) return null
        val addr = allocAddrs[pos]
        if (target > addr + THUNK_WINDOW) return null
        val raw = allocNames[pos]
        val name = raw.removeSuffix("@jt")
        // 允许：目标 == 符号；目标在符号前 0x80（CFI 存根）；目标在符号后 0x80（kallsyms
        // 记的是函数体，调用点可能落在外层 prelude 之后）
        if (kotlin.math.abs(target - addr) > THUNK_WINDOW) return null
        val okName = if (callee == "kmem_cache_alloc") {
            name == "kmem_cache_alloc"
        } else {
            name == callee
        }
        return if (okName) name else null
    }

    private fun readU32(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xFF) or
            ((b[o + 1].toInt() and 0xFF) shl 8) or
            ((b[o + 2].toInt() and 0xFF) shl 16) or
            ((b[o + 3].toInt() and 0xFF) shl 24)
}
