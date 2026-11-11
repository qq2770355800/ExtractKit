package com.extractkit.app

/**
 * 提权流程的阶段映射。
 *
 * payload 的日志是唯一可信的进度来源 —— 它每一步都会打点，所以界面不该只显示
 * "running"，而应该把日志映射成阶段：tracefs → direct map → 泄漏 → 回收 →
 * 写原语 → fake cred → KernelSU → 交接。
 *
 * 危险状态也在这里识别：一旦出现 "parking" / "exhausted retries" / "holding zombie"，
 * 说明 exploit 已经放弃写入并**故意按住僵尸进程**（那块页承载着活着的 cred），
 * 此时绝不能 kill，只能重启。
 */
object StageMap {

    enum class Stage(val order: Int, val title: String, val patterns: List<String>) {
        PREFLIGHT(0, "环境前提（shell / tracefs）", listOf("[check]", "preflight", "tracefs=")),
        TRACE(1, "开启 tracefs 事件", listOf("[probe]", "enable_event")),
        BASEMAP(2, "解 direct map 基址", listOf("[base]", "direct map base")),
        LEAK(3, "泄漏 cred / task_struct", listOf("[cred]", "cred leak")),
        RECLAIM(4, "slab 回收与堆喷", listOf("[+] plant", "slab padding", "burst hit", "burst missed")),
        WRITE(5, "写原语落地", listOf("[+] stage", "cred writes landed")),
        CRED(6, "fake cred / 关 SELinux", listOf("[fake]", "fake cred a=")),
        KSU(7, "KernelSU late-load", listOf("[ksu]", "kernelsu")),
        HANDOFF(8, "交接 root", listOf("[child]", "[verify]", "root handed", "su -c id")),
        DONE(9, "完成", listOf("[+] done")),
        ;

        companion object {
            val ALL = entries.sortedBy { it.order }
        }
    }

    /** 已经放弃写入、进程必须留活着的状态。 */
    private val parkedPatterns = listOf(
        "parking without reap",
        "exhausted retries",
        "holding zombie",
        "kernel_state_corrupted",
        "no successful plant",
    )

    /** 明确的内核异常。 */
    private val fatalPatterns = listOf(
        "kernel panic",
        "bug: ",
        "unable to handle kernel",
        "oops",
        "general protection fault",
    )

    data class Hit(val stage: Stage?, val parked: Boolean, val fatal: Boolean)

    fun classify(rawLine: String): Hit? {
        val line = rawLine.lowercase()
        if (line.isBlank()) return null

        val parked = parkedPatterns.any { line.contains(it) }
        val fatal = fatalPatterns.any { line.contains(it) }
        val stage = Stage.ALL.firstOrNull { s -> s.patterns.any { line.contains(it) } }
        if (stage == null && !parked && !fatal) return null
        return Hit(stage, parked, fatal)
    }

    fun label(stage: Stage): String = "[${stage.order + 1}/${Stage.ALL.size}] ${stage.title}"
}
