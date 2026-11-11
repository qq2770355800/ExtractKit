package com.extractkit.app

/**
 * 根管理器选择结果。
 *
 * 这一层的存在理由：管理器包名最终会被 payload 当作 `ksud late-load --package-name`，
 * 一旦选错（比如同时装了 SukiSU 和 MilkSU，却永远取表里第一个），提权看似成功、
 * 实际驱动注册到了另一个管理器，用选中的那个打开就是「没越狱」。
 * 所以选择逻辑抽成纯函数，可测、可解释（reason 会打到日志里）。
 */
data class ManagerChoice(
    /** 最终会用哪个包名；null = 一个已知管理器都没装 */
    val pkg: String?,
    /** 展示名（未知包名回落包名本身） */
    val label: String,
    /** true = 自动检测，false = 用户手动指定 */
    val auto: Boolean,
    /** 当前设备上已安装的已知管理器（按内置表顺序） */
    val installed: List<String>,
    /** 给日志/界面的解释文案 */
    val reason: String,
) {
    /** 副标题文案：自动且装了多个时把数量说清楚，避免「为什么是它」 */
    val summary: String
        get() = when {
            pkg == null -> "未检测到 · 点这里手动选择"
            !auto -> "手动 · $label"
            installed.size > 1 -> "自动 · $label（共 ${installed.size} 个已装）"
            else -> label
        }
}

object ManagerChooser {

    const val REASON_MANUAL = "手动选择"
    const val REASON_MANUAL_UNKNOWN = "手动选择（非已知管理器）"
    const val REASON_ONLY = "自动检测（唯一已装）"
    const val REASON_NONE = "未检测到已知管理器"

    /**
     * @param override 用户长按「根管理器」手选的包名
     * @param installed 设备上已安装的包名集合
     * @param order 内置管理器的优先级顺序
     * @param labels 包名 → 展示名
     */
    fun choose(
        override: String?,
        installed: Collection<String>,
        order: List<String>,
        labels: Map<String, String>,
    ): ManagerChoice {
        val present = order.filter { installed.contains(it) }

        // 手动指定优先：只要它确实装着就尊重，哪怕不是已知管理器
        val manual = override?.takeIf { it.isNotBlank() && installed.contains(it) }
        if (manual != null) {
            val isKnown = order.contains(manual)
            return ManagerChoice(
                pkg = manual,
                label = labels[manual] ?: manual,
                auto = false,
                installed = present,
                reason = if (isKnown) REASON_MANUAL else REASON_MANUAL_UNKNOWN,
            )
        }

        if (present.isEmpty()) {
            return ManagerChoice(null, "", true, emptyList(), REASON_NONE)
        }

        val picked = present.first()
        val label = labels[picked] ?: picked
        val reason = if (present.size == 1) {
            REASON_ONLY
        } else {
            "自动检测（共 ${present.size} 个已装，用了 $label）"
        }
        return ManagerChoice(picked, label, true, present, reason)
    }
}
