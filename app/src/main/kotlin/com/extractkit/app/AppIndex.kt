package com.extractkit.app

/** 应用列表里的一行（纯数据，便于单测）。 */
internal data class AppEntry(
    val pkg: String,
    val label: String,
    val isManager: Boolean,
) {
    /** 搜索用的合并串：名称 + 包名 */
    val haystack: String get() = "$label $pkg".lowercase()
}

private val MANAGER_HINTS = listOf("ksu", "suki", "kernelsu", "milk", "ksunext", "superuser", "magisk", "apatch", "root")

/** 包名像不像一个根管理器（不依赖安装列表）。 */
internal fun looksLikeManagerPkg(pkg: String): Boolean {
    val p = pkg.lowercase()
    return MANAGER_HINTS.any { p.contains(it) }
}

internal fun isKnownManager(pkg: String, known: Map<String, String>): Boolean =
    known.containsKey(pkg) || looksLikeManagerPkg(pkg)

/** 名称优先用已知中文标签，其次系统 label，最后回退包名。 */
internal fun displayName(pkg: String, label: String?, known: Map<String, String>): String =
    known[pkg] ?: label?.takeIf { it.isNotBlank() } ?: pkg

/** 选中非管理器时要二次确认。 */
internal fun needsConfirm(pkg: String, known: Map<String, String>): Boolean = false   // 选谁是用户的事，不拦

/** 按名称/包名过滤，保持原有顺序；空查询原样返回。 */
internal fun filterApps(apps: List<AppEntry>, query: String): List<AppEntry> {
    val q = query.trim().lowercase()
    if (q.isEmpty()) return apps
    return apps.filter { it.haystack.contains(q) }
}
