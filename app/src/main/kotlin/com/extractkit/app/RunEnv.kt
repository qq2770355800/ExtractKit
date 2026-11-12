package com.extractkit.app

/**
 * 传给 payload 的运行环境变量。
 *
 * payload 用 `EXTRACTKIT_MGR` 决定给哪个根管理器注册（`ksud late-load
 * --package-name`）。以前这里写死 com.sukisu.ultra，选 MilkSU / KernelSU Next
 * 之类的分支管理器就会出现「提权成功但管理器显示未工作」——驱动注册的包名和
 * 用户选的不一致。
 *
 * 包名会拼进 shell 命令，所以只放行 `[A-Za-z0-9._]`；其它字符一律丢弃，
 * 全丢光就返回 null（payload 侧回落到默认包名）。
 */
object RunEnv {
    private const val MAX_LEN = 64

    /** 过滤出合法包名；空串 / 全非法 / 超长（截断后为空）都返回 null。 */
    fun sanitizePkg(raw: String?): String? {
        if (raw.isNullOrEmpty()) return null
        val sb = StringBuilder()
        for (c in raw) {
            if (sb.length >= MAX_LEN) break
            if (c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '.' || c == '_') {
                sb.append(c)
            }
        }
        return if (sb.isEmpty()) null else sb.toString()
    }

    /** `EXTRACTKIT_MGR=<pkg> `（带尾随空格，直接当前缀拼）；无有效包名返回空串。 */
    fun prefix(pkg: String?): String {
        val safe = sanitizePkg(pkg) ?: return ""
        return "EXTRACTKIT_MGR=$safe "
    }

    /**
     * 组装实际执行的命令。
     *
     * 环境变量必须贴在**要被赋值的命令**前面：`VAR=x cd dir && ./bin` 只给 cd
     * 设了变量，`./bin` 一点都拿不到（这个坑真踩过，表现就是管理器选了没用）。
     */
    fun command(
        workDir: String,
        name: String,
        args: String,
        pkg: String?,
        slideHex: String? = null,
    ): String {
        val tail = if (args.isBlank()) "" else " $args"
        val slide = if (slideHex.isNullOrBlank()) "" else "EXTRACTKIT_SLIDE=$slideHex "
        return "cd $workDir && $slide${prefix(pkg)}./$name$tail"
    }
}
