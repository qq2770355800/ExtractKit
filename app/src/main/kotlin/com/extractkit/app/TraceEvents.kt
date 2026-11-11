package com.extractkit.app

/**
 * 从 tracefs 读 kmem 事件的 id。
 *
 * 这几个 id 是"构建期常量"（tracepoint 注册顺序决定），不同内核 build 都不一样。
 * 只在 shell 能读 `events/kmem/<name>/id` 的设备上可用；读不到就返回 null，
 * 由调用方回落到 cfg / 内置 profile 里的默认值。
 */
object TraceEvents {

    private val NAMES = listOf(
        "kmem_cache_alloc",
        "kmem_cache_free",
        "mm_page_alloc",
        "mm_page_free",
        "mm_page_pcpu_drain",
    )

    /** 顺序与 Measured 的 evCacheAlloc/evCacheFree/evPageAlloc/evPageFree/evPcpuDrain 一致。 */
    fun read(onLog: (String) -> Unit = {}): IntArray? {
        val out = IntArray(5)
        for ((i, n) in NAMES.withIndex()) {
            val (code, txt) = Shell.exec("cat /sys/kernel/tracing/events/kmem/$n/id 2>/dev/null")
            val v = txt.trim().toIntOrNull()
            if (code != 0 || v == null || v <= 0) {
                onLog("· 读不到 events/kmem/$n/id，用默认值")
                return null
            }
            out[i] = v
        }
        onLog("✓ 事件 id 读取成功：${out.joinToString()}")
        return out
    }
}
