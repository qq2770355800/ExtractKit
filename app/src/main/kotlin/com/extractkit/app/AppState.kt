package com.extractkit.app

/**
 * 跨界面/跨引擎的共享标记。
 * 原来放在 MainActivity.companion 里，Compose 首页读不到，现在抽出来。
 */
object AppState {
    /** 标定页生成/下发后置 true，首页下次 onResume 时重新探测一次 */
    @Volatile
    var needsReprobe = false

    /** 上次选用的是否 98937 后端（仅用于界面展示） */
    @Volatile
    var lastBackend98937 = false
}
