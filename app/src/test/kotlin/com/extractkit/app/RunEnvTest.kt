package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * 管理器包名消毒/前缀拼接的契约测试。
 *
 * 这个前缀会被拼进 shell 命令（`EXTRACTKIT_MGR=x ./payload`），所以任何
 * 空格 / 分号 / 引号 / 反引号都必须被丢掉，否则能在 root 子进程里注入命令。
 */
class RunEnvTest {
    @Test
    fun prefixWrapsNormalPackage() {
        assertEquals(
            "EXTRACTKIT_MGR=com.milksu.manager ",
            RunEnv.prefix("com.milksu.manager"),
        )
    }

    @Test
    fun prefixEmptyForNullOrBlank() {
        assertEquals("", RunEnv.prefix(null))
        assertEquals("", RunEnv.prefix(""))
    }

    @Test
    fun sanitizeDropsShellMetacharacters() {
        assertEquals("commilk", RunEnv.sanitizePkg("com;milk"))
        assertEquals("com milksu".replace(" ", ""), RunEnv.sanitizePkg("com milksu"))
        assertEquals("commilksu", RunEnv.sanitizePkg("com`milk`su"))
        assertEquals("com.milk_su", RunEnv.sanitizePkg("com.milk_su"))
    }

    @Test
    fun sanitizeReturnsNullWhenNothingLegalRemains() {
        assertNull(RunEnv.sanitizePkg(";|&$"))
        assertNull(RunEnv.sanitizePkg("   "))
    }

    @Test
    fun sanitizeTruncatesTo64() {
        val long = "a".repeat(100)
        val got = RunEnv.sanitizePkg(long)
        assertEquals(64, got!!.length)
    }

    /** 回归守卫：环境变量必须贴在 payload 前面，不能贴在 cd 前面。 */
    @Test
    fun commandPutsEnvOnPayloadNotCd() {
        val cmd = RunEnv.command(
            "/data/local/tmp/extract-kit",
            "cve-2026-98260-uid0",
            "",
            "io.milksu.manager",
        )
        assertEquals(
            "cd /data/local/tmp/extract-kit && EXTRACTKIT_MGR=io.milksu.manager ./cve-2026-98260-uid0",
            cmd,
        )
        assert(!cmd.startsWith("EXTRACTKIT_MGR")) { "env 不能贴在 cd 前面：$cmd" }
    }

    @Test
    fun commandKeepsArgsAndFallsBackWithoutPkg() {
        val cmd = RunEnv.command("/w", "bin", "fake --cpu 3", null)
        assertEquals("cd /w && ./bin fake --cpu 3", cmd)
    }
}
