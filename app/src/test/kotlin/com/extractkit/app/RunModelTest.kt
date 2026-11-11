package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RunModelTest {

    @Test
    fun absentShizukuShowsInstall() {
        val b = bannerFor(ShellState.ABSENT, rooted = false, busy = false, stage = "", lastFail = null)
        assertEquals("环境受限", b.title)
        assertEquals(BannerAction.INSTALL_SHIZUKU, b.action)
    }

    @Test
    fun noPermissionAsksForGrant() {
        val b = bannerFor(ShellState.NO_PERM, rooted = false, busy = false, stage = "", lastFail = null)
        assertEquals("需要授权", b.title)
        assertEquals(BannerAction.REQUEST_PERM, b.action)
    }

    @Test
    fun grantedAndIdleIsReady() {
        val b = bannerFor(ShellState.CONNECTED, rooted = false, busy = false, stage = "", lastFail = null)
        assertEquals("就绪", b.title)
        assertEquals(BannerAction.NONE, b.action)
    }

    @Test
    fun busyShowsStage() {
        val b = bannerFor(ShellState.CONNECTED, rooted = false, busy = true, stage = "预检环境", lastFail = null)
        assertEquals("执行中", b.title)
        assertEquals("预检环境", b.sub)
    }

    @Test
    fun failureBeatsRooted() {
        val b = bannerFor(ShellState.CONNECTED, rooted = true, busy = false, stage = "", lastFail = "CHAIN_STOP:check_uid0")
        assertEquals("未成功", b.title)
        assertEquals(BannerAction.SHOW_LOG, b.action)
    }

    @Test
    fun failureWithoutShellAsksForPermission() {
        val b = bannerFor(ShellState.NO_PERM, rooted = false, busy = false, stage = "", lastFail = "CHAIN_STOP:check_uid0")
        assertEquals("需要授权", b.title)
        assertEquals(BannerAction.REQUEST_PERM, b.action)
    }

    @Test
    fun rootedShowsOpenManager() {
        val b = bannerFor(ShellState.CONNECTED, rooted = true, busy = false, stage = "", lastFail = null)
        assertEquals("已提权", b.title)
        assertEquals(BannerAction.OPEN_MANAGER, b.action)
    }

    @Test
    fun autoOpenNeedsRootAndPackage() {
        assertTrue(shouldAutoOpenManager(ok = true, rooted = true, pkg = "io.milksu.manager"))
        assertFalse(shouldAutoOpenManager(ok = true, rooted = false, pkg = "io.milksu.manager"))
        assertFalse(shouldAutoOpenManager(ok = false, rooted = true, pkg = "io.milksu.manager"))
        assertFalse(shouldAutoOpenManager(ok = true, rooted = true, pkg = null))
        assertFalse(shouldAutoOpenManager(ok = true, rooted = true, pkg = "  "))
    }

    @Test
    fun backendLabelFollowsPref() {
        assertEquals("CVE-2026-98937", backendOf(pref98937 = true))
        assertEquals("CVE-2026-98260", backendOf(pref98937 = false))
    }
}
