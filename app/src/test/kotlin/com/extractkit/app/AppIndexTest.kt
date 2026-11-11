package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppIndexTest {

    private val known = mapOf("io.milksu.manager" to "MilkSU", "com.sukisu.ultra" to "SukiSU")

    private val apps = listOf(
        AppEntry("io.milksu.manager", "MilkSU", true),
        AppEntry("com.sukisu.ultra", "SukiSU", true),
        AppEntry("com.tencent.mm", "微信", false),
        AppEntry("zhdgt8hny72.uy1o9bi3.ji6i7mytd27q", "空间应用", false),
    )

    @Test
    fun emptyQueryKeepsOrder() {
        assertEquals(apps, filterApps(apps, ""))
        assertEquals(apps, filterApps(apps, "   "))
    }

    @Test
    fun filtersByPackageSubstring() {
        val r = filterApps(apps, "milksu")
        assertEquals(1, r.size)
        assertEquals("io.milksu.manager", r[0].pkg)
    }

    @Test
    fun filtersByLabelIgnoringCase() {
        val r = filterApps(apps, "微信")
        assertEquals(1, r.size)
        assertEquals("com.tencent.mm", r[0].pkg)
    }

    @Test
    fun unknownQueryGivesEmpty() {
        assertTrue(filterApps(apps, "nothing-here").isEmpty())
    }

    @Test
    fun knownManagersNeedNoConfirm() {
        assertFalse(needsConfirm("io.milksu.manager", known))
        assertFalse(needsConfirm("com.sukisu.ultra", known))
    }

    @Test
    fun hintPackagesNeedNoConfirm() {
        assertFalse(needsConfirm("com.example.kernelsu.next", known))
        assertFalse(needsConfirm("org.foo.ksu", known))
        assertFalse(needsConfirm("com.bar.milkmanager", known))
    }

    @Test
    fun ordinaryAppAlsoAllowed() {
        // 选谁是用户的事：任何已装应用都不再要求二次确认
        assertFalse(needsConfirm("com.tencent.mm", known))
        assertFalse(needsConfirm("zhdgt8hny72.uy1o9bi3.ji6i7mytd27q", known))
    }

    @Test
    fun displayNamePrefersKnownThenLabelThenPkg() {
        assertEquals("MilkSU", displayName("io.milksu.manager", "MilkSU 0.2.3", known))
        assertEquals("微信", displayName("com.tencent.mm", "微信", known))
        assertEquals("com.x.y", displayName("com.x.y", "", known))
        assertEquals("com.x.z", displayName("com.x.z", null, known))
    }
}
