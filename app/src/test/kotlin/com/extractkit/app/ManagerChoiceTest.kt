package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ManagerChoiceTest {

    private val labels = linkedMapOf(
        "com.sukisu.ultra" to "SukiSU",
        "io.milksu.manager" to "MilkSU",
        "me.weishu.kernelsu" to "KernelSU",
    )
    private val order = labels.keys.toList()

    @Test
    fun overrideWinsWhenInstalled() {
        val c = ManagerChooser.choose(
            override = "io.milksu.manager",
            installed = setOf("com.sukisu.ultra", "io.milksu.manager"),
            order = order,
            labels = labels,
        )
        assertEquals("io.milksu.manager", c.pkg)
        assertEquals("MilkSU", c.label)
        assertFalse(c.auto)
        assertEquals(ManagerChooser.REASON_MANUAL, c.reason)
        assertEquals(listOf("com.sukisu.ultra", "io.milksu.manager"), c.installed)
    }

    @Test
    fun overrideIgnoredWhenNotInstalled() {
        val c = ManagerChooser.choose(
            override = "com.example.gone",
            installed = setOf("com.sukisu.ultra"),
            order = order,
            labels = labels,
        )
        assertEquals("com.sukisu.ultra", c.pkg)
        assertTrue(c.auto)
        assertEquals(ManagerChooser.REASON_ONLY, c.reason)
    }

    @Test
    fun overrideUnknownButInstalledIsRespected() {
        val c = ManagerChooser.choose(
            override = "com.example.other",
            installed = setOf("com.sukisu.ultra", "com.example.other"),
            order = order,
            labels = labels,
        )
        assertEquals("com.example.other", c.pkg)
        assertEquals("com.example.other", c.label)
        assertEquals(ManagerChooser.REASON_MANUAL_UNKNOWN, c.reason)
        assertFalse(c.auto)
    }

    @Test
    fun singleInstalledIsAuto() {
        val c = ManagerChooser.choose(null, setOf("io.milksu.manager"), order, labels)
        assertEquals("io.milksu.manager", c.pkg)
        assertTrue(c.auto)
        assertEquals("MilkSU", c.summary)
    }

    @Test
    fun multiInstalledPicksOrderHeadAndSaysSo() {
        val c = ManagerChooser.choose(
            null,
            setOf("me.weishu.kernelsu", "io.milksu.manager", "com.sukisu.ultra"),
            order,
            labels,
        )
        assertEquals("com.sukisu.ultra", c.pkg)
        assertEquals(3, c.installed.size)
        // 顺序必须按内置表，不按集合迭代顺序
        assertEquals(listOf("com.sukisu.ultra", "io.milksu.manager", "me.weishu.kernelsu"), c.installed)
        assertTrue(c.reason.contains("共 3 个已装"))
        assertTrue(c.summary.contains("共 3 个已装"))
    }

    @Test
    fun nothingInstalled() {
        val c = ManagerChooser.choose(null, emptySet(), order, labels)
        assertNull(c.pkg)
        assertTrue(c.installed.isEmpty())
        assertEquals(ManagerChooser.REASON_NONE, c.reason)
        assertEquals("未检测到 · 点这里手动选择", c.summary)
    }

    @Test
    fun blankOverrideIgnored() {
        val c = ManagerChooser.choose("  ", setOf("com.sukisu.ultra"), order, labels)
        assertEquals("com.sukisu.ultra", c.pkg)
        assertTrue(c.auto)
    }

    @Test
    fun manualLabelFallsBackToPackage() {
        val c = ManagerChooser.choose(
            "com.example.other",
            setOf("com.example.other"),
            order,
            labels,
        )
        assertEquals("com.example.other", c.label)
        assertTrue(c.summary.startsWith("手动 · "))
    }
}
