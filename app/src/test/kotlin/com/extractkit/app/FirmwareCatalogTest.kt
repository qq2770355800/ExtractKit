package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Test

class FirmwareCatalogTest {

    /** contextNo 必须是 W + 8 位零填充，否则荣耀的接口直接 404。 */
    @Test
    fun contextNoIsZeroPadded() {
        assertEquals("W00061100", IknowResolver.contextNo("61100"))
        assertEquals("W00067373", IknowResolver.contextNo("67373"))
        assertEquals("W12345678", IknowResolver.contextNo("12345678"))
        // 带空白/非数字也能收拾干净
        assertEquals("W00061100", IknowResolver.contextNo(" 61100 "))
    }

    @Test
    fun humanSizeFormats() {
        assertEquals("未知大小", IknowResolver.humanSize(-1))
        assertEquals("2 KB", IknowResolver.humanSize(2048))
        assertEquals("3.0 MB", IknowResolver.humanSize(3L * 1024 * 1024))
        assertEquals("5.00 GB", IknowResolver.humanSize(5L shl 30))
    }
}
