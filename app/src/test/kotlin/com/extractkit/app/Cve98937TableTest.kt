package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class Cve98937TableTest {

    private val ppg = """
        release = "6.6.118-android15-8-g554929766a0d-abogki544555896-4k"
        vuln_type = "cve-2026-98937"
        page_offset = -551903297536
        offset = {
          task_cred = 2080
          task_struct_size = 4800
          cred_uid = 8
          cred_size = 184
          cred_security = 128
          cred_user = 136
          cred_user_ns = 144
          cred_ucounts = 152
          cred_groups = 160
          kitimer_size = 264
          kitimer_node = 120
          timer_link = -272726557460
          cred_link = -272728095656
          selinux_link = -272692960232
          user_ns = -272695234664
          root_user = -272695234008
          groups = -272695228536
          ucounts = -272695227144
        }
    """.trimIndent()

    @Test
    fun negativeLinksDecodeToKernelAddresses() {
        val t = Cve98937Tables.parse(ppg)
        assertEquals(-272726557460L, t.timerLink)
        assertEquals(-272728095656L, t.credLink)
        assertEquals(-272692960232L, t.selinuxLink)
        assertEquals(-551903297536L, t.pageOffset)
        assertEquals(0x820, t.taskCred)
        assertEquals(0x108, t.kitimerSize)
        assertEquals(0xb8, t.credSize)
    }

    @Test
    fun blobIs308BytesAndFramed() {
        val b = Cve98937.blob(Cve98937Tables.parse(ppg))
        assertEquals(312, b.size)
        val buf = ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN)
        assertEquals(308, buf.getInt())
        assertEquals("C982", String(b, 4, 4, Charsets.US_ASCII))
        // 版本 + recommend
        assertEquals(4, b[8].toInt())      // version 低字节
        assertEquals(0, b[9].toInt())      // version 高字节
        assertEquals(1, b[10].toInt())     // recommend_shizuku 低字节
    }
}
