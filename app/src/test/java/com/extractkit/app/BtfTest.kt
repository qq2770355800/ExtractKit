package com.extractkit.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

/**
 * 用合成 BTF 校验 Kotlin 版读取器，fixture 由 tools/test-gen-config.py 的同一份
 * 构造器生成（Python 那边已经 PASS），两边必须给出一模一样的偏移。
 *
 * 跑法: ./gradlew :app:testDebugUnitTest
 */
class BtfTest {

    private fun resource(name: String): ByteArray =
        javaClass.classLoader!!.getResourceAsStream(name)!!.readBytes()

    @Test
    fun parsesStructOffsets() {
        val btf = Btf.parse(resource("vmlinux.btf"))
        val off = ConfigGen.offsetsFromBtf(btf)

        assertEquals(0x108, off.itimerSize)
        assertEquals(0x78, off.itimerNode)       // k_itimer → it(匿名 union) → cpu → node
        assertEquals(0x98, off.itimerHead)
        assertEquals(0xA8, off.itimerElist)
        assertEquals(0xB8, off.itimerFiring)
        assertEquals(0xC0, off.itimerHandling)

        assertEquals(0x820, off.taskCred)
        assertEquals(0x830, off.taskComm)

        assertEquals(0xB8, off.credSize)
        assertEquals(0x8, off.credUid)
        assertEquals(0x80, off.credSecurity)
        assertEquals(0x88, off.credUser)
        assertEquals(0x90, off.credUserNs)
        assertEquals(0x98, off.credUcounts)
        assertEquals(0xA0, off.credGroups)
    }

    @Test
    fun anonymousUnionIsResolved() {
        val btf = Btf.parse(resource("vmlinux.btf"))
        assertNotNull(btf.struct("k_itimer"))
        assertNotNull(btf.struct("task_struct"))
        assertNotNull(btf.struct("cred"))
        assertEquals(0x78, btf.memberOffset("k_itimer", "node"))
        assertEquals(null, btf.memberOffset("k_itimer", "no_such_member"))
    }
}
