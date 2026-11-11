package com.extractkit.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GlassStateTest {

    @Test
    fun suUidZeroIsRecognised() {
        assertTrue(parseSuUid("uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0"))
        assertTrue(parseSuUid("uid=0(root) gid=0(root)"))
    }

    @Test
    fun shellUidIsNotRoot() {
        assertFalse(parseSuUid("uid=2000(shell) gid=2000(shell)"))
        assertFalse(parseSuUid("su -c id: not found"))
        assertFalse(parseSuUid(""))
    }

    @Test
    fun uidPrefixedByLongerNumbersDoesNotMatch() {
        // uid=10000 之类的不能被当成 uid=0
        assertFalse(parseSuUid("uid=10000(u0_a0) gid=10000(u0_a0)"))
    }
}
