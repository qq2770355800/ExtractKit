package com.extractkit.app

import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * 本地镜像 Harness：设了 `EXTRACTKIT_IMAGE` 才跑，否则整类跳过。
 *
 * 用来在一台新机器上验证「无 BTF」或「有 BTF」两条解析链路，
 * 例如：
 *
 * ```
 * EXTRACTKIT_IMAGE=/path/to/boot.img ./gradlew :app:testDebugUnitTest --tests '*LocalImageTest*'
 * ```
 *
 * 因为镜像动辄几十 MB，不可能进仓库，所以默认 assume 跳过。
 */
class LocalImageCalibTest {

    private fun load(path: String): ByteArray? = runCatching {
        val f = File(path)
        if (!f.isFile) return null
        val head = f.inputStream().use { it.readNBytes(8192) }
        if (head.size >= 64 && String(head, 0, 8, Charsets.US_ASCII) == "ANDROID!") {
            val size = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN).getInt(8)
            RandomAccessFile(f, "r").use { raf ->
                raf.seek(4096)
                ByteArray(size).also { raf.readFully(it) }
            }
        } else {
            f.readBytes()
        }
    }.getOrNull()

    @Test
    fun parsesImageAndProducesCfg() {
        val path = System.getenv("EXTRACTKIT_IMAGE")
        assumeTrue("未设置 EXTRACTKIT_IMAGE，跳过本地镜像测试", !path.isNullOrBlank())

        val img = load(path!!)
        assertTrue("读不到内核镜像：$path", img != null && img.size > 1 shl 20)

        val ks = KallsymsFinder.find(img!!)
        assertTrue("kallsyms 解析失败", ks != null)
        assertTrue("符号数量异常：${ks!!.symbols.size}", ks.symbols.size > 20_000)
        assertEquals(
            "relative_base 必须是页对齐",
            ks.relativeBase,
            ks.relativeBase and 0xFFFF_FFFF_FFFF_F000uL.toLong(),
        )
        println("[local] symbols=${ks.symbols.size} base=${"0x%016x".format(ks.relativeBase)}")

        val btf = BootImage.extractBtf(img)
        println("[local] btf=${if (btf == null) "none" else "${btf.size} B"}")
    }
}
