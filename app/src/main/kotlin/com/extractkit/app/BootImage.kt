package com.extractkit.app

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Android boot image 头解析（v0~v4）+ 内嵌 BTF 抽取。
 *
 * 只需要两件事：
 *   1. 从 boot.img 里把 arm64 的 kernel Image 切出来（KallsymsFinder 要扫它）
 *   2. Image 里通常内嵌 .BTF（magic 9f eb 01 00 18 00 00 00），直接切一段出来
 *
 * 设备上 shell 读不到 /sys/kernel/btf/vmlinux（SELinux），所以走 boot.img 这条路。
 */
object BootImage {

    data class Info(
        val headerVersion: Int,
        val kernelOffset: Long,
        val kernelSize: Int,
        val pageSize: Int,
    )

    private val MAGIC = "ANDROID!".toByteArray(Charsets.US_ASCII)
    private val VENDOR_MAGIC = "VNDRBOOT".toByteArray(Charsets.US_ASCII)
    private val ARM64_MAGIC = byteArrayOf('A'.code.toByte(), 'R'.code.toByte(), 'M'.code.toByte(), 0x64)

    class Unsupported(message: String) : Exception(message)

    /** 返回 null 表示头不合法；抛 Unsupported 表示认得出但走不通（比如 vendor_boot）。 */
    fun parseHeader(head: ByteArray): Info? {
        if (head.size < 64) return null
        val buf = ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN)

        // 已经是裸 Image（有人直接把 kernel 存成 boot.img）
        if (head[0x38] == ARM64_MAGIC[0] && head[0x39] == ARM64_MAGIC[1] &&
            head[0x3A] == ARM64_MAGIC[2] && head[0x3B] == ARM64_MAGIC[3]
        ) {
            return Info(headerVersion = -1, kernelOffset = 0, kernelSize = head.size, pageSize = 4096)
        }

        if (!head.startsWith(MAGIC)) {
            if (head.startsWith(VENDOR_MAGIC)) throw Unsupported("这是 vendor_boot.img，请选 boot.img")
            return null
        }

        val kernelSize = buf.getInt(8)
        if (kernelSize <= 0) return null

        val headerVersion = buf.getInt(40)
        if (headerVersion in 3..4) {
            // v3/v4：kernel 固定在 4096 之后
            return Info(headerVersion, kernelOffset = 4096L, kernelSize = kernelSize, pageSize = 4096)
        }

        // v0~v2：page_size 在 36
        val pageSize = buf.getInt(36)
        if (pageSize in intArrayOf(2048, 4096, 8192, 16384, 32768, 65536)) {
            return Info(headerVersion, kernelOffset = pageSize.toLong(), kernelSize = kernelSize, pageSize = pageSize)
        }
        return null
    }

    /** 从输入流里按 Info 切出 kernel Image（只读需要的那一段，boot.img 整体可能有 100 MB）。 */
    fun readKernel(stream: java.io.FileInputStream, info: Info, maxBytes: Int = 64 * 1024 * 1024): ByteArray {
        val size = minOf(info.kernelSize, maxBytes)
        val out = ByteArray(size)
        stream.channel.position(info.kernelOffset)
        var read = 0
        while (read < size) {
            val n = stream.read(out, read, size - read)
            if (n <= 0) break
            read += n
        }
        return if (read == size) out else out.copyOf(read)
    }

    /** Image 里的内核版本串，找不到就返回 null。 */
    fun kernelRelease(image: ByteArray): String? {
        val needle = "Linux version ".toByteArray(Charsets.US_ASCII)
        val at = indexOf(image, needle, 0, image.size) ?: return null
        var end = at
        while (end < image.size && end - at < 200 && image[end] != 0.toByte()) end++
        val line = String(image, at, end - at, Charsets.ISO_8859_1)
        // "Linux version 6.6.118-... (kleaf@build-host) ..."
        return line.removePrefix("Linux version ").substringBefore(' ').takeIf { it.isNotBlank() }
    }

    /** 在 Image 里找内嵌 BTF 并切出完整 BTF blob（header + types + strings）。 */
    fun extractBtf(image: ByteArray): ByteArray? {
        val magic = byteArrayOf(0x9f.toByte(), 0xeb.toByte(), 0x01, 0x00, 0x18, 0x00, 0x00, 0x00)
        val at = indexOf(image, magic, 0, image.size) ?: return null
        if (at + 24 > image.size) return null
        val buf = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN)
        val hdrLen = buf.getInt(at + 4)
        val typeOff = buf.getInt(at + 8)
        val typeLen = buf.getInt(at + 12)
        val strOff = buf.getInt(at + 16)
        val strLen = buf.getInt(at + 20)
        if (hdrLen <= 0 || typeLen <= 0 || strLen <= 0) return null
        val total = hdrLen + maxOf(typeOff + typeLen, strOff + strLen)
        if (total <= 0 || at + total > image.size) return null
        return image.copyOfRange(at, at + total)
    }

    private fun indexOf(hay: ByteArray, needle: ByteArray, from: Int, to: Int): Int? {
        val limit = minOf(to, hay.size) - needle.size
        var i = from
        outer@ while (i <= limit) {
            for (j in needle.indices) {
                if (hay[i + j] != needle[j]) {
                    i++
                    continue@outer
                }
            }
            return i
        }
        return null
    }

    private fun ByteArray.startsWith(prefix: ByteArray): Boolean {
        if (size < prefix.size) return false
        for (i in prefix.indices) if (this[i] != prefix[i]) return false
        return true
    }
}
