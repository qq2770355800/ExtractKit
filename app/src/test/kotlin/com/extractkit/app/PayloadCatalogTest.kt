package com.extractkit.app

import java.io.File
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 守住 `PayloadCatalog` 与 `app/src/main/assets/payload` 的一致性。
 *
 * 这条测试的由来：9.25 里 fam/6.1 的 sha 被写成了上一版二进制的值，装机后
 * `! sha256 不匹配 / 期望 3758680049… / 实际 a85757dcf…`，部署阶段直接中止。
 * 只靠人工比对哈希迟早复发，所以在编译期就把两者钉在一起。
 */
class PayloadCatalogTest {

    private fun sha256(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(1 shl 16)
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    private fun assetsRoot(): File =
        listOf("src/main/assets", "app/src/main/assets")
            .map { File(it) }
            .firstOrNull { it.isDirectory }
            ?: error("找不到 assets 目录（cwd=${File(".").absolutePath}）")

    private fun allPayloads(): List<Payload> =
        listOf(Payloads.UID0, Payloads.ANDROID) + Payloads.PER_FAMILY.values

    @Test
    fun everyPayloadExistsWithMatchingSha() {
        val root = assetsRoot()
        val failures = mutableListOf<String>()

        for (p in allPayloads()) {
            val f = File(root, p.asset)
            if (!f.isFile) {
                failures += "${p.asset} 不存在（catalog 里叫 ${p.name}）"
                continue
            }
            val real = sha256(f)
            if (!real.equals(p.sha256, ignoreCase = true)) {
                failures += "${p.asset}: catalog=${p.sha256.take(16)} 实际=${real.take(16)}"
            }
            assertTrue("${p.asset} 体积异常（${f.length()} B）", f.length() > 1_000)
        }

        assertTrue(
            "catalog 与 assets 不一致：\n" + failures.joinToString("\n"),
            failures.isEmpty(),
        )
    }

    @Test
    fun sha256SumsCoversEveryAssetPayload() {
        val root = assetsRoot()
        val sums = File(root, "payload/SHA256SUMS.txt")
        assertTrue("SHA256SUMS.txt 不存在", sums.isFile)

        val listed = sums.readLines()
            .filter { it.isNotBlank() }
            .associate { line ->
                val idx = line.indexOf("  ")
                require(idx > 0) { "SHA256SUMS 行格式不对: $line" }
                line.substring(idx + 2).trim() to line.substring(0, idx).trim()
            }

        for (p in allPayloads()) {
            val rel = p.asset.removePrefix("payload/")
            assertEquals(
                "SHA256SUMS 里 ${p.asset} 的哈希与 catalog 不一致",
                p.sha256,
                listed[rel],
            )
        }
    }
}
