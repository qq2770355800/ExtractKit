package com.extractkit.app

import java.net.HttpURLConnection
import java.net.URL

/**
 * 把固件索引里的 contextId 换成真实下载直链。
 *
 * 荣耀的公开下载入口会 302 到一个带签名的直链：
 * ```
 * GET https://iknow.service.hihonor.com/weknow/servlet/download/public?contextNo=W00061100
 *  → 302 Location: https://iknow-dl.service.hihonor.com/ctkbfm/servlet/download/downloadServlet/<payload>.zip
 * ```
 * contextNo 的格式是 `W` + 8 位零填充的数字，所以 61100 → `W00061100`。
 */
object IknowResolver {

    private const val ENDPOINT =
        "https://iknow.service.hihonor.com/weknow/servlet/download/public?contextNo="
    private const val UA = "Mozilla/5.0 (Linux; Android 17) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Mobile"

    data class Resolved(val directUrl: String, val sizeBytes: Long)

    fun contextNo(contextId: String): String {
        val digits = contextId.filter { it.isDigit() }
        return "W" + digits.padStart(8, '0')
    }

    /** 解析出直链；失败返回 null（网络不通 / 该 contextId 已下架）。 */
    fun resolve(contextId: String): String? {
        val url = ENDPOINT + contextNo(contextId)
        val c = URL(url).openConnection() as HttpURLConnection
        return try {
            c.instanceFollowRedirects = false
            c.connectTimeout = 8000
            c.readTimeout = 12000
            c.setRequestProperty("User-Agent", UA)
            when (c.responseCode) {
                in 300..399 -> c.getHeaderField("Location")
                in 200..299 -> c.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
                    .takeIf { it.startsWith("http") }
                else -> null
            }
        } catch (_: Throwable) {
            null
        } finally {
            c.disconnect()
        }
    }

    /**
     * 拿包体大小。荣耀的 CDN 会拒 HEAD，所以用 `Range: bytes=0-0` 发一个 1 字节的 GET，
     * 从 `Content-Range: bytes 0-0/123456789` 里读出总长度。
     */
    fun sizeOf(directUrl: String): Long {
        val c = URL(directUrl).openConnection() as HttpURLConnection
        return try {
            c.connectTimeout = 8000
            c.readTimeout = 8000
            c.setRequestProperty("User-Agent", UA)
            c.setRequestProperty("Range", "bytes=0-0")
            when (c.responseCode) {
                206 -> c.getHeaderField("Content-Range")?.substringAfterLast('/')?.trim()?.toLongOrNull() ?: -1
                in 200..299 -> c.contentLengthLong
                else -> -1
            }
        } catch (_: Throwable) {
            -1
        } finally {
            c.disconnect()
        }
    }

    fun humanSize(bytes: Long): String = when {
        bytes <= 0 -> "未知大小"
        bytes >= 1L shl 30 -> String.format("%.2f GB", bytes / 1024.0 / 1024.0 / 1024.0)
        bytes >= 1L shl 20 -> String.format("%.1f MB", bytes / 1024.0 / 1024.0)
        else -> "${bytes / 1024} KB"
    }
}
