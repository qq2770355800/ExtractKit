package com.extractkit.app

import java.io.File
import java.io.RandomAccessFile
import java.net.HttpURLConnection
import java.net.URL

/**
 * 从荣耀全量包里**只取 boot / init_boot / vendor_boot**，不下载整包。
 *
 * 全量包是标准 ZIP（可能是 ZIP64），里面的 `Software/dload/update_sd_base.zip`
 * 又是第二个 ZIP，镜像放在它的 `image/` 目录。两个 ZIP 的成员大多是 **stored**
 * （method 0），所以：
 *
 *  1. `Range: bytes=…` 读外层 EOCD → 中央目录 → 找到 update_sd_base.zip；
 *  2. 读它的 local header 算出数据起点，再读它的 EOCD / 中央目录；
 *  3. 只对 `image/boot.img`、`image/init_boot.img`（可选 vendor_boot）发 Range；
 *  4. 用原始字节重新打一个 zip（保留 method / crc / 大小），落盘给标定页用。
 *
 * 若某个镜像在包里是 deflate（method 8），仍然只下载它自己那一段压缩数据，
 * 原样塞进输出 zip，解压交给调用方。
 */
object FirmwareBootExtractor {

    private const val UA =
        "Mozilla/5.0 (Linux; Android 17) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Mobile"

    private const val SIG_EOCD = 0x06054b50
    private const val SIG_EOCD64 = 0x06064b50
    private const val SIG_LOCATOR64 = 0x07064b50
    private const val SIG_CD = 0x02014b50
    private const val SIG_LFH = 0x04034b50

    /** 中央目录里的一条记录（偏移已换算成「整个远端文件里的绝对偏移」）。 */
    data class Entry(
        val name: String,
        val method: Int,
        val crc: Long,
        val compSize: Long,
        val size: Long,
        val dataOffset: Long,
    )

    data class Plan(
        val entries: List<Entry>,
        val bytesToFetch: Long,
        val skipped: List<String>,
        /** 内层 zip 的数据起点；流式解压从这儿开始读。 */
        val nestedOffset: Long = 0,
        /** 镜像被 deflate 压过时只能顺序解压（读到需要的成员就停）。 */
        val streaming: Boolean = false,
    )

    class Failure(message: String) : Exception(message)

    // ---------------------------------------------------------------- HTTP

    private fun open(url: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            instanceFollowRedirects = false
            connectTimeout = 12_000
            readTimeout = 20_000
            setRequestProperty("User-Agent", UA)
        }

    /** 1 字节探测总长度（荣耀 CDN 不支持 HEAD）。 */
    fun lengthOf(url: String): Long {
        val c = open(url)
        return try {
            c.setRequestProperty("Range", "bytes=0-0")
            if (c.responseCode !in 200..299) throw Failure("HTTP ${c.responseCode}")
            val cr = c.getHeaderField("Content-Range")
            val total = cr?.substringAfter('/', "")?.toLongOrNull()
            total ?: c.getHeaderField("Content-Length")?.toLongOrNull()
            ?: throw Failure("拿不到包大小")
        } catch (e: Failure) {
            throw e
        } catch (t: Throwable) {
            throw Failure("连不上下载服务：${t.message}")
        } finally {
            c.disconnect()
        }
    }

    private fun readRange(url: String, start: Long, endInclusive: Long): ByteArray {
        if (endInclusive < start) return ByteArray(0)
        val c = open(url)
        return try {
            c.setRequestProperty("Range", "bytes=$start-$endInclusive")
            if (c.responseCode == 200) {
                // 服务端忽略了 Range，只能整包读——这里直接失败，避免偷偷下 10 GB
                throw Failure("服务端不支持分段下载")
            }
            if (c.responseCode !in 200..299) throw Failure("HTTP ${c.responseCode}")
            c.inputStream.use { it.readBytes() }
        } catch (e: Failure) {
            throw e
        } catch (t: Throwable) {
            throw Failure("下载中断：${t.message}")
        } finally {
            c.disconnect()
        }
    }

    private fun le16(b: ByteArray, o: Int) = (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8)
    private fun le32(b: ByteArray, o: Int): Long {
        var v = 0L
        for (i in 3 downTo 0) v = (v shl 8) or (b[o + i].toLong() and 0xff)
        return v
    }
    private fun le64(b: ByteArray, o: Int): Long {
        var v = 0L
        for (i in 7 downTo 0) v = (v shl 8) or (b[o + i].toLong() and 0xff)
        return v
    }

    // ---------------------------------------------------------------- ZIP

    private class Dir(val offset: Long, val size: Long, val count: Long)

    /** 找出（可能嵌套的）ZIP 的中央目录位置；`base` 是该 ZIP 在远端文件里的起点。 */
    private fun centralDirectory(url: String, base: Long, zipSize: Long): Dir {
        val tailLen = minOf(zipSize, 128L * 1024).toInt()
        val tailStart = base + zipSize - tailLen
        val tail = readRange(url, tailStart, tailStart + tailLen - 1)

        var eocd = -1
        var i = tail.size - 22
        while (i >= 0) {
            if (le32(tail, i) == SIG_EOCD.toLong()) {
                eocd = i
                break
            }
            i--
        }
        if (eocd < 0) throw Failure("这不是一个 ZIP（找不到 EOCD）")

        var cdSize = le32(tail, eocd + 12)
        var cdOff = le32(tail, eocd + 16)
        var count = le32(tail, eocd + 10)

        if (cdOff == 0xFFFFFFFFL || cdSize == 0xFFFFFFFFL || count == 0xFFFFL) {
            // ZIP64：EOCD 前面 20 字节是 locator
            var loc = -1
            var j = eocd - 20
            while (j >= 0) {
                if (le32(tail, j) == SIG_LOCATOR64.toLong()) {
                    loc = j
                    break
                }
                j--
            }
            if (loc < 0) throw Failure("ZIP64 结构损坏")
            val eocd64Abs = base + le64(tail, loc + 8)
            val hdr = readRange(url, eocd64Abs, eocd64Abs + 55)
            if (le32(hdr, 0) != SIG_EOCD64.toLong()) throw Failure("ZIP64 EOCD 损坏")
            count = le64(hdr, 32)
            cdSize = le64(hdr, 40)
            cdOff = le64(hdr, 48)
        }
        return Dir(base + cdOff, cdSize, count)
    }

    /** 读中央目录，顺便把每条记录的 local header 解出来换算数据起点。 */
    private fun entries(url: String, dir: Dir): List<Entry> {
        if (dir.size <= 0 || dir.size > 64L * 1024 * 1024) throw Failure("中央目录异常（${dir.size} B）")
        val cd = readRange(url, dir.offset, dir.offset + dir.size - 1)
        val out = ArrayList<Entry>()
        var p = 0
        while (p + 46 <= cd.size && le32(cd, p) == SIG_CD.toLong()) {
            val method = le16(cd, p + 10)
            val crc = le32(cd, p + 16)
            var comp = le32(cd, p + 20)
            var size = le32(cd, p + 24)
            val nameLen = le16(cd, p + 28)
            val extraLen = le16(cd, p + 30)
            val commentLen = le16(cd, p + 32)
            var localOff = le32(cd, p + 42)
            val name = String(cd, p + 46, nameLen, Charsets.UTF_8)

            // ZIP64 extra
            var e = p + 46 + nameLen
            val extraEnd = e + extraLen
            while (e + 4 <= extraEnd) {
                val id = le16(cd, e)
                val len = le16(cd, e + 2)
                if (id == 0x0001) {
                    var q = e + 4
                    if (size == 0xFFFFFFFFL && q + 8 <= e + 4 + len) { size = le64(cd, q); q += 8 }
                    if (comp == 0xFFFFFFFFL && q + 8 <= e + 4 + len) { comp = le64(cd, q); q += 8 }
                    if (localOff == 0xFFFFFFFFL && q + 8 <= e + 4 + len) { localOff = le64(cd, q); q += 8 }
                }
                e += 4 + len
            }

            // local header → 数据起点
            var dataOff = -1L
            if (comp > 0 && dir.offset >= 0) {
                val lfhAbs = dir.offset - dir.size + localOff
                val lfh = readRange(url, lfhAbs, lfhAbs + 29)
                if (le32(lfh, 0) == SIG_LFH.toLong()) {
                    val ln = le16(lfh, 26)
                    val le = le16(lfh, 28)
                    dataOff = lfhAbs + 30 + ln + le
                }
            }
            out.add(Entry(name, method, crc, comp, size, dataOff))
            p += 46 + nameLen + extraLen + commentLen
        }
        return out
    }

    // ---------------------------------------------------------------- plan

    private val BOOT_NAMES = listOf(
        "image/boot.img",
        "image/init_boot.img",
        "image/vendor_boot.img",
    )

    /**
     * 规划要抓哪些成员。`wantVendor` 为 false 时跳过 vendor_boot。
     * 抛出 [Failure] 表示这个包不支持分段提取（例如镜像本身被 deflate）。
     */
    fun plan(url: String, wantVendor: Boolean): Plan {
        val total = lengthOf(url)
        val outer = centralDirectory(url, 0L, total)
        val outerEntries = entries(url, outer)

        val nested = outerEntries.firstOrNull { it.name.endsWith("update_sd_base.zip") }
            ?: throw Failure("这个包里没有 update_sd_base.zip（结构不认识）")
        if (nested.method != 0) {
            throw Failure("update_sd_base.zip 在包内是压缩的，无法只取镜像")
        }
        if (nested.dataOffset < 0) throw Failure("读不到 update_sd_base.zip 的头部")

        val inner = centralDirectory(url, nested.dataOffset, nested.size)
        val innerEntries = entries(url, inner)

        val wanted = innerEntries.filter { e ->
            e.name in BOOT_NAMES && (wantVendor || !e.name.endsWith("vendor_boot.img"))
        }
        if (wanted.isEmpty()) throw Failure("包里没有 boot.img / init_boot.img")

        val skipped = ArrayList<String>()
        val ok = ArrayList<Entry>()
        for (e in wanted) {
            if (e.dataOffset < 0) skipped += "${e.name}（读不到头部）" else ok += e
        }
        if (ok.isEmpty()) throw Failure("镜像都取不到：${skipped.joinToString()}")

        // 成员是 deflate 时没法随机定位，只能从内层 zip 起点顺序解压
        val streaming = ok.any { it.method != 0 }
        return Plan(ok, ok.sumOf { it.compSize }, skipped, nested.dataOffset, streaming)
    }

    // ---------------------------------------------------------------- 输出 zip

    private fun putLe16(out: java.io.OutputStream, v: Int) {
        out.write(v and 0xff); out.write((v ushr 8) and 0xff)
    }

    private fun putLe32(out: java.io.OutputStream, v: Long) {
        for (i in 0 until 4) out.write(((v ushr (8 * i)) and 0xff).toInt())
    }

    /**
     * 顺序解压内层 zip：从 [Plan.nestedOffset] 开始读，读到需要的镜像就停。
     *
     * 全量包里的 `update_sd_base.zip` 多是 deflate，没法随机定位；但 `image/`
     * 目录在压缩流的前面，所以通常几百 MB 就能拿到 boot + init_boot。
     */
    fun extractStreaming(
        url: String,
        plan: Plan,
        outFile: File,
        onProgress: (Long, Long, String) -> Unit,
    ): File {
        val total = lengthOf(url)
        outFile.parentFile?.mkdirs()
        val conn = open(url)
        conn.setRequestProperty("Range", "bytes=${plan.nestedOffset}-")
        conn.connectTimeout = 12_000
        conn.readTimeout = 30_000

        val want = plan.entries.map { it.name }.toSet()
        val doneNames = LinkedHashSet<String>()
        var read = 0L

        try {
            java.util.zip.ZipInputStream(java.io.BufferedInputStream(conn.inputStream, 1 shl 16)).use { zis ->
                java.util.zip.ZipOutputStream(java.io.BufferedOutputStream(outFile.outputStream())).use { zos ->
                    val buf = ByteArray(1 shl 16)
                    while (true) {
                        val e = zis.nextEntry ?: break
                        val name = e.name
                        if (name in want && !doneNames.contains(name)) {
                            onProgress(read, total, name.substringAfterLast('/'))
                            zos.putNextEntry(java.util.zip.ZipEntry(name))
                            while (true) {
                                val n = zis.read(buf)
                                if (n <= 0) break
                                zos.write(buf, 0, n)
                                read += n
                                onProgress(read, total, name.substringAfterLast('/'))
                            }
                            zos.closeEntry()
                            doneNames += name
                            if (doneNames.size == want.size) break
                        } else if (doneNames.isNotEmpty() && !name.startsWith("image/")) {
                            break   // 已经拿到镜像，后面不再下
                        }
                    }
                }
            }
        } catch (t: Throwable) {
            outFile.delete()
            throw Failure("顺序解压失败：${t.message}")
        } finally {
            conn.disconnect()
        }
        if (doneNames.isEmpty()) {
            outFile.delete()
            throw Failure("压缩流里没有找到镜像")
        }
        return outFile
    }

    /**
     * 按计划抓取并写成一个 zip。`onProgress(done, total, currentName)`。
     * 返回写好的文件；中途失败会删掉半成品。
     */
    fun extract(
        url: String,
        plan: Plan,
        outFile: File,
        onProgress: (Long, Long, String) -> Unit,
    ): File {
        outFile.parentFile?.mkdirs()
        val total = plan.bytesToFetch
        var done = 0L
        val central = java.io.ByteArrayOutputStream()
        RandomAccessFile(outFile, "rw").use { raf ->
            raf.setLength(0)
            for (e in plan.entries) {
                onProgress(done, total, e.name.substringAfterLast('/'))
                val localOffset = raf.filePointer
                raf.write(byteArrayOf(0x50, 0x4b, 0x03, 0x04))
                val nameBytes = e.name.toByteArray(Charsets.UTF_8)
                val head = java.io.ByteArrayOutputStream()
                putLe16(head, 20)                    // version needed
                putLe16(head, 0)                     // flags
                putLe16(head, e.method)
                putLe16(head, 0)                     // time
                putLe16(head, 0)                     // date
                putLe32(head, e.crc)
                putLe32(head, e.compSize)
                putLe32(head, e.size)
                putLe16(head, nameBytes.size)
                putLe16(head, 0)                     // extra
                raf.write(head.toByteArray())
                raf.write(nameBytes)

                var copied = 0L
                val chunk = 4L * 1024 * 1024
                while (copied < e.compSize) {
                    val n = minOf(chunk, e.compSize - copied)
                    val buf = readRange(url, e.dataOffset + copied, e.dataOffset + copied + n - 1)
                    raf.write(buf)
                    copied += buf.size
                    done += buf.size
                    onProgress(done, total, e.name.substringAfterLast('/'))
                    if (buf.isEmpty()) break
                }

                val cd = java.io.ByteArrayOutputStream()
                putLe32(cd, SIG_CD.toLong())
                putLe16(cd, 20); putLe16(cd, 20); putLe16(cd, 0)
                putLe16(cd, e.method); putLe16(cd, 0); putLe16(cd, 0)
                putLe32(cd, e.crc); putLe32(cd, e.compSize); putLe32(cd, e.size)
                putLe16(cd, nameBytes.size); putLe16(cd, 0); putLe16(cd, 0)
                putLe16(cd, 0); putLe16(cd, 0)
                putLe32(cd, 0)
                putLe32(cd, localOffset)
                cd.write(nameBytes)
                central.write(cd.toByteArray())
            }
            val cdOffset = raf.filePointer
            raf.write(central.toByteArray())
            val eocd = java.io.ByteArrayOutputStream()
            putLe32(eocd, SIG_EOCD.toLong())
            putLe16(eocd, 0); putLe16(eocd, 0)
            putLe16(eocd, plan.entries.size); putLe16(eocd, plan.entries.size)
            putLe32(eocd, central.size().toLong())
            putLe32(eocd, cdOffset)
            putLe16(eocd, 0)
            raf.write(eocd.toByteArray())
        }
        return outFile
    }
}
