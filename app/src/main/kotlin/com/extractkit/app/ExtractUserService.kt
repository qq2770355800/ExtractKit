package com.extractkit.app

import android.content.Context
import android.os.ParcelFileDescriptor
import android.system.Os
import androidx.annotation.Keep
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.RandomAccessFile

/**
 * 运行在 Shizuku 提供的 shell 上下文里（uid 2000，`u:r:shell:s0`）。
 *
 * 这里只做三件事：起进程、把输出搬回来、把文件落盘。
 * 利用逻辑全部在被执行的 payload 里，本类不碰内核。
 */
@Keep
class ExtractUserService(@Suppress("UNUSED_PARAMETER") context: Context) : IExtractService.Stub() {

    private companion object {
        const val MAX_CAPTURE = 512 * 1024
        const val WORK_DIR = "/data/local/tmp/extract-kit"
        const val CHUNK = 8192
    }

    private var sink: FileOutputStream? = null
    private var sinkPath: String? = null

    override fun execStream(command: String, out: ParcelFileDescriptor): Int {
        var process: Process? = null
        try {
            process = newProcess(command)
            val source: InputStream = process.inputStream
            ParcelFileDescriptor.AutoCloseOutputStream(out).use { target ->
                val buf = ByteArray(CHUNK)
                while (true) {
                    val n = source.read(buf)
                    if (n <= 0) break
                    target.write(buf, 0, n)
                    target.flush()
                }
            }
            return process.waitFor()
        } catch (t: Throwable) {
            // 客户端提前关掉读端会在这里抛 IOException：收掉进程，别留孤儿
            runCatching { process?.destroy() }
            return -1
        }
    }

    override fun exec(command: String): String {
        var process: Process? = null
        return try {
            process = newProcess(command)
            val buffer = ByteArrayOutputStream()
            val buf = ByteArray(CHUNK)
            val input: InputStream = process.inputStream
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                if (buffer.size() + n > MAX_CAPTURE) {
                    buffer.write(buf, 0, MAX_CAPTURE - buffer.size())
                    break
                }
                buffer.write(buf, 0, n)
            }
            val code = process.waitFor()
            "$code\n" + buffer.toString(Charsets.UTF_8.name())
        } catch (t: Throwable) {
            runCatching { process?.destroy() }
            "-1\n$t"
        }
    }

    override fun fileOpen(path: String) {
        runCatching { File(path).parentFile?.mkdirs() }
        runCatching { sink?.close() }
        sink = FileOutputStream(path, false)
        sinkPath = path
    }

    override fun fileWrite(chunk: ByteArray) {
        val out = sink ?: throw IllegalStateException("fileOpen() 还没调用")
        out.write(chunk)
        out.flush()
    }

    override fun fileClose(mode: Int) {
        val out = sink
        runCatching { out?.fd?.sync() }
        runCatching { out?.close() }
        sink = null
        val path = sinkPath ?: return
        sinkPath = null
        runCatching { Os.chmod(path, mode) }
    }

    override fun readAt(path: String, offset: Long, length: Int): ByteArray {
        if (length <= 0) return ByteArray(0)
        return try {
            RandomAccessFile(path, "r").use { file ->
                val size = file.length()
                if (offset >= size) return ByteArray(0)
                val want = minOf(length.toLong(), size - offset).toInt()
                val buffer = ByteArray(want)
                file.seek(offset)
                var read = 0
                while (read < want) {
                    val n = file.read(buffer, read, want - read)
                    if (n <= 0) break
                    read += n
                }
                if (read == want) buffer else buffer.copyOf(read)
            }
        } catch (t: Throwable) {
            ByteArray(0)
        }
    }

    override fun destroy() {
        runCatching { sink?.close() }
        runCatching { System.exit(0) }
    }

    // ------------------------------------------------------------------ 内部

    private fun newProcess(command: String): Process {
        val work = File(WORK_DIR)
        runCatching { work.mkdirs() }
        val builder = ProcessBuilder("sh", "-c", command)
        runCatching { builder.directory(work) }
        builder.redirectErrorStream(true)
        val env = builder.environment()
        env["PATH"] = "/system/bin:/system/xbin:/vendor/bin:$WORK_DIR"
        env["HOME"] = WORK_DIR
        return builder.start()
    }
}
