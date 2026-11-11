package com.extractkit.app

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import rikka.shizuku.Shizuku
import java.io.InputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * shell 上下文访问层。
 *
 * Shizuku 的 `newProcess()` 是 private 的，普通 App 只能通过 **UserService** 拿到
 * 以 shell(uid 2000) 身份运行的进程，所以这里的正路是：
 *
 *   Shizuku.bindUserService()  →  ExtractUserService(跑在 shell 上下文)
 *        →  exec / execStream / pushFile
 *
 * 没有 Shizuku 授权时所有方法都返回失败，不会退回本地进程 —— 本机 uid 打不动内核。
 */
object Shell {

    const val PERMISSION_REQUEST = 4101

    @Volatile
    private var service: IExtractService? = null

    @Volatile
    private var boundConnection: ServiceConnection? = null

    @Volatile
    private var boundArgs: Shizuku.UserServiceArgs? = null

    @Volatile
    private var lastError: String? = null

    /** 记住最近一次 connect 的 Context，binder 失效时用来原地重连。 */
    @Volatile
    private var appContext: Context? = null

    fun alive(): Boolean = try {
        Shizuku.pingBinder()
    } catch (t: Throwable) {
        false
    }

    fun granted(): Boolean = try {
        alive() && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
    } catch (t: Throwable) {
        false
    }

    fun requestPermission() {
        runCatching { if (alive()) Shizuku.requestPermission(PERMISSION_REQUEST) }
    }

    fun providerUid(): Int = try {
        if (alive()) Shizuku.getUid() else -1
    } catch (t: Throwable) {
        -1
    }

    fun connected(): Boolean = service != null && isAlive()

    private fun isAlive(): Boolean = try {
        service?.asBinder()?.isBinderAlive == true
    } catch (t: Throwable) {
        false
    }

    fun error(): String? = lastError

    /**
     * 绑定 UserService。**必须在非主线程调用**：ServiceConnection 回调走主线程，
     * 在主线程上等 latch 会自己把自己锁死。
     */
    fun connect(ctx: Context, timeoutMs: Long = 25_000): Boolean {
        if (service != null && isAlive()) return true
        // 还拿着旧连接但已经不通了：先解绑，避免又起一个新进程
        if (boundConnection != null) disconnect()
        if (!granted()) {
            lastError = "Shizuku 未授权"
            return false
        }
        lastError = null

        val app = ctx.applicationContext
        appContext = app
        val args = Shizuku.UserServiceArgs(
            ComponentName(app.packageName, ExtractUserService::class.java.name),
        )
            .daemon(false)
            .processNameSuffix("shell")
            .debuggable(false)
            .version(BuildConfig.VERSION_CODE)

        val latch = CountDownLatch(1)
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                service = runCatching { IExtractService.Stub.asInterface(binder) }.getOrNull()
                if (service == null) lastError = "UserService binder 转换失败"
                latch.countDown()
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                service = null
                lastError = "UserService 已断开"
                latch.countDown()
            }
        }
        boundConnection = connection

        Handler(Looper.getMainLooper()).post {
            runCatching { Shizuku.bindUserService(args, connection) }
                .onFailure {
                    lastError = "bind 失败：$it"
                    latch.countDown()
                }
        }

        val done = runCatching { latch.await(timeoutMs, TimeUnit.MILLISECONDS) }.getOrDefault(false)
        if (!done || service == null) {
            if (lastError == null) lastError = "UserService 连接超时"
            runCatching { Shizuku.unbindUserService(args, connection, true) }
            boundConnection = null
            boundArgs = null
            return false
        }
        boundArgs = args
        return true
    }

    fun disconnect() {
        val args = boundArgs
        val conn = boundConnection
        if (args != null && conn != null) {
            runCatching { Shizuku.unbindUserService(args, conn, false) }
        }
        service = null
        boundConnection = null
        boundArgs = null
    }

    // -------------------------------------------------------------- 一次性执行

    fun exec(command: String): Pair<Int, String> {
        val svc = service ?: return -1 to (lastError ?: "UserService 未连接")
        return try {
            val raw = svc.exec(command)
            val idx = raw.indexOf('\n')
            if (idx < 0) {
                -1 to raw
            } else {
                (raw.substring(0, idx).toIntOrNull() ?: -1) to raw.substring(idx + 1)
            }
        } catch (t: Throwable) {
            -1 to t.toString()
        }
    }

    // ---------------------------------------------------------------- 推文件

    fun pushFile(path: String, bytes: ByteArray, executable: Boolean = true): Pair<Int, String> {
        var tries = 0
        while (true) {
            val svc = service ?: return -1 to (lastError ?: "UserService 未连接")
            val r = try {
                svc.fileOpen(path)
                val step = 256 * 1024
                var offset = 0
                while (offset < bytes.size) {
                    val n = minOf(step, bytes.size - offset)
                    svc.fileWrite(bytes.copyOfRange(offset, offset + n))
                    offset += n
                }
                svc.fileClose(if (executable) 493 else 420)
                0 to ""
            } catch (t: Throwable) {
                -1 to t.toString()
            }
            if (r.first == 0 || tries >= 1) return r
            // 重装或管理器刷新会让 UserService 进程换代：旧的 binder 还能 exec，
            // 但 fileOpen 已经在死进程里跑过 → "fileOpen() 还没调用"。
            // 这里断掉重连一次再推，避免整条链在部署阶段就失败。
            tries++
            disconnect()
            val ctx = appContext ?: return r
            connect(ctx)
        }
    }

    // ---------------------------------------------------------------- 读文件

    /**
     * 从 shell 侧整块读文件（/sys/kernel/btf/vmlinux 有 5~10 MiB，必须分块，
     * binder 单次事务上限 1 MiB）。
     */
    fun readFile(path: String, maxBytes: Long = 32L * 1024 * 1024): ByteArray? {
        val svc = service ?: run {
            lastError = lastError ?: "UserService 未连接"
            return null
        }
        val out = java.io.ByteArrayOutputStream()
        val step = 256 * 1024
        var offset = 0L
        while (offset < maxBytes) {
            val chunk = try {
                svc.readAt(path, offset, step)
            } catch (t: Throwable) {
                lastError = "读 $path 失败：$t"
                return null
            } ?: return null
            if (chunk.isEmpty()) break
            out.write(chunk)
            offset += chunk.size
            if (chunk.size < step) break
        }
        return out.toByteArray()
    }

    // ---------------------------------------------------------------- 流式执行

    class StreamSession internal constructor(
        val input: InputStream,
        private val exit: AtomicInteger,
        private val done: CountDownLatch,
        private val readEnd: ParcelFileDescriptor,
    ) {
        fun exitCodeOrNull(): Int? = if (done.count == 0L) exit.get() else null

        fun close() {
            runCatching { input.close() }
            runCatching { readEnd.close() }
        }
    }

    fun stream(command: String): StreamSession? {
        val svc = service ?: return null
        val pipe = ParcelFileDescriptor.createPipe()
        val readEnd = pipe[0]
        val writeEnd = pipe[1]
        val input = ParcelFileDescriptor.AutoCloseInputStream(readEnd)
        val code = AtomicInteger(Int.MIN_VALUE)
        val done = CountDownLatch(1)

        Thread {
            try {
                code.set(svc.execStream(command, writeEnd))
            } catch (t: Throwable) {
                code.set(-1)
            } finally {
                runCatching { writeEnd.close() }
                done.countDown()
            }
        }.apply {
            isDaemon = true
            name = "extract-stream"
        }.start()

        return StreamSession(input, code, done, readEnd)
    }
}
