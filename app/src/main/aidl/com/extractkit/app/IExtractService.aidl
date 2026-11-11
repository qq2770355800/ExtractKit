package com.extractkit.app;

import android.os.ParcelFileDescriptor;

/**
 * ExtractKit 的 Shizuku UserService 接口。
 *
 * 这个 Stub 由 Shizuku 以 shell(uid 2000 / u:r:shell:s0) 身份加载，
 * 所有 payload 都在这个进程里被 fork 出来 —— 这才是提取需要的上下文。
 */
interface IExtractService {

    /** 执行命令，stdout+stderr 合并写入 sink；阻塞到进程结束，返回 exit code。 */
    int execStream(String command, in ParcelFileDescriptor sink);

    /** 一次性执行，返回 "exitCode\n<合并输出>"（输出上限 512 KiB）。 */
    String exec(String command);

    /** 分块推文件（binder 单次事务有 1 MiB 上限，客户端按 256 KiB 切）。 */
    void fileOpen(String path);

    void fileWrite(in byte[] chunk);

    /** mode 是八进制数值，例如 0755 = 493。 */
    void fileClose(int mode);

    /** 从 shell 侧读文件（BTF / tracefs 之类 app 进不去的地方），分块调用。 */
    byte[] readAt(String path, long offset, int length);

    void destroy();
}
