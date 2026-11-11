# 来源与致谢

- **CVE-2026-98260**：内核 POSIX CPU timer 的 UAF 链路由公开研究披露；本仓库的 payload 是按公开原理独立实现的（含 fake cred、`selinux_state` 处理、`ksud late-load` 编排）。
- `app/src/main/assets/payload/cve-2026-98260-android`：公开 PoC 的 Android 移植版（aio spray + oracle），仅用于对照实验，不是主链。
- **[AndroidLiquidGlass](https://github.com/Kyant0/AndroidLiquidGlass)**（`io.github.kyant0:backdrop`）：`glass/` 下的源码按其许可证使用并做了本地化改造（去 Compose Multiplatform 依赖、加 Android 平台的 `RuntimeShader` 适配）。
- **Shizuku**：提供 shell 上下文（`IExtractService`）。
- **KernelSU / SukiSU / MilkSU / KernelSU-Next**：`ksud` 取自设备上已安装的管理器 APK，本仓库不打包任何管理器的二进制。
- 内置 profile 的镜像来自荣耀官方固件包；本仓库不包含任何第三方付费服务的数据。
