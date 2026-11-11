# 贡献指南

## 加一个内核 profile

1. 用官方固件包里的 `boot.img` / `Image`（不是整包 zip）在 App 的「标定」页解析；
2. 把解析结果里的 `release`、`prefix`（含 `g<hash>`）、符号地址、BTF 偏移、三个 call site 填进 `ConfigGen.BUILTIN_PROFILES`；
3. 在 `docs/supported-kernels.md` 里补一行，注明**是否真机验证过**（`真机` / `仅解析`）；
4. 跑 `./gradlew :app:testDebugUnitTest` —— `ConfigProfileTest` 会校验 `device.cfg` 的字节布局与 payload 读取顺序一致。

同一 `release` 下不同 build 必须分开写（按 `g<hash>`），不要合并、不要用「前 22 字符相同」判等。

## 提 PR 前

- `./gradlew :app:testDebugUnitTest` 全绿；
- `python tools/build_payload.py` 后 `SHA256SUMS.txt` 与 `PayloadCatalog.kt` 同步（`PayloadCatalogTest` 会查）；
- 不要在日志、截图、测试数据里留设备序列号、`android_id`、卡密、他人服务器的 token。

## 代码风格

Kotlin：4 空格缩进、`val` 优先、公开 API 写 KDoc 说明「为什么这么做」而不只是「做了什么」。
C payload：只用 `syscall()` 直调，不依赖 bionic 的封装；任何可能 panic 的写操作前必须有前置校验。
