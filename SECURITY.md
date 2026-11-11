# 安全说明

本项目实现的是**内核提权**，天然带有破坏性：

- 写错地址 → 内核 panic、设备重启；极端情况可能损坏 `/data`；
- 成功后进程驻留，**清理只能重启**；
- 部分机型 SELinux 策略会拒绝写 tracefs，此时成功率很低，不要反复重试（每次重试都会浪费一次 UAF 机会，同一 `boot_id` 只允许一次）。

请在**自己的设备**上使用。提交 issue 时不要贴完整日志里的序列号、`android_id`、他人卡密或服务器 token；贴之前把 `[mgr] manager package=`、`[guard] boot_id=` 之类无关行删掉即可。

发现本项目自身的漏洞（比如 profile 里带了错误的偏移导致必 panic），请开 issue 标 `bug`；如果是某个机型系统性不可用，标 `kernel-support` 并附上 `docs/supported-kernels.md` 需要的字段。
