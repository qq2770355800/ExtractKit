# 标定：从一个 boot.img 到 device.cfg

## 1. 拿镜像

- 官方整包里的是 `image/boot.img`（不是 `update_sd_base.zip` 本身）；
- 也接受直接切出来的 `Image`（`ARMd` 在偏移 0 或 0x38 都认）；
- `fwbox` 可以按型号 + 版本查出直链并只下到 `init_boot` 为止。

## 2. App 里解析

「标定」→「导入本机固件包」→ 选文件。日志会按阶段打印：

```
boot 头: version=4 kernel=35 MiB
BTF: 6069 KiB        (或 btf=none)
k_itimer  size=0x108 node=0x78
task_struct cred=0x820 comm=0x830
cred  size=0xb8 uid=0x8 security=0x80
符号 107687 个, base=0xffffffc080000000
call site: do_timer_create +0x94 / prepare_creds +0x20 / copy_process +0x144
device.cfg: 336 B
```

任何一步失败都会给具体原因（不是可识别的 boot.img / 找不到 kallsyms / 缺必需符号 / call site 为 0），
并且**不会**把不完整的结果写进 profile。

## 3. 判定能不能提权

`CalibrationModel.evaluate()` 的判据：

- 必需符号齐全（`do_timer_create` / `selinux_state` / `root_user` / `init_user_ns` / `init_groups`；`panic_on_warn` 缺失只在 sysctl≠0 时才致命）；
- 三个 call site 都非 0（为 0 说明 `bl` 没找到，通常是内核已经修了这个洞）；
- 偏移在合理范围（`cred.size` 8..0x200、`uid < size`、`task.cred < taskSize`）；
- 与本机内核一致（按 `g<hash>` 比，不是比版本号前 22 个字符）。

## 4. 分享与复用

「保存 profile」写出 `filesDir/profiles/*.profile`（纯文本 `key=value`，约 1 KB，只含 7 个符号 + 偏移），
「分享」导出同内容文本；同内核设备「导入」后免标定。
