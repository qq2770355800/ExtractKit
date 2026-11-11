# payload

这里的二进制是**上游已验证产物**，不是本仓库编译的：

| 文件 | 来源 | 说明 |
| --- | --- | --- |
| `cve-2026-98260-uid0` | `dada-cve-AN00/app/app/src/main/assets/cve98260/` | 静态 arm64；`check`/`leak`/`selftest`/`fake`/`shell`/`daemon`/`wait` |
| `cve-2026-98260-android` | 同上 | PIE；`--preflight` / `--smoke` / 默认全链 |

只保留 98260 两条链路；校验和见同目录 `SHA256SUMS.txt`，App 部署到设备后会再校验一次。

## 重新标定

`src/cve-2026-98260-uid0.c` 是 uid0 payload 的源码副本（与 `dada-cve-AN00/kernel/cve-2026-98260.c`
一致）。机型相关常量已经全部拆到 `src/device_config.h`：

```
symbols   ← kallsyms（do_timer_create / selinux_state / root_user / init_* 等）
offsets   ← BTF（k_itimer、task_struct、cred 的成员偏移）
EV_* 与三处 call site ← 只能在设备上实测
```

当前这份 `src/device_config.h` 是**从真实 boot.img 生成并经交叉验证**的
（内核 `6.6.118-android15-8-g554929766a0d-abogki544555896-4k`，符号与 call site 全部对得上），
生成逻辑见根目录 README 6.0。

生成方式（不要手改 .c 里的数字）：

```bash
python3 tools/gen-config.py --kallsyms kallsyms.txt --btf vmlinux.btf         --measure measurements.json --out payload/src/device_config.h

NDK=/path/to/android-ndk ./tools/build-payload.sh
```

`gen-config.py` 的解析逻辑有自测：`python3 tools/test-gen-config.py`（合成 BTF，无需真机）。
注意它会拦两类情况：缺符号、`cred.uid` 偏移不是 8（5.15/6.1 的 KMI 需要先改
`build_fake_cred()` 里的 `uid/gid` 布局假设）。

改完记得：
1. 覆盖 `app/src/main/assets/payload/cve-2026-98260-uid0`
2. 更新 `PayloadCatalog.kt` 里 `Payloads.UID0.sha256`
3. 先用「只读自检」验证 `[check] READY`，再跑「泄漏」确认能拿到 cred 地址

需要的常量清单和取值方法见仓库根目录 `README.md` 第 6 节。
