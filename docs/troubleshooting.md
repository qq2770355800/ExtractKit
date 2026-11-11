# 排错

## `CHAIN_STOP:check_uid0` 且 `[check] NOT_READY`

看 `[base]` 行：

- `candidates=0`：一条可用候选都没有。本机 `events/*/enable` 很可能被拒（看上面 `[trace] … denied (errno=13)`）。
- `best=0x…` 不是 2 MiB 对齐：老版本的信号投错页，升级即可。
- `via call_site samples=512 all samples agree` 才是健康状态。

## `[!] cred site 0x… != 0x…，按尺寸软匹配`

正确站点没命中，退化成「按尺寸找」。表现为 `matches` 里 `site_low` 全是别的地址。
新版会额外打印 `[cred] site-hit <期望站点>: total=… childPid=…`：`total>0` 说明事件在，是筛选条件丢了；
`total==0` 说明这个内核没给这条记录。若是前者，检查 `bytes_req`（object_size）与 `bytes_alloc`（slab 对齐尺寸）的差异。

## `[+] plant1 … hit=0 foreign=0 free_seen=0` 然后 `PARKED`

窗口没被确认。三档信号全没触发时我们**不盲写**（盲写会写坏其他对象 → panic）。
页事件被拒的机型，成功率取决于 pipe/AIO 页级 reclaim 是否抢到了受害者那页。

## `! sha256 不匹配`

catalog 里的哈希与 `assets/payload/**` 的二进制不一致 —— 通常是改了 payload 却没重跑
`python tools/build_payload.py`，或只换了其中一个分支。`PayloadCatalogTest` 会在编译期拦下这种不一致。

## 提权后管理器不认

`--package-name` 只在**加载那一刻**写进驱动；换了管理器必须重启，再跑一次。

## 日志

`/sdcard/Android/data/com.extractkit.app/files/logs/extract-*.log`，保留 10 份。
