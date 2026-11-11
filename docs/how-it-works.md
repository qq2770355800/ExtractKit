# 原理

## 1. 漏洞链（CVE-2026-98260）

```
timer_create(CLOCK_PROCESS_CPUTIME_ID)   → posix_timer 落到 kmem_cache(k_itimer, 0x108/0x118)
   │  子进程被 SIGKILL，timer 仍挂在父进程的 cpu_timer 上
   ▼
reap（wait）                              → k_itimer 被 kfree
   │  上面那块内存仍被 cpu_timer 引用 —— UAF
   ▼
用 kmem_cache_alloc 的 payload 把同一 slab 抢回来
   │  在 socket / pipe 缓冲里写入「假 cred 指针链」
   ▼
8 字节零写落到 cred 的 uid 字段            → uid=0
   ▼
ksud late-load 装载 KernelSU（KMI 由 uname -r 推）
```

关键点：

- **零写**只能写 0，所以不能「指向自己的 cred」，得让 `task_struct->cred` 指向一块**内容自己填**的假 cred；
- 假 cred 里的 `security` 必须指向一个 `selinux_blob`，才能绕过 `selinux_cred()` 的取值；
- 如果内核开了 `panic_on_warn`，`WARN_ON` 会先把机器带走，所以要读 sysctl 决定是否先清 `panic_on_warn`；
- 成功后 payload 必须驻留（`PARKED`），因为 cred 还被引用着。

## 2. 常量从哪来

| 常量 | 做法 |
| --- | --- |
| 符号地址 | `kallsyms`：`names`+`markers`+`token_table`+`token_index`+`offsets` 两代布局都能解；`relative_base` 与 `offsets` 不邻接时用 `±64B` 回溯 |
| call site | 反汇编 `do_timer_create` / `prepare_creds` / `copy_process`，找 `bl kmem_cache_alloc*`；开了 CFI 的 `bl` 会落在 `sym-0x38` 的 thunk 上，所以接受 `[addr-0x80, addr]` |
| 结构偏移 | 优先 `.BTF`；没有 BTF 时看 `cred_init`/`fork_init` 的 `kmem_cache_create(size)`（在 **w1**）与 `exit_creds` 的两个 `STR XZR`（大的是 `cred`，小的是 `real_cred`） |
| KASLR slide | 运行时从 `kmem_cache_alloc` 记录里的 `call_site` 反推：`slide = call_site - STATIC_TIMER_SITE`，候选必须 2 MiB 对齐 |

`device.cfg`（336 B, magic `EXKCFG01`）就是这些常量的定长落盘格式，payload 按固定顺序读。

## 3. 运行时窗口判定

理想信号是页级事件（`mm_page_alloc` 里出现「受害者那页」），但很多机型 SELinux 直接挡掉 `events/*/enable`。
按可靠性排序的三档：

1. `kmem_cache_alloc` 记录里 `ptr == V`（我们精确拿回了受害对象）；
2. 同页 `slab_own` 增加（对象没被换页，只是碎片回填）；
3. 页事件 `order==1 && pfn==slab_pfn`（最准，但常被拒）。

读模式（`--check` / 只读自检）只算 slide，不消耗 UAF；写模式一次开机只用一次（`boot_id` 守卫）。

## 4. 液态玻璃

`glass/` 是 [AndroidLiquidGlass](https://github.com/Kyant0/AndroidLiquidGlass) 的源码进仓改造版：
背景单独一个 `layerBackdrop` 的 Box 采样，卡片是它的兄弟节点 —— 如果让卡片自己进采样层，
会出现「卡片采样卡片」的无限递归，最终 `SIGSEGV ... libhwui.so computeTransformImpl`。
