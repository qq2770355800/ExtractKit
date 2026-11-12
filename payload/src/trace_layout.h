#ifndef TRACE_LAYOUT_H
#define TRACE_LAYOUT_H

/* 从 tracefs 的 format 文件里读出每个事件的真实字段偏移。
 * 5.10 / 6.1 / 6.6 / 6.12 的 kmem 事件字段排列并不一致
 * （*_node 变体多一个 node、mm_page_* 的 order/gfp 位置也不同），
 * 按固定偏移切会把指针当成 order、把低位当 site，base 校准就永远失败。 */

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LAY_MAX 32

enum {
	LK_NONE = 0,
	LK_CACHE_ALLOC,
	LK_CACHE_FREE,
	LK_PAGE_ALLOC,
	LK_PAGE_FREE,
	LK_DRAIN,
};

struct lay_field {
	int site, ptr, req, alloc, pfn, order, page;
	int has_site, has_ptr, has_req, has_alloc, has_pfn, has_order, has_page;
};

struct evlay {
	unsigned id;
	int kind;
	char name[48];
	struct lay_field f;
};

static struct evlay g_lay[LAY_MAX];
static int g_lay_n = -1;	/* -1 = 还没构建 */

static int lay_slot(struct lay_field *f, const char *name)
{
	if (!strcmp(name, "call_site"))
		return 1;
	if (!strcmp(name, "ptr"))
		return 2;
	if (!strcmp(name, "bytes_req"))
		return 3;
	if (!strcmp(name, "bytes_alloc"))
		return 4;
	if (!strcmp(name, "pfn"))
		return 5;
	if (!strcmp(name, "order"))
		return 6;
	if (!strcmp(name, "page"))
		return 7;
	return 0;
}

static void lay_set(struct lay_field *f, int slot, int off)
{
	switch (slot) {
	case 1: f->site = off; f->has_site = 1; break;
	case 2: f->ptr = off; f->has_ptr = 1; break;
	case 3: f->req = off; f->has_req = 1; break;
	case 4: f->alloc = off; f->has_alloc = 1; break;
	case 5: f->pfn = off; f->has_pfn = 1; break;
	case 6: f->order = off; f->has_order = 1; break;
	case 7: f->page = off; f->has_page = 1; break;
	default: break;
	}
}

/* format 里的行形如：
 *	field:unsigned long call_site;	offset:8;	size:8;	signed:0;
 * 名字是 ';' 前的最后一个 token，偏移是其后 "offset:" 的数字。 */
static void lay_parse_format(const char *path, struct lay_field *f)
{
	char buf[8192];
	FILE *fp = fopen(path, "r");
	size_t n;
	char *p;

	memset(f, 0, sizeof(*f));
	if (!fp)
		return;
	n = fread(buf, 1, sizeof(buf) - 1, fp);
	fclose(fp);
	buf[n] = 0;
	p = buf;
	for (;;) {
		char *q = strstr(p, "field:");
		char *semi, *offp, *name, *start;
		int slot, off;

		if (!q)
			break;
		semi = strchr(q, ';');
		if (!semi)
			break;
		name = semi;
		while (name > q + 6 && name[-1] == ' ')
			name--;
		start = name;
		while (start > q + 6 && start[-1] != ' ')
			start--;
		offp = strstr(semi, "offset:");
		if (!offp)
			break;
		off = atoi(offp + 7);
		if (name > start && (size_t)(name - start) < 24) {
			char nm[24];
			size_t len = (size_t)(name - start);

			memcpy(nm, start, len);
			nm[len] = 0;
			slot = lay_slot(f, nm);
			if (slot)
				lay_set(f, slot, off);
		}
		p = offp + 7;
	}
}

static int lay_kind_of(const char *name)
{
	if (!strncmp(name, "kmem_cache_alloc", 16))
		return LK_CACHE_ALLOC;
	if (!strncmp(name, "kmem_cache_free", 15))
		return LK_CACHE_FREE;
	if (!strncmp(name, "mm_page_alloc", 13))
		return LK_PAGE_ALLOC;
	if (!strncmp(name, "mm_page_free", 12))
		return LK_PAGE_FREE;
	if (!strncmp(name, "mm_page_pcpu_drain", 18))
		return LK_DRAIN;
	return LK_NONE;
}

static int lay_read_id(const char *dir, const char *name)
{
	char path[320];
	FILE *fp;
	int v = -1;

	snprintf(path, sizeof(path), "%s/%s/id", dir, name);
	fp = fopen(path, "r");
	if (!fp)
		return -1;
	if (fscanf(fp, "%d", &v) != 1)
		v = -1;
	fclose(fp);
	return v;
}

/* 返回登记的条目数；root 形如 /sys/kernel/tracing。 */
static int lay_build(const char *root)
{
	char dir[256];
	DIR *d;
	struct dirent *de;

	if (g_lay_n >= 0)
		return g_lay_n;
	g_lay_n = 0;
	snprintf(dir, sizeof(dir), "%s/events/kmem", root);
	d = opendir(dir);
	if (!d)
		return 0;
	while ((de = readdir(d)) && g_lay_n < LAY_MAX) {
		int kind = lay_kind_of(de->d_name);
		int id;
		struct evlay *e;
		char fp[384];

		if (kind == LK_NONE)
			continue;
		id = lay_read_id(dir, de->d_name);
		if (id < 0)
			continue;
		e = &g_lay[g_lay_n];
		memset(e, 0, sizeof(*e));
		e->id = (unsigned)id;
		e->kind = kind;
		snprintf(e->name, sizeof(e->name), "%s", de->d_name);
		{ size_t dl = strlen(dir);
		  snprintf(fp, sizeof(fp), "%.*s/%s/format",
		           (int)((dl && dir[dl - 1] == '/') ? dl - 1 : dl), dir, de->d_name); }
		lay_parse_format(fp, &e->f);
		if (!e->f.has_site && !e->f.has_pfn)
			continue;
		g_lay_n++;
	}
	closedir(d);
	return g_lay_n;
}

static const struct evlay *lay_for(unsigned id)
{
	for (int i = 0; i < g_lay_n; i++)
		if (g_lay[i].id == id)
			return &g_lay[i];
	return NULL;
}

/* ---- 没有 format 时的兜底：直接从记录本身嗅出字段位置 ---------------- */

static uint64_t lay_q(const unsigned char *b, size_t off)
{
	uint64_t v;

	memcpy(&v, b + off, sizeof(v));
	return v;
}

/* 在一条 kmem 记录里找一个 qword，满足
 *   (v & 0x1fffff) == 期望的调用点 low21   且   v 是高半区内核指针
 * 那就是 call_site；再找另一个高半区内核指针当 ptr。
 * 完全不假设字段顺序，命中就返回 1 并把偏移写回。 */
static int lay_sniff_offsets(const unsigned char *p, size_t avail,
			     uint64_t low21, int *site_off, int *ptr_off)
{
	if (!low21)
		return 0;
	for (size_t o = 8; o + 8 <= avail && o <= 96; o += 8) {
		uint64_t v = lay_q(p, o);

		if ((v & 0x1fffffULL) != low21)
			continue;
		if ((v >> 48) != 0xffff)
			continue;
		for (size_t o2 = 8; o2 + 8 <= avail && o2 <= 96; o2 += 8) {
			uint64_t w;

			if (o2 == o)
				continue;
			w = lay_q(p, o2);
			if ((w >> 48) != 0xffff || w == v)
				continue;
			*site_off = (int)o;
			*ptr_off = (int)o2;
			return 1;
		}
	}
	return 0;
}

/* ---- 原始字快照 + 列扫描 ---------------------------------------------
 * 只凭「单条记录里低 21 位对上」不够：别的列也可能凑巧对上，或者
 * 记录根本不是我们以为的那个事件。真正硬判据是「同一列在所有样本
 * 里取值恒定」——call_site 对每一次 do_timer_create 都相同，噪声不会。
 * 所以先把前 N 条 cache-alloc 记录的原始 qword 存下来，再逐列统计。*/
#define LAY_RAW_MAX 64
#define LAY_RAW_WORDS 12

static uint64_t g_lay_raw[LAY_RAW_MAX][LAY_RAW_WORDS];
static int g_lay_raw_n = 0;

static void lay_raw_capture(const unsigned char *b, size_t off, size_t avail)
{
	if (g_lay_raw_n >= LAY_RAW_MAX)
		return;
	if (avail < (size_t)(8 * LAY_RAW_WORDS))
		return;
	for (int i = 0; i < LAY_RAW_WORDS; i++)
		g_lay_raw[g_lay_raw_n][i] = lay_q(b, off + (size_t)i * 8);
	g_lay_raw_n++;
}

static int lay_col_const(int c)
{
	if (g_lay_raw_n < 2)
		return 0;
	for (int i = 1; i < g_lay_raw_n; i++)
		if (g_lay_raw[i][c] != g_lay_raw[0][c])
			return 0;
	return 1;
}

/* 找到「恒定 + 低 21 位匹配 + 高半区 0xffff」的列即 call_site；
 * 顺带把「恒定的小整数」列当 size 列（用于补 req/alloc）。*/
static int lay_scan_columns(uint64_t low21, int *col, uint64_t *val, int *size_col)
{
	int found = 0;

	if (size_col)
		*size_col = -1;
	if (g_lay_raw_n < 4 || !low21)
		return 0;
	for (int c = 1; c < LAY_RAW_WORDS; c++) {
		uint64_t v = g_lay_raw[0][c];

		if (!lay_col_const(c))
			continue;
		if (size_col && *size_col < 0 && v >= 8 && v <= 0x4000)
			*size_col = c;
		if (!found && (v & 0x1fffffULL) == low21 && (v >> 48) == 0xffff) {
			*col = c;
			*val = v;
			found = 1;
		}
	}
	return found;
}

#endif /* TRACE_LAYOUT_H */
