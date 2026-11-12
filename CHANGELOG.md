# 更新记录

## 9.61
- `fam/*` payload 统一为同一支（含 5.10 的 `req@+16 / alloc@+20` 嗅探修正、`[slab] task_struct objsize` 诊断、pipe 页级 reclaim 覆盖零写阶段）
- payload 自报的 `target:` 行改为按 `device.cfg` 实际值打印（不再硬编码机型名）
- `[lay]` 日志里的 `events/kmem//format` 双斜杠修正
- 9.59：`run98937` 先下发 `device.cfg`，标定器不再用编译期默认锚点；新增 `boot_id` 守卫（同一次开机只成功一次）
- 9.60：标定器日志前缀 `[calib]` → `[98937]`
- 9.52–9.58：彻底移除第三方 98937 后端（`assets/be/`、`assets/poc98937`、`assets/cve98937/profiles/`、`Cve98937Tables.kt`），APK 从 15.2 MB 降到 5.9 MB
- 9.58：标定器 arm 顺序修正 —— `enable_event:kmem:<name>` 必须写 `rss_stat/trigger`，`rss_stat/enable` 只接受数字（此前 `host=0 (EINVAL)` 导致标定一直空转）

## 9.26
- 修 `PayloadCatalog` 与 `assets` 的 sha 不一致（9.25 里 fam/6.1 残留旧值，装机即 `DEPLOY` 中止）
- `[cred]` 选择不再要求 `bytes_req == bytes_alloc`（SLUB 里这两者天生差一次对齐），改为尺寸区间 + 精确尺寸优先
- `task_struct` 偏移不被 cfg 命中时，按 `/proc/slabinfo` 实测 objsize 再扫一遍
- 新增 `PayloadCatalogTest`：catalog ↔ assets ↔ SHA256SUMS 三方一致的编译期校验

## 9.22–9.25
- `enable_events()` 改为扫描 `/events/kmem/` 目录（不同分支的事件名不同，`*_noprof`/`_node` 变体自动命中）
- `[cred] site-hit` 诊断：打印期望站点的总条数与子进程条数
- 6.1 / 5.10 / 5.15 各一支 payload（分支专用，跑错分支会 `[guard] refusing to run`）

## 9.20
- payload 精简为 4 支：`android` / `uid0`（6.6 字面版）/ `fam` 5.10 / `fam` 5.15
- 去掉包内第三方服务的痕迹

## 9.00
- 回到「字面常量 + 页事件等待」的原始链路，6.6.118 上 2 秒拿到 `uid=0`
