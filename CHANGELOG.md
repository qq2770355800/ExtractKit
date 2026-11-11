# 更新记录

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
