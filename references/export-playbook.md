# 异步导出 / 签名下载 playbook

## 形态

```
POST /exports            → 创建任务（kind/from/to）
GET  /exports            → 任务列表（租户/状态/行数/下载）
GET  /exports/<uuid>/download?exp=...&sig=...
```

常见实现：后台 worker 生成 CSV；下载 URL 带 HMAC 签名与过期时间。

## 测试矩阵

| 测试 | 期望 | 缺陷信号 |
|---|---|---|
| 自己的 URL | 200 | 基线 |
| exp+1，保留 sig | 403 | 200 = 签名不校验过期 |
| 去掉 sig | 403 | 200 = 不校验签名 |
| 随机 UUID + 自己的 sig | 404/403 | 200 = 不校验任务存在 |
| 别人的 job UUID + 自己的 sig | 403/404 | 200 = 签名不绑定任务 / 缺租户校验 |
| 列表 `?tenant_id=2` / `?all=1` / `X-Tenant-ID` | 仍只看到自己 | 出现他人 job = 列表越权 |
| 创建时塞 `tenant_id`/`owner_id` | 被忽略 | job 归属被改 = 批量赋值 |
| 下载不带 Cookie | 401/403 | 200 = 匿名可下载 |

## 关键点

- **UUID 可枚举**通常不是指 UUID 随机性，而是**某处泄露了 job ID**：审计日志、管理端、列表越权、错误页、其他账号。先找 ID 泄露源。
- 管理端审计的 `?action=` 过滤很好用：`/admin/audit?action=export`、`?action=export.download` 会把 `export_job#<uuid>` 当对象列出来；先看是否有非本租户的用户/对象，再取 UUID。
- 列表页、下载页、详情页要分别测；常见组合是“列表只给本租户，但详情/下载漏租户校验”。`/exports/<uuid>` 404 而 `/exports/<uuid>/download` 403，说明记录存在、卡在签名，不是不存在。
- 签名可能只覆盖 `exp`，也可能覆盖 `path`；用“换 job + 保留 sig”区分。
- 任务列表的租户过滤必须在服务端会话里，不能接受客户端 `tenant` 参数。
- 下载前先按 `job.tenant_id == session.tenant_id` 查任务，再校验签名。

## 工具

`export_probe.py`：创建任务 → 解析签名 URL → 跑上述矩阵 → findings。

```bash
python scripts/export_probe.py --base https://host --cookie-jar buyer.txt \
  --create-path /exports --list-path /exports --kind orders \
  --from 2026-07-01 --to 2026-10-24 --list-query tenant_id=2 --list-query all=1
```

## 证据

- 创建请求/响应、任务列表 HTML/JSON；
- 自己的 URL、变体 URL、状态码；
- 他人任务的 ID 来源；
- CSV 第一行/租户字段（脱敏）。
