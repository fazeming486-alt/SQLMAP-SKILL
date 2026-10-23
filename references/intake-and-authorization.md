# Intake and authorization

## Authorization gate (ask before anything else)

Use two questions, then stop:

1. 这个目标是你自己的，还是你有书面授权的靶场？授权范围（域名/路径/账号/时间窗）是什么？
2. 有哪些绝对不能碰的部分（生产路径、真实用户数据、支付、删除类操作）？

Acceptable answers:

- "我自己搭的本地靶场，地址 127.0.0.1:9300。"
- "客户授权测试，范围是 staging.example.com，时间是 10 月 20–25 日，禁止碰支付。"
- "公司内部系统，工单 #1234，只允许我的测试账号。"

Refuse:

- "这个站是我朋友的朋友的，应该没事。"
- "网上找的站，练练手。"
- "先打进去再说，出了事我负责。"
- Any request to use `--os-shell`, `--file-write`, `--sql-shell`, `--risk=3`, or to modify/delete data.

If the target is public, require `"public_target": true` in the job and a written scope note. Prefer a staging URL.

## Intake groups (ask 1–2 at a time)

### Group 1 — target and parameter

- 完整地址是什么？方法 GET 还是 POST？
- 参数在 URL、表单、JSON 请求体，还是路径里？
- 哪一个值正常时能查到东西？（这是基线值）
- 请在注入点放一个 `*`，例如 `...?keyword=1*&from=&to=`。

### Group 2 — session

- 需要登录吗？把 F12 → 网络 → 请求标头里的 `Cookie` 整行放进本地 job 文件。
- 是 POST/JSON 吗？那还需要 `X-CSRF-Token`，同样从请求头复制。
- 不要把 Cookie/CSRF 值直接贴在聊天里；写进 job 文件，并在报告里掩码。

### Group 3 — environment

- 知道数据库类型吗（SQLite / MySQL / PostgreSQL / SQL Server）？
- 有 WAF、Cloudflare、限速吗？允许的请求节奏是多少？
- 测试时间窗？输出目录用哪个？

Defaults:

- `level=1`, `risk=1`, `delay=1`, `time_sec=5`, `threads=1`.
- 一个 engagement 用一个 `output_dir`，后续阶段复用注入点缓存。
- 只 dump 指定列；全表必须单独确认。

## Goal question (ask exactly once)

> 这次你最想先确认什么？
> A. 能不能注入（只到判定）
> B. 库里有几张表、叫什么
> C. 某张表有哪些列
> D. 某张表的某几列数据（推荐）
> E. 全表导出（需要再确认一次影响）

Record the answer; do not escalate silently.

## Cookie / CSRF copy instructions (give to the user)

Cookie:

1. F12 → 网络（Network）→ 点一条站内请求。
2. 标头（Headers）→ 请求标头（Request Headers）→ `Cookie`。
3. 复制整行（如 `NB_SID=...`）。它是 HttpOnly 的，控制台 `document.cookie` 读不到。

CSRF:

1. 同一条请求的请求标头里找 `X-CSRF-Token`；或
2. 控制台：`copy(document.querySelector('meta[name="csrf-token"]').content)`.

GET 接口通常不需要 CSRF；POST/JSON 才需要。以实际请求头为准。

## Scope record (write into the job note)

Example:

```
authorization_note: "自有本地靶场 northbank，127.0.0.1:9300；只测 /api/checkout/coupon；2026-10-23 14:00–16:00；不碰支付与删除。"
```

This note is required by `scripts/sqlmap_run.py` and makes the engagement reproducible.
