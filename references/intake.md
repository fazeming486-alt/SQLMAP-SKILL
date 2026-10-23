# 技术 intake（只问技术，不问权限）

> v4 首选 `engage.json` 一次性描述目标/会话/模块；只有单模块手工测试或档案未命中时才走下面的 intake。

档案未命中时才走 intake；最多三个问题，每个都给默认值，用户说"默认"直接过。

## Q1 · 注入点在哪

- 完整地址是什么？GET 还是 POST？
- 参数在 URL、表单体、JSON 请求体，还是路径里？
- 哪个值正常时能查到东西？（这是基线值）
- 把 `*` 放在精确注入点：`...?keyword=1*&from=&to=`；JSON 里放值内：`{"code":"WELCOME10*"}`。

默认：用户给的 URL 里最像参数的那个；`*` 放在该参数值末尾。

## Q2 · 要不要会话

- 需要登录吗？需要就把 Cookie 整行写进 job 文件（不要贴聊天）。
- POST/JSON 接口通常还要 `X-CSRF-Token`，同样进 job 的 `headers`。
- Cookie 是 HttpOnly 的话 `document.cookie` 读不到，走 F12。

默认：不要会话；目标 302 到登录页时再回头补。

### Cookie / CSRF 复制指引（给用户的操作步骤）

Cookie：

1. F12 → 网络（Network）→ 点一条站内请求。
2. 标头（Headers）→ 请求标头（Request Headers）→ `Cookie`。
3. 复制整行（如 `PHPSESSID=...; security=low`），写进 job 的 `"cookie"`。

CSRF：

1. 同一条请求的请求标头里找 `X-CSRF-Token`；或
2. 控制台：`copy(document.querySelector('meta[name="csrf-token"]').content)`。

GET 接口通常不需要 CSRF；POST/JSON 才需要。以实际请求头为准。

## Q3 · 打到哪一步

- A. 能不能注入（只到判定）→ `detect`
- B. 库里有几张表、叫什么 → `current-db` + `tables`
- C. 某张表有哪些列 → `columns`（需要 `table`）
- D. 某表某几列数据（推荐）→ `dump` + `columns`
- E. 全表/全库导出 → `dump`（不带 columns）/ `dump-all`
- F. 拖哈希 → `passwords`（哈希格式串给 hashcat，`-m` 模式号自己查文档）
- G. 单发 SQL / 系统命令 / 读写文件 → `sql-query` / `os-cmd` / `file-read` / `file-write`

默认：A（detect），跑完报里程碑，想继续随时加 stage。

## job.json 字段速查

| 字段 | 说明 |
|---|---|
| `target` | 完整 URL，注入点用 `*` 标记（必填） |
| `method` / `data` | POST 时给 `data`（表单串或 JSON 串） |
| `cookie` | Cookie 整行；走会话脚本时自动填 |
| `headers` | 额外头数组，如 `"X-CSRF-Token: ..."` |
| `dbms` | 已知库类型（mysql/sqlite/postgresql/mssql），省指纹时间 |
| `threads` / `delay` | 并发 1–10 / 请求间隔 0–10 秒 |
| `risk` / `level` | 1–3 / 1–5 |
| `time_sec` | 时延注入等待 3–10 秒 |
| `tamper` | tamper 脚本串，作用于所有 stage |
| `stage` | 默认 detect |
| `table` / `columns` | columns/dump 需要；columns 推荐指定 |
| `query` / `cmd` | sql-query / os-cmd 的带值参数 |
| `file_read` / `file_write`+`file_dest` | file-read / file-write 的带值参数 |
| `output_dir` | 本 engagement 的产物根目录 |
| `proxy` | 走本地中继（TLS 指纹被拦时）：`http://127.0.0.1:8890`，target 同时改 `http://` |
| `scope_note` | 公网目标必填的一行范围记录 |
| `csrf_token` / `csrf_url` / `csrf_method` | POST 表单的 CSRF 参数名/取令牌页/取令牌方法（注意：sqlmap 的令牌获取不走 --proxy，指纹拦截场景改用固定令牌方案，见 playbook） |
