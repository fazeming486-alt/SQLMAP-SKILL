# sqlmap playbook（v2 全 stage）

## Stage ↔ flag 对应

| Stage | sqlmap flag | 作用 | job 额外字段 |
|---|---|---|---|
| detect | （无枚举 flag） | injectable? 技术/DBMS/列数 | — |
| dbs | `--dbs` | 列所有库 | — |
| current-db | `--current-db` | 当前库名 | — |
| tables | `--tables` | 当前库全部表 | — |
| columns | `-T <table> --columns` | 某表列名 | `table` |
| dump | `-T <table> [-C <cols>] --dump` | 取数 | `table`，`columns` 推荐 |
| dump-all | `--dump-all` | 全库导出 | —（量大） |
| passwords | `--passwords` | 拖口令哈希 | — |
| privileges | `--privileges` | 当前用户权限 | — |
| sql-query | `--sql-query="<语句>"` | 单发 SQL | `query` |
| os-cmd | `--os-cmd="<命令>"` | 单发系统命令 | `cmd` |
| file-read | `--file-read="<路径>"` | 读目标文件 | `file_read` |
| file-write | `--file-write="<本地源>" --file-dest="<目标路径>"` | 写文件 | `file_write` + `file_dest` |

规则：一个 engagement 用一个 `--output_dir`；只有 `detect` 带 `--flush-session`（复用注入点缓存）；要重置缓存就显式重跑 detect。

**交互式 shell**：`--os-shell` / `--sql-shell` 与 `--batch` 不兼容，运行器不支持。要交互 shell：先 `--dry-run` 抄出完整命令，用户自己在终端里跑（去掉 `--batch`）。

## 请求配方

### GET 查询参数

```
-u "http://host/path?keyword=1*&from=&to=" --cookie "NB_SID=..."
```

### 参数定向（多参数 URL 只测关心的那个）

```
-p "id"
```

job 里写 `"param": "id"`。多参数 URL 不定向时 sqlmap 会把每个参数都测一遍——慢且浪费请求。

### Burp/ZAP 请求文件（复杂请求首选）

```
-r request.txt
```

job 里写 `"request_file": "request.txt"`（`*` 直接标在文件里的参数值上）。Cookie、UA、自定义头、请求体全部从文件读，job 不用重复给。适用：POST/JSON、自定义头、需要精确重放的场景。抓包：Burp 右键 → Copy to file / Save item。

### POST 表单

```
-u "http://host/vulnerabilities/sqli/" --data "id=1*&Submit=Submit" --cookie "..."
```

`--data` 即 POST；仅当站点强制时才加 `--method POST`。

### POST JSON

```
-u "http://host/api/coupon" \
  --data '{"code":"WELCOME10*"}' \
  --headers "Content-Type: application/json
X-CSRF-Token: <token>" \
  --cookie "NB_SID=..."
```

- `*` 放 JSON 字符串值内部。
- 布尔类测试需要合法基线值（如 `WELCOME10`）；空基线会让真/假响应都为空 → 假阴性。
- JSON 里要双引号时转义为 `\"`。

## 核心参数

- `--batch` 非交互；threads 由 job 控制（私网档案可 1–10，公网建议 1）。
- `--level 1–5`：payload 广度；`--risk 1–3`：侵入度（3 含 OR 类改数语句，dump/共享库慎用）。
- `--user-agent "<串>"`：UA 有 UA 规则的目标必配浏览器串（DVWA 靶机实测：非浏览器 UA 全站 403；浏览器 UA 放行）。job 字段 `user_agent`，档案预填。
- `--dbms` 已知库类型就写（省指纹）。
- `--delay N` 请求间隔秒；公网/限速目标 1–3。
- `--time-sec 3–10` 时延注入等待。
- `--technique B/E/U/S/T` 强制技术：B 布尔、E 报错、U UNION、S 栈查、T 时延。
- `--union-cols N` / `--union-char X`：UNION 列数与占位符（非数字 char 可避免回显假阴性）。
- `--string "<标记>"`：布尔盲注时"真"响应独有的标记。
- `--tamper a,b,c`：payload 变形脚本串。DVWA medium 常用 `space2comment`；`between` 替换比较符；组合用逗号。tamper 是 job 级字段，作用于所有 stage。
- `--output-dir`：产物根；CSV 落 `<out>/<host>/dump/<db>/`。

## WAF→tamper 映射（参考表）

来源：sqlmap 本体 `--identify-waf` 的识别结果 + 社区经验（sqlmap-ai evasion_engine 同源）。**一次别超过 3–5 个脚本**，先单独试通用款（`space2comment` / `charencode`），组合太多反而假阴性。

| WAF（`WAF: xxx` 输出） | 建议 tamper（按顺序试） |
|---|---|
| 未识别但提示有 WAF | `space2comment` → `charencode` → `between,randomcase` |
| cloudflare | `charencode` → `charunicodeencode` → `between,randomcase` |
| modsecurity | `charencode` → `charunicodeencode` → `space2comment,randomcase` |
| imperva/incapsula | `charencode` → `equaltolike,greatest` → `randomcase,between` |
| aws-waf | `between` → `charencode,randomcase` → `space2plus` |
| f5/big-ip | `charencode` → `equaltolike,greatest` → `space2comment` |
| fortinet | `between` → `charencode,randomcase` → `space2comment` |
| akamai | `charencode` → `randomcase,between` → `base64encode` |
| **DVWA 靶机的 403** | **不是 WAF，是 UA 规则**——别上 tamper，job 加浏览器 `user_agent` 即可 |

baseline 的 `WAF_DETECTED/WAF_TYPE`（签名预检）与 sqlmap 的 `WAF:` 输出（`--identify-waf` 级）都看一眼再定 tamper。

## 结果解读

- `is vulnerable` / `might be injectable` → 可注入；`does not seem to be injectable` → 不可注入。
- `Type:` / `Title:` / `Payload:` → 技术与证据（milestone 会原样摘出）。
- `back-end DBMS:` → 库类型。
- `appears to have N columns` → UNION 列数。
- `retrieved: '...'` → tables/columns/dump 过程行。
- `dumped to CSV file '...'` → CSV 产物路径。
- `fetched data logged to text files under '...'` → 日志目录。
- `passwords` 阶段输出哈希行（如 `$2y$...` / `5f4dcc...`）：把哈希串交给 hashcat；**模式号自己查 hashcat 文档，不要问 AI**。

## 失败分诊

- **302 → /login / 401** — Cookie 过期或错主机。重跑会话脚本/重取 Cookie，重跑基线。
- **403（尤其整站统一 403）** — 先排除 UA 规则：job 加浏览器 `user_agent` 重试；仍 403 才是 WAF/Cloudflare。停；问用户对策（加白/staging）。
- **429** — 限速。加 `delay`、缩范围、等窗口；公网别并发。
- **全 200 但 not injectable** — 基线空、参数错、编码/CSRF 问题。用有数据的值复核，检查 `*` 位置，`level` 提 3。
- **500 连发 + dump 空** — 应用可能截断输入或吞错误。换短载荷，问用户上限。
- **UNION 假阴性** — 列数/回显位没对上。`--union-cols N`、换 `--union-char`；布尔用 `--string`。
- **时延不稳** — 链路慢/共享。调 `--time-sec`（3–10），或换技术。

## 产物与报告

- 日志：`<output_dir>/<stage>.log`（运行器自动落盘）。
- 数据：`<output_dir>/<host>/dump/<db>/<table>.csv`。
- milestone：`STAGE / STATUS / EVIDENCE / DBMS / TABLES / ARTIFACTS / LOG / EXIT`，逐 stage 报。
- 终报要素：目标与范围、入口、请求形态、技术与 payload、暴露数据、修法、产物路径、未测项。Cookie/CSRF/个人数据掩码。
