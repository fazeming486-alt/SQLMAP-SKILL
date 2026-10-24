---
name: web-pentest
description: 授权 Web 渗透测试工作台（v4）：可编排的侦察 → 角色/会话 → 配置面 → XSS → 越权/IDOR → SQLi/表达式注入 → SSRF → 上传面 → 证据 → HTML 报告。内置 httpkit/findings/engage 内核，统一预算、限速、Cookie 轮换、证据与去重；可选 nuclei/httpx/katana 等外部工具适配。触发场景：Web 渗透、漏洞侦察、攻击面、角色矩阵、SQL 注入、列名注入、XSS、越权、IDOR、SSRF、上传、配置错误、业务逻辑，以及 DVWA/北岸/南岭/NEXA 等自有靶场。中英触发词：web pentest、渗透测试、侦察、攻击面、SQL注入、SQL injection、sqli、XSS、SSRF、IDOR、越权、文件上传、misconfiguration、business logic、security report。
version: 4.1.3
display_name: Web 渗透测试工作台
argument-hint: <目标 URL / engage.json / 档案名，如 dvwa / northbank>
---

# Web 渗透测试工作台（v4）

把授权 Web 渗透测试做成**可编排的流水线**，而不是一个 sqlmap 外壳：

```
scope/session → recon → role matrix → baseline → modules → verify → findings → report
```

SQLi 只是模块之一。每个模块都遵守同一套工程纪律：**少量请求判定、3–4 发确认、证据落盘、统一 findings、可复现报告**。

## 0. 工程纪律

1. **预算先行**：任何 engagement 都设 `max_requests` 与 `rps`；超过预算/命中 429/403 安全校验立即停，不硬刚。
2. **基线先行**：模块探测前先确认目标 2xx、会话有效、最终地址不是登录页。
3. **证据留全**：每个请求写入 `runs/<name>/raw/`；finding 必须能指回原始响应。
4. **Cookie 不进聊天/报告**：日志与报告自动脱敏；Cookie/CSRF 只写本地 jar/配置。
5. **不默认跑长扫描**：先 3–4 发手工取证；确认后再决定是否让 sqlmap/nuclei 深挖。

## 1. 快速开始

### A. 全自动编排

```bash
cp examples/engage.example.json engage.json
# 填 base_url / scope / sessions / options
python scripts/engage.py --config engage.json --dry-run
python scripts/engage.py --config engage.json --report
```

产物：

```
runs/<name>/
  config.redacted.json   # 脱敏配置
  recon.json             # 可选侦察
  findings.json          # 统一发现
  summary.json           # 模块/预算/会话
  state.json
  raw/                   # 每个请求的原始证据
  report.html            # 单文件报告
```

### B. 单模块

```bash
python scripts/misconfig_probe.py --target https://host --rps 1.5
python scripts/xss_probe.py --target "https://host/search?q=*" --rps 1.5
python scripts/authz_probe.py --config authz.json --rps 1.5
python scripts/sqli_probe.py --target "https://host/export?dimension=*" --context expr
python scripts/ssrf_probe.py --target "https://host/fetch?url=*" --callback https://your-callback
python scripts/upload_probe.py --page https://host/upload
python scripts/export_probe.py --base https://host --cookie-jar buyer.txt
python scripts/api_probe.py --base https://host --route /partner/v1/profile
python scripts/oidc_probe.py --issuer https://host --client-id <id> --redirect-uri https://host/oidc/callback
python scripts/report.py --run-dir runs/demo
```

## 2. engage.json

```json
{
  "name": "demo",
  "base_url": "https://target.example",
  "scope": ["target.example"],
  "rps": 1.5,
  "max_requests": 300,
  "output_dir": "runs/demo",
  "sessions": {
    "anon": {},
    "buyer": {"login": {"url": "/login", "csrf_url": "/login",
                        "data": {"email": "...", "password": "..."},
                        "verify_url": "/buyer"}},
    "merchant": {"cookie_jar": "cookies/merchant.txt"},
    "admin": {"cookie": "sid=..."}
  },
  "modules": ["misconfig", "xss", "authz", "sqli", "upload"],
  "options": {
    "xss_targets": [{"url": "https://target.example/search?q=*", "role": "anon"}],
    "authz_resources": [
      {"url": "/admin/orders", "allow": ["admin"], "deny": ["anon", "buyer", "merchant"]},
      {"url": "/merchant/orders/{id}", "ids": [114, 1768], "allow": ["merchant"], "deny": ["buyer", "admin"]}
    ],
    "sqli_targets": [
      {"url": "https://target.example/reports/export?dimension=*", "role": "merchant",
       "context": "expr", "base": "category"}
    ],
    "ssrf_targets": ["https://target.example/fetch?url=*"],
    "ssrf_callback": "https://your-callback.example",
    "upload_pages": ["https://target.example/upload"],
    "upload_test": false
  }
}
```

**会话三个坑**：
- 登录 POST 通常要 `Referer` 与 `_csrf`；`httpkit.login()` 已带 Referer。缺 Referer 会 403「安全校验未通过」。
- 会话会轮换/过期；用 `cookie_jar`，不要在多模块长跑里复用静态 `--cookie`。`httpkit` 检测到被重定向到 `/login` 会自动重登一次。
- 登录也会限速（429）。不要把“重登”当无限重试；冷却后再试。MFA 账号在 `login.totp_secret` 配置 base32 密钥，`httpkit` 会自动算 TOTP。

## 3. 模块路由

| 模块 | 什么时候用 | 脚本 | 参考 | 请求量 |
|---|---|---|---|---|
| recon | 只有入口 URL，不知道端点/参数 | `recon.py` | `methodology.md` | 20–100 |
| misconfig | 每轮都跑：头/Cookie/CORS/方法/敏感路径/报错 | `misconfig_probe.py` | `misconfig-playbook.md` | 10–30 |
| xss | 有搜索/回显/表单 | `xss_probe.py` | `xss-playbook.md` | 4–20 |
| authz | 多角色/多工作台/数字 ID | `authz_probe.py` | `authz-playbook.md` | 角色×资源 |
| sqli | 参数含 q/id/sort/dimension/报表导出 | `sqli_probe.py` | `sqli-playbook.md` | 3–8 |
| ssrf | URL/回调/图片/代理类参数 | `ssrf_probe.py` | `ssrf-playbook.md` | 1–5/参数 |
| upload | 有 multipart 表单 | `upload_probe.py` | `upload-playbook.md` | 1/page |
| export | 异步导出/签名下载/任务 ID | `export_probe.py` | `export-playbook.md` | 3–10 |
| api | 合作方/移动 API，无导航无文档 | `api_probe.py` | `api-playbook.md` | 路由×方法 |
| oidc | OIDC/OAuth 登录、回调地址 | `oidc_probe.py` | `oidc-playbook.md` | 8–12 |
| nuclei | 想用社区模板补盲 | `tool_adapters.py` | `tooling.md` | 由模板决定 |

**决策原则**：先做“能直接解释的少量证据”，再上工具。sqlmap/nuclei 是放大器，不是第一步。

## 4. 计划树（PTT）

复杂目标不要线性扫。维护一个任务树，每完成一项就写结论/证据/下一步：

```
目标
├─ 资产与入口（recon）
├─ 身份与角色（buyer/merchant/admin；302/403/404）
├─ 会话与基线（每角色 2xx、非登录页）
├─ 输入面（GET/POST/JSON/路径/数组键/报表列名）
├─ 漏洞模块（配置/XSS/越权/SQLi/SSRF/上传）
└─ 证据与报告（findings.json → report.html）
```

模块失败不是“没漏洞”，要记录失败原因（会话、限速、输入校验、WAF）。

## 5. Findings 与证据

统一结构（`scripts/findings.py`）：

```json
{
  "id": "F-001", "module": "sqli", "title": "...",
  "severity": "high", "cvss": 7.5, "confidence": "confirmed",
  "endpoint": "...", "method": "GET", "parameter": "dimension",
  "evidence": {"payload": "...", "status": 200, "artifact": "raw/..."},
  "impact": "...", "remediation": "...", "references": ["WSTG-INPV-05"], "tags": ["sqli"]
}
```

- **confirmed**：可复现、证据链完整；
- **likely**：现象明确但边界未证；
- **needs-review**：需要人工/业务确认；
- **surface**：只发现入口，未验证利用。

报告默认按 severity 排序，同 endpoint+param 去重。

## 6. 报告

```bash
python scripts/report.py --run-dir runs/<name>
```

单文件、离线、深/浅色切换、可打印。内容：摘要卡片、模块覆盖、会话、发现（证据/影响/修复/参考）、方法与边界。

## 7. 外部工具

```bash
python scripts/tool_adapters.py --list
python scripts/tool_adapters.py --run nuclei --target https://host --rate 10
python scripts/tool_adapters.py --run httpx --target https://host
```

- 没安装就跳过，不阻塞；
- nuclei 默认排除 `intrusive,dos,fuzz,brute-force,default-login`；
- 工具输出统一进 findings（nuclei）或 surface（httpx/katana）；
- 详细命令与安装见 `references/tooling.md`。

## 8. 扩展原则

**一个工作台 + 按漏洞类拆 playbook + 少量 probe 脚本**，不要为每个漏洞新开顶层 skill。

- 新模块固定四段：`detect → confirm（3–4 发）→ impact → report`；
- 共享 `httpkit`（会话/预算/证据）、`findings`（去重/严重度）、`report`；
- 只有工具链分叉（浏览器 JS、带外回连）或 `SKILL.md` > ~300 行时，才拆子 skill 并抽 `common/`。

## 9. 失败分诊

| 症状 | 多半是 | 动作 |
|---|---|---|
| 登录 403「安全校验未通过」 | 缺 Referer / CSRF 失效 / 会话轮换 | 用 `httpkit.login()`；检查 cookie jar；重取 CSRF |
| 跑一半 302 → /login | 会话过期/轮换 | 重登；用 jar；降低单轮请求数 |
| 429 / 422「过于频繁」 | 限速 | 加大 delay、缩范围、停手冷却 |
| 整站 530 | Cloudflare Tunnel origin 掉线 | 等恢复；quick tunnel 重启会换域名 |
| XSS 反射在 `<title>`/属性值里 | 不是可执行上下文 | 看 `context_kind`；body/attr-breakout 才算 |
| `dimension=xxx'` 500，`(SELECT 1)` 返回 1 | 列名/表达式注入 | `sqli_probe --context expr`；读 information_schema |
| 报表导出只有 500/空 CSV | 输入截断/限速/错误被吞 | 换短载荷；问应用上限；看 raw 证据 |
| 工具没输出 | 未安装/参数不兼容 | `tool_adapters.py --list`；看 stderr |
| 登录 429 | 登录端点限速（不是封号） | 停手冷却；复用现有 session；不要循环重登；`--strict-auth` 防止未认证跑出假阴性 |
| 模块全 0 但 `summary.sessions` 有 login error | 会话没登上，结果不可信 | 先修会话；不要把匿名负例当结论 |
| SQLi expr 的 marker 只出现在 input/title | 搜索回显，不是 SQL 数据 | 只认 CSV/JSON 的结构化输出；或显式 `--context expr` |
| 导出签名 `exp+1` 仍 200 | 签名不校验过期 | 记录 high；报告里给 exp/sig 证据 |
| 导出下载换 job id 200 | 签名未绑定任务/缺租户校验 | 对象级授权缺失；记录 job/tenant |
| 合作方 API 401/405 | 路由存在但需要凭据/方法不对 | 405 看 Allow；401 找 API key/Bearer，不要爆破 |
| OIDC 400「客户端无效」 | client_id 不对/未提供 | 从凭据/前端配置取 client_id；不要猜 |
| OIDC 变体 302 到相似域名 | redirect_uri 前缀匹配 | 记录 critical；精确匹配修复 |

## References

- `references/intake.md` —— 目标/会话/参数 intake。
- `references/methodology.md` —— PTES/WSTG 映射、PTT、证据与预算。
- `references/sqli-playbook.md` —— SQLi/表达式注入全流程。
- `references/xss-playbook.md` —— 反射/存储/DOM XSS。
- `references/authz-playbook.md` —— 角色矩阵/IDOR/越权。
- `references/ssrf-playbook.md` —— 带外回调/内网探测。
- `references/upload-playbook.md` —— 上传面与安全测试。
- `references/export-playbook.md` —— 异步导出、签名下载、对象级授权。
- `references/api-playbook.md` —— 无文档 API 的 401/405/404 面与批量赋值。
- `references/oidc-playbook.md` —— OIDC/OAuth 回调地址与账号接管。
- `references/misconfig-playbook.md` —— 头/Cookie/CORS/敏感路径。
- `references/tooling.md` —— 外部工具适配与安全参数。
- `references/reporting.md` —— findings 模型、严重度、脱敏、报告结构。
- `references/lab-ops.md` —— 靶场/演练运维：短会话、登录 429、凭据缺失、记分板与复盘。
