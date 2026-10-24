# WEB-PENTEST-SKILL

授权 Web 渗透测试工作台（v4.1.3）。不是 sqlmap 外壳，而是一套可编排的流水线：

```
scope/session → recon → role matrix → baseline → modules → verify → findings → report
```

当前内置模块：配置面、反射/基础存储 XSS、越权/IDOR、SQLi/表达式注入、SSRF 带外、上传面盘点；外部工具适配 nuclei / httpx / katana / ffuf / dalfox / arjun / whatweb / wafw00f / sqlmap。

## 快速开始

```bash
cp examples/engage.example.json engage.json
# 填 base_url / scope / sessions / options
python scripts/engage.py --config engage.json --dry-run
python scripts/engage.py --config engage.json --report
```

产物：`runs/<name>/findings.json`、`summary.json`、`raw/` 原始证据、`report.html` 单文件报告。

单模块：

```bash
python scripts/misconfig_probe.py --target https://host
python scripts/xss_probe.py --target "https://host/search?q=*"
python scripts/authz_probe.py --config authz.json
python scripts/sqli_probe.py --target "https://host/export?dimension=*" --context expr
python scripts/ssrf_probe.py --target "https://host/fetch?url=*" --callback https://your-callback
python scripts/upload_probe.py --page https://host/upload
python scripts/export_probe.py --base https://host --cookie-jar buyer.txt
python scripts/api_probe.py --base https://host --route /partner/v1/profile
python scripts/oidc_probe.py --issuer https://host --client-id <id> --redirect-uri https://host/oidc/callback
python scripts/report.py --run-dir runs/demo
```

## 模块

| 模块 | 状态 | 脚本 | 参考 |
|---|---|---|---|
| 侦察/攻击面 | 可用 | `recon.py` | `references/methodology.md` |
| 配置面（头/Cookie/CORS/路径/报错） | 可用 | `misconfig_probe.py` | `references/misconfig-playbook.md` |
| 反射/基础存储 XSS | 可用 | `xss_probe.py` | `references/xss-playbook.md` |
| 越权/IDOR/角色矩阵 | 可用 | `authz_probe.py` | `references/authz-playbook.md` |
| SQLi/表达式注入 | 可用 | `sqli_probe.py`、`sqlmap_run.py` | `references/sqli-playbook.md` |
| SSRF 带外 | beta | `ssrf_probe.py` | `references/ssrf-playbook.md` |
| 上传面 | 可用（默认只盘面） | `upload_probe.py` | `references/upload-playbook.md` |
| 异步导出/签名下载 | 可用 | `export_probe.py` | `references/export-playbook.md` |
| 合作方/移动 API 面 | 可用 | `api_probe.py` | `references/api-playbook.md` |
| OIDC/OAuth 回调绕过 | 可用 | `oidc_probe.py` | `references/oidc-playbook.md` |
| 外部工具 | 可用（按安装） | `tool_adapters.py` | `references/tooling.md` |
| HTML 报告 | 可用 | `report.py`、`html_report.py` | `references/reporting.md` |
| DOM XSS / 业务逻辑 | 手工 | — | `references/xss-playbook.md` / `methodology.md` |

## 内核

| 文件 | 作用 |
|---|---|
| `scripts/httpkit.py` | 会话（Cookie/CSRF/Referer/轮换）、限速、预算、重试、归一化、证据脱敏 |
| `scripts/findings.py` | 统一 findings、去重、严重度/置信度、JSON |
| `scripts/engage.py` | 编排器：scope、登录、模块、预算、断点、summary、报告 |
| `scripts/report.py` | findings → 单文件 HTML（深/浅色、打印） |
| `scripts/tool_adapters.py` | 外部工具检测/调用/解析 |
| `scripts/recon.py` | 爬取、目录、CT 子域、JS 密钥、技术栈 |

每个模块固定四段：`detect（少量请求）→ confirm（3–4 发）→ impact → report`。

## 设计参考

- [PentestGPT](https://github.com/GreyDGL/PentestGPT)：Reasoning / Generation / Parsing 分层与 Pentesting Task Tree（本工作台的“计划树 + 证据”）。
- [Strix](https://github.com/usestrix/strix)：evidence-first、HTTP 代理/浏览器/终端工具面、多 agent 分工与 findings。
- [HexStrike AI](https://github.com/0x4m4/hexstrike-ai)：工具注册、决策引擎、进程管理/缓存/错误恢复。
- [PentAGI](https://github.com/vxcontrol/pentagi)：沙箱、工具调用上限、reflector、任务规划与报告。
- [OWASP WSTG](https://github.com/OWASP/wstg)：测试分类与判据。
- [ProjectDiscovery](https://github.com/projectdiscovery/nuclei)：nuclei/httpx/katana 的模板与 JSONL 输出。
- [Anthropic Agent Skills](https://www.anthropic.com/research/equipping-agents-for-the-real-world-with-agent-skills)：渐进披露——SKILL.md 做路由，细节放 references，脚本做执行器。

## 安装

**WorkBuddy**：复制到 `C:\Users\Administrator\.workbuddy\skills\web-pentest\`（或 `~/.workbuddy/skills/web-pentest/`）。

**Qoder**：复制到 `~/.qoder/skills/web-pentest/`，`/skills reload`，用 `/web-pentest`。

> 旧名 `sqlmap-skill` / `SQLMAP-SKILL` 已改名；GitHub 旧地址跳转。

## 实战记录

- **NEXA 星港云市（2026-10）**：买家侧 15+ 参数全部参数化；唯一 SQLi 在商家 `/merchant/reports/export?dimension=`——`category'` → 500，`(SELECT 1)` → CSV 第一列变 `1`；MariaDB 10.11，只读账号可读 2,198 客户 / 36,003 订单 / 120 商户。
- **南岭优选（2026-10）**：报表导出 LIKE 注入，UNION 跨用户读 CSV；应用限速 30 次/分钟，sqlmap 长语句被截断。
- **DVWA / 北岸商城**：档案化零问答；布尔/UNION、哈希链、WAF/UA 规则。

## 安全边界

无授权问答。目标、节奏、深度由使用者决定并自负其责；工作台只做技术质量把关（scope、预算、基线、证据、日志）。`jobs/`、`runs/`、日志、CSV 均已 gitignore，Cookie 不会进仓库。上传模块默认只盘面，不传文件；SSRF 默认不自动打云元数据。

## 变更

> v2.1 借鉴 sqlmap-ai：`-p` 参数定向、`-r` 请求文件、WAF 指纹、detect 决策树。
>
> v2.2 HTML 交互报告；v2.3 recon；v2.4 TLS 中继；v2.5 侦察升级；v2.6 成对取证；v2.7 表达式/列名注入。
>
> **v3.0 改名与定位**：`SQLMAP-SKILL` → `WEB-PENTEST-SKILL`；SQLi 成为第一个深度模块。
>
> **v4.1.3**：新增 `references/lab-ops.md`（短会话、登录 429、凭据缺失、记分板/复盘）；买家侧 OBSIDIAN 干净回归报告入库。
>
> **v4.1.2**：导出/API 模块支持显式角色（`export_role`/`api_role`），避免用匿名会话跑认证面；买家侧 OBSIDIAN 回归 0 high、7 info。
>
> **v4.1.1**：修正 `sqli_probe` 把搜索回显当表达式注入的假阳性；`engage` 增加 `--strict-auth`、登录失败告警、run 目录不覆盖；OIDC/导出模块遇登录页直接判 `login_required`；TOTP 登录参数贯通 authz/engage。
>
> **v4.1.0**：新增异步导出/签名下载（`export_probe.py`）、无文档 API 面（`api_probe.py`）、OIDC 回调绕过（`oidc_probe.py`）；`httpkit` 支持会话失效自动重登与 TOTP MFA；补 MSYS 路径参数转换。OBSIDIAN 实战：短会话、登录 429、partner API 401/405、OIDC 客户端无效。
>
> **v4.0.1**：登录失败不中断角色矩阵；修正 httpx 同名二进制识别。
>
> **v4.0 工作台化**：新增 `httpkit` / `findings` / `engage` / `report` 内核；新增配置面、XSS、越权/IDOR、SSRF、上传面模块；外部工具适配；统一预算/限速/证据/报告；SKILL.md 改为路由层，细节拆 references。

详见 `SKILL.md` 与 `references/`。
