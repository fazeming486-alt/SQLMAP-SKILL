# WEB-PENTEST-SKILL

授权 Web 渗透测试工作台（v3.0）。从侦察、角色/工作台枚举、基线核验，到 SQLi / 列名表达式注入、证据留档和 HTML 报告交付。

> **定位变化（v3.0）**：不再叫“sqlmap skill”。sqlmap 只是 SQLi 模块的一个执行器；工作台本身负责范围、侦察、会话、基线、证据、报告，并给后续漏洞类留扩展位。

## 安装

**WorkBuddy**：把本目录复制到 `C:\Users\Administrator\.workbuddy\skills\web-pentest\`（或 `~/.workbuddy/skills/web-pentest/`），提到“Web 渗透 / 侦察 / 注入”即自动触发。

**Qoder**：把本目录复制到 `~/.qoder/skills/web-pentest/`，然后 `/skills reload`，用 `/web-pentest` 调用。

> 旧名 `sqlmap-skill` 的目录/副本可以删除。GitHub 仓库已由 `SQLMAP-SKILL` 改名为 `WEB-PENTEST-SKILL`（GitHub 会保留旧地址跳转）。

## 工作流

解析目标 → 工作台/角色枚举 → 档案匹配（命中即零问答）→ 组装 job.json → 自动会话 → 基线核验 → 分模块运行 → 证据落盘 → HTML 报告。

### 模块

| 模块 | 状态 | 参考 | 主要脚本 |
|---|---|---|---|
| 侦察 / 攻击面 | 可用 | `SKILL.md` Step 2.5 | `recon.py` |
| 角色 / 工作台矩阵 | 可用 | `SKILL.md` Step 0.5 | 无（3 个请求分清 302/403/404） |
| SQLi（布尔/UNION/报错/时间） | 可用 | `references/sqli-playbook.md` | `sqlmap_run.py`、`inject_probe.py` |
| 列名 / 表达式注入（报表导出） | 可用 | `references/sqli-playbook.md` | `expr_probe.py` |
| TLS 指纹拦截中继 | 可用 | `references/sqli-playbook.md` | `tls_relay.py` |
| HTML 报告 | 可用 | `SKILL.md` Step 6 | `html_report.py` |
| 越权 / IDOR | 待建 | — | — |
| XSS（反射/存储/DOM） | 待建 | — | — |
| SSRF | 待建 | — | — |
| 文件上传 / 业务逻辑 | 待建 | — | — |

## 为什么是一个工作台，而不是一堆小 skill

共享部分占了大部分工程量：范围与目标、侦察、角色矩阵、会话、基线、证据、限速、报告。为每个漏洞新开一个顶层 skill 会重复这些逻辑，而且 agent 容易加载错模块。推荐：

- **一个核心 SKILL.md** 负责路由和工程纪律；
- **每个漏洞类一份 `references/<class>-playbook.md`**，按需读取，避免主提示词膨胀；
- **每个漏洞类少量 `scripts/<class>_probe.py`**，固定“detect → confirm（3–4 发）→ impact → report”四段；
- 只有工具链真正分叉（浏览器执行 JS 的 XSS、带外回连的 SSRF）或 `SKILL.md` 超过约 300 行时，才拆子 skill，并抽 `common/` 共享会话/证据/报告。

## v3 能力

- **侦察**（`recon.py`）：被动爬取（链接/表单/robots/sitemap/JS 端点）+ 目录发现 + CT 子域 + JS 密钥扫描 + 技术栈指纹，输出带 `*` 的候选注入点。
- **工作台枚举**：`/buyer`、`/merchant`、`/admin` 等入口用 302/403/404 快速判断“未登录 / 角色不对 / 不存在”；买家侧干净不代表整站干净。
- **SQLi 全流程**：detect / dbs / tables / columns / dump / passwords / privileges / sql-query；单发 `os-cmd` / `file-read` / `file-write` 替代交互 shell。
- **成对取证**（`inject_probe.py`）：基线/真值/假值 3 发结论，支持 numeric / quoted / **arraykey**；限速自动停手。
- **表达式注入**（`expr_probe.py`）：报表/导出接口的 `dimension`、`order_by` 一类列名参数，4 发确认；支持 `(SELECT ...)` 取数、cookie jar 跟随会话轮换、登录页误判保护。
- **TLS 中继**（`tls_relay.py`）：目标按 TLS 客户端指纹拦扫描器时，本地 Plain-HTTP → Clean-TLS 中继。
- **HTML 报告**（`html_report.py`）：单文件离线暗色报告，含概要、时间线、证据、dump 交互表、日志折叠。
- **工程纪律**：基线先行、日志与 CSV 落盘、Cookie 掩码、`--dry-run` 预览、失败分诊。

## 实战记录

- **NEXA 星港云市（2026-10）**：买家侧 15+ 参数全部参数化；唯一 SQLi 在商家 `/merchant/reports/export?dimension=`——参数被当列名拼接，`category'` → 500，`(SELECT 1)` → CSV 第一列变 `1`；MariaDB 10.11，只读账号可读 2,198 客户 / 36,003 订单 / 120 商户。结论：先数工作台，再看报表/排序列名，最后才上扫描器。
- **南岭优选（2026-10）**：报表导出 LIKE 注入，UNION 跨用户读 CSV；应用限速 30 次/分钟，sqlmap 长语句被截断。
- **DVWA / 北岸商城**：档案化零问答；布尔/UNION、哈希链、WAF/UA 规则。

## 安全边界

无授权问答。目标、节奏、深度由使用者决定并自负其责；skill 只做技术质量把关（基线、证据、日志）。`jobs/`、`runs/`、日志、CSV 均已 gitignore，Cookie 不会进仓库。

## 变更

> v2.1 借鉴 [atiilla/sqlmap-ai](https://github.com/atiilla/sqlmap-ai)：`-p` 参数定向、`-r` 请求文件、WAF 指纹预检、detect 后决策树。
>
> v2.2 新增 HTML 交互报告。
>
> v2.3 新增自动找注入点（`recon.py`）。
>
> v2.4 新增 TLS 中继（`tls_relay.py`）。
>
> v2.5 侦察升级：CT 子域、JS 密钥、技术栈、目录发现。
>
> v2.6 新增成对取证（`inject_probe.py`）。
>
> v2.7 新增表达式/列名注入取证（`expr_probe.py`），补工作台枚举与会话轮换分诊。
>
> **v3.0 改名与定位升级**：`SQLMAP-SKILL` → `WEB-PENTEST-SKILL`，`sqlmap-skill` → `web-pentest`；SQLi 成为第一个深度模块；明确“一个工作台 + 按漏洞类拆 playbook”的扩展架构。

详见 `SKILL.md` 与 `references/`。
