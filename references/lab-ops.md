# 靶场/演练运维 playbook（OBSIDIAN 实战）

## 先确认三件事

1. **入口**：Quick Tunnel 地址是否可达；`/health` 是否 200；本机代理是否干扰（Windows 上 `--noproxy "*"`）。
2. **账号**：哪些角色无 MFA、哪些需要 TOTP；TOTP secret/API key/OIDC client 是否在本地凭据文件。
3. **记分板**：`/scoreboard` 的目标、提示、flag 提交；不要只依赖扫描器。

## 会话

- 靶场会话 TTL 可能只有 1–3 分钟；页面会 303 `/login`。
- 用 cookie jar + `httpkit` 自动重登；不要在每条请求前手动登录。
- 登录端点也会限速（429）。**复用现有 session**，不要循环重登；冷却 5–10 分钟。
- MFA 账号：把 TOTP secret 放 `login.totp_secret`；不要爆破/猜码。

## 证据

- 每个请求落 `raw/`；findings 指回原始响应。
- 记录 `rid`（请求 ID）、时间、账号、状态码，供 MTTD/MTTR 复盘。
- 不记录 Cookie/TOTP/API key 到报告。

## 常见假阴性/假阳性

| 现象 | 处理 |
|---|---|
| 模块全 0，但 `summary.sessions` 有 login error | 先修会话；不要当“无漏洞” |
| SQLi expr marker 只在 input/title 出现 | 是回显，不是注入；只认 CSV/JSON 数据行 |
| 导出/API 模块用了匿名会话 | 显式 `export_role`/`api_role` |
| OIDC 测试返回登录页 200 | 先登录；否则不是 redirect_uri 结论 |
| 上传/下载/写操作 | 先确认可回滚；默认只读 |

## 拿不到凭据时

- 明确记录缺失项（TOTP/API key/client_id），向发起人要文件；不要把“猜”当进度。
- 先把无凭据面（登录页、OIDC discovery、公开 API 401/405、健康端点）做成可复用证据。
- 买家侧可做的：导出任务/签名、工单、搜索参数、越权矩阵；做完再等凭据。

## 演练结束

- 关闭 exercise flags、切回 hardened、重建 api/worker、重置数据；
- 保留审计与检测时间线；
- 复盘：MTTD/MTTC/MTTR、误报、漏报、回归测试、修复提交。
