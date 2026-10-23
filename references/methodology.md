# 方法论：从侦察到报告（v4）

本工作台把一次授权 Web 测试拆成可复用的阶段。每阶段都有明确的输入、输出和停止条件。

## 阶段

| 阶段 | 输入 | 输出 | 停止条件 |
|---|---|---|---|
| Scope | 目标、授权范围、账号 | `scope`、`sessions` | 目标不在 scope → 停 |
| Recon | 入口 URL | 端点/参数/表单/技术栈 | 预算用尽 |
| Roles | 账号/工作台 | 302/403/404 矩阵 | 无账号 → 只做匿名面 |
| Baseline | 每角色会话 | 2xx、非登录页 | 302/401/403 → 修会话 |
| Modules | 输入面 + 角色 | findings | 预算/限速/无信号 |
| Verify | findings | confirmed/likely | 无法复现 → 降级 |
| Report | findings + summary | HTML/JSON | — |

## WSTG 映射

| 模块 | WSTG |
|---|---|
| 信息收集/侦察 | WSTG-INFO |
| 配置/头/CORS | WSTG-CONF |
| 身份/会话 | WSTG-IDNT / WSTG-SESS |
| 越权/IDOR | WSTG-ATHZ |
| SQLi | WSTG-INPV-05 |
| XSS | WSTG-INPV-01/02 |
| SSRF | WSTG-INPV-19 |
| 上传 | WSTG-BUSL-09 |
| 错误处理 | WSTG-ERRH |
| 业务逻辑 | WSTG-BUSL |

## 计划树（PTT）

PentestGPT 的核心经验：LLM 在长上下文里会丢目标，用任务树把“当前在哪、下一步是什么”外置。

```
目标
├─ 资产/入口
│  ├─ 页面/表单/端点
│  └─ 技术栈/版本
├─ 身份/角色
│  ├─ buyer/merchant/admin
│  └─ 302/403/404 矩阵
├─ 输入面
│  ├─ GET/POST/JSON
│  ├─ 路径/数字 ID
│  └─ 数组键/报表列名
├─ 模块
│  ├─ 配置/XSS/越权/SQLi/SSRF/上传
│  └─ 每个模块：detect → confirm → impact
└─ 证据/报告
```

每完成一个节点，写三行：**结论 / 证据 / 下一步**。失败节点也要写原因（会话、限速、输入校验、WAF）。

## 预算与节奏

- `max_requests` 是硬上限；`rps` 是软节奏。
- 单模块先 3–4 发；确认后再放大。
- 429/422/403 安全校验 = 停，冷却；不要用并发绕过。
- 工具（sqlmap/nuclei）在确认后使用，避免“扫描器先跑 20 分钟”。

## 证据标准

一个可交付的 finding 至少要有：

1. 完整请求（方法、URL、参数、关键头）；
2. 响应状态 + 关键片段；
3. 对照（baseline/true/false 或 role A/role B）；
4. 原始响应落盘路径；
5. 可复现步骤（人或脚本）。

## 报告原则

- 先结论，后过程；
- 严重度基于影响，不基于 payload 数量；
- 未确认项明确标注 confidence；
- 敏感值掩码；挑战 token 按需脱敏；
- 写清未测项与限制。
