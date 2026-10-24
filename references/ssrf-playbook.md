# SSRF playbook（beta）

## 两种回调

- **目标与本机同网/同机**：`--callback http://<你的内网IP>:<port>`，`ssrf_probe.py --listen 0.0.0.0`。
- **远程目标**：`127.0.0.1` 是目标自己的回环；必须用公网可达的回调（自己的域名、interactsh、webhook）。

## 高价值参数

`url`、`uri`、`link`、`src`、`image`、`avatar`、`webhook`、`callback`、`next`、`redirect`、`return`、`returnUrl`、`continue`、`target`、`host`、`domain`、`feed`、`proxy`、`fetch`、`load`、`file`、`path`、`dest`、`destination`、`port`、`ip`、`endpoint`、`api`。

## 4 步

1. 基线：参数填一个正常 URL，确认 2xx/可解析。
2. 回调：填入带随机 token 的 callback URL。
3. 观察：监听器是否收到 token 的请求（DNS/HTTP）。
4. 影响：只证明“服务器发起了请求”；是否可读内网/元数据需单独验证，默认不自动打云元数据。

## 常见绕过（手工）

- `http://127.0.0.1`、`http://localhost`、`http://[::1]`
- 十进制/八进制/十六进制 IP、`127.1`、`0x7f000001`
- `http://evil@127.0.0.1`、`http://127.0.0.1#@evil`
- 短链接/重定向（302 到内网）
- DNS rebinding（需自己的 DNS）
- 协议：`file://`、`gopher://`、`dict://`（看库/客户端支持）

## 注意

- 不要自动请求云元数据（169.254.169.254）或内网管理面；只在授权范围与明确允许时测试。
- 回调可能被目标出站防火墙拦截；收不到 ≠ 无 SSRF，换 DNS/端口/协议再试。
- 证据：注入请求、回调日志（时间、path、源 IP）、原始响应。

## Webhook 首跳绕过（v4.2）

- 很多实现只校验“创建时的 URL”（HTTPS/公网），投递时默认跟随 302，不再校验。
- 用合法 HTTPS 重定向器（httpbin `/redirect-to`）作为首跳，内层指向 `http://api:8000/metrics` 等内部服务。
- OBSIDIAN 实测：`127.0.0.1:8000` 是 worker 自己的回环，Connection refused；Docker 服务名 `api:8000` 才通。
- 工具：`scripts/webhook_probe.py`；结果页若截断响应，优先找短内部端点/flag 路径。

## 工具

- `ssrf_probe.py`：本地回调 + token 命中。
- interactsh / Burp Collaborator：公网带外。
- `ssrfmap`：参数/协议字典（需授权）。
