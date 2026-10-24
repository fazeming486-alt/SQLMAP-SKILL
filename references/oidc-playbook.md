# OIDC / OAuth 回调地址 playbook

## 基础

- 发现文档：`/.well-known/openid-configuration`
- 授权端点：`/oidc/authorize`
- 令牌端点：`/oidc/token`
- 常见客户端类型：门户 Web、供应商门户、合作方 API、移动端。

## 回调地址校验的常见错误

| 写法 | 绕过 |
|---|---|
| `startswith(registered)` | `https://app.com.evil.com/cb` |
| `registered in uri` | `https://evil.com/?x=https://app.com/cb` |
| 只校验 host 后缀 | `https://app.com@evil.com/cb` |
| 未规范化 | `%2e`、`%2f`、大小写、尾随点、反斜杠 |
| 允许子路径 | `https://app.com/cb/../../evil` |
| 允许 query | `https://app.com/cb?next=https://evil.com` |

正确做法：**精确字符串匹配**注册值（协议、host、port、path、query 都一致），或使用严格的白名单解析后比较。

## 测试步骤

1. 取合法 `client_id` 与 `redirect_uri`（从登录页/前端配置/凭据文件）。
2. 不带参数请求 authorize，确认登录重定向。
3. 带合法参数请求，确认 302 回合法地址（可能带 code）。
4. 逐个变体请求，观察 `Location`：
   - 302 到攻击者域名且带 `code=` → critical；
   - 302 到相似域名但无 code → 需复核；
   - 400「redirect_uri 无效」→ 安全；
   - 400「客户端无效」→ client_id 不对，先解决这个。
5. 如拿到 code，用 token 端点换 token；确认能否访问受害者资源（仅授权演练）。

## 工具

`oidc_probe.py`：

```bash
python scripts/oidc_probe.py --issuer https://host --client-id <id> \
  --redirect-uri https://host/oidc/callback --cookie-jar buyer.txt
```

## MFA 与接管

- MFA 不阻止 redirect_uri 绕过：攻击者拿的是**已认证用户的授权码**。
- 若目标有“受害者模拟/机器人”，确认其登录后的回调；没有则只能证明校验缺陷，不能证明接管。
- 不要伪造/爆破 TOTP；用凭据文件里的 secret 或测试账号。

## 证据

- 授权请求 URL、状态码、`Location`；
- 合法 vs 变体对照；
- code 换 token 的响应（脱敏）；
- 受害者账号资源的访问结果（脱敏）。
