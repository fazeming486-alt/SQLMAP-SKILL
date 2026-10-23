# 配置面 playbook（misconfig）

`misconfig_probe.py` 覆盖：安全头、Cookie 属性、CORS、危险方法、敏感路径、错误页泄露。

## 安全响应头

| 头 | 缺失影响 |
|---|---|
| `Content-Security-Policy` | XSS 纵深防御缺失 |
| `Strict-Transport-Security` | 降级/劫持风险（HTTPS） |
| `X-Content-Type-Options: nosniff` | MIME 嗅探 |
| `X-Frame-Options` / `frame-ancestors` | 点击劫持 |
| `Referrer-Policy` | Referer 泄露 |
| `Permissions-Policy` | 浏览器能力滥用 |

## Cookie

- `Secure`：只走 HTTPS
- `HttpOnly`：脚本不可读
- `SameSite=Lax/Strict`：CSRF 纵深防御
- 作用域/过期时间/前缀（`__Host-`）

## CORS

- `Access-Control-Allow-Origin: *` + `Allow-Credentials: true` → 高危。
- 反射任意 Origin + 凭据 → 高危。
- 只允许固定白名单才安全。

## 方法

`OPTIONS` 看 `Allow`；`TRACE` 可能 XST；`PUT/DELETE` 是否未授权可用。

## 敏感路径

`/.git/config`、`/.env`、`/actuator/env`、`/actuator/health`、`/server-status`、`/phpinfo.php`、`/swagger-ui`、`/openapi.json`、`/backup.zip`、`/.DS_Store`。

判定 200 + 内容特征，不能只看状态码；登录页/404 页要排除。

## 错误处理

500/404 页面是否含堆栈、SQL 报错、框架版本、文件路径。统一错误页 + 服务端日志。

## TLS/域名

`testssl.sh`、证书链、HSTS 预加载、混合内容、HTTP→HTTPS 跳转。

## 修复

统一安全头；Cookie 全属性；CORS 白名单；关闭 TRACE；生产移除调试端点；错误页脱敏。
