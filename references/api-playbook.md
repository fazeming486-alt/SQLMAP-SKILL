# 无文档 API 面 playbook

## 为什么要做

合作方/移动端 API 往往没有导航、没有 OpenAPI，但路由真实存在。用 3 个状态码就能画地图：

| 状态 | 含义 | 下一步 |
|---|---|---|
| 404 | 路由不存在 | 换路径/前缀 |
| 405 | 路由存在，方法不对 | 看 `Allow`，换 GET/POST/PATCH/PUT |
| 401/403 | 路由存在，需要认证 | 找 Cookie/Bearer/API key；不要爆破 |
| 200 | 可直接访问 | 看数据敏感度；未授权 = 高危 |
| 500 | 路由存在但报错 | 看 body 是否泄露堆栈 |

## 常见前缀

`/partner/v1`、`/api/v1`、`/api`、`/v1`、`/internal`、`/admin/api`、`/mobile`、`/openapi.json`、`/docs`。

## 认证

**HMAC 签名**（OBSIDIAN 合作方 API）：`timestamp + "
" + METHOD + "
" + path_with_query + "
" + raw_body` 的 HMAC-SHA256，放在 `X-*-Signature`；用 `scripts/hmac_client.py` 直接调用。签名必须用**规范化后的 path**（Windows 下 `/partner/...` 会被 MSYS 转成 `C:/Program Files/Git/...`）。

- Cookie（门户会话）
- `Authorization: Bearer <token>`
- `X-API-Key`
- HTTP Basic（少见）
- HMAC 签名头（`X-Signature`/`X-Timestamp`）

先确认认证方式，再测业务。**401 不是漏洞**；200 未授权才是。

## 高价值测试

1. **对象级授权**：`/orders/{id}`、`/profile/{id}`、`/invoices/{id}` 换 ID/租户。
2. **批量赋值**：PATCH/POST 塞 `role`、`tier`、`is_verified`、`commission_rate`、`tenant_id`。
3. **方法覆盖**：GET 不允许但 POST/PATCH 允许；`X-HTTP-Method-Override`。
4. **版本降级**：`/v2` 安全、`/v1` 旧逻辑。
5. **内容类型**：JSON 与 form-urlencoded 走不同校验。
6. **分页/导出**：`limit=100000`、`page=0`、`all=true`。

## 工具

`api_probe.py`：路由×方法枚举，分类 401/405/404/200，输出 surface findings。

```bash
python scripts/api_probe.py --base https://host \
  --route /partner/v1/profile --route /partner/v1/orders \
  --route /partner/v1/invoices/import --methods GET,POST,PATCH
```

带认证：

```bash
python scripts/api_probe.py --base https://host --bearer <token> --api-key <key>
```

## 证据

- 每个状态码的请求/响应片段；
- `Allow` 头；
- 认证失败与成功对照；
- 批量赋值前后的对象差异。
