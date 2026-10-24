# 案例：OBSIDIAN 多租户供应链靶场

授权演练案例（2026-10-24）。只记录方法与失败点，不保留任何 flag 值、Cookie、API secret。

## 目标结构

- 四个工作台：买家 `/buyer`、供应商 `/supplier`、运营 `/admin`、审计（只读）。
- 合作方 API：`/partner/v1/profile|orders|invoices/import`，HMAC-SHA256（`timestamp\nMETHOD\npath\nbody`）。
- OIDC：`/.well-known/openid-configuration`、`/oidc/authorize`、`/oidc/token`、`/oidc/callback`；三个客户端（local/supplier/public）。
- 业务面：退款审批、保存报表、Webhook、导出、工单、旧版工单视图、评分板。

## 已确认的缺陷与打法

### RPT-02 保存报表二阶注入

- 保存时校验，运行（worker 重放）时把 `status` 拼进 SQL。
- 布尔判据：`paid' OR '1'='1` → 7 组/293 单；`paid' AND 1=2` → 0 组。
- **关键坑**：模板尾部还有 `GROUP BY status`；用 `-- ` 注释会拆掉它 → `GroupingError`。用不带注释的 `paid' AND 1=1 AND 'x'='x`（末尾 `'x` 靠模板收尾引号闭合）。
- 判库：`information_schema.tables` 存在、`sqlite_master` 报 `UndefinedTable` → PostgreSQL。
- 一次性取值思路：`paid' UNION SELECT to_jsonb(feature_flags)::text AS status,1,1 FROM feature_flags WHERE 'x'='x`；把整行 JSON 作为分组键回显。若 UNION 被外层 GROUP BY 拒绝，退回布尔盲注。
- 报表创建有**节流**（“报表创建过于频繁”），失败尝试会重置冷却；报表无编辑/删除，run 不接受 `status` 覆盖。冷却期用 `--existing-id` 复跑已有报表。

### HOOK-03 Webhook 重定向 SSRF

- 创建时只校验首跳 HTTPS/公网；投递时跟随 302，不再校验。
- 首跳用 `https://httpbin.org/redirect-to?url=...`，内层 `http://api:8000/metrics` → 200；`127.0.0.1:8000` 是 worker 回环，Connection refused。
- 结果页把响应体截到 ~500 字符，`/metrics` 前 500 字节是 Python GC 指标；短内部端点（`/flag`、`/internal/flag`）是 404。
- 端点配额“最多 5 个启用中”，无编辑/删除路由；测试接口忽略 `url` 覆盖参数。配额满时会挡住继续换内网路径，先规划好要打的内部端点。
- 内网服务名用 Compose 服务名（`api`、`worker`、`db`），不要用 127.0.0.1。

### TKT-04 管理端旧版工单存储型 XSS

- 同一字段：标准视图转义，旧版 `/admin/tickets/<id>` 原文渲染。
- 但 CSP 是 `script-src 'self' 'nonce-...'` + `require-trusted-types-for 'script'`：`<img onerror>`、`<script>` 内联都不执行；要真正执行需同源脚本或 nonce 绕过（本靶场未提供上传面）。
- 查看动作会写审计 `security.stored_xss_viewed`（主体/对象/时间），这本身是“视图被触发”的证据；flag 不在页面、Cookie、localStorage。
- 教训：看到“原文渲染”先读 CSP，再判断能否执行；不要只凭源码未转义就断定可利用。

### OAUTH-05 OIDC 回调前缀绕过（已夺旗）

- 合法回调后追加 `?next=https://evil.example/` 仍被接受，授权码出现在回调 URL。
- 客户端 `obs-portal-public` 的 redirect_uri 精确匹配不严；`startswith`/`in` 校验是根因。
- 前缀/后缀/@/编码变体：`app.com.evil.com`、`app.com@evil.com`、`%2e%2e`、尾随点。

### API-08 合作方资料批量赋值（已夺旗）

- `PATCH /partner/v1/profile {"tier":"platinum"}` 接受特权字段，响应带 `changed/privileged` 与 `settlement_token`。
- 正常字段 `label` 可改；`tier/status/fee_bps/region` 是特权字段。字段白名单 + 服务端角色校验。

### PAY-06 退款并发

- 10 个真并发（独立连接、barrier、相同 Cookie/CSRF）仍只有 1 个成功，其余“该退款已处理”。
- 状态检查是原子的（或至少比客户端窗口快）；不要因为并发没打出双花就断定无漏洞，记录“已测并发与判据”。
- 待试：不同 worker、不同会话、approve 与其他动作的组合、请求体额外字段（amount/refund_id）。

### EXP-01 导出 IDOR

- 导出列表、详情、下载分开测。`/exports/<uuid>` 404、`/exports/<uuid>/download` 403 说明记录存在但缺签名。
- job UUID 来源：管理端审计 `?action=export` 会列 `export_job#<uuid>`；本次拿到的都是本租户（user#3）的历史任务。
- 签名是否绑定 job：用自己签名 URL 换别人 UUID（保留 exp/sig）→ 403 说明绑定了路径；需要另找签名泄露或列表越权。

### XML-07 发票 XXE

- `/partner/v1/invoices/import` 必须 merchant key；buyer key 明确 403“api client must belong to a merchant org”。
- 根不是 `<invoice>` → `XML 解析失败`；是 `<invoice>` 但字段不对 → `字段缺失`（不告诉你缺哪个）。
- 已试：snake_case/camelCase/PascalCase、中文标签、属性、header/items 嵌套、命名空间猜测、settlement_token、合法订单号 —— 仍“字段缺失”。下一步优先从源码/配置/同类发票规范反推 schema，或从 SQLi 读 `feature_flags`/配置表。
- 外部实体：`&xxe;` 形式未触发 OOB；参数实体直接报解析失败。先确认解析器/网络策略，再打文件读取。

## 运维/会话教训

- 登录 POST 必须带 Referer 且 Cookie jar 全程开启；否则 403“安全校验未通过”。
- UA 与会话绑定：自定义 `http.client` 的 UA 少 `(KHTML, like Gecko)` 会被 303 回登录。
- 会话 TTL 1–3 分钟；把“登录 → 多步操作 → 取证”放在同一进程，避免中途掉线。
- 登录 429 冷却 5–10 分钟；报表创建另有“过于频繁”节流，失败尝试会重置计时。
- Quick Tunnel 会间歇 530；遇到 530 先停手，恢复后先验证 `/login` 再继续，不要在 530 上重试写操作。

## 工具对应

| 场景 | 脚本 |
|---|---|
| 保存报表二阶注入 | `report_probe.py` |
| Webhook 重定向 SSRF | `webhook_probe.py` |
| HMAC API | `hmac_client.py` |
| OIDC 回调变体 | `oidc_probe.py` |
| 导出签名矩阵 | `export_probe.py` |
| 本地验证两探针 | `selftest_workbench.py` |
