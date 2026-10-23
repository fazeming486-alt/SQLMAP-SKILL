# 报告与 findings（reporting）

## Findings 结构

```json
{
  "id": "F-001",
  "module": "sqli",
  "title": "列名/表达式 SQL 注入（报表导出）",
  "severity": "high",
  "cvss": 7.5,
  "confidence": "confirmed",
  "endpoint": "https://host/merchant/reports/export",
  "method": "GET",
  "parameter": "dimension",
  "evidence": {
    "payload": "(SELECT 1)",
    "status": 200,
    "scalar": "1",
    "artifact": "raw/module/sqli-expr-scalar.txt"
  },
  "impact": "可读取整库/跨租户数据。",
  "remediation": "列名白名单映射；参数化。",
  "references": ["WSTG-INPV-05"],
  "tags": ["sqli", "expr"]
}
```

## 严重度

| 级别 | 参考 | 例子 |
|---|---|---|
| critical | 9.0–10 | 未授权 RCE、全库读写 |
| high | 7.0–8.9 | 跨租户读取、SQLi、存储型 XSS |
| medium | 4.0–6.9 | 反射 XSS、CORS 任意源、错误泄露 |
| low | 0.1–3.9 | 缺安全头、Cookie 属性、TRACE |
| info | 0 | 上传面、调试入口、技术栈 |

CVSS 只是参考；报告里写清“需要什么权限、能读/写什么、影响多少数据”。

## 置信度

- `confirmed`：可复现、证据链完整；
- `likely`：现象明确但边界未证；
- `needs-review`：需业务/人工确认；
- `surface`：只发现入口，未验证。

## 证据

- 原始请求/响应落盘，报告只放关键片段；
- 对照实验（baseline/true/false、角色 A/B）；
- 路径、时间、状态码、关键头；
- 敏感值脱敏（Cookie/CSRF/token/PII）。

## 报告结构

1. 封面/范围/日期/最高风险；
2. 摘要卡片 + 一句话结论；
3. 模块覆盖与会话；
4. 发现（按严重度）：端点、参数、证据、影响、修复、参考；
5. 方法与边界（未测项、限制）；
6. 附录（运行目录、原始证据、时间线）。

## 去重

同 `module + title + endpoint + parameter` 合并，保留最强证据；不要把同一根因拆成十条。

## 交付

`report.py` 生成单文件 HTML；需要 PDF 时用浏览器打印。报告目录整体打包时，注意 `raw/` 可能含 Cookie/PII，先脱敏或只交付报告。
