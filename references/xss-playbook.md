# XSS playbook（反射 / 存储 / DOM）

## 三类

| 类型 | 判定 | 自动化 |
|---|---|---|
| 反射 | 请求参数原样进入响应，且处于可执行上下文 | `xss_probe.py` |
| 存储 | payload 入库，后续页面回显 | 部分（表单提交后重取） |
| DOM | 前端 JS 把 location/hash/参数写入 sink | 需浏览器，手工/Playwright |

## 反射型：4 步

1. **canary**：发送唯一字符串 `wpxss123456`，确认反射点。
2. **上下文**：看 canary 落在 HTML body、属性、`<title>`、`<textarea>`、`<script>` 还是 URL。
3. **闭合**：按上下文选 payload：
   - body：`<svg/onload=alert(1)>`
   - 双引号属性：`"><svg/onload=alert(1)>`
   - 单引号属性：`'><svg/onload=alert(1)>`
   - `href/src`：`javascript:alert(1)`
   - JS 字符串：`';alert(1)//`
4. **确认**：payload 原样出现且未编码，且上下文可执行。

## 假阳性（必须排除）

- 反射在 `<title>` / `<textarea>` / `<xmp>`：HTML 被当文本，不执行。
- 反射在普通属性值里，payload 没有闭合引号：不执行。
- `<` 被编码为 `&lt;`、`\x3c`、`\u003c`：不执行。
- `javascript:` 出现在纯文本/标题里：不是链接，不执行。
- CSP 可能阻止 inline script；但存储型仍可能通过其他 sink 利用，需看策略。

`xss_probe.py` 的 `context_kind` 会给出 `html-body` / `attr-breakout` / `event-handler` / `js-url` 才算危险；`title-text` / `attr-value` 不算。

## 存储型

1. 找会持久化并回显的字段：工单、资料、评论、昵称、公司名、订单备注。
2. 提交 canary，再从**另一个页面/角色**读取。
3. 确认回显上下文后再提交 payload；不要在生产环境弹窗。
4. 证据：提交请求 + 回显页面 + 原始响应。

## DOM 型

- 看 `innerHTML`、`document.write`、`eval`、`location.hash`、`postMessage`、`jQuery.html()`。
- 用浏览器 DevTools 断点或 Playwright：
  ```js
  page.goto(url + "#<img src=x onerror=alert(1)>")
  ```
- 注意 SPA 路由参数、`javascript:` URL、`srcdoc`。

## 工具

- `dalfox url <target> --silence`：快速反射扫描；结果需人工复核上下文。
- `xss_probe.py`：少量请求、上下文判断、证据落盘。
- 浏览器/Playwright：DOM 与存储型最终验证。

## 修复

按输出上下文编码（HTML/属性/JS/URL/CSS）；富文本用白名单清洗；CSP 作为纵深防御；Cookie 加 HttpOnly。
