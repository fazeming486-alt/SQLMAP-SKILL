# 文件上传 playbook

## 先盘面，再测试

`upload_probe.py` 默认只找 `multipart/form-data` 表单和 `input type=file`，记 info；不传文件。

```bash
python scripts/upload_probe.py --page https://host/upload
python scripts/upload_probe.py --page https://host/upload --test   # 提交无害 .txt
```

## 测试维度

1. **扩展名**：`.php`、`.phtml`、`.jsp`、`.aspx`、`.svg`、`.html`、双扩展名、大小写、尾随点/空格/`%00`。
2. **Content-Type**：`image/png` 配 PHP 内容；`text/plain` 配 HTML。
3. **内容**：magic bytes（GIF89a + PHP）、SVG 带脚本、HTML 带 JS。
4. **存储路径**：返回 URL、可预测文件名、目录遍历、Web 根可访问。
5. **执行**：上传目录是否解析脚本；`.htaccess`/`web.config`；解析链。
6. **竞争**：上传后短窗口内访问/执行（race）。
7. **大小/数量**：拒绝服务/磁盘耗尽（仅在授权且明确允许时）。

## 安全测试约束

- 只用**无害测试文件**（txt/svg 带静态标记），不要 webshell、不要反弹 shell。
- 不上传到生产；演示环境也先确认可回滚。
- 不自动测试云元数据/内网。

## 判定

- 上传成功 ≠ 漏洞；需要证明“可访问/可执行/可覆盖/可穿越”。
- 证据：上传请求（multipart 原文）、响应、文件 URL、访问/执行结果。

## 修复

扩展名+MIME+magic bytes 三重校验；随机文件名；存储到非 Web 根；禁止执行；大小/数量限制；图片重编码；隔离域。
