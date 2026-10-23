# 外部工具适配（tooling）

`tool_adapters.py` 只做“检测 + 安全调用 + 结果归一”。没安装就跳过。

```bash
python scripts/tool_adapters.py --list
python scripts/tool_adapters.py --run httpx --target https://host
python scripts/tool_adapters.py --run nuclei --target https://host --rate 10
```

## 推荐工具栈

| 用途 | 工具 | 说明 |
|---|---|---|
| 存活/标题/技术栈 | httpx | JSONL，适合 recon |
| 爬虫/端点 | katana | `-jc` 解析 JS，`-d` 深度 |
| 模板扫描 | nuclei | 默认排除 intrusive/dos/fuzz |
| 目录/参数 fuzz | ffuf | 需 wordlist；限速 |
| XSS | dalfox | 结果需上下文复核 |
| 参数发现 | arjun | 响应差分 |
| 指纹 | whatweb | 技术栈 |
| WAF | wafw00f | 指纹 |
| SQLi | sqlmap | 确认后深度利用 |
| 上传/SSRF | 自写 probe | 见对应 playbook |

## 安装（按需）

```bash
# Go 工具
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/hahwul/dalfox/v2@latest

# Python
pip install arjun
```

## 安全参数

- `-rl` / `--rate-limit` 限速；公网默认 ≤10 req/s。
- nuclei `-etags intrusive,dos,fuzz,brute-force,default-login`。
- 不用 `--headless` 打生产；不用 `-f` 暴力。
- 输出统一落 `runs/<name>/`，原始文件保留。

## 解析约定

- nuclei JSONL → findings（severity/template/matched-at/curl）。
- httpx/katana → surface（URL/技术栈/端点）。
- dalfox/ffuf → 人工复核后进 findings。
- 所有工具结果都带 `artifact` 路径，报告可追溯。
