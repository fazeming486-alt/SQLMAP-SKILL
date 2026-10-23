# SQLMAP-SKILL

sqlmap 分阶段自动化注入的 agent skill（v2）。

## 安装

**WorkBuddy**：把本目录复制到 `C:\Users\Administrator\.workbuddy\skills\sqlmap-skill\`（或 `~/.workbuddy/skills/sqlmap-skill/`），对话里提到"用 sqlmap 打 …"即自动触发。

**Qoder**：把本目录复制到 `~/.qoder/skills/sqlmap-skill/`，然后 `/skills reload`，用 `/sqlmap-skill` 调用。

## 工作流

解析目标 → 档案匹配（命中即零问答）→ 组装 job.json → 自动会话（登录取 Cookie）→ 基线核验 → 分阶段运行 → 里程碑汇报。

## v2 能力

- **靶场档案**（`profiles/`）：DVWA、北岸商城预置；命中档案零问答直通，节奏/注入点/会话方式全部预填。
- **自动会话**：`scripts/dvwa_session.py` 自动登录取 token → 登录 → 切安全档位 → 输出 sqlmap 可用 Cookie（`--json`）。
- **全能力 stage**：detect / dbs / current-db / tables / columns / dump / dump-all / passwords / privileges / sql-query / os-cmd / file-read / file-write。交互式 shell 与 `--batch` 不兼容，用单发 `--os-cmd` / `--sql-query` 替代。
- **节奏自定**：threads 1–10、delay 0–10、risk 1–3、level 1–5，档案预填、随时改。
- **工程纪律**：基线先行（2xx + 非登录页才开跑）、日志与 CSV 全部落盘、milestone 输出证据行、Cookie 自动掩码、`--dry-run` 预览。
- **公网目标**：job 里写一行 `scope_note`（仅记录，不阻断）。

## 安全边界

无授权问答。目标、节奏、深度由使用者决定并自负其责；skill 只做技术质量把关（基线、证据、日志）。`jobs/`、`runs/`、日志、CSV 均已 gitignore，Cookie 不会进仓库。

详见 `SKILL.md` 与 `references/`。
