# SQLMAP-SKILL

用于 sqlmap 自动化注入的 agent skill。

## 安装

把本目录复制到 `~/.qoder/skills/sqlmap-skill/`，然后 `/skills reload`，用 `/sqlmap-skill` 调用。

## 工作流

授权确认 → 目标/会话/参数 intake → 基线核验 → 问目标（判定 / 表 / 列 / 数据）→ 分阶段运行 sqlmap → 每阶段汇报。

## 安全边界

仅用于自有或书面授权目标；不含 OS shell、文件读写、改数据选项；默认单线程 + 延迟；公网目标需要显式确认。

详见 `SKILL.md` 与 `references/`。
