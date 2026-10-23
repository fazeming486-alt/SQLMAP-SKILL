---
name: sqlmap-skill
description: Guided sqlmap CLI workflow for authorized SQL injection tests. Use when a user asks to test SQL injection with sqlmap on a target they own or are explicitly authorized to test, or wants a conversational assistant that collects scope/authorization/parameter/goal, verifies a baseline, runs staged detection/enumeration/dumps, and reports each milestone.
argument-hint: <authorized-target-url>
---

# SQLMap Guided Skill

Run sqlmap as a guided engagement: **authorization → intake → baseline → goal → staged runs → report**.
Never start sqlmap before the authorization gate and the baseline check pass.

## Hard rules

- **Authorized targets only.** Ask who owns the target, for the written permission/scope, the allowed window, and any forbidden paths. If the user cannot state this, stop.
- If the host is not loopback/private, require an explicit statement `"I own it / I have written authorization"` and the job flag `public_target: true`. Warn about production impact; prefer a staging URL.
- **Never** use `--os-shell`, `--os-cmd`, `--sql-shell`, `--file-write`, `--file-read`, `--udf-inject`, `--eval`, or `--risk=3`. No data modification.
- **Never** run `--dump-all` without explicit consent. Ask which table/columns; prefer `-C`.
- One request at a time: `--threads=1`. Use `--delay` on rate-limited targets. Stop on 403/429/WAF pages or a burst of 5xx.
- Do not dump personal data wholesale. Mask secrets and personal fields in reports; never echo cookies, CSRF tokens, or session IDs.
- This is not a scanner for random websites. If the user says "scan this site I found", refuse.

## Conversation flow

Ask **one or two questions at a time**, propose defaults, and reflect back what you heard.
Do not interrogate; the target is a shared map, not a form.

### Gate 0 — Authorization

Ask:

1. 这个目标是你自己的，还是你有书面授权的靶场？授权范围（域名/路径/账号/时间窗）是什么？
2. 有哪些绝对不能碰的部分（生产路径、真实用户数据、支付、删除类操作）？

Do not proceed without a clear answer. If the target is public and the user cannot state authorization, stop.

### Gate 1 — Intake

Collect, in small groups:

- **Target**: full URL, method (GET/POST), where the parameter lives (query / form / JSON / path), and one normal value that returns data.
- **Injection marker**: put `*` at the exact injection point, e.g. `...?keyword=1*&from=&to=`.
- **Session**: Cookie header (e.g. `NB_SID=...`) and, for POST/JSON, CSRF header (`X-CSRF-Token: ...`). Explain how to copy them from DevTools (Network → Request Headers). Never ask the user to paste them into the chat if they can place them in a local job file.
- **Content type**: `application/json`, `application/x-www-form-urlencoded`, etc.
- **Known DBMS** (optional; saves time), **WAF/Cloudflare**, rate limits, test window.
- **Output dir**: use one directory for the whole engagement so later stages reuse the detected injection point.

Then run the baseline check:

```bash
python scripts/baseline.py --authorized \
  --url "http://127.0.0.1:9300/api/report/export?keyword=1&from=&to=" \
  --cookie "NB_SID=..." --header "X-CSRF-Token: ..."
```

Require a 2xx, a non-login final URL, and the expected content (e.g. CSV rows). If it fails, fix the session/URL first. A broken baseline is not a "not injectable" result.

### Gate 2 — Goal

Ask exactly one question:

> 这次你最想先确认什么？
> A. 能不能注入（只到判定）
> B. 库里有几张表、叫什么
> C. 某张表有哪些列
> D. 某张表的某几列数据（推荐）
> E. 全表导出（需要再确认一次影响）

Record the chosen goal and stick to it. Do not silently escalate to a full dump.

### Gate 3 — Staged runs

Run one stage, report, then ask whether to continue. Use the same `output_dir`.

1. **detect** — confirm injectable, technique, DBMS, column count.
2. **tables** — enumerate table names.
3. **columns** — for one table.
4. **dump** — selected columns (or full table with explicit consent).

Use `scripts/sqlmap_run.py`:

```bash
python scripts/sqlmap_run.py --job job.json --stage detect
python scripts/sqlmap_run.py --job job.json --stage tables
python scripts/sqlmap_run.py --job job.json --stage columns
python scripts/sqlmap_run.py --job job.json --stage dump
```

`--dry-run` prints the command with the cookie masked; use it to confirm the shape before spending requests.

### Gate 4 — Report

After each stage, report a short block:

```
STAGE: detect
STATUS: injectable
EVIDENCE: UNION, 5 columns; DBMS SQLite
ARTIFACTS: runs/.../detect.log
NEXT: 列表名（--stage tables）
```

Final report: target/scope, entry, request, technique/payloads, data exposed, fix, artifacts, and what was not tested. Mask cookies and personal data.

## Job file

Store `job.json` outside the repo (it contains a live session cookie). Minimal shape:

```json
{
  "authorized": true,
  "authorization_note": "owner of the local lab; written approval 2026-10-23",
  "target": "http://127.0.0.1:9300/api/report/export?keyword=1*&from=&to=",
  "method": "GET",
  "data": null,
  "cookie": "NB_SID=...",
  "headers": ["X-CSRF-Token: ..."],
  "dbms": "sqlite",
  "stage": "detect",
  "table": null,
  "columns": null,
  "level": 1,
  "risk": 1,
  "delay": 1,
  "time_sec": 5,
  "output_dir": "runs/20261023-report-export"
}
```

Rules enforced by the script: `authorized: true`, a non-empty `authorization_note`, `*` marker in the target, `risk ≤ 2`, `level ≤ 3`, `threads=1`, no shell/file options. For `dump`, provide `table` and `columns`; a full table needs `"allow_full_table": true`.

## Failure triage

| Symptom | Likely cause | Action |
|---|---|---|
| 302 → /login, 401 | Cookie expired/invalid | Re-copy the Cookie header; redo the baseline |
| 403 / challenge page | WAF or Cloudflare | Stop; do not tamper blindly; ask the owner to allowlist or provide a staging URL |
| 429 | Rate limit | Increase `--delay`, reduce scope, wait |
| All 200, "not injectable" | Empty baseline / wrong param / quotes not sent | Use a value that returns data; check encoding; try `--level 2` |
| 500 burst + blank dump | Input length cap or error swallowing | Check the app's max length; use shorter manual payloads; ask the owner |
| sqlmap suggests `--random-agent`/`--tamper` | Generic advice | Only with authorization; not on production |

## References

- `references/intake-and-authorization.md` — question bank, scope wording, examples.
- `references/sqlmap-playbook.md` — flags, POST/JSON recipes, stage commands, artifacts.
