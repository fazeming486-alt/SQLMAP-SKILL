#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run one staged sqlmap job with guardrails. Stdlib only.

Usage:
  python sqlmap_run.py --job job.json --stage detect [--dry-run]
  python sqlmap_run.py --job job.json --stage tables
  python sqlmap_run.py --job job.json --stage columns
  python sqlmap_run.py --job job.json --stage dump

Exit codes: 0 success, 1 error, 2 not injectable, 3 refused by guardrail.
"""
import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from urllib.parse import urlparse

FORBIDDEN = (
    "--os-shell", "--os-cmd", "--sql-shell", "--file-write", "--file-read",
    "--udf-inject", "--eval", "--dump-all",
)
STAGES = ("detect", "tables", "columns", "dump", "dbs", "current-db")


def fail(message, code=3):
    print("REFUSED: " + message)
    sys.exit(code)


def find_sqlmap():
    candidates = []
    env = os.environ.get("SQLMAP_PATH")
    if env:
        candidates.append(env)
    which = shutil.which("sqlmap")
    if which:
        candidates.append(which)
    home = os.path.expanduser("~")
    candidates += [
        os.path.join(home, "Desktop", "sqlmap-GUI", "sqlmap", "sqlmap.py"),
        os.path.join(home, ".workbuddy", "tools", "sqlmap", "sqlmap.py"),
        os.path.join(home, "sqlmap", "sqlmap.py"),
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            if path.lower().endswith(".py"):
                return [sys.executable, path]
            return [path]
    return None


def host_is_private(host):
    if not host:
        return False
    if host in ("localhost", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return host.endswith(".local") or host.endswith(".localhost")


def redact(text, cookie, headers):
    text = str(text)
    if cookie:
        for part in cookie.split(";"):
            if "=" in part:
                value = part.split("=", 1)[1].strip()
                if len(value) >= 6:
                    text = text.replace(value, "<redacted>")
    for header in headers or []:
        if ":" in header:
            name, value = header.split(":", 1)
            value = value.strip()
            if len(value) >= 6:
                text = text.replace(value, "<redacted>")
    return text


def load_job(path):
    try:
        raw = open(path, "rb").read()
    except Exception as exc:
        fail("读不到 job 文件：%s" % exc)
    job = None
    for encoding in ("utf-8-sig", "utf-8", "gbk"):
        try:
            job = json.loads(raw.decode(encoding))
            break
        except Exception:
            continue
    if job is None:
        fail("job 不是合法的 JSON（已尝试 UTF-8 / UTF-8-SIG / GBK）")
    if not isinstance(job, dict):
        fail("job 必须是 JSON 对象")
    if job.get("authorized") is not True:
        fail("authorized 必须为 true。只允许自有或书面授权的目标。")
    note = str(job.get("authorization_note") or "").strip()
    if len(note) < 8:
        fail("请在 authorization_note 里写清楚授权来源/范围（至少 8 个字符）。")
    target = str(job.get("target") or "").strip()
    if not target.startswith(("http://", "https://")):
        fail("target 必须是 http(s) 完整地址")
    if "*" not in target:
        fail("target 里必须用 * 标出注入点，例如 ...?keyword=1*&from=&to=")
    parsed = urlparse(target)
    if not host_is_private(parsed.hostname) and job.get("public_target") is not True:
        fail("检测到公网目标。确认你有书面授权后，在 job 里加 \"public_target\": true。")
    return job


def validate(job, stage):
    if stage not in STAGES:
        fail("stage 只能是：%s" % ", ".join(STAGES))
    level = int(job.get("level", 1) or 1)
    risk = int(job.get("risk", 1) or 1)
    delay = float(job.get("delay", 1) or 0)
    time_sec = int(job.get("time_sec", 5) or 5)
    if not 1 <= level <= 3:
        fail("level 只允许 1–3（更高会发更多请求，先和用户确认）")
    if not 1 <= risk <= 2:
        fail("risk 只允许 1–2（3 会含改数据类语句，本 skill 禁用）")
    if not 0 <= delay <= 10:
        fail("delay 必须在 0–10 秒之间")
    if not 3 <= time_sec <= 10:
        fail("time_sec 必须在 3–10 秒之间")
    if stage in ("columns", "dump"):
        table = str(job.get("table") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_]+", table):
            fail("stage=%s 需要合法的 table 名（字母/数字/下划线）" % stage)
        if stage == "dump":
            columns = job.get("columns") or []
            if isinstance(columns, str):
                columns = [c.strip() for c in columns.split(",") if c.strip()]
            if not columns and job.get("allow_full_table") is not True:
                fail("dump 请指定 columns（推荐），全表需要 allow_full_table=true 并再次确认影响")
            for col in columns:
                if not re.fullmatch(r"[A-Za-z0-9_]+", str(col)):
                    fail("列名只能包含字母/数字/下划线：%s" % col)
    where = str(job.get("where") or "")
    if ";" in where:
        fail("where 里不允许分号")
    technique = str(job.get("technique") or "").upper()
    if technique and not re.fullmatch(r"[BEUST]+", technique):
        fail("technique 只能是 B/E/U/S/T 的组合")
    return level, risk, delay, time_sec


def build_command(job, stage, level, risk, delay, time_sec):
    base = find_sqlmap()
    if not base:
        fail("找不到 sqlmap。设置 SQLMAP_PATH，或把 sqlmap.py 放到 ~/Desktop/sqlmap-GUI/sqlmap/。", 1)
    out_dir = os.path.abspath(str(job.get("output_dir") or os.path.join("runs", "sqlmap-job")))
    os.makedirs(out_dir, exist_ok=True)
    cmd = base + [
        "-u", str(job["target"]),
        "--batch",
        "--threads", "1",
        "--level", str(level),
        "--risk", str(risk),
        "--time-sec", str(time_sec),
        "--output-dir", out_dir,
    ]
    if delay > 0:
        cmd += ["--delay", str(delay)]
    if job.get("cookie"):
        cmd += ["--cookie", str(job["cookie"])]
    headers = [str(h) for h in (job.get("headers") or []) if str(h).strip()]
    if headers:
        cmd += ["--headers", "\n".join(headers)]
    if job.get("dbms"):
        cmd += ["--dbms=" + str(job["dbms"])]
    if job.get("data"):
        cmd += ["--data", str(job["data"])]
        if job.get("method"):
            cmd += ["--method", str(job["method"]).upper()]
    elif job.get("method"):
        cmd += ["--method", str(job["method"]).upper()]
    if job.get("technique"):
        cmd += ["--technique=" + str(job["technique"]).upper()]
    if job.get("union_cols"):
        cmd += ["--union-cols", str(int(job["union_cols"]))]
    if job.get("union_char"):
        cmd += ["--union-char", str(job["union_char"])]
    if stage == "detect":
        cmd += ["--flush-session"]
    elif stage == "tables":
        cmd += ["--tables"]
    elif stage == "columns":
        cmd += ["-T", str(job["table"]), "--columns"]
    elif stage == "dump":
        cmd += ["-T", str(job["table"])]
        columns = job.get("columns") or []
        if isinstance(columns, str):
            columns = [c.strip() for c in columns.split(",") if c.strip()]
        if columns:
            cmd += ["-C", ",".join(str(c) for c in columns)]
        if job.get("where"):
            cmd += ["--where", str(job["where"])]
        cmd += ["--dump"]
    elif stage == "dbs":
        cmd += ["--dbs"]
    elif stage == "current-db":
        cmd += ["--current-db"]
    lowered = " ".join(cmd).lower()
    for bad in FORBIDDEN:
        if bad in lowered:
            fail("命令里出现禁用选项：%s" % bad)
    return cmd, out_dir


def summarize(out, stage):
    info = {
        "injectable": None,
        "types": [],
        "dbms": None,
        "columns": None,
        "tables": [],
        "artifacts": [],
        "blocked": False,
        "errors": [],
    }
    for line in out.splitlines():
        low = line.lower()
        if "is vulnerable" in low or ("appears to be" in low and "injectable" in low):
            info["injectable"] = True
        if ("does not seem to be injectable" in low
                or "do not appear to be injectable" in low
                or "does not appear to be injectable" in low):
            info["injectable"] = False
        if "back-end dbms:" in low:
            info["dbms"] = line.split(":", 1)[1].strip()
        m = re.search(r"appears to have (\d+) columns", line)
        if m:
            info["columns"] = int(m.group(1))
        m = re.search(r"dumped to CSV file '([^']+)'", line)
        if m:
            info["artifacts"].append(m.group(1))
        m = re.search(r"fetched data logged to text files under '([^']+)'", line)
        if m:
            info["artifacts"].append(m.group(1))
        if stage == "tables":
            m = re.search(r"retrieved: '([^']+)'", line)
            if m:
                info["tables"].append(m.group(1))
        if ("Type:" in line or "Title:" in line or "Payload:" in line) and line.strip() not in info["types"]:
            info["types"].append(line.strip())
        if "[ERROR]" in line or "[CRITICAL]" in line:
            info["errors"].append(line.strip())
    seen = set()
    info["tables"] = [t for t in info["tables"] if not (t in seen or seen.add(t))]
    info["artifacts"] = list(dict.fromkeys(info["artifacts"]))
    blocked = len(re.findall(r"403 \(Forbidden\)", out)) + len(re.findall(r"429 \(Too Many Requests\)", out))
    info["blocked"] = blocked >= 3
    return info


def print_milestone(stage, info, artifact_dir, log_path, exit_code):
    if info["blocked"]:
        status = "blocked"
    elif stage == "detect" and info["injectable"] is False:
        status = "not_injectable"
    elif info["errors"] and not info["artifacts"] and stage != "detect":
        status = "error"
    else:
        status = "success"
    print("=== STAGE: %s ===" % stage)
    print("STATUS: %s" % status)
    if info["injectable"] is not None:
        print("INJECTABLE: %s" % ("true" if info["injectable"] else "false"))
    if info["types"]:
        print("EVIDENCE:")
        for line in info["types"][:8]:
            print("  " + line)
    if info["dbms"]:
        print("DBMS: %s" % info["dbms"])
    if info["columns"]:
        print("QUERY_COLUMNS: %d" % info["columns"])
    if info["tables"]:
        print("TABLES (%d): %s" % (len(info["tables"]), ", ".join(info["tables"])))
    if info["artifacts"]:
        print("ARTIFACTS:")
        for path in info["artifacts"][:6]:
            print("  " + path)
    if info["errors"]:
        print("ERRORS:")
        for line in info["errors"][:4]:
            print("  " + line)
    print("LOG: %s" % log_path)
    print("OUTPUT_DIR: %s" % artifact_dir)
    print("EXIT: %d" % exit_code)


def main():
    parser = argparse.ArgumentParser(description="Staged sqlmap runner with guardrails")
    parser.add_argument("--job", required=True)
    parser.add_argument("--stage", choices=STAGES, default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    job = load_job(args.job)
    stage = args.stage or str(job.get("stage") or "detect")
    level, risk, delay, time_sec = validate(job, stage)
    cmd, out_dir = build_command(job, stage, level, risk, delay, time_sec)
    shown = redact(" ".join(cmd), job.get("cookie"), job.get("headers") or [])
    print("COMMAND (redacted):")
    print("  " + shown)
    if args.dry_run:
        return 0

    log_path = os.path.join(out_dir, stage + ".log")
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=int(job.get("timeout", 900)),
        )
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        info = summarize(out, stage)
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(out)
        print_milestone(stage, info, out_dir, log_path, 1)
        print("TIMEOUT: 超过 %s 秒，已中断。" % job.get("timeout", 900))
        return 1
    out = proc.stdout or ""
    if proc.stderr:
        out += "\n[stderr]\n" + proc.stderr
    with open(log_path, "w", encoding="utf-8") as f:
        f.write(out)
    info = summarize(out, stage)
    code = proc.returncode
    if info["blocked"]:
        code = 2
    elif stage == "detect" and info["injectable"] is False:
        code = 2
    print_milestone(stage, info, out_dir, log_path, code)
    return code


if __name__ == "__main__":
    sys.exit(main())
