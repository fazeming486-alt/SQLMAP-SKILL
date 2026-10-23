#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run one staged sqlmap job. Stdlib only.

Usage:
  python sqlmap_run.py --job job.json --stage detect [--dry-run]

Stages:
  detect | dbs | current-db | tables | columns | dump | dump-all |
  passwords | privileges | sql-query | os-cmd | file-read | file-write

节奏/深度（threads、delay、risk、level、time_sec、tamper）全部来自 job，
档案预填。私网/回环目标零声明直通；公网目标在 job 里写一行 scope_note（仅记录）。

Exit codes: 0 success, 1 error, 2 not injectable / blocked, 3 refused.
"""
import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from urllib.parse import urlparse

if hasattr(sys.stdout, "reconfigure"):  # 固定 UTF-8，避免 GBK 控制台/管道乱码
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

STAGES = (
    "detect", "dbs", "current-db", "tables", "columns", "dump", "dump-all",
    "passwords", "privileges", "sql-query", "os-cmd", "file-read", "file-write",
)

VALUE_STAGE_FIELD = {
    "sql-query": "query",
    "os-cmd": "cmd",
    "file-read": "file_read",
    "file-write": "file_write",
}


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
        os.path.join(home, ".workbuddy", "tools", "sqlmap", "sqlmap.py"),
        os.path.join(home, "Desktop", "sqlmap-GUI", "sqlmap", "sqlmap.py"),
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
    request_file = str(job.get("request_file") or "").strip()
    if request_file:
        if not os.path.isfile(request_file):
            fail("request_file 不存在：%s" % request_file)
        raw = open(request_file, "rb").read().decode("utf-8", "replace")
        if "*" not in raw:
            fail("request_file 里必须用 * 标出注入点（直接写在请求行或请求体的参数值里）")
        m = re.search(r"(?im)^host:\s*(\S+)", raw)
        host = m.group(1).split(":")[0] if m else None
    else:
        target = str(job.get("target") or "").strip()
        if not target.startswith(("http://", "https://")):
            fail("target 必须是 http(s) 完整地址（或用 request_file 指向 Burp/ZAP 请求文件）")
        if "*" not in target:
            fail("target 里必须用 * 标出注入点，例如 ...?keyword=1*&from=&to=")
        host = urlparse(target).hostname
    if not host_is_private(host):
        note = str(job.get("scope_note") or "").strip()
        if len(note) < 8:
            fail("公网目标：在 job 里写一行 scope_note（如 \"客户授权测试，范围 staging.example.com，10-20 至 10-25\"）。仅作记录，不阻断。")
    return job


def validate(job, stage):
    if stage not in STAGES:
        fail("stage 只能是：%s" % ", ".join(STAGES))
    level = int(job.get("level", 1) or 1)
    risk = int(job.get("risk", 1) or 1)
    delay = float(job.get("delay", 0) or 0)
    time_sec = int(job.get("time_sec", 5) or 5)
    threads = int(job.get("threads", 1) or 1)
    if not 1 <= level <= 5:
        fail("level 只允许 1–5")
    if not 1 <= risk <= 3:
        fail("risk 只允许 1–3（3 含 OR 类改数语句，共享库慎用）")
    if not 0 <= delay <= 10:
        fail("delay 必须在 0–10 秒之间")
    if not 3 <= time_sec <= 10:
        fail("time_sec 必须在 3–10 秒之间")
    if not 1 <= threads <= 10:
        fail("threads 只允许 1–10")
    tamper = str(job.get("tamper") or "").strip()
    if tamper and not re.fullmatch(r"[A-Za-z0-9_,]+", tamper):
        fail("tamper 只能是逗号分隔的脚本名（字母/数字/下划线）")
    if job.get("param") and not re.fullmatch(r"[A-Za-z0-9_\-\.\[\]\$@]+", str(job["param"])):
        fail("param 只能是参数名（字母/数字/下划线/-/./[]/$/@）")
    if stage in ("columns", "dump"):
        table = str(job.get("table") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_\.]+", table):
            fail("stage=%s 需要合法的 table 名（字母/数字/下划线/点）" % stage)
        if stage == "dump":
            columns = job.get("columns") or []
            if isinstance(columns, str):
                columns = [c.strip() for c in columns.split(",") if c.strip()]
            for col in columns:
                if not re.fullmatch(r"[A-Za-z0-9_\.]+", str(col)):
                    fail("列名只能包含字母/数字/下划线/点：%s" % col)
    where = str(job.get("where") or "")
    if ";" in where:
        fail("where 里不允许分号")
    technique = str(job.get("technique") or "").upper()
    if technique and not re.fullmatch(r"[BEUST]+", technique):
        fail("technique 只能是 B/E/U/S/T 的组合")
    if stage in ("sql-query", "os-cmd", "file-read", "file-write"):
        field = VALUE_STAGE_FIELD[stage]
        value = str(job.get(field) or "").strip()
        if not value:
            fail("stage=%s 需要 job 字段 %s" % (stage, field))
        if stage == "file-write":
            dest = str(job.get("file_dest") or "").strip()
            if not dest:
                fail("stage=file-write 还需要 file_dest（目标机上的写入路径）")
            if not os.path.isfile(value):
                fail("file_write 本地源文件不存在：%s" % value)
    return level, risk, delay, time_sec, threads, tamper


def build_command(job, stage, level, risk, delay, time_sec, threads, tamper):
    base = find_sqlmap()
    if not base:
        fail("找不到 sqlmap。设置 SQLMAP_PATH，或把 sqlmap 装到 ~/.workbuddy/tools/sqlmap/。", 1)
    out_dir = os.path.abspath(str(job.get("output_dir") or os.path.join("runs", "sqlmap-job")))
    os.makedirs(out_dir, exist_ok=True)
    request_file = str(job.get("request_file") or "").strip()
    cmd = base + [
        "-r" if request_file else "-u",
        request_file if request_file else str(job["target"]),
        "--batch",
        "--threads", str(threads),
        "--level", str(level),
        "--risk", str(risk),
        "--time-sec", str(time_sec),
        "--output-dir", out_dir,
    ]
    if delay > 0:
        cmd += ["--delay", str(delay)]
    if tamper:
        cmd += ["--tamper=" + tamper]
    if job.get("param"):
        cmd += ["-p", str(job["param"])]
    if not request_file:  # 请求文件自带 Cookie/UA/头/请求体，不再重复
        if job.get("cookie"):
            cmd += ["--cookie", str(job["cookie"])]
        if job.get("user_agent"):
            cmd += ["--user-agent=" + str(job["user_agent"])]
        headers = [str(h) for h in (job.get("headers") or []) if str(h).strip()]
        if headers:
            cmd += ["--headers", "\n".join(headers)]
        if job.get("data"):
            cmd += ["--data", str(job["data"])]
            if job.get("method"):
                cmd += ["--method", str(job["method"]).upper()]
        elif job.get("method"):
            cmd += ["--method", str(job["method"]).upper()]
    if job.get("dbms"):
        cmd += ["--dbms=" + str(job["dbms"])]
    if job.get("technique"):
        cmd += ["--technique=" + str(job["technique"]).upper()]
    if job.get("union_cols"):
        cmd += ["--union-cols", str(int(job["union_cols"]))]
    if job.get("union_char"):
        cmd += ["--union-char", str(job["union_char"])]
    where = str(job.get("where") or "").strip()
    if stage == "detect":
        cmd += ["--flush-session"]
    elif stage == "dbs":
        cmd += ["--dbs"]
    elif stage == "current-db":
        cmd += ["--current-db"]
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
        if where:
            cmd += ["--where", where]
        cmd += ["--dump"]
    elif stage == "dump-all":
        cmd += ["--dump-all"]
    elif stage == "passwords":
        cmd += ["--passwords"]
    elif stage == "privileges":
        cmd += ["--privileges"]
    elif stage == "sql-query":
        cmd += ["--sql-query=" + str(job["query"])]
    elif stage == "os-cmd":
        cmd += ["--os-cmd=" + str(job["cmd"])]
    elif stage == "file-read":
        cmd += ["--file-read=" + str(job["file_read"])]
    elif stage == "file-write":
        cmd += ["--file-write=" + str(job["file_write"]),
                "--file-dest=" + str(job["file_dest"])]
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
        "tail": [],
        "params": [],
        "os_info": None,
        "web_tech": None,
        "waf_type": None,
        "connect_error": False,
        "no_params": False,
    }
    lines = out.splitlines()
    for line in lines:
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
        m = re.search(r"Parameter: (\S+) \((\w+)\)", line)
        if m and m.group(1) not in info["params"]:
            info["params"].append(m.group(1))
        m = re.search(r"web server operating system: (.+)$", line.strip())
        if m:
            info["os_info"] = m.group(1).strip()
        m = re.search(r"web application technology: (.+)$", line.strip())
        if m:
            info["web_tech"] = m.group(1).strip()
        m = re.search(r"WAF/IPS identified as ['\"]?([^'\"\r\n]+)", line)
        if m:
            info["waf_type"] = m.group(1).strip()
        if "connection refused" in low or "unable to connect to the target url" in low:
            info["connect_error"] = True
        if "no parameter(s) found for testing" in low:
            info["no_params"] = True
        if "retrieved: " in line:
            m = re.search(r"retrieved: '?([^'\r\n]+)'?", line)
            if m:
                info["tables"].append(m.group(1).strip())
        if ("Type:" in line or "Title:" in line or "Payload:" in line) and line.strip() not in info["types"]:
            info["types"].append(line.strip())
        if "[ERROR]" in line or "[CRITICAL]" in line:
            info["errors"].append(line.strip())
    low_out = out.lower()
    if not info["waf_type"] and "might be behind some kind of waf/ips" in low_out:
        info["waf_type"] = "未识别型号（sqlmap 提示有 WAF/IPS）"
    seen = set()
    info["tables"] = [t for t in info["tables"] if not (t in seen or seen.add(t))]
    info["artifacts"] = list(dict.fromkeys(info["artifacts"]))
    blocked = len(re.findall(r"403 \(Forbidden\)", out)) + len(re.findall(r"429 \(Too Many Requests\)", out))
    info["blocked"] = blocked >= 3
    if stage in ("sql-query", "os-cmd", "file-read", "file-write", "passwords", "privileges"):
        tail = [l for l in lines if l.strip()]
        info["tail"] = tail[-14:]
    return info


def stage_status(stage, info):
    if info.get("timeout"):
        return "timeout"
    if info["blocked"]:
        return "blocked"
    if stage == "detect" and info["injectable"] is False:
        return "not_injectable"
    if info["errors"] and not info["artifacts"] and stage != "detect":
        return "error"
    return "success"


def write_summary(out_dir, job, stage, info, exit_code, log_path, started_at, duration_sec):
    """把一个 stage 的结构化结果合并进 <out_dir>/summary.json（Cookie/头掩码），供 html_report.py 渲染。"""
    redacted = dict(job)
    redacted["cookie"] = "<redacted>" if job.get("cookie") else None
    if job.get("headers"):
        redacted["headers"] = ["<redacted>"] * len(job["headers"])
    path = os.path.join(out_dir, "summary.json")
    data = {"job": {}, "stages": {}}
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {"job": {}, "stages": {}}
    slim_info = {k: v for k, v in info.items() if k != "tail"}
    if isinstance(slim_info.get("tables"), list):
        slim_info["tables"] = slim_info["tables"][:50]
    data["job"] = redacted
    data["generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    data.setdefault("stages", {})[stage] = {
        "status": stage_status(stage, info),
        "exit": exit_code,
        "log": os.path.basename(log_path),
        "started_at": time.strftime("%H:%M:%S", time.localtime(started_at)),
        "duration_sec": round(duration_sec, 1),
        "info": slim_info,
        "tail": info.get("tail", [])[:14],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def print_milestone(stage, info, artifact_dir, log_path, exit_code):
    status = stage_status(stage, info)
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
    if info["os_info"]:
        print("OS: %s" % info["os_info"])
    if info["web_tech"]:
        print("WEB_TECH: %s" % info["web_tech"])
    if info["waf_type"]:
        print("WAF: %s" % info["waf_type"])
    if info["params"]:
        print("VULN_PARAMS: %s" % ", ".join(info["params"][:8]))
    if info["connect_error"]:
        print("CONNECT_ERROR: 目标连不上，先查网络/端口/主机")
    if info["no_params"]:
        print("NO_PARAMS: URL 里没找到可测参数，检查 * 位置或用 param 定向")
    if info["columns"]:
        print("QUERY_COLUMNS: %d" % info["columns"])
    if info["tables"]:
        print("RETRIEVED (%d): %s" % (len(info["tables"]), ", ".join(info["tables"][:30])))
    if info["tail"]:
        print("RESULT_TAIL:")
        for line in info["tail"]:
            print("  " + line)
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
    parser = argparse.ArgumentParser(description="Staged sqlmap runner")
    parser.add_argument("--job", required=True)
    parser.add_argument("--stage", choices=STAGES, default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    job = load_job(args.job)
    stage = args.stage or str(job.get("stage") or "detect")
    level, risk, delay, time_sec, threads, tamper = validate(job, stage)
    cmd, out_dir = build_command(job, stage, level, risk, delay, time_sec, threads, tamper)
    shown = redact(" ".join(cmd), job.get("cookie"), job.get("headers") or [])
    print("COMMAND (redacted):")
    print("  " + shown)
    if args.dry_run:
        return 0

    log_path = os.path.join(out_dir, stage + ".log")
    started_at = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=int(job.get("timeout", 900)),
        )
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        info = summarize(out, stage)
        info["timeout"] = True
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(out)
        print_milestone(stage, info, out_dir, log_path, 1)
        write_summary(out_dir, job, stage, info, 1, log_path, started_at, time.time() - started_at)
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
    write_summary(out_dir, job, stage, info, code, log_path, started_at, time.time() - started_at)
    return code


if __name__ == "__main__":
    sys.exit(main())
