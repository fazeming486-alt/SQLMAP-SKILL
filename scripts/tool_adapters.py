#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tool_adapters.py —— 外部工具适配层（ProjectDiscovery / 社区工具）。

原则：
- 工具只是执行器，结论统一进 findings；
- 默认限速、排除 intrusive/dos/fuzz 模板；
- 没装工具就跳过，不阻塞工作流；
- 所有命令可复现，原始输出落盘。

已适配：nuclei / httpx / katana / ffuf / dalfox / arjun / whatweb / wafw00f / sqlmap。
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from findings import FindingStore

TOOLS = {
    "nuclei": {"bin": "nuclei", "purpose": "模板化漏洞扫描（默认排除 intrusive/dos/fuzz）"},
    "httpx": {"bin": "httpx", "purpose": "HTTP 存活/标题/技术栈/状态码"},
    "katana": {"bin": "katana", "purpose": "爬虫/端点发现"},
    "ffuf": {"bin": "ffuf", "purpose": "目录/参数 fuzz（需 wordlist）"},
    "dalfox": {"bin": "dalfox", "purpose": "XSS 扫描"},
    "arjun": {"bin": "arjun", "purpose": "隐藏参数发现"},
    "whatweb": {"bin": "whatweb", "purpose": "Web 技术指纹"},
    "wafw00f": {"bin": "wafw00f", "purpose": "WAF 指纹"},
    "sqlmap": {"bin": "sqlmap", "purpose": "SQLi 深度利用（由 sqlmap_run.py 调用）"},
}

NUCLEI_EXCLUDE_TAGS = "intrusive,dos,fuzz,brute-force,default-login"


def _is_projectdiscovery(path):
    """同名二进制冲突：Python httpx 也叫 httpx；用 -version 识别 PD 版。"""
    code, out, err = _run([path, "-version"], timeout=8)
    blob = (out + " " + err).lower()
    return code == 0 and ("projectdiscovery" in blob or "current version" in blob)


def available():
    out = {}
    for name, spec in TOOLS.items():
        path = shutil.which(spec["bin"])
        if not path:
            out[name] = False
            continue
        if name in ("httpx", "nuclei", "katana"):
            out[name] = _is_projectdiscovery(path)
        else:
            out[name] = True
    return out


def _run(cmd, timeout=600, cwd=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd,
                           encoding="utf-8", errors="replace")
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "not installed: " + cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timeout: " + " ".join(cmd[:3])


def run_nuclei(target, store, rate=10, severity="low,medium,high,critical", out_dir=".", timeout=900):
    if not shutil.which("nuclei"):
        return []
    out = os.path.join(out_dir, "nuclei.jsonl")
    cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-rl", str(rate),
           "-severity", severity, "-etags", NUCLEI_EXCLUDE_TAGS, "-o", out]
    code, stdout, stderr = _run(cmd, timeout=timeout)
    findings = []
    if os.path.exists(out):
        for line in open(out, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            info = d.get("info", {}) or {}
            sev = (info.get("severity") or "info").lower()
            if sev not in ("critical", "high", "medium", "low", "info"):
                sev = "info"
            findings.append(store.add(
                module="nuclei", title=info.get("name") or d.get("template-id", "nuclei finding"),
                severity=sev, endpoint=d.get("matched-at") or target,
                method=(d.get("request") or "GET").split(" ")[0] if d.get("request") else "GET",
                confidence="confirmed" if d.get("matcher-name") else "likely",
                evidence={"template_id": d.get("template-id"), "matcher": d.get("matcher-name"),
                          "curl": d.get("curl-command"), "raw": d},
                impact=info.get("description") or "模板命中，请结合证据复核影响。",
                remediation=info.get("remediation") or "按模板说明修复。",
                references=info.get("reference") if isinstance(info.get("reference"), list)
                else ([info.get("reference")] if info.get("reference") else []),
                tags=["nuclei"] + (info.get("tags") or []),
            ))
    return findings


def run_httpx(target, out_dir="."):
    path = shutil.which("httpx")
    if not path:
        return []
    if not _is_projectdiscovery(path):
        print("WARN: 找到的 httpx 不是 ProjectDiscovery 版（可能是 Python httpx），跳过。")
        return []
    out = os.path.join(out_dir, "httpx.jsonl")
    cmd = ["httpx", "-u", target, "-json", "-silent", "-title", "-tech-detect",
           "-status-code", "-web-server", "-o", out]
    _run(cmd, timeout=300)
    rows = []
    if os.path.exists(out):
        for line in open(out, encoding="utf-8", errors="replace"):
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


def run_katana(target, out_dir=".", depth=2, rate=10):
    if not shutil.which("katana"):
        return []
    out = os.path.join(out_dir, "katana.jsonl")
    cmd = ["katana", "-u", target, "-jsonl", "-silent", "-d", str(depth),
           "-rl", str(rate), "-jc", "-o", out]
    _run(cmd, timeout=600)
    urls = []
    if os.path.exists(out):
        for line in open(out, encoding="utf-8", errors="replace"):
            try:
                d = json.loads(line)
                u = d.get("request", {}).get("endpoint") or d.get("url")
                if u:
                    urls.append(u)
            except Exception:
                pass
    return urls


def run_dalfox(target, out_dir="."):
    if not shutil.which("dalfox"):
        return []
    out = os.path.join(out_dir, "dalfox.txt")
    cmd = ["dalfox", "url", target, "--silence", "--output", out]
    _run(cmd, timeout=600)
    return open(out, encoding="utf-8", errors="replace").read().splitlines() if os.path.exists(out) else []


def run_arjun(target, out_dir="."):
    if not shutil.which("arjun"):
        return {}
    out = os.path.join(out_dir, "arjun.json")
    cmd = ["arjun", "-u", target, "-oJ", out, "-m", "GET,POST"]
    _run(cmd, timeout=600)
    try:
        return json.load(open(out, encoding="utf-8"))
    except Exception:
        return {}


def main():
    p = argparse.ArgumentParser(description="External tool adapters")
    p.add_argument("--list", action="store_true")
    p.add_argument("--run", choices=list(TOOLS), default=None)
    p.add_argument("--target", default=None)
    p.add_argument("--out-dir", default=".")
    p.add_argument("--rate", type=int, default=10)
    p.add_argument("--severity", default="low,medium,high,critical")
    p.add_argument("--findings", default="tool-findings.json")
    args = p.parse_args()
    if args.list or not args.run:
        avail = available()
        for name, spec in TOOLS.items():
            mark = "OK " if avail.get(name) else "-- "
            print("%s %-10s %s" % (mark, name, spec["purpose"]))
        return
    if not args.target:
        print("--target is required with --run")
        return
    store = FindingStore(args.findings)
    if args.run == "nuclei":
        run_nuclei(args.target, store, args.rate, args.severity, args.out_dir)
    elif args.run == "httpx":
        for row in run_httpx(args.target, args.out_dir):
            print(json.dumps(row, ensure_ascii=False))
    elif args.run == "katana":
        for u in run_katana(args.target, args.out_dir, rate=args.rate):
            print(u)
    elif args.run == "dalfox":
        for line in run_dalfox(args.target, args.out_dir):
            print(line)
    elif args.run == "arjun":
        print(json.dumps(run_arjun(args.target, args.out_dir), ensure_ascii=False, indent=2))
    else:
        print("%s adapter is registered; use the tool directly for now" % args.run)
    store.save()
    print("findings:", os.path.abspath(args.findings))


if __name__ == "__main__":
    main()
