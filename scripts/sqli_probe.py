#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sqli_probe.py —— SQLi / 表达式注入的少量请求取证。

覆盖三类上下文：
- numeric：`1 AND 1=1` / `1 AND 1=2`
- quoted：`1' AND '1'='1' -- ` / `1' AND '1'='2' -- `
- expr：列名/表达式位点（报表 dimension），`(SELECT 'marker')` / `(SELECT 1)`

判据：真值响应 ≈ 基线，且假值响应 ≠ 基线；expr 位点看 marker 是否回显。
确认后是否上 sqlmap 由调用方决定；本脚本不自动跑长扫描。
"""
import argparse
import json
import os
import random
import re
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import httpkit
from findings import FindingStore


def apply_url(template, value):
    parts = urllib.parse.urlsplit(template)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    out = []
    for k, v in pairs:
        if "*" in k:
            k = k.replace("*", value, 1)
        if "*" in v:
            v = v.replace("*", value, 1)
        out.append((k, v))
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                    urllib.parse.urlencode(out, quote_via=urllib.parse.quote),
                                    parts.fragment))


def apply_body(template, value):
    pairs = urllib.parse.parse_qsl(template, keep_blank_values=True)
    out = []
    for k, v in pairs:
        if "*" in k:
            k = k.replace("*", value, 1)
        if "*" in v:
            v = v.replace("*", value, 1)
        out.append((k, v))
    return urllib.parse.urlencode(out, quote_via=urllib.parse.quote)


def _same(a, b):
    if a["status"] != b["status"]:
        return False
    if a["normalized"] == b["normalized"]:
        return True
    return httpkit.similarity(a["normalized"], b["normalized"]) >= 0.995


def _diff(a, b):
    if a["status"] != b["status"]:
        return True
    return httpkit.similarity(a["normalized"], b["normalized"]) < 0.99


def _send(client, template, data, value, tag, method="GET"):
    if data and "*" in data:
        return client.request(method, template, data=apply_body(data, value), tag=tag)
    return client.request(method, apply_url(template, value), tag=tag)


def _first_data_row(text):
    if not text or "<html" in text[:200].lower() or "<!doctype" in text[:200].lower():
        return None
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) < 2:
        return None
    return lines[1].split(",")[0].strip().strip('"')


def probe_sqli(client, template, data, store, method="GET", base="1", context="auto"):
    if "*" not in template and not (data and "*" in data):
        return None
    base_r = _send(client, template, data, base, "sqli-baseline", method)
    contexts = ["numeric", "quoted"] if context == "auto" else [context]
    for ctx in contexts:
        if ctx == "numeric":
            true_v = base + " AND 1=1"
            false_v = base + " AND 1=2"
        elif ctx == "quoted":
            true_v = base + "' AND '1'='1' -- "
            false_v = base + "' AND '1'='2' -- "
        else:
            continue
        t = _send(client, template, data, true_v, "sqli-true-" + ctx, method)
        f = _send(client, template, data, false_v, "sqli-false-" + ctx, method)
        if _same(t, base_r) and _diff(f, base_r):
            return store.add(
                module="sqli", title="SQL 注入（%s 上下文）" % ctx, severity="high",
                endpoint=template, method=method, parameter="*", confidence="confirmed",
                cvss=8.1,
                evidence={"context": ctx, "base": base, "true_payload": true_v,
                          "false_payload": false_v,
                          "base_status": base_r["status"], "true_status": t["status"],
                          "false_status": f["status"],
                          "true_similarity": round(httpkit.similarity(base_r["normalized"], t["normalized"]), 4),
                          "false_similarity": round(httpkit.similarity(base_r["normalized"], f["normalized"]), 4),
                          "base_artifact": base_r.get("evidence"),
                          "true_artifact": t.get("evidence"),
                          "false_artifact": f.get("evidence")},
                impact="可读取/篡改数据库中的业务数据；具体范围取决于数据库权限。",
                remediation="参数化查询；不要拼接用户输入；最小权限数据库账号。",
                references=["WSTG-INPV-05", "OWASP SQL Injection Prevention Cheat Sheet"],
                tags=["sqli", ctx],
            )
    # expr 位点
    if context in ("auto", "expr"):
        marker = "WPX" + str(random.randint(100000, 999999))
        m = _send(client, template, data, "(SELECT '%s')" % marker, "sqli-expr-marker", method)
        s = _send(client, template, data, "(SELECT 1)", "sqli-expr-scalar", method)
        if m["status"] == 200 and marker in (m["text"] or ""):
            return store.add(
                module="sqli", title="列名/表达式 SQL 注入（报表导出）", severity="high",
                endpoint=template, method=method, parameter="dimension/expr",
                confidence="confirmed", cvss=7.5,
                evidence={"payload": "(SELECT '%s')" % marker, "marker": marker,
                          "status": m["status"], "scalar": _first_data_row(s["text"]),
                          "scalar_status": s["status"],
                          "artifact": m.get("evidence")},
                impact="可执行标量子查询，读取整库/跨租户数据；回显通道通常是导出 CSV 第一列。",
                remediation="列名/排序参数用固定白名单映射；不要把用户输入拼进 SELECT/GROUP BY。",
                references=["WSTG-INPV-05"],
                tags=["sqli", "expr", "report-export"],
            )
        if s["status"] == 200 and _first_data_row(s["text"]) == "1" and _diff(s, base_r):
            return store.add(
                module="sqli", title="疑似列名/表达式注入", severity="medium",
                endpoint=template, method=method, parameter="dimension/expr",
                confidence="likely", cvss=6.5,
                evidence={"payload": "(SELECT 1)", "scalar": _first_data_row(s["text"]),
                          "status": s["status"], "artifact": s.get("evidence")},
                impact="表达式被执行；需进一步确认是否可读取任意数据。",
                remediation="同列名白名单。",
                references=["WSTG-INPV-05"],
                tags=["sqli", "expr"],
            )
    return None


def run(ctx):
    store = ctx["store"]
    targets = ctx.get("options", {}).get("sqli_targets") or ctx.get("targets") or []
    for i, t in enumerate(targets):
        if isinstance(t, dict):
            client = ctx["clients"].get(t.get("role", "anon"), ctx["anon"])
            probe_sqli(client, t["url"], t.get("data"), store,
                       t.get("method", "GET"), t.get("base", "1"),
                       t.get("context", "auto"))
        else:
            client = ctx.get("anon") or ctx["clients"].get("anon")
            probe_sqli(client, t, None, store)
    return store.items


def main():
    p = argparse.ArgumentParser(description="Measured SQLi / expression injection probe")
    p.add_argument("--target", action="append", default=[], help="含 * 的 URL，可重复")
    p.add_argument("--data", default=None, help="POST body，含 *")
    p.add_argument("--method", default="GET")
    p.add_argument("--context", default="auto", choices=["auto", "numeric", "quoted", "expr"])
    p.add_argument("--base", default="1")
    p.add_argument("--cookie-jar", default=None)
    p.add_argument("--cookie", default=None)
    p.add_argument("--rps", type=float, default=1.0)
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("--out", default="sqli-findings.json")
    p.add_argument("--evidence-dir", default="sqli-raw")
    args = p.parse_args()
    client = httpkit.HttpClient(base_url="", cookie=args.cookie,
                                cookie_jar=args.cookie_jar, rps=args.rps,
                                timeout=args.timeout, evidence_dir=args.evidence_dir)
    store = FindingStore(args.out)
    for i, t in enumerate(args.target):
        probe_sqli(client, t, args.data, store, args.method, args.base, args.context)
    store.save()
    print(json.dumps(store.summary(), ensure_ascii=False))
    print("findings:", os.path.abspath(args.out))


if __name__ == "__main__":
    main()
