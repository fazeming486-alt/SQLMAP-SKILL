#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""export_probe.py —— 异步导出 / 签名下载的对象级授权（IDOR/BOLA）取证。

场景：报表/导出先创建任务，再通过带 exp+sig 的 URL 下载。常见缺陷：
- 下载只校验签名，不校验任务归属（拿到别人的任务 ID + 自己的签名即可）；
- 签名只覆盖过期时间，不覆盖路径；
- 任务列表按 tenant 过滤，但查询参数/头部可绕过；
- 下载不校验任务是否存在/租户。

用法：
  python export_probe.py --base https://host --cookie-jar buyer.txt \
      --create-path /exports --list-path /exports --kind orders \
      --from 2026-07-01 --to 2026-10-24
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import httpkit
from findings import FindingStore

JOB_RE = re.compile(r"/exports/([a-f0-9-]{36})/download\?([^\"'<> ]+)")


def extract_csrf(text):
    m = re.search(r'name="_csrf"\s+value="([^"]+)"', text or "")
    return m.group(1) if m else None


def parse_jobs(text):
    jobs = []
    for m in JOB_RE.finditer(text or ""):
        jid, qs = m.group(1), m.group(2).replace("&amp;", "&")
        jobs.append({"id": jid, "query": qs,
                     "url": "/exports/%s/download?%s" % (jid, qs)})
    # 去重
    seen = set()
    out = []
    for j in jobs:
        if j["id"] not in seen:
            seen.add(j["id"])
            out.append(j)
    return out


def run(ctx):
    store = ctx["store"]
    base = ctx["base_url"]
    client = ctx["anon"] or ctx["clients"].get("anon")
    opts = ctx.get("options", {})
    create_path = httpkit.normalize_path(opts.get("export_create_path", "/exports"))
    list_path = httpkit.normalize_path(opts.get("export_list_path", "/exports"))
    kind = opts.get("export_kind", "orders")
    date_from = opts.get("export_from", "2026-07-01")
    date_to = opts.get("export_to", "2026-10-24")

    page = client.get(create_path, tag="export-create-page")
    if "登录工作台" in (page["text"] or "") or "/login" in (page["url"] or ""):
        store.add(module="export", title="导出测试需要有效登录会话", severity="info",
                  endpoint=base + create_path, method="GET", confidence="surface",
                  evidence={"status": page["status"], "url": page["url"],
                            "artifact": page.get("evidence")},
                  impact="未登录时创建页会跳登录，无法测试导出授权。",
                  remediation="提供买家/商家 cookie jar 或登录配置。",
                  tags=["export", "session"])
        return store.items
    csrf = extract_csrf(page["text"])
    if not csrf:
        print("export_probe: no CSRF on create page; check session")
        return store.items
    r = client.post(create_path, data={"_csrf": csrf, "kind": kind,
                                      "from": date_from, "to": date_to},
                    headers={"Referer": base + create_path}, tag="export-create")
    time.sleep(float(opts.get("export_wait", 2)))
    listing = client.get(list_path, tag="export-list")
    jobs = parse_jobs(listing["text"])
    if not jobs:
        print("export_probe: no job/download URL found")
        return store.items
    job = jobs[0]
    store.add(module="export", title="已创建导出任务（基线）", severity="info",
              endpoint=base + list_path, method="POST", confidence="confirmed",
              evidence={"job_id": job["id"], "download": job["url"],
                        "create_status": r["status"], "artifact": r.get("evidence")},
              impact="用于后续对象级授权与签名校验测试，本身不是漏洞。",
              remediation="—", tags=["export", "baseline"])

    # 基线下载
    def dl(path, tag):
        return client.get(path, tag=tag)

    base_r = dl(job["url"], "export-baseline")
    job_path = "/exports/%s/download" % job["id"]
    qs = urllib.parse.parse_qs(job["query"])
    exp = qs.get("exp", [""])[0]
    sig = qs.get("sig", [""])[0]

    if base_r["status"] != 200:
        print("export_probe: baseline download failed", base_r["status"])

    tests = [
        ("exp+1", "%s?exp=%s&sig=%s" % (job_path, int(exp) + 1 if exp.isdigit() else exp, sig)),
        ("no-sig", job_path),
        ("random-job", "/exports/00000000-0000-4000-8000-000000000000/download?exp=%s&sig=%s" % (exp, sig)),
    ]
    for name, path in tests:
        tr = dl(path, "export-" + name)
        if name == "exp+1" and tr["status"] == 200:
            store.add(module="export", title="导出签名不校验过期时间", severity="high",
                      endpoint=base + job_path, method="GET", confidence="confirmed", cvss=7.1,
                      evidence={"test": name, "status": tr["status"], "artifact": tr.get("evidence")},
                      impact="签名有效期可被绕过，过期链接仍可下载。",
                      remediation="HMAC 覆盖 exp 与路径；服务端校验时间。", tags=["export", "signature"])
        elif name == "no-sig" and tr["status"] == 200:
            store.add(module="export", title="导出下载不校验签名", severity="high",
                      endpoint=base + job_path, method="GET", confidence="confirmed", cvss=7.5,
                      evidence={"test": name, "status": tr["status"], "artifact": tr.get("evidence")},
                      impact="任何拿到任务 ID 的人都能下载导出文件。",
                      remediation="强制校验签名与过期时间。", tags=["export", "signature"])
        elif name == "random-job" and tr["status"] == 200:
            store.add(module="export", title="导出下载不校验任务存在性", severity="medium",
                      endpoint=base + job_path, method="GET", confidence="confirmed", cvss=5.3,
                      evidence={"test": name, "status": tr["status"], "artifact": tr.get("evidence")},
                      impact="下载接口对任务 ID 的处理异常，需复核是否可越权。",
                      remediation="先按租户查任务，再校验签名。", tags=["export"])

    # 指定其他任务 ID（来自审计/列表/其他账号）
    other = opts.get("export_other_job")
    if other:
        oth = client.get("/exports/%s/download?exp=%s&sig=%s" % (other, exp, sig),
                         tag="export-other")
        if oth["status"] == 200:
            store.add(module="export", title="导出下载跨任务/跨租户越权", severity="high",
                      endpoint=base + "/exports/%s/download" % other, method="GET",
                      confidence="confirmed", cvss=8.1,
                      evidence={"other_job": other, "status": oth["status"],
                                "snippet": httpkit.redact((oth["text"] or "")[:300]),
                                "artifact": oth.get("evidence")},
                      impact="用当前账号签名可下载其他任务的文件，构成对象级授权缺失。",
                      remediation="下载前按 job.tenant_id == session.tenant_id 校验；签名绑定任务。",
                      tags=["export", "idor", "bola"])

    # 列表参数绕过
    for q in opts.get("export_list_queries", []):
        lr = client.get(list_path + ("&" if "?" in list_path else "?") + q, tag="export-list-" + q)
        alt = parse_jobs(lr["text"])
        alt_ids = {j["id"] for j in alt} - {j["id"] for j in jobs}
        if alt_ids:
            store.add(module="export", title="导出任务列表可越权枚举", severity="high",
                      endpoint=base + list_path, method="GET", parameter=q,
                      confidence="confirmed", cvss=8.1,
                      evidence={"query": q, "new_job_ids": sorted(alt_ids)[:5],
                                "artifact": lr.get("evidence")},
                      impact="通过查询参数/头部看到其他租户的导出任务与下载链接。",
                      remediation="租户过滤放在服务端会话，不接收客户端 tenant 参数。",
                      tags=["export", "idor"])
    return store.items


def main():
    p = argparse.ArgumentParser(description="Async export / signed-download IDOR probe")
    p.add_argument("--base", required=True)
    p.add_argument("--cookie-jar", default=None)
    p.add_argument("--cookie", default=None)
    p.add_argument("--create-path", default="/exports")
    p.add_argument("--list-path", default="/exports")
    p.add_argument("--kind", default="orders")
    p.add_argument("--from", dest="date_from", default="2026-07-01")
    p.add_argument("--to", dest="date_to", default="2026-10-24")
    p.add_argument("--wait", type=float, default=2)
    p.add_argument("--other-job", default=None)
    p.add_argument("--list-query", action="append", default=[],
                   help="列表绕过测试，如 tenant_id=2 / all=1，可重复")
    p.add_argument("--rps", type=float, default=1.0)
    p.add_argument("--out", default="export-findings.json")
    p.add_argument("--evidence-dir", default="export-raw")
    args = p.parse_args()
    client = httpkit.HttpClient(base_url=args.base, cookie=args.cookie,
                                cookie_jar=args.cookie_jar, rps=args.rps,
                                evidence_dir=args.evidence_dir)
    store = FindingStore(args.out)
    ctx = {"base_url": args.base, "anon": client, "clients": {"anon": client}, "store": store,
           "options": {"export_create_path": args.create_path, "export_list_path": args.list_path,
                       "export_kind": args.kind, "export_from": args.date_from,
                       "export_to": args.date_to, "export_wait": args.wait,
                       "export_other_job": args.other_job,
                       "export_list_queries": args.list_query},
           "evidence_dir": args.evidence_dir}
    run(ctx)
    store.save()
    print(json.dumps(store.summary(), ensure_ascii=False))
    print("findings:", os.path.abspath(args.out))


if __name__ == "__main__":
    main()
