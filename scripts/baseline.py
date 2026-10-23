#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Send one normal request to verify target/session before sqlmap.

Usage:
  python baseline.py \
    --url "http://127.0.0.1:9300/api/report/export?keyword=1&from=&to=" \
    --cookie "NB_SID=..." --header "X-CSRF-Token: ..."

私网/回环目标自动放行；公网目标需要 --public-target（一行式记录由 job 的 scope_note 负责，不做问答）。

Exit codes: 0 2xx, 1 network error, 2 non-2xx, 3 refused.
"""
import argparse
import ipaddress
import sys
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse

if hasattr(sys.stdout, "reconfigure"):  # 固定 UTF-8，避免 GBK 控制台/管道乱码
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


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


# WAF 指纹签名（借自 atiilla/sqlmap-ai 的 evasion_engine，精简为 stdlib 可判的串）
WAF_SIGNATURES = {
    "cloudflare": ["cf-ray", "__cfduid", "cloudflare", "attention required"],
    "aws-waf": ["x-amzn-requestid", "blocked by aws waf", "awselb"],
    "modsecurity": ["mod_security", "modsecurity", "406 not acceptable"],
    "imperva/incapsula": ["x-iinfo", "incap_ses", "visid_incap", "incapsula"],
    "f5/big-ip": ["bigipserver", "x-wa-info", "the requested url was rejected"],
    "fortinet": ["fortigate", "fortinet"],
    "sucuri": ["x-sucuri-id", "sucuri"],
    "akamai": ["x-akamai", "akamai reference"],
}


def detect_waf(headers, body_text):
    text = (str(headers) + " " + body_text[:20000]).lower()
    best, best_hits = None, 0
    for waf_type, sigs in WAF_SIGNATURES.items():
        hits = sum(1 for s in sigs if s in text)
        if hits > best_hits:
            best, best_hits = waf_type, hits
    return best, best_hits


def main():
    parser = argparse.ArgumentParser(description="One-request baseline check")
    parser.add_argument("--url", required=True)
    parser.add_argument("--method", default=None)
    parser.add_argument("--data", default=None)
    parser.add_argument("--cookie", default=None)
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--authorized", action="store_true")
    parser.add_argument("--public-target", action="store_true")
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--preview", type=int, default=240)
    args = parser.parse_args()

    if not args.url.startswith(("http://", "https://")):
        print("REFUSED: --url 必须是 http(s) 完整地址。")
        return 3
    host = urlparse(args.url).hostname
    if host_is_private(host):
        args.authorized = True  # 私网/回环/本地靶场：零声明直通
    if not args.authorized and not args.public_target:
        print("REFUSED: 公网目标需要 --public-target（范围记录写在 job 的 scope_note）。")
        return 3

    headers = {"User-Agent": "web-pentest-baseline/3.0"}
    if args.cookie:
        headers["Cookie"] = args.cookie
    for raw in args.header:
        if ":" in raw:
            name, value = raw.split(":", 1)
            headers[name.strip()] = value.strip()

    data = None
    method = (args.method or ("POST" if args.data else "GET")).upper()
    if args.data is not None:
        data = args.data.encode("utf-8")
        if not any(k.lower() == "content-type" for k in headers):
            snippet = args.data.lstrip()
            if snippet.startswith("{") or snippet.startswith("["):
                headers["Content-Type"] = "application/json"
            else:
                headers["Content-Type"] = "application/x-www-form-urlencoded"

    req = urllib.request.Request(args.url, data=data, headers=headers, method=method)
    rheaders = None
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            status = resp.status
            final_url = resp.geturl()
            rheaders = resp.headers
            ctype = resp.headers.get("Content-Type", "")
            cdisp = resp.headers.get("Content-Disposition", "")
            body = resp.read(1_000_000)
    except urllib.error.HTTPError as exc:
        status = exc.code
        final_url = exc.geturl()
        rheaders = exc.headers
        ctype = exc.headers.get("Content-Type", "") if exc.headers else ""
        cdisp = exc.headers.get("Content-Disposition", "") if exc.headers else ""
        try:
            body = exc.read(200_000)
        except Exception:
            body = b""
    except Exception as exc:
        print("ERROR: 请求失败：%s" % exc)
        return 1

    text = body.decode("utf-8", "replace")
    login_redirect = "/login" in final_url or "login?" in final_url
    waf_type, waf_hits = detect_waf(rheaders or {}, text)
    rows = None
    first_line = text.lstrip("\ufeff").splitlines()[0] if text.strip() else ""
    if "text/csv" in ctype.lower() or (first_line.count(",") >= 2 and "html" not in ctype.lower()):
        lines = [line for line in text.splitlines() if line.strip()]
        rows = max(0, len(lines) - 1)

    print("URL: %s" % args.url)
    print("METHOD: %s" % method)
    print("STATUS: %s" % status)
    print("FINAL_URL: %s" % final_url)
    print("CONTENT_TYPE: %s" % ctype)
    if cdisp:
        print("CONTENT_DISPOSITION: %s" % cdisp)
    print("BYTES_READ: %d" % len(body))
    print("LOGIN_REDIRECT: %s" % ("yes" if login_redirect else "no"))
    print("WAF_DETECTED: %s" % ("yes" if waf_type else "no"))
    if waf_type:
        print("WAF_TYPE: %s (signatures=%d)" % (waf_type, waf_hits))
        print("WARN: 基线响应带 WAF 指纹——先看 playbook 的 WAF→tamper 表再开跑。")
    if rows is not None:
        print("CSV_DATA_ROWS: %d" % rows)
    preview = text[: max(0, args.preview)].replace("\r", "")
    if preview:
        print("PREVIEW:")
        print(preview)
    if login_redirect:
        print("WARN: 最终地址是登录页，Cookie/会话大概率无效。")
    return 0 if (200 <= status < 300 and not login_redirect) else 2


if __name__ == "__main__":
    sys.exit(main())
