#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Send one normal request to verify target/session before sqlmap.

Usage:
  python baseline.py --authorized \
    --url "http://127.0.0.1:9300/api/report/export?keyword=1&from=&to=" \
    --cookie "NB_SID=..." --header "X-CSRF-Token: ..."

Exit codes: 0 2xx, 1 network error, 2 non-2xx.
"""
import argparse
import ipaddress
import sys
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlparse


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

    if not args.authorized:
        print("REFUSED: 需要 --authorized（只允许自有或书面授权的目标）。")
        return 3
    if not args.url.startswith(("http://", "https://")):
        print("REFUSED: --url 必须是 http(s) 完整地址。")
        return 3
    host = urlparse(args.url).hostname
    if not host_is_private(host) and not args.public_target:
        print("REFUSED: 检测到公网目标。确认书面授权后加 --public-target。")
        return 3

    headers = {"User-Agent": "sqlmap-skill-baseline/1.0"}
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
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            status = resp.status
            final_url = resp.geturl()
            ctype = resp.headers.get("Content-Type", "")
            cdisp = resp.headers.get("Content-Disposition", "")
            body = resp.read(1_000_000)
    except urllib.error.HTTPError as exc:
        status = exc.code
        final_url = exc.geturl()
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
