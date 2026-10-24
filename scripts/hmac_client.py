#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hmac_client.py —— 通用 HMAC 签名 API 客户端。

适配常见“时间戳 + 方法 + 路径 + body”签名方案（OBSIDIAN 合作方 API 即此类）：
  X-<Prefix>-Key / X-<Prefix>-Timestamp / X-<Prefix>-Signature
  signature = hex(HMAC-SHA256(secret, timestamp + "\n" + METHOD + "\n" + path + "\n" + raw_body))

用法：
  python hmac_client.py --base https://host --key KEY --secret SECRET \
      --method GET --path /partner/v1/profile
  python hmac_client.py ... --method PATCH --path /partner/v1/profile \
      --body '{"tier":"platinum"}' --content-type application/json
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def sign(secret, timestamp, method, path, body):
    msg = (str(timestamp) + "\n" + method.upper() + "\n" + path + "\n").encode() + body
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def main():
    p = argparse.ArgumentParser(description="Generic HMAC-signed API client")
    p.add_argument("--base", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--secret", required=True)
    p.add_argument("--method", default="GET")
    p.add_argument("--path", required=True, help="含 query 的路径，如 /partner/v1/orders?page=1")
    p.add_argument("--body", default=None)
    p.add_argument("--body-file", default=None)
    p.add_argument("--content-type", default="application/json")
    p.add_argument("--header-prefix", default="X-Obsidian", help="默认 X-Obsidian")
    p.add_argument("--timestamp-header", default=None)
    p.add_argument("--signature-header", default=None)
    p.add_argument("--out", default=None)
    args = p.parse_args()

    path = args.path.replace("\\", "/")
    for pref in ("C:/Program Files/Git/", "C:/Program Files (x86)/Git/"):
        if path.lower().startswith(pref.lower()):
            path = "/" + path[len(pref):]
            break
    if not path.startswith("/"):
        path = "/" + path
    args.path = path

    body = b""
    if args.body_file:
        body = open(args.body_file, "rb").read()
    elif args.body:
        body = args.body.encode()
    for h in (args.timestamp_header, args.signature_header):
        if h and not h.startswith("X-"):
            print("header name should start with X-", file=sys.stderr)
            return 2

    ts = str(int(time.time()))
    sig = sign(args.secret, ts, args.method, args.path, body)
    prefix = args.header_prefix
    headers = {
        prefix + "-Key": args.key,
        args.timestamp_header or (prefix + "-Timestamp"): ts,
        args.signature_header or (prefix + "-Signature"): sig,
    }
    if body:
        headers["Content-Type"] = args.content_type

    req = urllib.request.Request(args.base.rstrip("/") + args.path, data=body or None,
                                 headers=headers, method=args.method.upper())
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read().decode("utf-8", "replace")
            code = r.status
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "replace")
        code = e.code
    print("STATUS:", code)
    print(text)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text)
    return 0 if 200 <= code < 300 else 1


if __name__ == "__main__":
    sys.exit(main())
