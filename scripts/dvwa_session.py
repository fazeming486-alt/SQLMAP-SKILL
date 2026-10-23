#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DVWA 会话助手：登录 -> 切档位 -> 输出可直接用于 sqlmap 的 Cookie。

Usage:
  python dvwa_session.py --base-url http://192.168.0.103:8080 \
    --user admin --pass password --level low --json

输出:
  --json    {"login":"ok","base_url":"...","level":"low","requested_level":"low","cookie":"PHPSESSID=...; security=low"}
  普通       逐行打印，末行给出可直接粘贴的 --cookie "..." 形态

兼容 user_token 单/双引号两种属性写法（DVWA 各版本页面属性顺序不同）。

Exit codes: 0 成功, 1 网络错误/超时, 3 登录失败。
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar as cj

if hasattr(sys.stdout, "reconfigure"):  # 固定 UTF-8，避免 GBK 控制台/管道乱码
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def emit(args, payload):
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        for key in ("login", "base_url", "level", "requested_level", "cookie"):
            if key in payload and payload[key] is not None:
                print("%s: %s" % (key, payload[key]))
        if payload.get("login") == "ok" and payload.get("cookie"):
            print('--cookie "%s"' % payload["cookie"])


def main():
    parser = argparse.ArgumentParser(description="DVWA session helper for sqlmap")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--user", default="admin")
    parser.add_argument("--pass", dest="password", default="password")
    parser.add_argument("--level", choices=["low", "medium", "high", "impossible"], default=None)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--user-agent",
                        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    jar = cj.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    op.addheaders = [("User-Agent", args.user_agent)]

    def get(path):
        with op.open(base + path, timeout=args.timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")

    def post(path, fields):
        data = urllib.parse.urlencode(fields).encode()
        with op.open(base + path, data, timeout=args.timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")

    try:
        code, body = get("/login.php")
    except Exception as exc:
        emit(args, {"login": "error", "base_url": base, "error": str(exc)})
        return 1

    m = re.search(r'name=["\']user_token["\'][^>]*value=["\']([^"\']+)', body)
    if not m:
        m = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']user_token', body)
    fields = {"username": args.user, "password": args.password, "Login": "Login"}
    if m:
        fields["user_token"] = m.group(1)

    try:
        code, body = post("/login.php", fields)
    except Exception as exc:
        emit(args, {"login": "error", "base_url": base, "error": str(exc)})
        return 1

    if "logout.php" not in body:
        emit(args, {
            "login": "failed",
            "base_url": base,
            "hint": "检查用户名/口令（DVWA 出厂 admin/password）；或页面结构变化",
        })
        return 3

    level_now = None
    try:
        code, page = get("/security.php")
        cur = re.search(r'<option value="([a-z]+)"\s+selected', page)
        level_now = cur.group(1) if cur else None
    except Exception:
        page = ""

    if args.level and level_now != args.level:
        try:
            code, page = post("/security.php", {"security": args.level, "seclev_submit": "Submit"})
            cur2 = re.search(r'<option value="([a-z]+)"\s+selected', page)
            level_now = cur2.group(1) if cur2 else level_now
        except Exception:
            pass

    cookie = "; ".join("%s=%s" % (c.name, c.value) for c in jar)
    emit(args, {
        "login": "ok",
        "base_url": base,
        "level": level_now,
        "requested_level": args.level,
        "cookie": cookie,
    })
    if args.level and level_now != args.level:
        if not args.json:
            print("WARN: 档位切换未确认（请求 %s，读到 %s）；继续用当前档位。" % (args.level, level_now))
    return 0


if __name__ == "__main__":
    sys.exit(main())
