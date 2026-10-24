#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""api_probe.py —— API 路由与方法面枚举（401/405/404 分类）。

针对合作方/移动端 API：没有导航、没有 OpenAPI 时，用少量请求区分
“路由存在但需要认证（401）”“方法不对（405）”“不存在（404）”“可直接访问（200）”。

用法：
  python api_probe.py --base https://host --cookie-jar buyer.txt \
      --route /partner/v1/profile --route /partner/v1/orders
  python api_probe.py --base https://host --wordlist api-paths.txt
"""
import argparse
import json
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import httpkit
from findings import FindingStore

DEFAULT_PATHS = [
    "/partner/v1/profile", "/partner/v1/orders", "/partner/v1/invoices/import",
    "/partner/v1/webhooks", "/partner/v1/users", "/partner/v1/me",
    "/api/v1/profile", "/api/v1/orders", "/api/v1/invoices", "/api/v1/users",
    "/api/me", "/api/profile", "/api/orders", "/health", "/metrics",
]


def run(ctx):
    store = ctx["store"]
    base = ctx["base_url"]
    client = ctx["anon"] or ctx["clients"].get("anon")
    opts = ctx.get("options", {})
    paths = opts.get("api_paths") or DEFAULT_PATHS
    methods = opts.get("api_methods") or ["GET", "POST", "PATCH", "PUT"]
    rows = []
    for path in paths:
        for method in methods:
            try:
                r = client.request(method, path, tag="api-%s-%s" % (method, path.replace("/", "_")))
            except Exception as e:
                rows.append({"path": path, "method": method, "status": "ERR", "error": str(e)})
                continue
            rows.append({"path": path, "method": method, "status": r["status"],
                         "size": len(r["text"] or ""),
                         "snippet": httpkit.redact((r["text"] or "")[:120]),
                         "artifact": r.get("evidence")})
            if r["status"] == 200 and method in ("GET", "POST"):
                # 只有在没有显式认证配置时，200 才按“未授权可访问”记录
                if not (opts.get("api_authenticated")):
                    store.add(module="api", title="API 未授权可访问", severity="high",
                              endpoint=base + path, method=method, confidence="confirmed",
                              cvss=7.5,
                              evidence={"status": r["status"],
                                        "snippet": httpkit.redact((r["text"] or "")[:500]),
                                        "artifact": r.get("evidence")},
                              impact="未携带认证即可读取/操作 API，需确认数据敏感度。",
                              remediation="统一认证中间件；默认拒绝。",
                              tags=["api", "auth"])
            elif r["status"] in (401, 403):
                store.add(module="api", title="API 路由存在（受保护）", severity="info",
                          endpoint=base + path, method=method, confidence="surface",
                          evidence={"status": r["status"], "artifact": r.get("evidence")},
                          impact="发现 API 面；需要有效凭据才能测试业务逻辑。",
                          remediation="—", tags=["api", "surface"])
            elif r["status"] == 405:
                store.add(module="api", title="API 路由存在（方法受限）", severity="info",
                          endpoint=base + path, method=method, confidence="surface",
                          evidence={"status": 405, "allow": r["headers"].get("allow"),
                                    "artifact": r.get("evidence")},
                          impact="路由存在但该方法不允许；尝试其他方法或查看 Allow。",
                          remediation="—", tags=["api", "surface"])
    ctx["api_rows"] = rows
    return store.items


def main():
    p = argparse.ArgumentParser(description="API surface enumeration (401/405/404)")
    p.add_argument("--base", required=True)
    p.add_argument("--cookie-jar", default=None)
    p.add_argument("--cookie", default=None)
    p.add_argument("--bearer", default=None)
    p.add_argument("--api-key", default=None, help="附加 X-API-Key")
    p.add_argument("--route", action="append", default=[])
    p.add_argument("--wordlist", default=None)
    p.add_argument("--methods", default="GET,POST,PATCH,PUT")
    p.add_argument("--rps", type=float, default=1.0)
    p.add_argument("--out", default="api-findings.json")
    p.add_argument("--evidence-dir", default="api-raw")
    args = p.parse_args()
    paths = [httpkit.normalize_path(x) for x in args.route]
    if args.wordlist:
        paths += [httpkit.normalize_path(l.strip()) for l in open(args.wordlist, encoding="utf-8") if l.strip()]
    if not paths:
        paths = DEFAULT_PATHS
    headers = {}
    if args.bearer:
        headers["Authorization"] = "Bearer " + args.bearer
    if args.api_key:
        headers["X-API-Key"] = args.api_key
    client = httpkit.HttpClient(base_url=args.base, cookie=args.cookie,
                                cookie_jar=args.cookie_jar, headers=headers,
                                rps=args.rps, evidence_dir=args.evidence_dir)
    store = FindingStore(args.out)
    ctx = {"base_url": args.base, "anon": client, "clients": {"anon": client}, "store": store,
           "options": {"api_paths": paths, "api_methods": [m.strip().upper() for m in args.methods.split(",")],
                       "api_authenticated": bool(args.cookie or args.cookie_jar or args.bearer or args.api_key)},
           "evidence_dir": args.evidence_dir}
    run(ctx)
    store.save()
    for row in ctx.get("api_rows", []):
        print("%-6s %-40s %s" % (row.get("method"), row.get("path"), row.get("status")))
    print(json.dumps(store.summary(), ensure_ascii=False))
    print("findings:", os.path.abspath(args.out))


if __name__ == "__main__":
    main()
