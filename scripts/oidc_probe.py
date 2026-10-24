#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""oidc_probe.py —— OIDC/OAuth 回调地址（redirect_uri）校验绕过取证。

判据：合法 redirect_uri 通过；变体如果被接受并 302 到攻击者域名（或带 code=），
说明校验用了字符串前缀/包含，而不是精确域名边界。

用法：
  python oidc_probe.py --issuer https://host --client-id <id> \
      --redirect-uri https://host/oidc/callback --cookie-jar buyer.txt
"""
import argparse
import json
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import httpkit
from findings import FindingStore


def variants(redirect):
    p = urllib.parse.urlsplit(redirect)
    host = p.hostname or "target.example"
    path = p.path or "/callback"
    base = "%s://%s%s" % (p.scheme, host, path)
    evil = "evil.example"
    return [
        ("legit", base),
        ("host-suffix", "%s://%s.%s%s" % (p.scheme, host, evil, path)),
        ("at-confusion", "%s://%s@%s%s" % (p.scheme, host, evil, path)),
        ("path-prefix", "%s://%s/%s%s" % (p.scheme, evil, host, path)),
        ("encoded-dot", "%s://%s%%2E%s%s" % (p.scheme, host, evil, path)),
        ("backslash", "%s://%s\\@%s%s" % (p.scheme, host, evil, path)),
        ("trailing-query", "%s?next=https://%s/" % (base, evil)),
        ("case", "%s://%s%s" % (p.scheme, host.upper(), path)),
    ]


def run(ctx):
    store = ctx["store"]
    client = ctx["anon"] or ctx["clients"].get("anon")
    opts = ctx.get("options", {})
    issuer = ctx["base_url"].rstrip("/")
    client_id = opts.get("oidc_client_id")
    redirect = opts.get("oidc_redirect_uri")
    if not client_id or not redirect:
        print("oidc_probe: --client-id and --redirect-uri are required")
        return store.items
    authorize = httpkit.normalize_path(opts.get("oidc_authorize") or "/oidc/authorize")
    for name, uri in variants(redirect):
        q = urllib.parse.urlencode({"response_type": "code", "client_id": client_id,
                                    "redirect_uri": uri, "scope": "openid"})
        r = client.get(authorize + "?" + q, tag="oidc-" + name)
        loc = r["headers"].get("location", "")
        body = r["text"] or ""
        if "登录工作台" in body or "/login" in (r["url"] or ""):
            store.add(module="oidc", title="OIDC 测试需要有效登录会话", severity="info",
                      endpoint=issuer + authorize, method="GET", confidence="surface",
                      evidence={"status": r["status"], "url": r["url"],
                                "artifact": r.get("evidence")},
                      impact="未登录时 authorize 会先跳登录，无法判断 redirect_uri。",
                      remediation="提供该角色的 cookie jar 或登录配置。",
                      tags=["oidc", "session"])
            return store.items
        leaked = "code=" in loc and "evil.example" in loc
        accepted = r["status"] in (302, 303) and loc and "login" not in loc
        if leaked:
            store.add(module="oidc", title="OIDC redirect_uri 前缀绕过（授权码外泄）",
                      severity="critical", endpoint=issuer + authorize, method="GET",
                      parameter="redirect_uri", confidence="confirmed", cvss=9.1,
                      evidence={"variant": name, "redirect_uri": uri, "status": r["status"],
                                "location": httpkit.redact(loc), "artifact": r.get("evidence")},
                      impact="攻击者可用相似域名接收授权码，接管账号。",
                      remediation="redirect_uri 必须精确匹配注册值；不要用 startswith/包含判断。",
                      references=["WSTG-ATHN-05", "RFC 6749 §3.1.2"],
                      tags=["oidc", "oauth", "redirect_uri"])
        elif accepted and name != "legit":
            store.add(module="oidc", title="OIDC redirect_uri 变体被接受（待复核）",
                      severity="medium", endpoint=issuer + authorize, method="GET",
                      parameter="redirect_uri", confidence="needs-review", cvss=5.3,
                      evidence={"variant": name, "redirect_uri": uri, "status": r["status"],
                                "location": httpkit.redact(loc), "artifact": r.get("evidence")},
                      impact="变体未被拒绝，需确认实际回调是否会把 code 发到非预期域名。",
                      remediation="精确匹配 redirect_uri；拒绝用户信息/后缀/编码变体。",
                      tags=["oidc", "redirect_uri"])
        elif name == "legit" and r["status"] == 400:
            store.add(module="oidc", title="OIDC 客户端或回调配置无效", severity="info",
                      endpoint=issuer + authorize, method="GET", confidence="surface",
                      evidence={"status": 400, "snippet": httpkit.redact(body[:300]),
                                "artifact": r.get("evidence")},
                      impact="需要有效的 client_id/redirect_uri 才能继续测试。",
                      remediation="—", tags=["oidc", "config"])
    return store.items


def main():
    p = argparse.ArgumentParser(description="OIDC redirect_uri bypass probe")
    p.add_argument("--issuer", required=True)
    p.add_argument("--client-id", required=True)
    p.add_argument("--redirect-uri", required=True)
    p.add_argument("--authorize", default="/oidc/authorize")
    p.add_argument("--cookie-jar", default=None)
    p.add_argument("--cookie", default=None)
    p.add_argument("--rps", type=float, default=1.0)
    p.add_argument("--out", default="oidc-findings.json")
    p.add_argument("--evidence-dir", default="oidc-raw")
    args = p.parse_args()
    client = httpkit.HttpClient(base_url=args.issuer, cookie=args.cookie,
                                cookie_jar=args.cookie_jar, rps=args.rps,
                                evidence_dir=args.evidence_dir)
    store = FindingStore(args.out)
    ctx = {"base_url": args.issuer, "anon": client, "clients": {"anon": client}, "store": store,
           "options": {"oidc_client_id": args.client_id, "oidc_redirect_uri": args.redirect_uri,
                       "oidc_authorize": args.authorize},
           "evidence_dir": args.evidence_dir}
    run(ctx)
    store.save()
    print(json.dumps(store.summary(), ensure_ascii=False))
    print("findings:", os.path.abspath(args.out))


if __name__ == "__main__":
    main()
