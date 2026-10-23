#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ssrf_probe.py —— SSRF 带外回调取证（beta）。

启动一个本地 HTTP 回调监听器，把带随机 token 的回调 URL 注入目标参数；
如果监听器收到该 token 的请求，说明目标端发起了服务端请求。

注意：
- 目标与监听器在同一台机器/内网时，用 --listen 0.0.0.0 + 内网地址即可；
- 目标是远程时，127.0.0.1 是目标自己的回环，不是你的机器；必须用
  --callback 指向公网可达的地址（你自己的域名/interactsh/webhook）。
"""
import argparse
import json
import os
import random
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import httpkit
from findings import FindingStore

HITS = []
LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        with LOCK:
            HITS.append({"path": self.path, "headers": dict(self.headers),
                         "time": time.strftime("%Y-%m-%d %H:%M:%S")})
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    do_POST = do_GET

    def log_message(self, *args):
        return


def apply_url(template, value):
    parts = urllib.parse.urlsplit(template)
    pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    out = []
    for k, v in pairs:
        if "*" in k:
            k = k.replace("*", value, 1)
        if "*" in v:
            v = v.replace("*", value, 1)
        out.append((k, v))
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                    urllib.parse.urlencode(out, quote_via=urllib.parse.quote),
                                    parts.fragment))


def start_listener(host, port):
    srv = ThreadingHTTPServer((host, port), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def run(ctx):
    store = ctx["store"]
    targets = ctx.get("options", {}).get("ssrf_targets") or ctx.get("targets") or []
    callback = ctx.get("options", {}).get("ssrf_callback")
    wait = float(ctx.get("options", {}).get("ssrf_wait", 3))
    if not callback:
        return store.items
    for i, t in enumerate(targets):
        token = "wpxssrf%d" % random.randint(100000, 999999)
        url = apply_url(t, callback.rstrip("/") + "/" + token)
        client = ctx.get("anon") or ctx["clients"].get("anon")
        try:
            r = client.get(url, tag="ssrf-%d" % (i + 1))
        except Exception as e:
            print("SSRF request error:", e)
            continue
        deadline = time.time() + wait
        hit = None
        while time.time() < deadline:
            with LOCK:
                for h in HITS:
                    if token in h["path"]:
                        hit = h
                        break
            if hit:
                break
            time.sleep(0.2)
        if hit:
            store.add(
                module="ssrf", title="服务端请求伪造（带外回调命中）", severity="high",
                endpoint=t, method="GET", parameter="*", confidence="confirmed", cvss=8.2,
                evidence={"payload": url, "hit": hit, "status": r["status"],
                          "artifact": r.get("evidence")},
                impact="攻击者可让服务器访问内网/元数据/其他服务，可能进一步读取凭据或横向移动。",
                remediation="URL 白名单、禁止内网/元数据地址、解析后二次校验、出站代理。",
                references=["WSTG-INPV-19", "OWASP SSRF Prevention Cheat Sheet"],
                tags=["ssrf", "oob"],
            )
    return store.items


def main():
    p = argparse.ArgumentParser(description="SSRF out-of-band probe (beta)")
    p.add_argument("--target", action="append", default=[], help="含 * 的 URL，可重复")
    p.add_argument("--callback", required=True, help="目标可访问的回调基础 URL")
    p.add_argument("--listen", default="127.0.0.1")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--wait", type=float, default=3)
    p.add_argument("--rps", type=float, default=1.0)
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("--out", default="ssrf-findings.json")
    p.add_argument("--evidence-dir", default="ssrf-raw")
    args = p.parse_args()
    srv = start_listener(args.listen, args.port)
    print("callback listener on %s:%d" % (args.listen, srv.server_address[1]))
    client = httpkit.HttpClient(base_url="", rps=args.rps, timeout=args.timeout,
                                evidence_dir=args.evidence_dir)
    store = FindingStore(args.out)
    ctx = {"base_url": "", "anon": client, "clients": {"anon": client}, "store": store,
           "options": {"ssrf_targets": args.target, "ssrf_callback": args.callback,
                       "ssrf_wait": args.wait}, "evidence_dir": args.evidence_dir}
    run(ctx)
    store.save()
    print(json.dumps(store.summary(), ensure_ascii=False))
    print("findings:", os.path.abspath(args.out))
    srv.shutdown()


if __name__ == "__main__":
    main()
