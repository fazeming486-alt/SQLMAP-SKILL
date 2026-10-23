#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""selftest_target.py —— inject_probe.py 的本地自检靶点（可注入 / 不可注入 / 限速 / 保护）。

用法：
  python selftest_target.py --port 8899
  python selftest.py            # 一键跑三态自检

端点：
  /vuln      真值有数据、假值空结果（长度不同）→ 期望判定 INJECTABLE
  /inval     任何 AND 都被过滤 → 期望判定 not_injectable_same_behavior
  /limited   第二次请求起 429 → 期望取证器限速中止（exit 2）
  /protected 403「安全校验未通过」→ 期望限速中止
"""
import argparse
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

STATE = {"limited": 0}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        import urllib.parse
        parts = urllib.parse.urlparse(self.path)
        val = (urllib.parse.parse_qs(parts.query).get("id") or ["1"])[0]
        if parts.path == "/vuln":
            if re.search(r"AND\s+1\s*=\s*2", val):
                self._send(200, "ROWS: 0 | total 0")
            else:
                self._send(200, "ROWS: 10 | product electronics-113 | total 10")
        elif parts.path == "/inval":
            self._send(200, "ROWS: 10 | product electronics-113 | total 10")
        elif parts.path == "/limited":
            STATE["limited"] += 1
            if STATE["limited"] > 1:
                self._send(429, "<html>请求过于频繁，请稍后再试</html>")
            else:
                self._send(200, "ROWS: 10 | total 10")
        elif parts.path == "/protected":
            self._send(403, "<html>安全校验未通过或页面停留过久，请刷新后重试</html>")
        else:
            self._send(404, "not found")


def main():
    p = argparse.ArgumentParser(description="selftest target for inject_probe.py")
    p.add_argument("--port", type=int, default=8899)
    args = p.parse_args()
    srv = HTTPServer(("127.0.0.1", args.port), Handler)
    print("selftest target on http://127.0.0.1:%d  (/vuln /inval /limited /protected)" % args.port)
    srv.serve_forever()


if __name__ == "__main__":
    main()
