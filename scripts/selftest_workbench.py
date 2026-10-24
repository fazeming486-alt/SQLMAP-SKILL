#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""selftest_workbench.py —— report_probe / webhook_probe 的本地自检靶点（仅标准库）。

用法：
  python scripts/selftest_workbench.py --port 8899

  # 另开终端：
  python scripts/report_probe.py --base http://127.0.0.1:8899 --email a@b.c \
      --password x --payload "paid' OR '1'='1" --payload "paid' AND 1=2" \
      --payload "paid' UNION SELECT 1" --wait 0.2
  python scripts/webhook_probe.py --base http://127.0.0.1:8899 --email a@b.c \
      --password x --redirector "http://127.0.0.1:8899/redirect?url=" \
      --inner "http://internal:8000/flag" --wait 0.2

模拟行为：
  - 保存报表最多 8 条；运行结果按 status 关键字返回 7 组 / 1 组 / GroupingError。
  - Webhook 最多 5 个；测试投递把 redirector 的 url 参数当作内层，返回 302->200。
  - 内层含 "flag" 时结果里带 FLAG{selftest-webhook}。
仅用于验证解析与判据，不是真实漏洞实现。
"""
import argparse
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOK = "selftest-csrf"
STATE = {"reports": [], "results": {}, "hooks": [], "deliveries": [],
         "rid": 1, "wid": 1, "max_reports": 8, "max_hooks": 5}


def page_reports():
    rows = "".join("<tr><td>%s</td><td>%s</td></tr>" % (r["name"], r["status"])
                   for r in STATE["reports"])
    runs = "".join("<tr><td>%s</td><td>%s</td></tr>" % (k, v)
                   for k, v in STATE["results"].items())
    links = "".join('<form method="post" action="/supplier/reports/%d/run">'
                    '<input type="hidden" name="_csrf" value="%s"></form>'
                    % (r["id"], TOK) for r in STATE["reports"])
    return ("<html><body><h3>Reports</h3><form method='post' action='/supplier/reports'>"
            "<input type='hidden' name='_csrf' value='%s'>"
            "<input name='name'><input name='dimension'><input name='status'>"
            "<input name='from'><input name='to'><button>save</button></form>"
            "<table>%s</table><table>%s</table>%s</body></html>"
            % (TOK, rows, runs, links))


def page_hooks():
    rows = "".join("<tr><td>%d</td><td>%s</td></tr>" % (h["id"], h["url"])
                   for h in STATE["hooks"])
    dels = "".join("<tr><td>%s</td></tr>" % d for d in STATE["deliveries"])
    links = "".join('<form method="post" action="/supplier/webhooks/%d/test">'
                    '<input type="hidden" name="_csrf" value="%s"></form>'
                    % (h["id"], TOK) for h in STATE["hooks"])
    return ("<html><body><h3>Webhooks</h3><form method='post' action='/supplier/webhooks'>"
            "<input type='hidden' name='_csrf' value='%s'>"
            "<input name='url'><input name='events'><button>create</button></form>"
            "<table>%s</table><table>%s</table>%s</body></html>"
            % (TOK, rows, dels, links))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def send(self, code, body="", headers=None):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def redirect(self, loc):
        self.send(303, "", [("Location", loc)])

    def authed(self):
        return "sess=ok" in (self.headers.get("Cookie") or "")

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/login":
            return self.send(200, "<form method=\"post\"><input type=\"hidden\" name=\"_csrf\" "
                                  "value=\"%s\"><input name=\"email\"><input name=\"password\"></form>" % TOK)
        if not self.authed():
            return self.redirect("/login")
        if path == "/supplier/reports":
            return self.send(200, page_reports())
        if path == "/supplier/webhooks":
            return self.send(200, page_hooks())
        self.send(404, "not found")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        n = int(self.headers.get("Content-Length") or 0)
        form = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
        if path == "/login":
            return self.send(303, "", [("Location", "/supplier/reports"),
                                        ("Set-Cookie", "sess=ok; Path=/")])
        if not self.authed():
            return self.redirect("/login")
        if form.get("_csrf", [""])[0] != TOK:
            return self.send(403, "bad csrf")
        m = re.match(r"/supplier/reports/(\d+)/run$", path)
        if m:
            rid = int(m.group(1))
            rep = next((r for r in STATE["reports"] if r["id"] == rid), None)
            if rep:
                s = rep["status"]
                if "UNION" in s.upper():
                    STATE["results"][rep["name"]] = "失败 — GroupingError: 1056"
                elif "OR '1'='1" in s:
                    STATE["results"][rep["name"]] = "已完成 — 7 组"
                else:
                    STATE["results"][rep["name"]] = "已完成 — 1 组"
            return self.redirect("/supplier/reports")
        if path == "/supplier/reports":
            if len(STATE["reports"]) < STATE["max_reports"]:
                STATE["reports"].append({"id": STATE["rid"],
                                         "name": form.get("name", ["p"])[0],
                                         "status": form.get("status", [""])[0]})
                STATE["rid"] += 1
            return self.redirect("/supplier/reports")
        m = re.match(r"/supplier/webhooks/(\d+)/test$", path)
        if m:
            hid = int(m.group(1))
            hook = next((h for h in STATE["hooks"] if h["id"] == hid), None)
            if hook:
                q = urllib.parse.parse_qs(urllib.parse.urlparse(hook["url"]).query)
                inner = (q.get("url") or [hook["url"]])[0]
                flag = " FLAG{selftest-webhook}" if "flag" in inner else ""
                STATE["deliveries"].append("1 httpbin 302 -> 200 %s%s" % (inner, flag))
            return self.redirect("/supplier/webhooks")
        if path == "/supplier/webhooks":
            if len(STATE["hooks"]) < STATE["max_hooks"]:
                STATE["hooks"].append({"id": STATE["wid"],
                                       "url": form.get("url", [""])[0]})
                STATE["wid"] += 1
            return self.redirect("/supplier/webhooks")
        self.send(404, "not found")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8899)
    args = p.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print("selftest workbench on http://127.0.0.1:%d (Ctrl+C to stop)" % args.port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
