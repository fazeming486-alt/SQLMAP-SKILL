#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tls_relay.py —— 本地 Plain-HTTP → Clean-TLS 中继。

用途：目标（或其 CDN）按 TLS 客户端指纹（JA3）拦扫描器时，让 sqlmap 以
http:// 目标 + --proxy 指向本中继：sqlmap 到中继是明文 HTTP（零 TLS 指纹），
中继用标准 TLS 重新向 https:// 目标发起请求。

用法：
  python tls_relay.py --port 8890 [--log 请求日志]
  sqlmap -u "http://<host>/<path>" --proxy http://127.0.0.1:8890 ...

Exit codes: 0（Ctrl+C 退出）, 1 端口占用等错误。
"""
import argparse
import http.client
import socket
import ssl
import sys
import threading

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TLS_CTX = ssl.create_default_context()
HOP_HEADERS = {"connection", "proxy-connection", "keep-alive", "transfer-encoding",
               "upgrade", "proxy-authenticate", "proxy-authorization", "te", "trailer"}
# 每个上游主机一个会话 cookie 袋：响应里的 Set-Cookie 进袋，转发时注入。
# 解决"Secure cookie 不走 http"（sqlmap 经中继用 http://，浏览器语义会扣下 Secure cookie）。
COOKIE_JARS = {}
JAR_LOCK = threading.Lock()


def store_cookies(hostport, set_cookie_values):
    with JAR_LOCK:
        jar = COOKIE_JARS.setdefault(hostport, {})
        for raw in set_cookie_values:
            first = raw.split(";", 1)[0].strip()
            if "=" in first:
                k, v = first.split("=", 1)
                jar[k.strip()] = v.strip()


def cookie_header(hostport):
    with JAR_LOCK:
        jar = COOKIE_JARS.get(hostport) or {}
    return "; ".join("%s=%s" % (k, v) for k, v in jar.items()) if jar else None


def log_line(path, text):
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text.rstrip() + "\n")
    except Exception:
        pass


def read_request(conn):
    """读一个完整 HTTP 请求（头 + 按 Content-Length 的体）。返回 (method, target, headers, body) 或 None。"""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            return None
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2:
        return None
    method, target = parts[0], parts[1]
    headers = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))
    clen = 0
    for k, v in headers:
        if k.lower() == "content-length":
            clen = int(v)
    while len(rest) < clen:
        chunk = conn.recv(65536)
        if not chunk:
            break
        rest += chunk
    return method, target, headers, rest[:clen] if clen else rest


def handle(conn, args):
    conn.settimeout(120)
    try:
        req = read_request(conn)
        if not req:
            conn.close()
            return
        method, target, headers, body = req
        # 绝对 URI: http://host[:port]/path?query
        if not target.lower().startswith("http://"):
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            conn.close()
            return
        rest = target[len("http://"):]
        hostport, _, path = rest.partition("/")
        path = "/" + path
        host = hostport.rsplit(":", 1)[0] if ":" in hostport else hostport
        port = 443  # 上游始终走 TLS 443（目标 URL 的 http:// 只是给 sqlmap 看的明文层）
        fwd_headers = [(k, v) for k, v in headers
                       if k.lower() not in HOP_HEADERS and k.lower() not in ("host", "cookie")]
        fwd_headers.append(("Host", hostport))
        jar_cookie = cookie_header(hostport)
        client_cookies = "; ".join(v for k, v in headers if k.lower() == "cookie")
        merged = "; ".join(c for c in (client_cookies, jar_cookie) if c)
        if merged:
            fwd_headers.append(("Cookie", merged))

        up = http.client.HTTPSConnection(host, port, timeout=60, context=TLS_CTX)
        up.request(method, path, body=body if body else None, headers=dict(fwd_headers))
        resp = up.getresponse()
        rbody = resp.read()
        all_set_cookies = resp.msg.get_all("Set-Cookie") or []
        if all_set_cookies:
            store_cookies(hostport, all_set_cookies)
        status_line = "HTTP/1.1 %d %s\r\n" % (resp.status, resp.reason or "")
        out_headers = []
        for k, v in resp.getheaders():
            if k.lower() in HOP_HEADERS or k.lower() in ("content-length", "set-cookie"):
                continue
            out_headers.append("%s: %s\r\n" % (k, v))
        out_headers.append("Content-Length: %d\r\n" % len(rbody))
        out_headers.append("Connection: close\r\n\r\n")
        conn.sendall(status_line.encode("iso-8859-1") + "".join(out_headers).encode("iso-8859-1", "replace") + rbody)
        log_line(args.log, "[relay] %s %s -> %s (%d bytes)" % (method, target, resp.status, len(rbody)))
        up.close()
    except Exception as exc:
        try:
            conn.sendall(("HTTP/1.1 502 Relay Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").encode())
        except Exception:
            pass
        log_line(args.log, "[relay] ERROR %s" % exc)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="Plain-HTTP -> clean-TLS relay for scanner-fingerprint bypass")
    parser.add_argument("--port", type=int, default=8890)
    parser.add_argument("--log", default=r"C:/Users/Administrator/.workbuddy/tmp_relay_http.log")
    args = parser.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", args.port))
    except OSError as exc:
        print("BIND FAILED: %s" % exc)
        return 1
    srv.listen(16)
    print("tls_relay listening on 127.0.0.1:%d (sqlmap: --proxy http://127.0.0.1:%d)" % (args.port, args.port))
    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=handle, args=(conn, args), daemon=True).start()
    except KeyboardInterrupt:
        print("\nrelay stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
