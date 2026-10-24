#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""httpkit.py —— web-pentest 工作台的共享 HTTP 内核。

职责：会话（静态 Cookie / Netscape jar / 自动登录）、限速、预算、重试、
响应归一化、相似度、证据落盘与脱敏。所有模块共用这一层，避免每个探测脚本
重复处理 Cookie 轮换、429、超时和日志。

设计参考：
- PentestGPT 的 reasoning/generation/parsing 分层：本文件只做“执行与取证”，不做判断。
- Strix 的 evidence-first：每个请求都落盘，结论必须能指回原始响应。
- HexStrike / PentAGI 的 tool-call limits：预算与速率是一等公民。
"""
import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import re
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

RATE_LIMIT_HINTS = ("过于频繁", "稍后再试", "too many requests", "rate limit",
                    "安全校验未通过", "try again later", "慢一点")


class BudgetExceeded(RuntimeError):
    pass


class RateLimited(RuntimeError):
    pass


class Budget:
    """整个 engagement 共享的请求预算。"""

    def __init__(self, max_requests=500):
        self.max_requests = int(max_requests)
        self.used = 0

    def spend(self, n=1):
        if self.max_requests and self.used + n > self.max_requests:
            raise BudgetExceeded("request budget exhausted (%d/%d)" % (self.used, self.max_requests))
        self.used += n

    def left(self):
        if not self.max_requests:
            return 10 ** 9
        return max(0, self.max_requests - self.used)


def load_netscape_jar(path):
    """读取 curl/Netscape cookie jar。expires=0 按 session cookie 处理。"""
    cj = http.cookiejar.CookieJar()
    if not path or not os.path.exists(path):
        return cj
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#HttpOnly_"):
                line = line[len("#HttpOnly_"):]
            elif line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 7:
                continue
            domain, _inc, cpath, secure, _exp, name, value = parts
            c = http.cookiejar.Cookie(
                0, name, value, None, False, domain, False, False, cpath, True,
                secure.upper() == "TRUE", None, True, None, None, {"HttpOnly": None})
            cj.set_cookie(c)
    return cj


def generate_totp(secret, digits=6, period=30):
    """RFC 6238 TOTP（SHA1），用于 MFA 账号的自动登录。secret 为 base32。"""
    if not secret:
        return ""
    s = re.sub(r"\s+", "", secret).upper()
    pad = "=" * ((8 - len(s) % 8) % 8)
    key = base64.b32decode(s + pad)
    counter = int(time.time()) // period
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def normalize_path(path):
    """Windows/MSYS 会把以 / 开头的参数转成 C:/Program Files/Git/...；这里还原。"""
    if not path:
        return path
    p = path.replace("\\", "/")
    for prefix in ("C:/Program Files/Git/", "C:/Program Files (x86)/Git/"):
        if p.lower().startswith(prefix.lower()):
            p = "/" + p[len(prefix):]
            break
    if not p.startswith("/"):
        p = "/" + p
    return p


def redact(text):
    """日志/报告脱敏：Cookie、Authorization、CSRF、常见 session 值。"""
    if text is None:
        return ""
    s = text
    s = re.sub(r"(?i)(cookie|set-cookie|authorization|x-csrf-token)\s*:\s*[^\r\n]+",
               r"\1: <redacted>", s)
    s = re.sub(r"(?i)(_csrf|csrf_token|authenticity_token)=([^&\s\"']+)", r"\1=<redacted>", s)
    s = re.sub(r"(?i)(nexa_sid|PHPSESSID|JSESSIONID|sessionid)=([^;\s\"']+)", r"\1=<redacted>", s)
    return s


def digest(text):
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()[:16]


def normalize(text):
    """把动态 token、时间戳、空白去掉，用于跨请求比较。"""
    if text is None:
        return ""
    s = re.sub(r"[0-9a-fA-F]{32,128}", "TOKEN", text)
    s = re.sub(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?", "TIMESTAMP", s)
    s = re.sub(r"\b\d{10,13}\b", "EPOCH", s)
    s = re.sub(r"\s+", "", s)
    return s


def similarity(a, b):
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    # 对长页面用集合相似度，避免 difflib 的 O(n^2)
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    return inter / float(len(sa | sb))


def _decode(raw, headers):
    ctype = headers.get("content-type", "") if headers else ""
    m = re.search(r"charset=([\w-]+)", ctype, re.I)
    enc = m.group(1) if m else "utf-8"
    try:
        return raw.decode(enc, "replace")
    except LookupError:
        return raw.decode("utf-8", "replace")


def _header_dict(msg):
    out = {}
    for k, v in msg.items():
        out[k.lower()] = v
    return out


class HttpClient:
    """带会话、限速、预算、证据的 HTTP 客户端。"""

    def __init__(self, base_url="", cookie=None, cookie_jar=None, headers=None,
                 user_agent=DEFAULT_UA, proxy=None, timeout=30, rps=1.0,
                 retries=2, evidence_dir=None, budget=None, allow_redirects=True):
        self.base_url = base_url.rstrip("/")
        self.cookie = cookie
        self.jar = load_netscape_jar(cookie_jar) if cookie_jar else http.cookiejar.CookieJar()
        self.headers = {"User-Agent": user_agent, "Accept": "*/*",
                        "Accept-Encoding": "identity"}
        if headers:
            self.headers.update(headers)
        self.proxy = proxy
        self.timeout = timeout
        self.rps = max(0.0, float(rps or 0))
        self.retries = max(0, int(retries))
        self.evidence_dir = evidence_dir
        self.budget = budget or Budget(0)
        self.allow_redirects = allow_redirects
        self._last = 0.0
        self.used = 0
        self._login_kwargs = None
        self._logging_in = False
        handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy})] \
            if proxy else [urllib.request.ProxyHandler({})]
        handlers.append(urllib.request.HTTPCookieProcessor(self.jar))
        self.opener = urllib.request.build_opener(*handlers)

    def _throttle(self):
        if self.rps <= 0:
            return
        wait = (1.0 / self.rps) - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()

    def _save_evidence(self, tag, method, url, req_headers, body, status, resp_headers, text, elapsed):
        if not self.evidence_dir:
            return None
        os.makedirs(self.evidence_dir, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", tag or "req")[:80]
        path = os.path.join(self.evidence_dir, "%s.txt" % safe)
        with open(path, "w", encoding="utf-8") as f:
            f.write("%s %s\n" % (method, url))
            f.write("ELAPSED: %.3fs  STATUS: %s\n\n" % (elapsed, status))
            f.write("--- request headers ---\n")
            for k, v in (req_headers or {}).items():
                f.write("%s: %s\n" % (k, redact(str(v))))
            if body:
                f.write("\n--- request body ---\n%s\n" % redact(body))
            f.write("\n--- response headers ---\n")
            for k, v in (resp_headers or {}).items():
                f.write("%s: %s\n" % (k, redact(str(v))))
            f.write("\n--- response body ---\n%s\n" % redact(text))
        return path

    def request(self, method, url, data=None, json_body=None, headers=None,
                allow_redirects=None, tag=None):
        """请求一次；若被重定向到 /login 且配置了登录，自动重登后重试一次。"""
        r = self._request_once(method, url, data=data, json_body=json_body,
                               headers=headers, allow_redirects=allow_redirects, tag=tag)
        if (self._login_kwargs and not self._logging_in
                and "/login" in (r.get("url") or "")
                and "/login" not in (url or "")):
            try:
                self.login(**self._login_kwargs)
                r = self._request_once(method, url, data=data, json_body=json_body,
                                       headers=headers, allow_redirects=allow_redirects, tag=tag)
            except (RateLimited, BudgetExceeded):
                raise
            except Exception:
                pass
        return r

    def _request_once(self, method, url, data=None, json_body=None, headers=None,
                      allow_redirects=None, tag=None):
        if url.startswith("/") and self.base_url:
            url = self.base_url + url
        elif not url.startswith(("http://", "https://")) and self.base_url:
            url = self.base_url + "/" + url.lstrip("/")

        req_headers = dict(self.headers)
        if headers:
            req_headers.update(headers)
        if self.cookie and "Cookie" not in req_headers:
            req_headers["Cookie"] = self.cookie

        body_bytes = None
        if json_body is not None:
            body_bytes = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        elif data is not None:
            if isinstance(data, bytes):
                body_bytes = data
            elif isinstance(data, dict) or isinstance(data, list):
                body_bytes = urllib.parse.urlencode(data, doseq=True).encode("utf-8")
            else:
                body_bytes = str(data).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

        last_err = None
        for attempt in range(self.retries + 1):
            self._throttle()
            self.budget.spend()
            self.used += 1
            req = urllib.request.Request(url, data=body_bytes, headers=req_headers,
                                         method=method.upper())
            started = time.time()
            try:
                with self.opener.open(req, timeout=self.timeout) as r:
                    raw = r.read()
                    hdrs = _header_dict(r.headers)
                    text = _decode(raw, hdrs)
                    elapsed = time.time() - started
                    bug = self._save_evidence(tag, method.upper(), r.geturl(), req_headers,
                                              body_bytes.decode("utf-8", "replace") if body_bytes else None,
                                              r.status, hdrs, text, elapsed)
                    return {
                        "status": r.status, "headers": hdrs, "text": text,
                        "url": r.geturl(), "request_url": url,
                        "elapsed": elapsed, "elapsed_ms": int(elapsed * 1000),
                        "digest": digest(text), "normalized": normalize(text),
                        "evidence": bug, "method": method.upper(),
                    }
            except urllib.error.HTTPError as e:
                raw = e.read()
                hdrs = _header_dict(e.headers)
                text = _decode(raw, hdrs)
                elapsed = time.time() - started
                bug = self._save_evidence(tag, method.upper(), url, req_headers,
                                          body_bytes.decode("utf-8", "replace") if body_bytes else None,
                                          e.code, hdrs, text, elapsed)
                low = text.lower()
                if e.code == 429 or any(h in low for h in RATE_LIMIT_HINTS):
                    raise RateLimited("rate limited (HTTP %s): %s" % (e.code, url))
                return {
                    "status": e.code, "headers": hdrs, "text": text,
                    "url": url, "request_url": url,
                    "elapsed": elapsed, "elapsed_ms": int(elapsed * 1000),
                    "digest": digest(text), "normalized": normalize(text),
                    "evidence": bug, "method": method.upper(),
                }
            except Exception as e:  # URLError/timeout/TLS
                last_err = e
                if attempt < self.retries:
                    time.sleep(1.2 * (attempt + 1))
                    continue
                raise
        raise last_err

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, data=None, **kw):
        return self.request("POST", url, data=data, **kw)

    def login(self, url, data, csrf_url=None, csrf_regex=r'name=["\']_csrf["\']\s+value=["\']([^"\']+)["\']',
              csrf_field="_csrf", method="POST", tag="login", totp_secret=None,
              totp_field="code", mfa_url="/mfa"):
        """通用登录：CSRF → 密码 →（可选）TOTP MFA。成功后 jar 自动更新，并记住登录参数用于自动重登。"""
        self._login_kwargs = {"url": url, "data": data, "csrf_url": csrf_url,
                              "csrf_field": csrf_field, "method": method, "tag": tag,
                              "totp_secret": totp_secret, "totp_field": totp_field,
                              "mfa_url": mfa_url}
        self._logging_in = True
        try:
            csrf = None
            if csrf_url:
                r = self.get(csrf_url, tag=tag + "-csrf")
                m = re.search(csrf_regex, r["text"])
                if m:
                    csrf = m.group(1)
            payload = dict(data)
            if csrf:
                payload[csrf_field] = csrf
            referer = csrf_url or url
            if referer.startswith("/"):
                referer = self.base_url + referer
            r = self.request(method, url, data=payload, headers={"Referer": referer}, tag=tag)
            # MFA
            if totp_secret and "/mfa" in (r.get("url") or ""):
                mr = self.get(mfa_url, tag=tag + "-mfa")
                m2 = re.search(csrf_regex, mr["text"])
                code = generate_totp(totp_secret)
                mfa_payload = {totp_field: code}
                if m2:
                    mfa_payload[csrf_field] = m2.group(1)
                r = self.request(method, mfa_url, data=mfa_payload,
                                 headers={"Referer": self.base_url + mfa_url}, tag=tag + "-mfa-post")
            return r, csrf
        finally:
            self._logging_in = False
