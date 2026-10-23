#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""recon.py v3 —— 自动侦察：被动爬取 + CT 子域 + 密钥扫描 + 指纹 + 目录发现 + 参数探测。

机制来源（均为公开工程理念，stdlib 独立实现）：
  - s0md3v/Arjun            : 参数名候选 + 响应差分判活
  - GerbenJavado/LinkFinder : JS 端点字符串提取
  - six2dez/reconftw        : CT 日志（crt.sh）子域枚举 → 解析 → HTTP 活性探测流水线
  - 公知密钥正则（gitleaks/trufflehog/secretfinder 同源标准模式）

Usage:
  python recon.py --base-url https://host[:port]/path [--max-pages 25]
                  [--subdomains] [--dirs] [--probe] [--no-crawl]
                  [--cookie "..."] [--user-agent "..."] [--scope-note "..."]
                  [--wordlist 文件] [--delay 0.4] [--timeout 15] [--json]
                  [--out candidates.json]

阶段： P1 爬取（默认）· P2 CT 子域（--subdomains）· P3 密钥扫描（默认开）
       P4 技术栈指纹（默认开）· P5 目录发现（--dirs）· P6 参数探测（--probe）

私网/回环目标直通；公网目标需要一行 --scope-note（仅记录）。
Exit codes: 0 成功, 1 错误, 3 refused。
"""
import argparse
import csv
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

if hasattr(sys.stdout, "reconfigure"):  # 固定 UTF-8，避免 GBK 控制台/管道乱码
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

# LinkFinder 式：JS 里引号包裹的路径型字符串
JS_ENDPOINT_RE = re.compile(
    r"""["'`]((?:/[A-Za-z0-9_\-][A-Za-z0-9_\-./]{1,90})|(?:(?:api|v\d)[/A-Za-z0-9_\-./]{2,90}))["'`]"""
)
STATIC_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
              ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webp")

# 公知密钥模式（gitleaks/trufflehog/secretfinder 标准集，值一律掩码展示）
SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("GitHub Token", re.compile(r"gh[pousr]_[0-9a-zA-Z]{36}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}")),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+")),
    ("Stripe Live Key", re.compile(r"[sr]k_live_[0-9a-zA-Z]{24}")),
    ("Twilio Key", re.compile(r"SK[0-9a-fA-F]{32}")),
    ("SendGrid Key", re.compile(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}")),
    ("Mailgun Key", re.compile(r"key-[0-9a-zA-Z]{32}")),
    ("npm Token", re.compile(r"npm_[0-9a-zA-Z]{36}")),
    ("PyPI Token", re.compile(r"pypi-[0-9A-Za-z\-_]{16,}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]{10,}")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY")),
    ("Generic Key/Secret",
     re.compile(r"""(?i)(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']([0-9a-zA-Z\-_./+=]{16,})["']""")),
]

# 技术栈指纹（Server 头 / X-Powered-By / Cookie / 页面特征）
TECH_SIGNATURES = [
    ("nginx", [("server", "nginx")]),
    ("Apache", [("server", "apache")]),
    ("IIS", [("server", "microsoft-iis")]),
    ("Tomcat", [("server", "tomcat")]),
    ("PHP", [("x-powered-by", "php"), ("set-cookie", "phpsessid")]),
    ("Express", [("x-powered-by", "express")]),
    ("ASP.NET", [("x-powered-by", "asp.net"), ("set-cookie", "aspsessionid")]),
    ("Laravel", [("set-cookie", "laravel_session"), ("set-cookie", "xsrf-token")]),
    ("Django", [("set-cookie", "csrftoken"), ("set-cookie", "sessionid")]),
    ("Rails", [("set-cookie", "_session_id"), ("server", "phusion")]),
    ("WordPress", [("body", "wp-content"), ("body", "wp-login.php")]),
    ("Next.js", [("body", "__next_data__")]),
    ("Vue", [("body", "data-v-")]),
    ("Angular", [("body", "ng-version")]),
    ("Cloudflare", [("server", "cloudflare")]),
    ("jQuery", [("body", "jquery")]),
]

# 目录发现清单（轻量、高频暴露点）
DIR_PATHS = [
    "/admin", "/administrator", "/login", "/api", "/api/v1", "/graphql",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/openapi.json", "/docs",
    "/backup", "/backup.zip", "/.git/", "/.git/config", "/.env", "/config",
    "/config.json", "/server-status", "/status", "/health", "/healthz",
    "/debug", "/phpinfo.php", "/phpinfo", "/wp-login.php", "/xmlrpc.php",
    "/actuator", "/actuator/env", "/actuator/health", "/console", "/adminer.php",
    "/.DS_Store", "/crossdomain.xml", "/trace", "/rest", "/v1", "/v2",
    "/internal", "/private", "/test", "/staging", "/dev", "/.well-known/security.txt",
]

PROBE_WORDS = [
    "id", "user", "username", "user_id", "userid", "uid", "name", "q", "query",
    "keyword", "kw", "search", "term", "page", "p", "per_page", "limit", "offset",
    "sort", "order", "orderby", "type", "category", "cat", "item", "product",
    "product_id", "pid", "order_id", "oid", "coupon", "code", "token", "email",
    "phone", "mobile", "address", "date", "from", "to", "start", "end", "status",
    "level", "role", "group", "dept", "report", "export", "file", "path", "url",
    "redirect", "next", "callback", "view", "no", "num", "count", "qty", "price",
    "amount", "min", "max", "filter", "lang", "theme", "version", "format",
    "debug", "test", "admin", "key", "api_key", "session", "sid", "cid", "rid",
    "gid", "aid", "tid", "month", "year", "day", "week", "zone", "area", "city",
    "province", "country", "tag", "label", "title", "desc", "detail", "info",
    "mode", "action", "op", "cmd", "func", "method", "target", "host", "ip",
]


def host_is_private(host):
    if not host:
        return False
    if host in ("localhost", "::1"):
        return True
    import ipaddress
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return host.endswith(".local") or host.endswith(".localhost")


def fail(message, code=3):
    print("REFUSED: " + message)
    sys.exit(code)


def registrable_domain(host):
    """粗取可注册域（启发式；gov.cn/edu.cn 这类不开放三级注册的后缀特判）。
    深网后缀边界以 Public Suffix List 为准，此处只覆盖常见情形。"""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two = ".".join(parts[-2:])
    if two in ("gov.cn", "edu.cn", "ac.cn", "mil.cn"):
        return two  # 这类后缀本身即区域顶点
    if parts[-2] in ("com", "net", "org", "gov", "edu", "co", "ac") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return two


def mask_secret(value):
    value = str(value)
    if len(value) <= 10:
        return value[:3] + "***"
    return value[:6] + "***" + value[-2:]


class PageParser(HTMLParser):
    """收集 <a href>、<form>、<script src>、内联 <script> 文本、<title>。"""

    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []
        self.scripts = []
        self.inline_js = []
        self.title = ""
        self._form = None
        self._in_script = False
        self._in_title = False
        self._script_buf = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a":
            href = a.get("href")
            if href:
                self.links.append(href)
        elif tag == "script":
            src = a.get("src")
            if src:
                self.scripts.append(src)
            else:
                self._in_script = True
                self._script_buf = []
        elif tag == "form":
            self._form = {"action": a.get("action") or "", "method": (a.get("method") or "get").upper(),
                          "fields": []}
        elif tag in ("input", "select", "textarea") and self._form is not None:
            name = a.get("name")
            if name:
                self._form["fields"].append({"name": name, "type": a.get("type", tag)})
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag == "script" and self._in_script:
            self._in_script = False
            self.inline_js.append("".join(self._script_buf))
        elif tag == "title" and self._in_title:
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data.strip()
        if self._in_script:
            self._script_buf.append(data)


def fetch(op, url, timeout):
    with op.open(url, timeout=timeout) as r:
        return r.getcode(), r.geturl(), r.read(2_000_000).decode("utf-8", "replace"), dict(r.headers)


def same_host(url, base_netloc):
    try:
        return urllib.parse.urlparse(url).netloc == base_netloc
    except Exception:
        return False


def normalize(url, base):
    url = urllib.parse.urljoin(base, url.split("#")[0].strip())
    return url if url.startswith(("http://", "https://")) else None


def is_page_like(url):
    path = urllib.parse.urlparse(url).path.lower()
    return not any(path.endswith(ext) for ext in STATIC_EXT)


def extract_title(html_text):
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", html_text)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:80] if m else ""


def fingerprint(headers, body_text):
    """返回命中的技术栈名列表。"""
    hdrs = {k.lower(): str(v).lower() for k, v in headers.items()}
    body = body_text[:200000].lower()
    hits = []
    for tech, rules in TECH_SIGNATURES:
        for place, needle in rules:
            if place == "body":
                if needle in body:
                    hits.append(tech)
                    break
            elif needle in hdrs.get(place, ""):
                hits.append(tech)
                break
    return hits


def scan_secrets(text, source, findings):
    """密钥扫描：命中即记录（值掩码）。"""
    for name, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            value = m.group(1) if m.groups() else m.group(0)
            if name == "Generic Key/Secret" and not re.search(r"[0-9]", value):
                continue  # 纯字母串多半是普通配置词
            findings.append({"type": name, "source": source, "value_masked": mask_secret(value),
                             "offset": m.start()})


def extract_js_endpoints(text, base, base_netloc):
    found = []
    for m in JS_ENDPOINT_RE.finditer(text):
        ep = m.group(1)
        if any(ep.lower().endswith(ext) for ext in STATIC_EXT):
            continue
        if len(ep) < 4 or ("/api" not in ep and len(ep.split("/")) < 2):
            continue
        full = normalize(ep, base)
        if full and same_host(full, base_netloc):
            found.append(full)
    return found


# ---------------- P2 CT 子域 ----------------

def ct_subdomains(domain, args):
    """crt.sh 证书透明日志枚举子域（被动情报，无密钥）。"""
    url = "https://crt.sh/?q=%s&output=json" % urllib.parse.quote("%." + domain)
    req = urllib.request.Request(url, headers={"User-Agent": args.user_agent})
    try:
        with urllib.request.urlopen(req, timeout=args.timeout + 30) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as exc:
        print("  [ct] crt.sh 查询失败：%s" % str(exc)[:80])
        return []
    names = set()
    for entry in data if isinstance(data, list) else []:
        for field in ("name_value", "common_name"):
            v = entry.get(field) or ""
            for n in v.split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n.endswith("." + domain) and n != domain:
                    names.add(n)
    return sorted(names)


def probe_host(host, args):
    """活性探测：DNS 解析 + HTTP(S) 状态 + 标题。"""
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return None
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(scheme + "://" + host + "/",
                                         headers={"User-Agent": args.user_agent})
            with urllib.request.urlopen(req, timeout=args.timeout) as r:
                body = r.read(300_000).decode("utf-8", "replace")
                return {"host": host, "ip": ip, "status": r.status,
                        "title": extract_title(body), "scheme": scheme}
        except urllib.error.HTTPError as exc:
            return {"host": host, "ip": ip, "status": exc.code, "title": "", "scheme": scheme}
        except Exception:
            continue
    return {"host": host, "ip": ip, "status": None, "title": "", "scheme": None}


# ---------------- P1 爬取 ----------------

def crawl(op, base_url, args, base_netloc):
    seen_pages, queue = set(), [base_url]
    endpoints = {}
    findings = []
    fingerprints = {}
    stats = {"pages": 0, "forms": 0, "js_files": 0, "js_endpoints": 0, "errors": 0,
             "secrets": 0, "inline_js": 0}

    def add_endpoint(url, method, params, form_fields, source, status=None, needs_session=False):
        key = (method, url)
        if key not in endpoints:
            endpoints[key] = {"url": url, "method": method, "params": sorted(set(params)),
                              "form_fields": form_fields, "sources": set(), "status": status,
                              "needs_session": needs_session}
        ep = endpoints[key]
        ep["sources"].add(source)
        if params:
            ep["params"] = sorted(set(ep["params"]) | set(params))
        if form_fields:
            ep["form_fields"] = form_fields
        if status:
            ep["status"] = status
        ep["needs_session"] = ep["needs_session"] or needs_session

    # robots / sitemap
    for extra, source in (("/robots.txt", "robots"), ("/sitemap.xml", "sitemap")):
        try:
            code, final, text, _h = fetch(op, urllib.parse.urljoin(base_url, extra), args.timeout)
            for line in text.splitlines():
                line = line.strip()
                if source == "robots" and line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                    path = line.split(":", 1)[1].strip()
                    full = normalize(path, base_url)
                    if full and same_host(full, base_netloc):
                        add_endpoint(full.split("?")[0], "GET", [], [], source, code)
                if source == "sitemap" and "<loc>" in line:
                    full = normalize(re.sub(r"</?loc>", "", line).strip(), base_url)
                    if full and same_host(full, base_netloc):
                        add_endpoint(full, "GET", [], [], source, code)
            time.sleep(args.delay)
        except Exception:
            pass

    while queue and stats["pages"] < args.max_pages:
        url = queue.pop(0)
        norm = normalize(url, base_url)
        if not norm or norm in seen_pages or not same_host(norm, base_netloc) or not is_page_like(norm):
            continue
        seen_pages.add(norm)
        try:
            code, final_url, text, headers = fetch(op, norm, args.timeout)
        except Exception as exc:
            add_endpoint(norm, "GET", [], [], "page", None, False)
            endpoints[("GET", norm)]["sources"].add("error:" + str(exc)[:60])
            stats["errors"] += 1
            continue
        stats["pages"] += 1
        needs_session = "/login" in final_url

        # P3 密钥扫描（页面 + 内联 JS）
        scan_secrets(text, norm, findings)

        add_endpoint(norm, "GET", list(urllib.parse.parse_qs(urllib.parse.urlparse(norm).query).keys()),
                     [], "page", code, needs_session)

        # P4 指纹
        fp = fingerprint(headers, text)
        if fp:
            fingerprints[norm] = fp

        parser = PageParser()
        try:
            parser.feed(text)
        except Exception:
            pass
        for js in parser.inline_js:
            stats["inline_js"] += 1
            scan_secrets(js, norm + " (inline)", findings)
        for form in parser.forms:
            stats["forms"] += 1
            action = normalize(form["action"] or norm, norm) or norm
            add_endpoint(action, form["method"] if form["method"] != "GET" else "GET",
                         [], [f["name"] for f in form["fields"]], "form", code, needs_session)
        for href in parser.links:
            full = normalize(href, norm)
            if full and same_host(full, base_netloc) and is_page_like(full) and full not in seen_pages:
                if len(queue) < args.max_pages * 3:
                    queue.append(full)
        for src in parser.scripts:
            js_url = normalize(src, norm)
            if not js_url or not same_host(js_url, base_netloc):
                continue
            try:
                _c, _f, js_text, _h = fetch(op, js_url, args.timeout)
                stats["js_files"] += 1
                scan_secrets(js_text, js_url, findings)
                for ep in extract_js_endpoints(js_text, js_url, base_netloc):
                    stats["js_endpoints"] += 1
                    q = urllib.parse.parse_qs(urllib.parse.urlparse(ep).query)
                    add_endpoint(ep.split("?")[0], "GET", list(q.keys()), [], "js", None, needs_session)
            except Exception:
                stats["errors"] += 1
            time.sleep(args.delay)
        time.sleep(args.delay)

    stats["secrets"] = len(findings)
    return endpoints, findings, fingerprints, stats, len(seen_pages)


# ---------------- P5 目录发现 ----------------

def dir_discovery(op, base_url, args):
    results = []
    for path in DIR_PATHS:
        url = urllib.parse.urljoin(base_url, path)
        try:
            code, final, text, _h = fetch(op, url, args.timeout)
            title = extract_title(text)
        except urllib.error.HTTPError as exc:
            code, title = exc.code, ""
        except Exception:
            continue
        interesting = (
            (code and code < 400 and code != 404)
            or (code in (401, 403) and path in ("/.git/config", "/.env", "/backup", "/actuator/env"))
        )
        if code and code != 404:
            results.append({"path": path, "status": code, "title": title, "interesting": interesting})
        time.sleep(args.delay)
    return results


# ---------------- P6 参数探测 ----------------

def probe_params(op, ep, args):
    try:
        code0, _f, text0, _h = fetch(op, ep["url"], args.timeout)
    except Exception:
        return []
    base_len = len(text0)
    hits = []
    words = list(PROBE_WORDS)
    if args.wordlist and os.path.isfile(args.wordlist):
        words = [w.strip() for w in open(args.wordlist, encoding="utf-8", errors="replace")
                 if w.strip()][:3000]
    for w in words:
        probe = ep["url"] + ("&" if "?" in ep["url"] else "?") + w + "=1"
        try:
            code, _f, text, _h = fetch(op, probe, args.timeout)
        except Exception:
            continue
        reflected = "1" in text and text != text0 and re.search(r"[\"'>]%s[\"'<]" % re.escape("1"), text[:5000])
        if (code != code0 and code >= 400) or abs(len(text) - base_len) > 40 or reflected:
            hits.append({"param": w, "status": code, "len": len(text),
                         "delta": len(text) - base_len, "reflected": bool(reflected)})
        time.sleep(args.delay)
    return hits


# ---------------- 汇总输出 ----------------

def score_endpoint(ep):
    s = 0
    if ep["params"]:
        s += 3 + len(ep["params"])
    if ep["form_fields"]:
        s += 2
    if "/api" in ep["url"] or re.search(r"/v\d/", ep["url"]):
        s += 2
    if ep["status"] and 200 <= ep["status"] < 300:
        s += 1
    if ep["needs_session"]:
        s -= 1
    return s


def suggest_target(ep):
    if ep["method"] == "GET" and ep["params"]:
        parts = urllib.parse.urlparse(ep["url"])
        q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        if q:
            first = q[0][0]
            newq = "&".join((k + ("=1*" if k == first else "=" + v)) for k, v in q)
            return urllib.parse.urlunparse(parts._replace(query=newq))
        names = [n for n in ep["params"] if n]
        if names:
            newq = "&".join((n + ("=1*" if i == 0 else "=1")) for i, n in enumerate(names))
            return urllib.parse.urlunparse(parts._replace(query=newq))
        return ep["url"] + "?1*"
    if ep["method"] == "POST" and ep["form_fields"]:
        body = "&".join(f + ("=1*" if i == 0 else "=") for i, f in enumerate(ep["form_fields"]))
        return "%s  POST data: %s" % (ep["url"], body)
    if ep["params"] or ep["form_fields"]:
        return ep["url"] + "  （参数见上，人工标 *）"
    return None


def main():
    parser = argparse.ArgumentParser(description="Recon: crawl + CT subdomains + secrets + fingerprint + dirs + probe")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--max-pages", type=int, default=25)
    parser.add_argument("--cookie", default=None)
    parser.add_argument("--user-agent", default=DEFAULT_UA)
    parser.add_argument("--scope-note", default="")
    parser.add_argument("--subdomains", action="store_true", help="CT 日志子域枚举 + 活性探测")
    parser.add_argument("--dirs", action="store_true", help="目录发现（~45 个高频暴露路径）")
    parser.add_argument("--probe", action="store_true", help="Arjun 式参数名探测")
    parser.add_argument("--no-crawl", action="store_true", help="跳过页面爬取")
    parser.add_argument("--wordlist", default=None)
    parser.add_argument("--delay", type=float, default=0.4)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--out", default="candidates.json")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    base = args.base_url.strip()
    if not base.startswith(("http://", "https://")):
        fail("--base-url 必须是 http(s) 完整地址")
    parts = urllib.parse.urlparse(base)
    host = parts.hostname
    scope = args.scope_note.strip()
    if not host_is_private(host) and len(scope) < 8:
        fail("公网目标需要一行 --scope-note（如 \"自有靶场，tunnel 暴露，仅测试期\"）。仅记录，不阻断。")

    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
    op.addheaders = [("User-Agent", args.user_agent)]
    if args.cookie:
        op.addheaders.append(("Cookie", args.cookie))

    endpoints, findings, fingerprints = {}, [], {}
    stats = {"pages": 0, "forms": 0, "js_files": 0, "js_endpoints": 0, "errors": 0,
             "secrets": 0, "inline_js": 0}
    pages = 0
    if not args.no_crawl:
        try:
            endpoints, findings, fingerprints, stats, pages = crawl(op, base, args, parts.netloc)
        except Exception as exc:
            print("ERROR: 爬取失败：%s" % exc)
            return 1

    # P2 CT 子域
    subs, live_subs = [], []
    if args.subdomains:
        domain = registrable_domain(host)
        print("[子域] CT 日志查询 %s ..." % domain)
        subs = ct_subdomains(domain, args)
        for s in subs[:80]:
            live_subs.append(probe_host(s, args))
            time.sleep(args.delay)

    # P5 目录
    dirs = dir_discovery(op, base, args) if args.dirs else []

    # P6 参数探测
    probes = {}
    if args.probe:
        candidates = [e for e in endpoints.values() if e["method"] == "GET" and not e["params"]
                      and e["status"] and 200 <= e["status"] < 300 and is_page_like(e["url"])]
        for ep in candidates[:8]:
            hits = probe_params(op, ep, args)
            if hits:
                probes[ep["url"]] = hits
                ep["params"] = [h["param"] for h in hits]
                ep["sources"].append("probe")

    # 按 (method, path) 去重合并
    merged = {}
    for (method, url), ep in endpoints.items():
        p = urllib.parse.urlparse(url)
        key = (method, p.scheme, p.netloc, p.path)
        if key not in merged:
            merged[key] = ep
        else:
            keep = merged[key]
            keep["params"] = sorted(set(keep["params"]) | set(ep["params"]))
            keep["form_fields"] = sorted(set(keep["form_fields"]) | set(ep["form_fields"]))
            keep["sources"] = sorted(set(keep["sources"]) | set(ep["sources"]))
            keep["needs_session"] = keep["needs_session"] or ep["needs_session"]
            if ep.get("status") and 200 <= ep["status"] < 300:
                keep["status"] = ep["status"]
    out_eps = list(merged.values())
    for ep in out_eps:
        ep["sources"] = sorted(ep["sources"])
        ep["score"] = score_endpoint(ep)
        ep["suggest"] = suggest_target(ep)
    out_eps.sort(key=lambda e: (-e["score"], e["url"]))

    result = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "base_url": base,
        "scope_note": scope or None,
        "stats": dict(stats, pages_visited=pages, subdomains=len(subs),
                      live_subdomains=sum(1 for s in live_subs if s and s.get("status"))),
        "fingerprints": fingerprints,
        "secrets": findings,
        "subdomains": live_subs,
        "dirs": dirs,
        "endpoints": out_eps,
        "probe_results": probes,
    }
    out_path = os.path.abspath(args.out)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    ranked = [e for e in out_eps if e["score"] > 0]
    print("=== 侦察完成：%s ===" % base)
    print("页面 %d · 表单 %d · JS %d（内联 %d）· JS 端点 %d · 候选端点 %d（评分>0：%d）"
          % (pages, stats["forms"], stats["js_files"], stats["inline_js"],
             stats["js_endpoints"], len(out_eps), len(ranked)))
    print("OUT: %s" % out_path)

    if fingerprints:
        print("\n[技术栈指纹]")
        for url, techs in list(fingerprints.items())[:6]:
            print("  %-58s %s" % (url[:58], ", ".join(techs)))

    if findings:
        print("\n[密钥命中 %d 处]" % len(findings))
        for s in findings[:15]:
            print("  %-18s %-38s %s" % (s["type"], s["source"][-38:], s["value_masked"]))
    else:
        print("\n[密钥] 未命中")

    if subs:
        print("\n[子域] CT 共 %d 个，活性 %d：" % (len(subs), sum(1 for s in live_subs if s and s.get("status"))))
        for s in live_subs:
            if not s:
                continue
            print("  %-50s %-15s %s %s" % (s["host"], s["ip"] or "?", s["status"] or "?", s["title"][:40]))

    if dirs:
        print("\n[目录]")
        for d in dirs:
            mark = " ★" if d["interesting"] else ""
            print("  %-24s %s %s%s" % (d["path"], d["status"], d["title"][:40], mark))

    for i, ep in enumerate(ranked[:12], 1):
        print("\n#%d score=%d [%s] %s" % (i, ep["score"], ep["method"], ep["url"]))
        if ep["params"]:
            print("   params: %s" % ", ".join(ep["params"]))
        if ep["form_fields"]:
            print("   form: %s" % ", ".join(ep["form_fields"]))
        print("   来源: %s%s" % (",".join(ep["sources"]),
                                 "  ⚠需登录" if ep["needs_session"] else ""))
        if ep["suggest"]:
            print("   建议: %s" % ep["suggest"])

    if probes:
        print("\n[参数探测命中]")
        for url, hits in probes.items():
            print("  %s" % url)
            for h in hits[:10]:
                print("    %-14s status=%s len=%+d%s" % (h["param"], h["status"], h["delta"],
                                                         " (反射)" if h["reflected"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
