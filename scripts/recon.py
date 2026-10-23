#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""自动侦察注入点：被动爬取（链接/表单/robots/sitemap/JS 端点）+ 可选参数探测。

机制借鉴（均为理念借鉴，实现为 stdlib 独立重写）：
  - s0md3v/Arjun  : 参数名候选表 + 响应差分（状态码/长度/反射）判定参数活性
  - GerbenJavado/LinkFinder : JS 文件内端点字符串正则提取

Usage:
  python recon.py --base-url https://host[:port]/path [--depth 2] [--max-pages 25]
                  [--cookie "..."] [--user-agent "..."] [--scope-note "..."]
                  [--probe] [--wordlist 文件] [--delay 0.4] [--timeout 15] [--json]

私网/回环目标直通；公网目标需要一行 --scope-note（仅记录）。
输出：打印候选注入点排行 + 写 <out> JSON（默认 candidates.json，可直接挑一条喂 sqlmap job）。

Exit codes: 0 成功, 1 错误, 3 refused。
"""
import argparse
import json
import os
import re
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
QUERYLESS_SKIP = STATIC_EXT

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


class PageParser(HTMLParser):
    """收集 <a href>、<form>（action/method + 字段）、<script src>。"""

    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []          # {action, method, fields:[{name,type}]}
        self.scripts = []
        self._form = None

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
        elif tag == "form":
            self._form = {"action": a.get("action") or "", "method": (a.get("method") or "get").upper(),
                          "fields": []}
        elif tag in ("input", "select", "textarea") and self._form is not None:
            name = a.get("name")
            if name:
                self._form["fields"].append({"name": name, "type": a.get("type", tag)})

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def fetch(op, url, timeout):
    with op.open(url, timeout=timeout) as r:
        return r.getcode(), r.geturl(), r.read(2_000_000).decode("utf-8", "replace")


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
    return not any(path.endswith(ext) for ext in QUERYLESS_SKIP)


def extract_js_endpoints(text, base):
    found = []
    for m in JS_ENDPOINT_RE.finditer(text):
        ep = m.group(1)
        if any(ep.lower().endswith(ext) for ext in STATIC_EXT):
            continue
        if len(ep) < 4 or ep.startswith("/assets/") is False and "/api" not in ep and len(ep.split("/")) < 2:
            continue
        full = normalize(ep, base)
        if full and same_host(full, base):
            found.append(full)
    return found


def crawl(op, base_url, args, base_netloc):
    """BFS 被动爬取。返回 endpoints 列表 + 统计。"""
    seen_pages, queue = set(), [base_url]
    endpoints = {}
    stats = {"pages": 0, "forms": 0, "js_files": 0, "js_endpoints": 0, "errors": 0}

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

    # robots.txt / sitemap.xml
    for extra, source in (("/robots.txt", "robots"), ("/sitemap.xml", "sitemap")):
        try:
            code, final, text = fetch(op, urllib.parse.urljoin(base_url, extra), args.timeout)
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
            code, final_url, text = fetch(op, norm, args.timeout)
        except Exception as exc:
            add_endpoint(norm, "GET", [], [], "page", None, False)
            endpoints[(("GET"), norm)]["sources"].add("error:" + str(exc)[:60])
            stats["errors"] += 1
            continue
        stats["pages"] += 1
        needs_session = "/login" in final_url
        add_endpoint(norm, "GET", list(urllib.parse.parse_qs(urllib.parse.urlparse(norm).query).keys()),
                     [], "page", code, needs_session)

        parser = PageParser()
        try:
            parser.feed(text)
        except Exception:
            pass
        # 表单 → POST 候选
        for form in parser.forms:
            stats["forms"] += 1
            action = normalize(form["action"] or norm, norm) or norm
            add_endpoint(action, form["method"] if form["method"] != "GET" else "GET",
                         [], [f["name"] for f in form["fields"]], "form", code, needs_session)
        # 链接
        for href in parser.links:
            full = normalize(href, norm)
            if full and same_host(full, base_netloc) and is_page_like(full) and full not in seen_pages:
                if len(queue) < args.max_pages * 3:
                    queue.append(full)
        # JS 资产 → 端点提取
        for src in parser.scripts:
            js_url = normalize(src, norm)
            if not js_url or not same_host(js_url, base_netloc):
                continue
            try:
                _c, _f, js_text = fetch(op, js_url, args.timeout)
                stats["js_files"] += 1
                for ep in extract_js_endpoints(js_text, js_url):
                    stats["js_endpoints"] += 1
                    q = urllib.parse.parse_qs(urllib.parse.urlparse(ep).query)
                    add_endpoint(ep.split("?")[0], "GET", list(q.keys()), [], "js", None, needs_session)
            except Exception:
                stats["errors"] += 1
            time.sleep(args.delay)
        time.sleep(args.delay)

    # 按 (method, path) 去重合并：参数名取并集，URL 留一个代表
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
    return out_eps, stats, len(seen_pages)


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
    """给出可直接放进 job 的带 * 目标串。"""
    if ep["method"] == "GET" and ep["params"]:
        parts = urllib.parse.urlparse(ep["url"])
        q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        if q:
            first = q[0][0]
            newq = "&".join((k + ("=1*" if k == first else "=" + v)) for k, v in q)
            return urllib.parse.urlunparse(parts._replace(query=newq))
        # URL 无查询串但已知参数名（去重合并后的代表 URL）：按参数名构造
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


def probe_params(op, ep, args):
    """Arjun 式：对无参 GET 端点逐个试参数名，响应差分判活。返回疑似参数。"""
    try:
        code0, _f, text0 = fetch(op, ep["url"], args.timeout)
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
            code, _f, text = fetch(op, probe, args.timeout)
        except Exception:
            continue
        reflected = "1" in text and text != text0 and re.search(r"[\"'>]%s[\"'<]" % re.escape("1"), text[:5000])
        if (code != code0 and code >= 400) or abs(len(text) - base_len) > 40 or reflected:
            hits.append({"param": w, "status": code, "len": len(text),
                         "delta": len(text) - base_len, "reflected": bool(reflected)})
        time.sleep(args.delay)
    return hits


def main():
    parser = argparse.ArgumentParser(description="Injection-point recon (passive crawl + optional probe)")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--depth", type=int, default=2, help="（保留字段，BFS 由 max-pages 控制）")
    parser.add_argument("--max-pages", type=int, default=25)
    parser.add_argument("--cookie", default=None)
    parser.add_argument("--user-agent", default=DEFAULT_UA)
    parser.add_argument("--scope-note", default="")
    parser.add_argument("--probe", action="store_true", help="对无参 GET 端点做参数名探测（请求量=词表×端点，公网慎用）")
    parser.add_argument("--wordlist", default=None)
    parser.add_argument("--delay", type=float, default=0.4)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--out", default="candidates.json")
    parser.add_argument("--json", action="store_true", help="只输出 JSON（静默模式）")
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

    try:
        endpoints, stats, pages = crawl(op, base, args, parts.netloc)
    except Exception as exc:
        print("ERROR: 爬取失败：%s" % exc)
        return 1

    # 参数探测（可选）
    probes = {}
    if args.probe:
        candidates = [e for e in endpoints if e["method"] == "GET" and not e["params"]
                      and e["status"] and 200 <= e["status"] < 300 and is_page_like(e["url"])]
        for ep in candidates[:8]:
            hits = probe_params(op, ep, args)
            if hits:
                probes[ep["url"]] = hits
                ep["params"] = [h["param"] for h in hits]
                ep["sources"].append("probe")

    for ep in endpoints:
        ep["score"] = score_endpoint(ep)
        ep["suggest"] = suggest_target(ep)
    endpoints.sort(key=lambda e: (-e["score"], e["url"]))

    result = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "base_url": base,
        "scope_note": scope or None,
        "stats": dict(stats, pages_visited=pages),
        "endpoints": endpoints,
        "probe_results": probes,
    }
    out_path = os.path.abspath(args.out)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    ranked = [e for e in endpoints if e["score"] > 0]
    print("=== 侦察完成：%s ===" % base)
    print("页面 %d · 表单 %d · JS 文件 %d · JS 端点 %d · 候选端点 %d（评分>0：%d）"
          % (pages, stats["forms"], stats["js_files"], stats["js_endpoints"],
             len(endpoints), len(ranked)))
    print("OUT: %s" % out_path)
    for i, ep in enumerate(ranked[:15], 1):
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
