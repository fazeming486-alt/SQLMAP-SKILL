#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""misconfig_probe.py —— 低风险但高价值的配置面检查。

检查：安全响应头、Cookie 属性、CORS、危险 HTTP 方法、常见敏感路径、
错误页堆栈泄露。默认只发 GET/OPTIONS，不改数据。

用法：
  python misconfig_probe.py --target https://host --cookie-jar cookies.txt \
      --rps 2 --out runs/demo/misconfig.json

也可以被 engage.py 作为模块调用：run(ctx)。
"""
import argparse
import json
import os
import random
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import httpkit
from findings import FindingStore

SECURITY_HEADERS = {
    "content-security-policy": "CSP",
    "strict-transport-security": "HSTS",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

SENSITIVE_PATHS = [
    ("/.git/config", "high", "Git 配置泄露", "[core]"),
    ("/.env", "high", "环境变量文件泄露", "="),
    ("/actuator/env", "high", "Spring Actuator 环境变量", "\"activeProfiles\"|propertySources"),
    ("/actuator/health", "low", "Actuator 健康端点", "\"status\""),
    ("/server-status", "low", "Apache server-status", "Apache Server Status"),
    ("/phpinfo.php", "medium", "phpinfo 暴露", "PHP Version"),
    ("/swagger-ui.html", "medium", "Swagger UI 暴露", "swagger"),
    ("/swagger-ui/", "medium", "Swagger UI 暴露", "swagger"),
    ("/openapi.json", "medium", "OpenAPI 文档暴露", "\"openapi\"|\"swagger\""),
    ("/debug", "low", "调试入口", "debug"),
    ("/backup.zip", "high", "备份文件可下载", "PK\\x03\\x04"),
    ("/.DS_Store", "low", "DS_Store 泄露", "Bud1"),
]

ERROR_MARKERS = [
    "Traceback (most recent call last)", "SQLSTATE", "You have an error in your SQL syntax",
    "org.springframework", "Werkzeug Debugger", "Django", "PHP Warning", "PHP Fatal error",
    "ORA-", "Microsoft OLE DB", "Stack trace", "at java.", "Notice: Undefined",
]


def _snippet(text, limit=500):
    return httpkit.redact((text or "")[:limit])


def check_headers(client, base_url, store, evidence_dir):
    r = client.get(base_url, tag="misconfig-headers")
    h = r["headers"]
    missing = [name for key, name in SECURITY_HEADERS.items() if key not in h]
    if "strict-transport-security" in missing and not base_url.startswith("https://"):
        missing.remove("strict-transport-security")
    if missing:
        store.add(
            module="misconfig", title="缺少关键安全响应头", severity="low",
            endpoint=base_url, method="GET",
            confidence="confirmed", cvss=3.0,
            evidence={"missing": missing, "status": r["status"],
                      "present": {k: h.get(k) for k in SECURITY_HEADERS if k in h},
                      "artifact": r.get("evidence")},
            impact="浏览器侧防护不足，增加 XSS/点击劫持/嗅探等攻击的可利用性。",
            remediation="补齐 CSP、HSTS、X-Content-Type-Options、X-Frame-Options、Referrer-Policy、Permissions-Policy。",
            references=["WSTG-CONF-07", "OWASP Secure Headers Project"],
            tags=["headers"],
        )
    # Cookie 属性
    sc = h.get("set-cookie")
    if sc:
        low = sc.lower()
        issues = []
        if "httponly" not in low:
            issues.append("HttpOnly 缺失")
        if "secure" not in low:
            issues.append("Secure 缺失")
        if "samesite" not in low:
            issues.append("SameSite 缺失")
        if issues:
            store.add(
                module="misconfig", title="会话 Cookie 属性不完整", severity="low",
                endpoint=base_url, method="GET", cvss=3.0,
                evidence={"set_cookie": httpkit.redact(sc), "issues": issues,
                          "artifact": r.get("evidence")},
                impact="Cookie 可能被脚本读取或在明文链路中发送。",
                remediation="设置 Secure、HttpOnly、SameSite=Lax/Strict。",
                references=["WSTG-SESS-02"],
                tags=["cookie"],
            )
    return r


def check_cors(client, base_url, store):
    origin = "https://evil.example"
    r = client.get(base_url, headers={"Origin": origin}, tag="misconfig-cors")
    h = r["headers"]
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower()
    if not acao:
        return
    reflected = acao.strip() in (origin, "*")
    if reflected and acac == "true":
        sev = "high"
    elif reflected:
        sev = "medium"
    else:
        return
    store.add(
        module="misconfig", title="CORS 配置允许任意来源", severity=sev,
        endpoint=base_url, method="GET", parameter="Origin",
        cvss=7.1 if sev == "high" else 5.0,
        evidence={"origin": origin, "access-control-allow-origin": acao,
                  "access-control-allow-credentials": acac,
                  "status": r["status"], "artifact": r.get("evidence")},
        impact="任意站点可跨域读取响应；若同时允许凭据，可代表已登录用户读取敏感数据。",
        remediation="使用来源白名单；不要同时设置 ACAO=* 与 ACAC=true。",
        references=["WSTG-CLNT-11", "OWASP CORS"],
        tags=["cors"],
    )


def check_methods(client, base_url, store):
    r = client.request("OPTIONS", base_url, tag="misconfig-options")
    allow = r["headers"].get("allow", "")
    if "TRACE" in allow.upper():
        store.add(
            module="misconfig", title="OPTIONS 宣告 TRACE 方法", severity="low",
            endpoint=base_url, method="OPTIONS", cvss=3.1,
            evidence={"allow": allow, "status": r["status"], "artifact": r.get("evidence")},
            impact="TRACE 可能用于跨站追踪（XST），也可能暴露代理行为。",
            remediation="在反向代理/应用层禁用 TRACE。",
            references=["WSTG-CONF-06"],
            tags=["methods"],
        )


def check_paths(client, base_url, store):
    for path, sev, title, marker in SENSITIVE_PATHS:
        try:
            r = client.get(path, tag="misconfig-path" + path.replace("/", "_"))
        except Exception:
            continue
        if r["status"] != 200:
            continue
        body = r["text"] or ""
        if marker and not re.search(marker, body, re.I):
            continue
        if "text/html" in r["headers"].get("content-type", "") and \
                ("<title>404" in body or "登录" in body[:2000]):
            continue
        store.add(
            module="misconfig", title=title, severity=sev,
            endpoint=base_url + path, method="GET",
            cvss={"high": 7.5, "medium": 5.3, "low": 3.1}.get(sev, 3.1),
            evidence={"status": r["status"], "content_type": r["headers"].get("content-type"),
                      "snippet": _snippet(body), "artifact": r.get("evidence")},
            impact="敏感配置/调试信息可能帮助攻击者进一步利用。",
            remediation="在生产环境移除或限制访问；加认证与网络 ACL。",
            references=["WSTG-CONF-04", "WSTG-CONF-05"],
            tags=["exposure"],
        )


def check_error_leak(client, base_url, store):
    rand = "wpx" + str(random.randint(10000, 99999))
    r = client.get("/" + rand, tag="misconfig-error")
    body = r["text"] or ""
    hits = [m for m in ERROR_MARKERS if m.lower() in body.lower()]
    if r["status"] >= 500 or hits:
        store.add(
            module="misconfig", title="错误页泄露技术细节", severity="medium",
            endpoint=base_url + "/" + rand, method="GET", cvss=5.3,
            evidence={"status": r["status"], "markers": hits, "snippet": _snippet(body, 800),
                      "artifact": r.get("evidence")},
            impact="堆栈/框架/数据库错误可帮助攻击者定位技术栈与注入点。",
            remediation="统一错误页，关闭 debug，记录到服务端日志而不是响应体。",
            references=["WSTG-ERRH-01", "WSTG-ERRH-02"],
            tags=["error-handling"],
        )


def run(ctx):
    """engage.py 模块入口。ctx: dict(base_url, clients, anon, store, options)."""
    base = ctx["base_url"]
    client = ctx.get("anon") or ctx["clients"].get("anon")
    store = ctx["store"]
    check_headers(client, base, store, ctx.get("evidence_dir"))
    check_cors(client, base, store)
    check_methods(client, base, store)
    check_paths(client, base, store)
    check_error_leak(client, base, store)
    return store.items


def main():
    p = argparse.ArgumentParser(description="Security misconfiguration probe")
    p.add_argument("--target", required=True)
    p.add_argument("--cookie-jar", default=None)
    p.add_argument("--cookie", default=None)
    p.add_argument("--rps", type=float, default=1.0)
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("--out", default="misconfig-findings.json")
    p.add_argument("--evidence-dir", default="misconfig-raw")
    args = p.parse_args()
    client = httpkit.HttpClient(base_url=args.target, cookie=args.cookie,
                                cookie_jar=args.cookie_jar, rps=args.rps,
                                timeout=args.timeout, evidence_dir=args.evidence_dir)
    store = FindingStore(args.out)
    ctx = {"base_url": args.target, "anon": client, "clients": {"anon": client},
           "store": store, "evidence_dir": args.evidence_dir}
    run(ctx)
    store.save()
    print(json.dumps(store.summary(), ensure_ascii=False))
    print("findings:", os.path.abspath(args.out))


if __name__ == "__main__":
    main()
