#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""upload_probe.py —— 上传面盘点（默认只检测入口，不传文件）。

默认：抓取页面，找 multipart 表单与 file input，记为 info 发现（上传面）。
--test：提交一个无害的 .txt 测试文件，记录响应；不验证执行、不写 webshell。
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


def find_forms(text):
    forms = []
    for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", text or "", re.I | re.S):
        attrs, inner = m.group(1), m.group(2)
        action = re.search(r'action=["\']([^"\']*)', attrs, re.I)
        method = re.search(r'method=["\']([^"\']*)', attrs, re.I)
        enctype = re.search(r'enctype=["\']([^"\']*)', attrs, re.I)
        file_inputs = re.findall(r'<input[^>]*type=["\']file["\'][^>]*>', inner, re.I)
        if not file_inputs:
            continue
        names = []
        for fi in file_inputs:
            nm = re.search(r'name=["\']([^"\']+)', fi, re.I)
            if nm:
                names.append(nm.group(1))
        forms.append({"action": action.group(1) if action else "",
                      "method": (method.group(1) if method else "post").upper(),
                      "enctype": enctype.group(1) if enctype else "",
                      "file_fields": names,
                      "snippet": m.group(0)[:500]})
    return forms


def multipart(fields, file_field, filename, content, boundary):
    lines = []
    for k, v in fields.items():
        lines.append("--" + boundary)
        lines.append('Content-Disposition: form-data; name="%s"' % k)
        lines.append("")
        lines.append(str(v))
    lines.append("--" + boundary)
    lines.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (file_field, filename))
    lines.append("Content-Type: text/plain")
    lines.append("")
    lines.append(content)
    lines.append("--" + boundary + "--")
    return "\r\n".join(lines).encode("utf-8")


def run(ctx):
    store = ctx["store"]
    pages = ctx.get("options", {}).get("upload_pages") or []
    test = bool(ctx.get("options", {}).get("upload_test"))
    client = ctx.get("anon") or ctx["clients"].get("anon")
    for page in pages:
        r = client.get(page, tag="upload-page")
        for form in find_forms(r["text"]):
            action = form["action"] or page
            store.add(
                module="upload", title="发现文件上传入口", severity="info",
                endpoint=action, method=form["method"], parameter=",".join(form["file_fields"]),
                confidence="surface", evidence={"page": r["url"], "form": form,
                                                "artifact": r.get("evidence")},
                impact="上传面需要进一步验证扩展名/内容类型/存储路径/执行权限；本工具默认不传文件。",
                remediation="白名单扩展名 + MIME 校验 + 随机文件名 + 存储到非 Web 根 + 禁止执行。",
                references=["WSTG-BUSL-09", "OWASP File Upload Cheat Sheet"],
                tags=["upload", "surface"],
            )
            if test:
                boundary = "----wpx" + str(random.randint(100000, 999999))
                body = multipart({}, form["file_fields"][0] if form["file_fields"] else "file",
                                 "wpx-test.txt", "wpx upload test " + boundary, boundary)
                tr = client.request("POST", action, data=body,
                                    headers={"Content-Type": "multipart/form-data; boundary=" + boundary},
                                    tag="upload-test")
                store.add(
                    module="upload", title="上传测试文件已提交（未验证执行）", severity="info",
                    endpoint=action, method="POST", parameter="file", confidence="needs-review",
                    evidence={"status": tr["status"], "url": tr["url"],
                              "snippet": httpkit.redact((tr["text"] or "")[:500]),
                              "artifact": tr.get("evidence")},
                    impact="仅确认服务器接受 multipart 提交；是否可执行/可访问需人工验证。",
                    remediation="同上；不要把用户上传目录暴露为可执行路径。",
                    references=["WSTG-BUSL-09"],
                    tags=["upload"],
                )
    return store.items


def main():
    p = argparse.ArgumentParser(description="Upload surface probe (safe default)")
    p.add_argument("--page", action="append", default=[], help="页面 URL，可重复")
    p.add_argument("--cookie-jar", default=None)
    p.add_argument("--cookie", default=None)
    p.add_argument("--test", action="store_true", help="提交无害 .txt 测试文件")
    p.add_argument("--rps", type=float, default=1.0)
    p.add_argument("--out", default="upload-findings.json")
    p.add_argument("--evidence-dir", default="upload-raw")
    args = p.parse_args()
    client = httpkit.HttpClient(base_url="", cookie=args.cookie, cookie_jar=args.cookie_jar,
                                rps=args.rps, evidence_dir=args.evidence_dir)
    store = FindingStore(args.out)
    ctx = {"base_url": "", "anon": client, "clients": {"anon": client}, "store": store,
           "options": {"upload_pages": args.page, "upload_test": args.test},
           "evidence_dir": args.evidence_dir}
    run(ctx)
    store.save()
    print(json.dumps(store.summary(), ensure_ascii=False))
    print("findings:", os.path.abspath(args.out))


if __name__ == "__main__":
    main()
