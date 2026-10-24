#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""authz_probe.py —— 角色矩阵 / 越权 / IDOR 取证。

给定多个角色的会话与资源 URL，逐个角色请求，比较状态码与响应内容：
- 配置为 deny 的角色返回 200 且不是登录/403/404 页 → 越权（高）；
- 同一资源多个角色都 200 且内容高度相似 → 共享对象访问（需人工确认）；
- allow 角色反而 403/404 → 配置或角色问题（info）。

用法：
  python authz_probe.py --config authz.json --out runs/demo/authz.json
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import httpkit
from findings import FindingStore

DENY_MARKERS = ("没有访问权限", "无权限", "403", "404", "登录", "login", "not found")


def _title(text):
    m = re.search(r"<title>(.*?)</title>", text or "", re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def _is_denied(resp):
    text = resp.get("text") or ""
    title = _title(text).lower()
    if resp["status"] in (401, 403, 404):
        return True
    if "登录" in title or "login" in title:
        return True
    low = text[:4000].lower()
    return any(m in low for m in ("没有访问权限", "无权限", "access denied", "forbidden"))


def make_client(role_cfg, base_url, evidence_dir, rps=1.0, timeout=30):
    c = httpkit.HttpClient(base_url=base_url, cookie=role_cfg.get("cookie"),
                           cookie_jar=role_cfg.get("cookie_jar"),
                           headers=role_cfg.get("headers"), rps=rps, timeout=timeout,
                           evidence_dir=evidence_dir)
    login = role_cfg.get("login")
    if login:
        try:
            c.login(login.get("url"), login.get("data", {}),
                    csrf_url=login.get("csrf_url"), csrf_field=login.get("csrf_field", "_csrf"),
                    method=login.get("method", "POST"), tag="login-" + role_cfg.get("name", "role"),
                    totp_secret=login.get("totp_secret"))
        except Exception as e:
            print("WARN login failed for %s: %s" % (role_cfg.get("name", "role"), e))
    return c


def run(ctx):
    store = ctx["store"]
    base = ctx["base_url"]
    clients = ctx["clients"]
    resources = ctx.get("options", {}).get("authz_resources") or []
    for res in resources:
        url_t = res["url"]
        ids = res.get("ids") or [None]
        allow = set(res.get("allow", []))
        deny = set(res.get("deny", []))
        for rid in ids:
            url = url_t.replace("{id}", str(rid)) if rid is not None else url_t
            responses = {}
            for role, client in clients.items():
                if role not in allow and role not in deny:
                    continue
                try:
                    r = client.get(url, tag="authz-%s-%s" % (role, str(rid)))
                except Exception as e:
                    responses[role] = {"status": "ERR", "error": str(e)}
                    continue
                responses[role] = r
            for role in deny:
                r = responses.get(role)
                if not r or r.get("status") == "ERR":
                    continue
                if r["status"] == 200 and not _is_denied(r):
                    store.add(
                        module="authz",
                        title=res.get("title", "越权访问：%s 不应访问该资源" % role),
                        severity=res.get("severity", "high"),
                        endpoint=url, method=res.get("method", "GET"),
                        parameter=res.get("parameter"),
                        confidence="confirmed",
                        cvss=res.get("cvss", 7.5),
                        evidence={"role": role, "status": r["status"], "final_url": r["url"],
                                  "title": _title(r["text"]),
                                  "snippet": httpkit.redact((r["text"] or "")[:500]),
                                  "artifact": r.get("evidence"),
                                  "responses": {k: (v.get("status") if isinstance(v, dict) else v)
                                                for k, v in responses.items()}},
                        impact=res.get("impact", "低权限角色可读取/操作不属于自己的资源，构成越权或 IDOR。"),
                        remediation="服务端按对象归属与角色做授权校验；不要只依赖前端隐藏入口。",
                        references=["WSTG-ATHZ-01", "WSTG-ATHZ-02", "WSTG-ATHZ-04"],
                        tags=["authz", "idor"],
                    )
            # 多角色均 200 且内容高度相似 → 共享对象（需人工判断）
            ok = {k: v for k, v in responses.items() if isinstance(v, dict) and v.get("status") == 200}
            if len(ok) >= 2:
                roles = list(ok)
                a, b = ok[roles[0]], ok[roles[1]]
                sim = httpkit.similarity(a["normalized"], b["normalized"])
                if sim > 0.95 and set(roles) & deny and set(roles) & allow:
                    store.add(
                        module="authz",
                        title=res.get("title", "多角色看到同一敏感对象"),
                        severity="medium", endpoint=url, method="GET",
                        confidence="needs-review", cvss=5.3,
                        evidence={"roles": roles, "similarity": round(sim, 3),
                                  "artifact": a.get("evidence")},
                        impact="不同角色可能共享同一对象视图，需确认是否包含越权数据。",
                        remediation="按角色/归属返回最小字段；对敏感对象做服务端授权。",
                        references=["WSTG-ATHZ-01"],
                        tags=["authz"],
                    )
            for role in allow:
                r = responses.get(role)
                if isinstance(r, dict) and r.get("status") in (401, 403, 404):
                    store.add(
                        module="authz", title="配置的 allow 角色被拒绝", severity="info",
                        endpoint=url, method="GET", confidence="needs-review",
                        evidence={"role": role, "status": r["status"], "artifact": r.get("evidence")},
                        impact="可能是角色/会话配置错误，也可能是授权策略变化。",
                        remediation="复核角色、Cookie 与对象归属。",
                        tags=["config"],
                    )
    return store.items


def main():
    p = argparse.ArgumentParser(description="Role matrix / IDOR probe")
    p.add_argument("--config", required=True, help="JSON: base_url, roles, resources")
    p.add_argument("--out", default="authz-findings.json")
    p.add_argument("--evidence-dir", default="authz-raw")
    p.add_argument("--rps", type=float, default=1.0)
    p.add_argument("--timeout", type=float, default=30)
    args = p.parse_args()
    cfg = json.load(open(args.config, encoding="utf-8-sig"))
    base = cfg["base_url"]
    clients = {}
    for role, rc in cfg.get("roles", {}).items():
        rc = dict(rc); rc.setdefault("name", role)
        clients[role] = make_client(rc, base, args.evidence_dir, args.rps, args.timeout)
    store = FindingStore(args.out)
    ctx = {"base_url": base, "clients": clients, "anon": clients.get("anon"),
           "store": store, "options": {"authz_resources": cfg.get("resources", [])},
           "evidence_dir": args.evidence_dir}
    run(ctx)
    store.save()
    print(json.dumps(store.summary(), ensure_ascii=False))
    print("findings:", os.path.abspath(args.out))


if __name__ == "__main__":
    main()
