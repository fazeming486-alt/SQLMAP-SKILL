#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""engage.py —— web-pentest 工作台编排器。

读取 engage.json，按模块顺序执行：
  recon（可选）→ misconfig → xss → authz → sqli → ssrf → nuclei（可选）
统一管理会话、预算、限速、证据、findings 与报告。

用法：
  python engage.py --config engage.json --dry-run
  python engage.py --config engage.json --only misconfig,xss --max-requests 80
  python engage.py --config engage.json --report
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import httpkit
from findings import FindingStore

MODULE_ORDER = ["recon", "misconfig", "xss", "authz", "sqli", "ssrf", "upload", "export", "api", "oidc", "nuclei"]


def _redact_obj(o):
    if isinstance(o, dict):
        return {k: _redact_obj(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_redact_obj(v) for v in o]
    if isinstance(o, str):
        return httpkit.redact(o)
    return o


def _load(path):
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


def _resolve(path, base_dir):
    if not path:
        return path
    if os.path.isabs(path):
        return path
    return os.path.normpath(os.path.join(base_dir, path))


def _host(url):
    return urllib.parse.urlsplit(url).hostname or ""


def _in_scope(url, scope):
    host = _host(url)
    for s in scope:
        s = s.strip().lstrip(".")
        if host == s or host.endswith("." + s):
            return True
    return False


def build_clients(cfg, base_dir, evidence_root, budget, rps, timeout):
    clients = {}
    status = {}
    base_url = cfg["base_url"]
    for role, rc in (cfg.get("sessions") or {"anon": {}}).items():
        rc = dict(rc or {})
        rc.setdefault("name", role)
        jar = _resolve(rc.get("cookie_jar"), base_dir)
        ev = os.path.join(evidence_root, "session-" + role)
        client = httpkit.HttpClient(
            base_url=base_url, cookie=rc.get("cookie"), cookie_jar=jar,
            headers=rc.get("headers"), proxy=rc.get("proxy"), timeout=timeout,
            rps=rc.get("rps", rps), evidence_dir=ev, budget=budget)
        login = rc.get("login")
        if login:
            try:
                client.login(login.get("url"), login.get("data", {}),
                             csrf_url=login.get("csrf_url"),
                             csrf_field=login.get("csrf_field", "_csrf"),
                             method=login.get("method", "POST"),
                             tag="login-" + role,
                             totp_secret=login.get("totp_secret"))
            except Exception as e:
                status[role] = {"login": "error", "error": str(e)}
                clients[role] = client
                continue
        verify = rc.get("verify_url") or base_url
        try:
            r = client.get(verify, tag="verify-" + role)
            status[role] = {"verify_url": verify, "status": r["status"],
                            "final_url": r["url"], "requests": client.used}
        except Exception as e:
            status[role] = {"verify_url": verify, "error": str(e)}
        clients[role] = client
    return clients, status


def run_recon(cfg, base_dir, run_dir, timeout=300):
    recon_cfg = cfg.get("recon") or {}
    if not recon_cfg.get("enabled", True):
        return None
    out = os.path.join(run_dir, "recon.json")
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recon.py")
    cmd = [sys.executable, script, "--base-url", cfg["base_url"],
           "--scope-note", "engage.py recon", "--out", out,
           "--max-pages", str(recon_cfg.get("max_pages", 20))]
    if recon_cfg.get("dirs"):
        cmd.append("--dirs")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        return {"status": p.returncode, "out": out,
                "stdout": p.stdout[-2000:], "stderr": p.stderr[-2000:]}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def run_module(name, ctx):
    if name == "misconfig":
        import misconfig_probe
        return misconfig_probe.run(ctx)
    if name == "xss":
        import xss_probe
        return xss_probe.run(ctx)
    if name == "authz":
        import authz_probe
        return authz_probe.run(ctx)
    if name == "sqli":
        import sqli_probe
        return sqli_probe.run(ctx)
    if name == "ssrf":
        import ssrf_probe
        return ssrf_probe.run(ctx)
    if name == "upload":
        import upload_probe
        return upload_probe.run(ctx)
    if name == "export":
        import export_probe
        return export_probe.run(ctx)
    if name == "api":
        import api_probe
        return api_probe.run(ctx)
    if name == "oidc":
        import oidc_probe
        return oidc_probe.run(ctx)
    if name == "nuclei":
        import tool_adapters
        return tool_adapters.run_nuclei(ctx["base_url"], ctx["store"],
                                        rate=ctx["options"].get("nuclei_rate", 10),
                                        severity=ctx["options"].get("nuclei_severity",
                                                                    "low,medium,high,critical"),
                                        out_dir=ctx["run_dir"])
    raise ValueError("unknown module: " + name)


def main():
    p = argparse.ArgumentParser(description="Web pentest engagement orchestrator")
    p.add_argument("--config", required=True)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--only", default=None, help="comma list: recon,misconfig,xss,authz,sqli,ssrf,nuclei")
    p.add_argument("--skip", default=None)
    p.add_argument("--max-requests", type=int, default=None)
    p.add_argument("--rps", type=float, default=None)
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("--report", action="store_true", help="generate HTML report at the end")
    p.add_argument("--no-report", action="store_true")
    p.add_argument("--strict-auth", action="store_true",
                   help="任一非匿名角色登录失败则中止")
    args = p.parse_args()

    cfg = _load(args.config)
    base_dir = os.path.dirname(os.path.abspath(args.config))
    base_url = cfg["base_url"]
    scope = cfg.get("scope") or [_host(base_url)]
    if not _in_scope(base_url, scope):
        print("REFUSED: base_url host %s is not in scope %s" % (_host(base_url), scope))
        return 3

    modules = cfg.get("modules") or ["misconfig", "xss", "authz", "sqli"]
    if args.only:
        modules = [m.strip() for m in args.only.split(",") if m.strip()]
    if args.skip:
        skip = {m.strip() for m in args.skip.split(",")}
        modules = [m for m in modules if m not in skip]
    modules = [m for m in modules if m in MODULE_ORDER]
    unknown = [m for m in (cfg.get("modules") or []) if m not in MODULE_ORDER]
    if unknown:
        print("WARN unknown modules ignored:", unknown)

    max_requests = args.max_requests or cfg.get("max_requests", 500)
    rps = args.rps if args.rps is not None else cfg.get("rps", 1.0)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    run_dir = cfg.get("output_dir") or os.path.join("runs", "%s-%s" % (cfg.get("name", "engagement"), stamp))
    run_dir = os.path.abspath(os.path.join(base_dir, run_dir)) if not os.path.isabs(run_dir) else run_dir
    if os.path.exists(run_dir) and not cfg.get("overwrite"):
        run_dir = run_dir + "-" + stamp
    evidence_root = os.path.join(run_dir, "raw")

    print("=== engagement: %s ===" % cfg.get("name"))
    print("target:", base_url)
    print("scope:", scope)
    print("modules:", modules)
    print("budget:", max_requests, "requests, rps:", rps)
    if args.dry_run:
        print("dry-run: no requests sent")
        for m in modules:
            print(" -", m)
        print("sessions:", list((cfg.get("sessions") or {"anon": {}}).keys()))
        print("options keys:", list((cfg.get("options") or {}).keys()))
        return 0

    os.makedirs(evidence_root, exist_ok=True)
    budget = httpkit.Budget(max_requests)
    clients, session_status = build_clients(cfg, base_dir, evidence_root, budget, rps, args.timeout)
    failed_roles = [r for r, st in session_status.items()
                    if r != "anon" and (st.get("login") == "error"
                                       or st.get("status") in (301, 302, 303, 401, 403))]
    if failed_roles:
        print("WARN unauthenticated roles:", failed_roles)
        if args.strict_auth or cfg.get("strict_auth"):
            print("STOP: strict auth enabled")
            return 2
    anon = clients.get("anon") or next(iter(clients.values()))
    store = FindingStore(os.path.join(run_dir, "findings.json"))
    ctx = {
        "base_url": base_url, "clients": clients, "anon": anon, "store": store,
        "options": cfg.get("options") or {}, "run_dir": run_dir, "evidence_dir": evidence_root,
        "budget": budget,
    }

    recon_result = None
    state = {"name": cfg.get("name"), "target": base_url, "scope": scope,
             "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
             "modules": [], "sessions": session_status}
    for m in modules:
        started = time.time()
        print("\n--- module: %s ---" % m)
        try:
            if m == "recon":
                recon_result = run_recon(cfg, base_dir, run_dir)
                state["modules"].append({"module": m, "status": "done", "result": recon_result,
                                         "duration": round(time.time() - started, 2),
                                         "findings": 0, "requests": budget.used})
                print("recon:", recon_result.get("status") if recon_result else "skipped")
                continue
            before = len(store.items)
            run_module(m, ctx)
            store.save()
            added = len(store.items) - before
            state["modules"].append({"module": m, "status": "done",
                                     "duration": round(time.time() - started, 2),
                                     "findings": added, "requests": budget.used})
            print("%s: +%d findings, %d requests used" % (m, added, budget.used))
        except (httpkit.BudgetExceeded, httpkit.RateLimited) as e:
            state["modules"].append({"module": m, "status": "stopped", "error": str(e),
                                     "duration": round(time.time() - started, 2),
                                     "requests": budget.used})
            print("STOP:", e)
            break
        except Exception as e:
            state["modules"].append({"module": m, "status": "error", "error": str(e),
                                     "duration": round(time.time() - started, 2),
                                     "requests": budget.used})
            print("ERROR in %s: %s" % (m, e))

    store.save()
    summary = {
        "engagement": cfg.get("name"), "target": base_url, "scope": scope,
        "started_at": state["started_at"], "finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "requests_used": budget.used, "max_requests": max_requests,
        "findings": store.summary(), "modules": state["modules"],
        "sessions": session_status,
    }
    with open(os.path.join(run_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    with open(os.path.join(run_dir, "config.redacted.json"), "w", encoding="utf-8") as f:
        json.dump(_redact_obj(cfg), f, ensure_ascii=False, indent=2)
    with open(os.path.join(run_dir, "state.json"), "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    print("\n=== summary ===")
    print(json.dumps(summary, ensure_ascii=False, indent=2)[:2000])
    print("run dir:", run_dir)

    if args.report and not args.no_report:
        try:
            import report
            report.generate(run_dir)
            print("report:", os.path.join(run_dir, "report.html"))
        except Exception as e:
            print("report error:", e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
