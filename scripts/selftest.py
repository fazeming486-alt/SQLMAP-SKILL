#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""selftest.py —— inject_probe.py 三态自检（可注入 / 不可注入 / 限速）。

用法： python selftest.py
自建靶点 → 跑三种场景 → 校验判定与退出码 → 打印 PASS/FAIL。
"""
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, "inject_probe.py")
TARGET = os.path.join(HERE, "selftest_target.py")
PORT = 8899
BASE = "http://127.0.0.1:%d" % PORT

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def run_probe(path, **kw):
    cmd = [sys.executable, PROBE, "--target", "%s%s" % (BASE, path),
           "--context", "numeric", "--base", "1", "--pairs", "1", "--gap", "1",
           "--out", os.path.join(HERE, "_selftest_ev.json"),
           "--out-dir", os.path.join(HERE, "_selftest_raw")]
    for k, v in kw.items():
        cmd += ["--" + k.replace("_", "-"), str(v)]
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.returncode, p.stdout or ""


def main():
    srv = subprocess.Popen([sys.executable, TARGET, "--port", str(PORT)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    results = []
    try:
        # 1) 可注入 → 期望 verdict INJECTABLE
        code, out = run_probe("/vuln?id=1*", marker="electronics-113")
        ok = "INJECTABLE" in out
        results.append(("可注入靶点 → INJECTABLE", ok, out.strip().splitlines()[-1] if out.strip() else ""))
        # 2) 不可注入 → 期望 not_injectable
        code, out = run_probe("/inval?id=1*", marker="electronics-113")
        ok = "not_injectable" in out
        results.append(("过滤靶点 → not_injectable", ok, out.strip().splitlines()[-1] if out.strip() else ""))
        # 3) 限速 → 期望 exit 2 且报限速
        code, out = run_probe("/limited?id=1*")
        ok = (code == 2) and ("限速" in out)
        results.append(("限速靶点 → 中止 exit 2", ok, "exit=%s" % code))
        # 4) 403 保护 → 期望也识别为限速
        code, out = run_probe("/protected?id=1*")
        ok = (code == 2)
        results.append(("403 保护 → 识别为限速", ok, "exit=%s" % code))
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except Exception:
            srv.kill()

    print("=== inject_probe.py 自检 ===")
    failed = 0
    for name, ok, detail in results:
        print("  [%s] %-28s %s" % ("PASS" if ok else "FAIL", name, detail[:60]))
        if not ok:
            failed += 1
    print("结论：%s" % ("全部通过" if not failed else "%d 项失败" % failed))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
