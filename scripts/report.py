#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""report.py —— 把 findings.json + summary.json 渲染成单文件 HTML 报告。

离线、无外部依赖、深/浅色切换、可打印。报告只认 findings 结构，
因此手工探测、内置模块、nuclei 适配器的结果都能进同一份报告。
"""
import argparse
import html
import json
import os
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {"critical": "#ff4d6d", "high": "#ff7a45", "medium": "#ffb454",
             "low": "#7ce3c2", "info": "#8fa8b3"}
SEV_CN = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}


def esc(x):
    return html.escape(str(x if x is not None else ""))


def load(run_dir):
    summary = {}
    findings = []
    config = {}
    for name, target in (("summary.json", "summary"), ("findings.json", "findings"),
                         ("config.redacted.json", "config")):
        p = os.path.join(run_dir, name)
        if os.path.exists(p):
            try:
                data = json.load(open(p, encoding="utf-8"))
                if target == "findings":
                    findings = data.get("findings", [])
                elif target == "summary":
                    summary = data
                else:
                    config = data
            except Exception:
                pass
    return summary, findings, config


def render_evidence(ev):
    if not ev:
        return ""
    if isinstance(ev, dict):
        # 去掉过长的原始响应
        clean = {}
        for k, v in ev.items():
            if isinstance(v, str) and len(v) > 1200:
                v = v[:1200] + "..."
            clean[k] = v
        return '<pre class="evidence">%s</pre>' % esc(json.dumps(clean, ensure_ascii=False, indent=2))
    return '<pre class="evidence">%s</pre>' % esc(str(ev)[:2000])


def finding_card(f):
    sev = f.get("severity", "info")
    color = SEV_COLOR.get(sev, "#8fa8b3")
    refs = f.get("references") or []
    refs_html = "".join('<span class="ref">%s</span>' % esc(r) for r in refs)
    return """
    <article class="finding" style="--sev:%s">
      <div class="finding-head">
        <div>
          <div class="finding-id">%s · %s</div>
          <h3>%s</h3>
          <div class="finding-meta"><span class="mono">%s</span> %s
            %s</div>
        </div>
        <div class="sev"><span class="sev-dot"></span>%s · CVSS %s</div>
      </div>
      <div class="finding-body">
        <div class="cols">
          <div><div class="label">端点</div><div class="mono">%s</div></div>
          <div><div class="label">参数 / 位置</div><div class="mono">%s</div></div>
          <div><div class="label">置信度</div><div>%s</div></div>
        </div>
        <h4>证据</h4>
        %s
        <div class="cols two">
          <div><h4>影响</h4><p>%s</p></div>
          <div><h4>修复建议</h4><p>%s</p></div>
        </div>
        %s
      </div>
    </article>""" % (
        color, esc(f.get("id", "")), esc(SEV_CN.get(sev, sev)),
        esc(f.get("title", "")),
        esc(f.get("method", "GET")), esc(f.get("endpoint", "")),
        ('<span class="param">' + esc(f.get("parameter")) + "</span>") if f.get("parameter") else "",
        esc(SEV_CN.get(sev, sev)), esc(f.get("cvss", "")),
        esc(f.get("endpoint", "")), esc(f.get("parameter") or "—"),
        esc(f.get("confidence", "confirmed")),
        render_evidence(f.get("evidence")),
        esc(f.get("impact", "")), esc(f.get("remediation", "")),
        ('<div class="refs">参考：%s</div>' % refs_html) if refs_html else "",
    )


def generate(run_dir, out=None):
    summary, findings, config = load(run_dir)
    out = out or os.path.join(run_dir, "report.html")
    counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in SEV_ORDER}
    modules = summary.get("modules") or []
    sessions = summary.get("sessions") or {}
    target = summary.get("target") or config.get("base_url") or ""
    name = summary.get("engagement") or config.get("name") or "engagement"
    used = summary.get("requests_used", "—")
    cards = "".join(
        '<div class="stat" style="--sev:%s"><div class="label">%s</div><div class="value">%d</div></div>'
        % (SEV_COLOR[s], SEV_CN[s], counts[s]) for s in SEV_ORDER)

    module_rows = "".join(
        "<tr><td class='mono'>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(m.get("module")), esc(m.get("status")), esc(m.get("findings", 0)),
            esc(m.get("requests", "")), esc(m.get("error") or m.get("duration", "")))
        for m in modules)
    session_rows = "".join(
        "<tr><td class='mono'>%s</td><td>%s</td><td class='mono'>%s</td></tr>" % (
            esc(role), esc(d.get("status", d.get("login", "n/a"))), esc(d.get("final_url") or d.get("error") or ""))
        for role, d in sessions.items())

    findings_html = "".join(finding_card(f) for f in findings) or """
      <div class="empty"><h3>本轮没有确认漏洞</h3>
      <p>这不等于“绝对安全”。请结合模块覆盖、未测项和人工复核判断。</p></div>"""

    html_doc = """<!DOCTYPE html>
<html lang="zh-CN" data-theme="dark">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s · Web 渗透测试报告</title>
<style>
:root{--bg:#070d12;--panel:#0e1a22;--panel2:#12232c;--line:#1d3742;--text:#dbe9ee;--muted:#8fa8b3;
--accent:#7ce3c2;--code:#061016;--mono:ui-monospace,Consolas,monospace;--sans:"Segoe UI","Microsoft YaHei",system-ui,sans-serif}
html[data-theme=light]{--bg:#f4f7f6;--panel:#fff;--panel2:#f6faf8;--line:#d6e2dd;--text:#12211c;--muted:#5b746c;
--accent:#0f7a63;--code:#0e1a22}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.65}
.wrap{max-width:1100px;margin:0 auto;padding:32px 22px 70px}
.hero{border:1px solid var(--line);border-radius:18px;padding:30px;background:linear-gradient(135deg,var(--panel),var(--panel2));
box-shadow:0 18px 50px rgba(0,0,0,.25)}
.eyebrow{font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:var(--accent);font-weight:700}
h1{font-size:32px;line-height:1.2;margin:8px 0}.sub{color:var(--muted);font-size:14px}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}.chip{border:1px solid var(--line);background:var(--panel2);
padding:5px 10px;border-radius:999px;font-size:11.5px;color:var(--muted)}.chip b{color:var(--text)}
.stats{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;margin-top:16px}
.stat{border:1px solid var(--line);border-radius:12px;padding:14px;background:var(--panel);border-top:3px solid var(--sev,#666)}
.stat .label{font-size:11px;color:var(--muted)}.stat .value{font-size:26px;font-weight:800}
.section{margin-top:34px}.section h2{font-size:20px;margin:0 0 12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px}
.mono{font-family:var(--mono);font-size:12.5px}pre{margin:0;padding:14px;background:var(--code);border:1px solid var(--line);
border-radius:10px;overflow:auto;font-size:12px;color:#cfe9f1;max-height:360px}
html[data-theme=light] pre{color:#cfe9f1}
.finding{border:1px solid var(--line);border-left:4px solid var(--sev);border-radius:14px;background:var(--panel);margin:14px 0;overflow:hidden}
.finding-head{padding:18px 20px;display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;
background:linear-gradient(90deg,color-mix(in srgb,var(--sev) 14%,transparent),transparent 70%);border-bottom:1px solid var(--line)}
.finding-id{font-size:11px;color:var(--muted);letter-spacing:.08em}.finding h3{margin:4px 0 6px;font-size:18px}
.finding-meta{font-size:12px;color:var(--muted)}.param{color:var(--accent);margin-left:4px}
.sev{color:var(--sev);border:1px solid var(--sev);border-radius:999px;padding:5px 10px;font-size:12px;font-weight:700;height:fit-content}
.sev-dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--sev);margin-right:6px}
.finding-body{padding:18px 20px}.cols{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin-bottom:8px}
.cols.two{grid-template-columns:repeat(2,minmax(0,1fr));margin-top:12px}
.label{font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:2px}
h4{font-size:12px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin:16px 0 6px}
p{margin:4px 0}.refs{margin-top:12px;font-size:11.5px;color:var(--muted)}.ref{display:inline-block;border:1px solid var(--line);
border-radius:999px;padding:2px 8px;margin:2px 4px 0 0}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line)}
th{font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}tr:last-child td{border-bottom:0}
.tablewrap{border:1px solid var(--line);border-radius:12px;overflow:auto;background:var(--panel)}
.empty{border:1px dashed var(--line);border-radius:14px;padding:26px;color:var(--muted);text-align:center}
.footer{margin-top:40px;border-top:1px solid var(--line);padding-top:14px;color:var(--muted);font-size:12px;
display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
button.btn{border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:8px;padding:7px 10px;
font-size:12px;cursor:pointer}button.btn:hover{border-color:var(--accent);color:var(--accent)}
@media(max-width:900px){.stats{grid-template-columns:repeat(2,1fr)}.cols,.cols.two{grid-template-columns:1fr}}
@media print{:root{--bg:#fff;--panel:#fff;--panel2:#f7faf9;--text:#111;--muted:#555;--line:#ccc;--code:#f4f6f6}
body{background:#fff}.wrap{max-width:100%;padding:0}pre{color:#111;max-height:none}.finding{break-inside:avoid}
button{display:none}}
</style>
</head>
<body><div class="wrap">
<div class="hero">
  <div class="eyebrow">Authorized Web Penetration Test</div>
  <h1>%s · Web 渗透测试报告</h1>
  <p class="sub">目标：<span class="mono">%s</span><br>由 web-pentest v4 工作台生成；报告只包含可复现证据与已确认/待复核发现。</p>
  <div class="chips">
    <span class="chip">开始 <b>%s</b></span>
    <span class="chip">请求 <b>%s</b></span>
    <span class="chip">模块 <b>%s</b></span>
    <span class="chip">发现 <b>%s</b></span>
  </div>
  <div style="margin-top:14px"><button class="btn" onclick="document.documentElement.dataset.theme=document.documentElement.dataset.theme==='light'?'dark':'light'">切换主题</button>
  <button class="btn" onclick="window.print()">打印 / PDF</button></div>
</div>

<div class="stats">%s</div>

<section class="section"><h2>模块覆盖</h2><div class="tablewrap"><table>
<thead><tr><th>模块</th><th>状态</th><th>发现</th><th>累计请求</th><th>耗时/错误</th></tr></thead>
<tbody>%s</tbody></table></div></section>

<section class="section"><h2>会话 / 角色</h2><div class="tablewrap"><table>
<thead><tr><th>角色</th><th>状态</th><th>最终地址</th></tr></thead><tbody>%s</tbody></table></div></section>

<section class="section"><h2>发现</h2>%s</section>

<section class="section"><h2>方法与边界</h2><div class="card">
<p>参考 OWASP WSTG、PTES 与本次实战模块：侦察 → 工作台/角色矩阵 → 基线 → 模块探测（配置、XSS、越权、SQLi、SSRF）→ 证据 → 报告。</p>
<p class="small">未执行：写库、删改数据、上传 webshell、爆破、拒绝服务、对非授权目标的任何操作。未确认项需人工复核；报告中的敏感值按需脱敏。</p>
</div></section>

<div class="footer"><div>web-pentest · 单文件离线报告</div><div>生成时间 %s</div></div>
</div></body></html>"""
    values = [esc(name), esc(name), esc(target), esc(summary.get("started_at", "")), esc(used),
              esc(len(modules)), esc(len(findings)), cards, module_rows, session_rows,
              findings_html, time.strftime("%Y-%m-%d %H:%M:%S")]
    for i in range(len(values)):
        html_doc = html_doc.replace("%s", "@@TPL%d@@" % i, 1)
    for i, v in enumerate(values):
        html_doc = html_doc.replace("@@TPL%d@@" % i, str(v))

    with open(out, "w", encoding="utf-8") as f:
        f.write(html_doc)
    return out


def main():
    p = argparse.ArgumentParser(description="Render HTML report from a run directory")
    p.add_argument("--run-dir", required=True)
    p.add_argument("--out", default=None)
    args = p.parse_args()
    print(generate(args.run_dir, args.out))


if __name__ == "__main__":
    main()
