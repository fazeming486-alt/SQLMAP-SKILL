#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 engagement 输出目录生成单文件交互式 HTML 报告。Stdlib only，离线可用（file:// 直接开）。

Usage:
  python html_report.py --output-dir runs/<标签> [--title 报告标题] [--out <path>]

读取：
  <output-dir>/summary.json   —— sqlmap_run.py 每个 stage 落盘的结构化结果
  <output-dir>/<stage>.log    —— 原始日志
  <output-dir>/**/*.csv       —— dump 落盘的数据表

输出： <output-dir>/report.html （内联 CSS/JS，无外部请求）

Exit codes: 0 成功, 1 输出目录不可用。
"""
import argparse
import csv
import html as html_mod
import json
import os
import re
import sys
import time

if hasattr(sys.stdout, "reconfigure"):  # 固定 UTF-8，避免 GBK 控制台/管道乱码
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

MAX_LOG_LINES = 600        # 每份日志最多内联的行数（保留末尾）
MAX_ROWS_PER_TABLE = 2000  # 每张 CSV 最多内联的行数
HASH_RE = re.compile(
    r"(\$2y\$[./A-Za-z0-9]{20,}|\$argon2(?:id|i|d)\$[^\s,\"']{10,}"
    r"|\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b)"
)


def read_text(path, limit_bytes=2_000_000):
    raw = open(path, "rb").read(limit_bytes)
    for enc in ("utf-8-sig", "utf-8", "gbk"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", "replace")


def load_summary(out_dir):
    path = os.path.join(out_dir, "summary.json")
    if not os.path.isfile(path):
        return {"job": {}, "stages": {}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"job": {}, "stages": {}}


def collect_logs(out_dir, stages):
    logs = {}
    for stage in stages:
        path = os.path.join(out_dir, stage + ".log")
        if not os.path.isfile(path):
            continue
        text = read_text(path)
        lines = text.splitlines()
        omitted = max(0, len(lines) - MAX_LOG_LINES)
        logs[stage] = {
            "lines": len(lines),
            "omitted": omitted,
            "text": ("\n[前 %d 行已省略，完整日志: %s]\n" % (omitted, path) if omitted else "")
                    + "\n".join(lines[-MAX_LOG_LINES:]),
        }
    return logs


def sniff_delimiter(sample):
    try:
        return csv.Sniffer().sniff(sample[:4096], delimiters=",;\t|").delimiter
    except Exception:
        return ","


def collect_csvs(out_dir):
    tables = []
    for root, _dirs, files in os.walk(out_dir):
        for name in files:
            if not name.lower().endswith(".csv"):
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, out_dir).replace("\\", "/")
            try:
                text = read_text(full)
            except Exception:
                continue
            if not text.strip():
                continue
            delim = sniff_delimiter(text)
            reader = csv.reader(text.splitlines(), delimiter=delim)
            rows = [r for r in reader if any((c or "").strip() for c in r)]
            if not rows:
                continue
            columns = [c.strip() for c in rows[0]]
            data = rows[1:]
            count = len(data)
            truncated = count > MAX_ROWS_PER_TABLE
            tables.append({
                "label": os.path.splitext(name)[0],
                "rel": rel,
                "columns": columns,
                "rows": data[:MAX_ROWS_PER_TABLE],
                "count": count,
                "truncated": truncated,
            })
    tables.sort(key=lambda t: t["rel"])
    return tables


def build_payload(out_dir, title):
    summary = load_summary(out_dir)
    stages = summary.get("stages") or {}
    logs = collect_logs(out_dir, stages)
    tables = collect_csvs(out_dir)
    job = summary.get("job") or {}
    target = job.get("target") or job.get("request_file") or "(未知目标)"
    return {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "output_dir": out_dir,
            "title": title or ("sqlmap 交互报告 · %s" % target),
            "target": target,
            "scope_note": job.get("scope_note") or "",
        },
        "job": job,
        "stages": {k: dict(v, log=log) for k, (v, log) in
                   ((s, (stages[s], logs.get(s))) for s in stages)},
        "tables": tables,
    }


TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{
  --bg:#0d1117; --panel:#161b22; --panel2:#1c2330; --line:#2d3748;
  --text:#e6edf3; --muted:#8b98a5; --accent:#58a6ff;
  --ok:#3fb950; --bad:#f85149; --warn:#d29922; --idle:#6e7681;
  --code-bg:#0a0e14; --hash:#f778ba;
}
body.light{
  --bg:#f6f8fa; --panel:#ffffff; --panel2:#eef2f7; --line:#d0d7de;
  --text:#1f2328; --muted:#59636e; --accent:#0969da;
  --ok:#1a7f37; --bad:#cf222e; --warn:#9a6700; --idle:#6e7781;
  --code-bg:#f6f8fa; --hash:#bf3989;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
  font:14px/1.65 "Segoe UI","Microsoft YaHei",system-ui,sans-serif;}
a{color:var(--accent);text-decoration:none}
.wrap{max-width:1180px;margin:0 auto;padding:24px 20px 60px}
header.top{display:flex;align-items:flex-start;gap:14px;flex-wrap:wrap;
  border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:20px}
header.top h1{font-size:20px;margin:0 0 4px}
header.top .sub{color:var(--muted);font-size:12.5px;word-break:break-all}
.spacer{flex:1}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;
  font-weight:600;border:1px solid var(--line);background:var(--panel2)}
.badge.ok{color:var(--ok);border-color:var(--ok)}
.badge.bad{color:var(--bad);border-color:var(--bad)}
.badge.warn{color:var(--warn);border-color:var(--warn)}
.badge.idle{color:var(--idle)}
button.theme{background:var(--panel);border:1px solid var(--line);color:var(--text);
  border-radius:8px;padding:6px 12px;cursor:pointer;font-size:12.5px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
  gap:12px;margin:18px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card .k{font-size:11.5px;color:var(--muted);letter-spacing:.04em;text-transform:uppercase}
.card .v{font-size:14.5px;margin-top:4px;word-break:break-all;font-weight:600}
.card .v.ok{color:var(--ok)} .card .v.bad{color:var(--bad)} .card .v.warn{color:var(--warn)}
.section{margin-top:26px}
.section>h2{font-size:15.5px;margin:0 0 10px;display:flex;align-items:center;gap:8px}
.section>h2 .cnt{color:var(--muted);font-weight:400;font-size:12.5px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
.timeline{display:flex;flex-direction:column;gap:0}
.trow{display:flex;gap:12px;align-items:center;padding:10px 14px;
  border-bottom:1px solid var(--line);flex-wrap:wrap}
.trow:last-child{border-bottom:0}
.trow .stage{font-family:Consolas,monospace;font-weight:700;min-width:110px}
.trow .meta{color:var(--muted);font-size:12.5px}
.pill{font-size:11.5px;padding:2px 10px;border-radius:999px;font-weight:700}
.pill.success{background:rgba(63,185,80,.15);color:var(--ok)}
.pill.not_injectable{background:rgba(110,118,129,.15);color:var(--idle)}
.pill.blocked{background:rgba(210,153,34,.15);color:var(--warn)}
.pill.timeout{background:rgba(210,153,34,.15);color:var(--warn)}
.pill.error{background:rgba(248,81,73,.15);color:var(--bad)}
.evidence{font-family:Consolas,"Courier New",monospace;font-size:12.5px;
  background:var(--code-bg);border-top:1px solid var(--line);padding:10px 14px;white-space:pre-wrap;word-break:break-all}
.copybtn{background:var(--panel2);border:1px solid var(--line);color:var(--muted);
  border-radius:6px;font-size:11px;padding:2px 8px;cursor:pointer;margin-left:8px}
.copybtn:hover{color:var(--accent);border-color:var(--accent)}
.donut{display:flex;gap:20px;align-items:center;flex-wrap:wrap}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12.5px;color:var(--muted)}
.legend i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
.tab{background:var(--panel);border:1px solid var(--line);color:var(--text);
  border-radius:8px;padding:6px 12px;cursor:pointer;font-size:12.5px}
.tab.active{border-color:var(--accent);color:var(--accent);font-weight:600}
.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:10px;flex-wrap:wrap}
.toolbar input{background:var(--panel);border:1px solid var(--line);color:var(--text);
  border-radius:8px;padding:7px 12px;font-size:13px;min-width:240px}
.toolbar .info{color:var(--muted);font-size:12.5px}
.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:10px;max-height:520px}
table.data{border-collapse:collapse;width:100%;font-size:13px}
table.data th{position:sticky;top:0;background:var(--panel2);text-align:left;
  padding:8px 12px;border-bottom:1px solid var(--line);cursor:pointer;white-space:nowrap;user-select:none}
table.data th:hover{color:var(--accent)}
table.data td{padding:7px 12px;border-bottom:1px solid var(--line);vertical-align:top}
table.data tr:hover td{background:var(--panel2)}
.hash{color:var(--hash);font-family:Consolas,monospace}
details.log{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  margin-top:10px;overflow:hidden}
details.log summary{cursor:pointer;padding:10px 14px;font-weight:600;font-size:13px}
details.log pre{margin:0;padding:12px 14px;background:var(--code-bg);
  font:12px/1.55 Consolas,monospace;white-space:pre-wrap;word-break:break-all;max-height:420px;overflow:auto}
.foot{margin-top:34px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:14px}
.foot code{background:var(--panel2);padding:1px 6px;border-radius:5px}
.empty{color:var(--muted);padding:14px}
.scope{margin-top:8px;font-size:12.5px;color:var(--warn)}
@media print{.theme,.tabs,.toolbar{display:none!important}body{background:#fff;color:#000}}
</style>
</head>
<body>
<div class="wrap">
<header class="top">
  <div>
    <h1>__TITLE__</h1>
    <div class="sub">目标：<span id="target"></span>　·　生成于 <span id="gen"></span></div>
    <div class="sub">产出目录：<span id="outdir"></span></div>
    <div class="scope" id="scope"></div>
  </div>
  <div class="spacer"></div>
  <div style="text-align:right">
    <div id="overall" style="margin-bottom:8px"></div>
    <button class="theme" onclick="toggleTheme()">◐ 明暗切换</button>
  </div>
</header>

<div class="cards" id="cards"></div>

<div class="section">
  <h2>阶段时间线 <span class="cnt" id="stagecnt"></span></h2>
  <div class="panel">
    <div class="timeline" id="timeline"></div>
  </div>
  <div class="donut" style="margin-top:14px">
    <svg id="donut" width="96" height="96" viewBox="0 0 42 42"></svg>
    <div class="legend" id="legend"></div>
  </div>
</div>

<div class="section" id="evsec">
  <h2>注入证据（EVIDENCE）<span class="cnt">对应日志原文，可复制</span></h2>
  <div class="panel" id="evidence"></div>
</div>

<div class="section" id="datasec">
  <h2>数据表（DUMP）<span class="cnt" id="datacnt"></span></h2>
  <div class="tabs" id="tabs"></div>
  <div class="toolbar">
    <input id="search" placeholder="搜索本表（所有列）…" oninput="renderTable()">
    <span class="info" id="tinfo"></span>
  </div>
  <div class="tablewrap"><table class="data" id="datatable"></table></div>
</div>

<div class="section" id="logsec">
  <h2>原始日志（LOGS）<span class="cnt">折叠展开，强制指回</span></h2>
  <div id="logdetails"></div>
</div>

<div class="foot" id="foot"></div>
</div>

<script id="report-data" type="application/json">__PAYLOAD_JSON__</script>
<script>
const D = JSON.parse(document.getElementById("report-data").textContent);
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s==null?"":s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const STAGE_CN = {detect:"注入判定",dbs:"列库","current-db":"当前库",tables:"列表",columns:"列列名",dump:"取数","dump-all":"全库导出",passwords:"拖哈希",privileges:"看权限","sql-query":"单发SQL","os-cmd":"单发命令","file-read":"读文件","file-write":"写文件"};

function toggleTheme(){document.body.classList.toggle("light");}

/* ---- 头部 ---- */
$("target").textContent = D.meta.target;
$("gen").textContent = D.meta.generated_at;
$("outdir").textContent = D.meta.output_dir;
document.title = D.meta.title;
if (D.meta.scope_note) $("scope").innerHTML = "范围记录（scope_note）：" + esc(D.meta.scope_note);
const stageNames = Object.keys(D.stages||{});
const okCount = stageNames.filter(s=>D.stages[s].status==="success").length;
let overall = '<span class="badge idle">无阶段记录</span>';
if (stageNames.length){
  if (stageNames.includes("detect") && D.stages.detect.info && D.stages.detect.info.injectable === true)
    overall = '<span class="badge ok">INJECTABLE · 已确认可注入</span>';
  else if (stageNames.includes("detect") && D.stages.detect.info && D.stages.detect.info.injectable === false)
    overall = '<span class="badge idle">NOT INJECTABLE · 未注入成功</span>';
  else overall = '<span class="badge warn">进行中 · ' + okCount + "/" + stageNames.length + ' 阶段成功</span>';
}
$("overall").innerHTML = overall;

/* ---- 概要卡片 ---- */
function firstInfo(keys){for(const s of ["detect","current-db","dbs","tables","columns","dump","passwords","sql-query","os-cmd","file-read","file-write","dump-all","privileges"]){const st=D.stages&&D.stages[s];if(st&&st.info){for(const k of keys){if(st.info[k])return st.info[k];}}}return null;}
const j = D.job||{};
const cards = [
  ["DBMS", firstInfo(["dbms"]), ""],
  ["服务器 OS", firstInfo(["os_info"]), ""],
  ["Web 技术", firstInfo(["web_tech"]), ""],
  ["WAF", firstInfo(["waf_type"]), "warn"],
  ["受影响参数", (firstInfo(["params"])||[]).join(", "), "ok"],
  ["注入点", (()=>{const i=D.stages&&D.stages.detect&&D.stages.detect.info;return i&&i.columns?i.columns+" 列":""})(), ""],
  ["节奏", [j.threads?("threads="+j.threads):null, j.risk?("risk="+j.risk):null, j.level?("level="+j.level):null, j.delay?("delay="+j.delay):null, j.tamper?("tamper="+j.tamper):null].filter(Boolean).join(" · "), ""],
  ["会话", j.cookie?"已带 Cookie（掩码）":"匿名/未记录", ""],
];
$("cards").innerHTML = cards.map(c=>{
  if(!c[1]) return "";
  return '<div class="card"><div class="k">'+esc(c[0])+'</div><div class="v '+c[2]+'">'+esc(c[1])+'</div></div>';
}).join("");

/* ---- 时间线 ---- */
const order = ["detect","dbs","current-db","tables","columns","dump","dump-all","passwords","privileges","sql-query","os-cmd","file-read","file-write"];
const sorted = stageNames.slice().sort((a,b)=>order.indexOf(a)-order.indexOf(b));
$("stagecnt").textContent = sorted.length ? sorted.length+" 个阶段" : "（还没有阶段数据——先跑 sqlmap_run.py）";
$("timeline").innerHTML = sorted.map(s=>{
  const st = D.stages[s];
  const extra = [];
  const i = st.info||{};
  if(i.injectable!==null&&i.injectable!==undefined) extra.push("injectable="+i.injectable);
  if(i.dbms) extra.push(i.dbms);
  if(i.columns) extra.push(i.columns+" 列");
  if(i.tables&&i.tables.length) extra.push(i.tables.length+" 项");
  if(i.waf_type) extra.push("WAF: "+i.waf_type);
  return '<div class="trow"><span class="stage">'+esc(s)+'</span>'
    + '<span class="pill '+esc(st.status)+'">'+esc(st.status)+'</span>'
    + '<span class="meta">'+esc(STAGE_CN[s]||"")+' · '+esc(st.started_at||"")+' · '+esc(st.duration_sec)+"s · exit "+esc(st.exit)+'</span>'
    + (extra.length?'<span class="meta">｜'+esc(extra.join(" · "))+'</span>':"")
    + '</div>';
}).join("") || '<div class="empty">无阶段数据。用 sqlmap_run.py 跑至少一个 stage 后重新生成报告。</div>';

/* ---- SVG 环形图（阶段状态占比） ---- */
(function(){
  const counts = {success:0,not_injectable:0,blocked:0,error:0};
  sorted.forEach(s=>{counts[D.stages[s].status]=(counts[D.stages[s].status]||0)+1;});
  const total = sorted.length;
  const colors = {success:"var(--ok)",not_injectable:"var(--idle)",blocked:"var(--warn)",error:"var(--bad)"};
  const names = {success:"成功",not_injectable:"不可注入",blocked:"被拦",error:"出错"};
  if(!total){$("legend").innerHTML='<span class="empty">—</span>';return;}
  let offset = 0, segs = "";
  for(const k of ["success","not_injectable","blocked","error"]){
    if(!counts[k]) continue;
    const frac = counts[k]/total;
    const dash = frac*100;
    segs += '<circle r="15.9" cx="21" cy="21" fill="transparent" stroke="'+colors[k]
      +'" stroke-width="6" stroke-dasharray="'+dash+' '+(100-dash)
      +'" stroke-dashoffset="'+(25-offset)+'"></circle>';
    offset += dash;
    $("legend").innerHTML += '<span><i style="background:'+colors[k]+'"></i>'+names[k]+' ×'+counts[k]+'</span>';
  }
  $("donut").innerHTML = segs + '<text x="21" y="24" text-anchor="middle" font-size="8" fill="var(--text)">'+total+'</text>';
})();

/* ---- 证据 ---- */
(function(){
  const boxes = [];
  sorted.forEach(s=>{
    const st = D.stages[s]; const i = st.info||{};
    const lines = [];
    (i.types||[]).forEach(t=>lines.push(t));
    (i.tail||[]).forEach(t=>{ if(!lines.some(l=>l===t)) lines.push(t); });
    if(!lines.length) return;
    const body = lines.map(l=>
      '<div style="display:flex;align-items:flex-start">'
      +'<code style="flex:1;white-space:pre-wrap;word-break:break-all;color:var(--text)">'+esc(l)+'</code>'
      +'<button class="copybtn" onclick="copyTxt(this)">复制</button></div>').join("");
    boxes.push('<div><div class="trow" style="border-bottom:1px solid var(--line)"><span class="stage">'+esc(s)
      +'</span><span class="pill '+esc(st.status)+'">'+esc(st.status)+'</span>'
      +'<span class="meta">日志：'+esc((st.log&&st.log.text)?"见下方日志":"未捕获")+'</span></div>'
      +'<div class="evidence">'+body+'</div></div>');
  });
  $("evidence").innerHTML = boxes.join("") || '<div class="empty">暂无证据行（先跑 detect）</div>';
})();

function copyTxt(btn){
  const code = btn.parentElement.querySelector("code");
  const txt = code.textContent;
  const done = ()=>{btn.textContent="已复制";setTimeout(()=>btn.textContent="复制",1200);};
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(txt).then(done,()=>fallback());}
  else fallback();
  function fallback(){const ta=document.createElement("textarea");ta.value=txt;document.body.appendChild(ta);ta.select();try{document.execCommand("copy");done();}catch(e){}document.body.removeChild(ta);}
}

/* ---- 数据表 ---- */
let curTable = 0, curRows = null, sortCol = -1, sortAsc = true, page = 0;
const PER = 50;
function renderTable(){
  const t = D.tables[curTable];
  if(!t){$("datatable").innerHTML="";$("tinfo").textContent="";return;}
  let rows = t.rows;
  const q = ($("search").value||"").toLowerCase();
  if(q) rows = rows.filter(r=>r.some(c=>String(c==null?"":c).toLowerCase().includes(q)));
  if(sortCol>=0){
    rows = rows.slice().sort((a,b)=>{
      const x=String(a[sortCol]==null?"":a[sortCol]), y=String(b[sortCol]==null?"":b[sortCol]);
      const nx=parseFloat(x), ny=parseFloat(y);
      const cmp = (!isNaN(nx)&&!isNaN(ny)&&x!==""&&y!=="") ? nx-ny : x.localeCompare(y);
      return sortAsc?cmp:-cmp;
    });
  }
  curRows = rows;
  const pages = Math.max(1, Math.ceil(rows.length/PER));
  if(page>=pages) page = pages-1;
  const slice = rows.slice(page*PER,(page+1)*PER);
  const hl = (v)=>{
    let s = esc(v);
    s = s.replace(HASH_G, '<span class="hash">$1</span>');
    return s;
  };
  $("datatable").innerHTML = '<thead><tr>'
    + t.columns.map((c,i)=>'<th onclick="sortBy('+i+')">'+esc(c)+(sortCol===i?(sortAsc?" ▲":" ▼"):"")+'</th>').join("")
    + '</tr></thead><tbody>'
    + (slice.length?slice.map(r=>'<tr>'+t.columns.map((c,i)=>'<td>'+hl(r[i])+'</td>').join("")+'</tr>').join("")
      :'<tr><td colspan="'+t.columns.length+'" class="empty">无匹配行</td></tr>')
    + '</tbody>';
  $("tinfo").textContent = "共 "+t.count+" 行"+(t.truncated?"（报告内嵌前 "+MAX_ROWS+" 行，完整数据见 CSV）":"")
    +" · 过滤后 "+rows.length+" 行 · 第 "+(page+1)+"/"+pages+" 页"
    +(rows.length>PER?"（<a href='#' onclick=\"page++;renderTable();return false\">下一页</a>）":"");
}
const MAX_ROWS = 2000;
const HASH_G = /(\$2y\$[.\/A-Za-z0-9]{20,}|\$argon2(?:id|i|d)\$[^\s,"']{10,}|\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b)/g;
function sortBy(i){ if(sortCol===i){sortAsc=!sortAsc;}else{sortCol=i;sortAsc=true;} renderTable(); }
(function initTables(){
  $("datacnt").textContent = D.tables.length ? D.tables.length+" 张表" : "（无 CSV 产物——dump 类 stage 才会产出）";
  $("tabs").innerHTML = D.tables.map((t,i)=>
    '<button class="tab'+(i===0?" active":"")+'" onclick="curTable='+i+';page=0;sortCol=-1;renderTabs();renderTable();">'
    + esc(t.label)+' <span class="cnt">'+t.count+'</span></button>').join("")
    || '<span class="empty">无数据表</span>';
  renderTable();
})();
function renderTabs(){
  document.querySelectorAll(".tab").forEach((el,i)=>el.classList.toggle("active",i===curTable));
}

/* ---- 日志 ---- */
$("logdetails").innerHTML = sorted.map(s=>{
  const lg = D.stages[s].log;
  if(!lg) return "";
  return '<details class="log"><summary>'+esc(s)+'.log · '+lg.lines+' 行'
    +(lg.omitted?'（内嵌末尾 '+MAX_LOG_LINES+' 行）':"")+'</summary><pre>'+esc(lg.text)+'</pre></details>';
}).join("") || '<div class="empty">无日志</div>';

/* ---- 页脚 ---- */
$("foot").innerHTML = "由 sqlmap-skill <code>html_report.py</code> 生成 · 单文件离线报告 · "
  + "产物目录 <code>"+esc(D.meta.output_dir)+"</code> · "
  + (D.tables.length?("CSV "+D.tables.length+" 份 · "):"")
  + "Cookie 已掩码。数据只用于授权范围内的测试与复现。";
</script>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description="Interactive HTML report for a sqlmap engagement")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--title", default=None)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    out_dir = os.path.abspath(args.output_dir)
    if not os.path.isdir(out_dir):
        print("REFUSED: 输出目录不存在：%s" % out_dir)
        return 1
    payload = build_payload(out_dir, args.title)
    payload_json = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    html_out = (TEMPLATE
                .replace("__PAYLOAD_JSON__", payload_json)
                .replace("__TITLE__", html_mod.escape(payload["meta"]["title"])))
    out_path = os.path.abspath(args.out or os.path.join(out_dir, "report.html"))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_out)
    n_stages = len(payload["stages"])
    n_rows = sum(t["count"] for t in payload["tables"])
    print("REPORT: %s" % out_path)
    print("SIZE: %.1f KB" % (os.path.getsize(out_path) / 1024.0))
    print("STAGES: %d" % n_stages)
    print("TABLES: %d (%d rows)" % (len(payload["tables"]), n_rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
