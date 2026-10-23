#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""findings.py —— 统一发现模型、去重、严重度与 JSON 输出。

一个 finding 至少包含：模块、标题、严重度、端点、方法、参数、置信度、证据、
影响、修复建议、参考。报告器只认这个结构；扫描器/手工探测都往这里写。
"""
import argparse
import json
import os
import re
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}
DEFAULT_CVSS = {"critical": 9.0, "high": 7.5, "medium": 5.5, "low": 3.0, "info": 0.0}
SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium",
             "low": "Low", "info": "Info"}


class FindingStore:
    def __init__(self, path=None):
        self.path = path
        self.items = []

    def _next_id(self):
        return "F-%03d" % (len(self.items) + 1)

    def add(self, module, title, severity, endpoint, method="GET", parameter=None,
            confidence="confirmed", cvss=None, evidence=None, impact="",
            remediation="", references=None, tags=None):
        severity = (severity or "info").lower()
        if severity not in SEVERITIES:
            severity = "info"
        key = (module, title, endpoint, parameter or "")
        for it in self.items:
            if (it["module"], it["title"], it["endpoint"], it.get("parameter") or "") == key:
                # 合并证据，不重复计分
                if evidence:
                    it.setdefault("evidence", {}).update(evidence)
                return it
        item = {
            "id": self._next_id(),
            "module": module,
            "title": title,
            "severity": severity,
            "severity_label": SEV_LABEL[severity],
            "cvss": float(cvss if cvss is not None else DEFAULT_CVSS[severity]),
            "confidence": confidence,
            "endpoint": endpoint,
            "method": method,
            "parameter": parameter,
            "evidence": evidence or {},
            "impact": impact,
            "remediation": remediation,
            "references": references or [],
            "tags": tags or [],
        }
        self.items.append(item)
        return item

    def save(self, path=None):
        path = path or self.path
        if not path:
            raise ValueError("no output path")
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.items.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["id"]))
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "findings": self.items}, f, ensure_ascii=False, indent=2)
        return path

    @classmethod
    def load(cls, path):
        store = cls(path)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            store.items = data
        else:
            store.items = data.get("findings", [])
        return store

    def summary(self):
        counts = {s: 0 for s in SEVERITIES}
        for it in self.items:
            counts[it["severity"]] = counts.get(it["severity"], 0) + 1
        return counts

    def markdown(self):
        lines = ["# Findings", ""]
        for s in SEVERITIES:
            group = [x for x in self.items if x["severity"] == s]
            if not group:
                continue
            lines.append("## %s (%d)" % (SEV_LABEL[s], len(group)))
            for it in group:
                lines.append("- **%s** `%s` — %s %s" % (it["id"], it["endpoint"],
                                                       it["method"], it.get("parameter") or ""))
                lines.append("  - %s" % it["title"])
        return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="Findings store utility")
    p.add_argument("--file", required=True)
    p.add_argument("--show", action="store_true")
    p.add_argument("--markdown", action="store_true")
    p.add_argument("--merge", nargs="*", default=[])
    args = p.parse_args()
    store = FindingStore.load(args.file) if os.path.exists(args.file) else FindingStore(args.file)
    for extra in args.merge:
        other = FindingStore.load(extra)
        for it in other.items:
            store.add(it["module"], it["title"], it["severity"], it["endpoint"],
                      it.get("method", "GET"), it.get("parameter"), it.get("confidence", "confirmed"),
                      it.get("cvss"), it.get("evidence"), it.get("impact", ""),
                      it.get("remediation", ""), it.get("references"), it.get("tags"))
    if args.merge:
        store.save()
    if args.markdown:
        print(store.markdown())
    elif args.show:
        print(json.dumps({"summary": store.summary(), "findings": store.items},
                         ensure_ascii=False, indent=2))
    else:
        print(json.dumps(store.summary(), ensure_ascii=False))


if __name__ == "__main__":
    main()
