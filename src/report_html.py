#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Manuel FLURY
#
# This file is part of jMeter_OpenLDAP_replay: replays OpenLDAP access-log
# traffic with Apache JMeter and renders an HTML dashboard. Distributed
# under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later);
# see the LICENSE file for the full text.
#
"""Generate a self-contained HTML report from `replay_report.txt` produced by
the jMeter JSR223 replay script (section markers are stable).  All formatters
are written with the Python standard library (no external dep).

Display labels for the LDAP server and the injector host are controlled by
`LDAP_HOST_LABEL` / `INJECTOR_HOST_LABEL`; the column prefixes used by
host_monitor.sh (`slapd_<name>_cpu_usr` for LDAP instances, `injector_*` for
the injector host) by `SLAPD_PREFIX` / `INJECTOR_PREFIX`. Each value is
resolved as: environment variable, then the optional `jmeter_replay.conf`
file next to this script (bash `KEY="${KEY:-default}"` lines), then the
built-in default below — mirroring the shell scripts' precedence."""

from __future__ import annotations

import argparse
import bisect
import html
import json
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple


def _load_config(path: Path) -> dict:
    """Read the optional jmeter_replay.conf (KEY="${KEY:-default}" lines)."""
    values = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^(\w+)="?\$\{\1:-(.*)\}"?$', line)
        if m:
            values[m.group(1)] = m.group(2).strip('"')
    return values


_CONFIG = _load_config(Path(__file__).resolve().parent / "jmeter_replay.conf")


def _param(name: str, default: str) -> str:
    """Resolve a parameter: environment variable, then config file, then default."""
    env = os.environ.get(name)
    if env:
        return env
    return _CONFIG.get(name, default)


# --- Display labels (env, then jmeter_replay.conf, then these defaults) ------
# Generic, environment-agnostic defaults; rename to your own LDAP / injector
# hosts if desired.
LDAP_HOST_LABEL = _param("LDAP_HOST_LABEL", "LDAP server")
INJECTOR_HOST_LABEL = _param("INJECTOR_HOST_LABEL", "injector host")
INJECTOR_PREFIX = _param("INJECTOR_PREFIX", "injector")      # host_metrics columns: injector_cpu_usr, ...
SLAPD_PREFIX = _param("SLAPD_PREFIX", "slapd")                # host_metrics columns: slapd_<inst>_cpu_usr

# --- Project identity --------------------------------------------------------
# Version and repository links shown in the footer of every generated page.
PROJECT_NAME = "jMeter_OpenLDAP_replay"
PROJECT_VERSION = "1.0.0"
PROJECT_URLS = (
    "https://github.com/zx97/jMeter_OpenLDAP_replay",
    "https://gitlab.com/ooo.manu.ooo/jMeter_OpenLDAP_replay",
)


def parse_report(path: Path) -> dict:
    """Parse the textual report produced by replay_ldap.groovy."""
    text = path.read_text(encoding="utf-8")

    # Header (4 lines): file, time range, run duration / throughput, total
    header_lines = text.splitlines()[:4]
    out = {
        "source_file": _colon(header_lines[0]),
        "run_duration_raw": _colon(header_lines[2]) if len(header_lines) > 2 else "",
        "run_duration": "—",
        "time_range": _colon(header_lines[1]) if len(header_lines) > 1 else "",
        "global": _colon(header_lines[3]) if len(header_lines) > 3 else "",
    }
    m = re.search(r"(\d+)\s*ms", out["run_duration_raw"])
    if m:
        out["run_duration"] = _fmt_elapsed(int(m.group(1)) / 1000.0)

    # METRICS BY TYPE block (primary: response times / load-test view)
    m = re.search(
        r"^METRICS BY TYPE[^\n]*:\n(?P<lines>(?:.*\n)*?)(?=\n\n|\nFIDELITY|\Z)",
        text,
        re.MULTILINE,
    )
    if m:
        out["metrics_by_type"] = _parse_table(m.group("lines").rstrip("\n"))

    # FIDELITY CHECK block (secondary, informational)
    m = re.search(
        r"^FIDELITY CHECK[^\n]*:\n(?P<lines>(?:.*\n)*?)(?=\n\n|\nBEHAVIOUR|\Z)",
        text,
        re.MULTILINE,
    )
    if m:
        out["fidelity_check"] = _parse_table(m.group("lines").rstrip("\n"))
    else:
        out["fidelity_check"] = []

    # BEHAVIOUR OVER TIME blocks (one per TYPE)
    timeline = {}
    for tm in re.finditer(
        r"^\s{2}(?P<type>[A-Z]+):\n(?P<body>(?:.*\n)+?)(?=^\s{2}\w+:|\nINFRASTRUCTURE|\nFIDELITY|\nAll replays|\nNo infra|\Z)",
        text,
        re.MULTILINE,
    ):
        typ = tm.group("type")
        body = tm.group("body")
        bucket = []
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("MINUTE"):
                continue
            parts = re.split(r"\s+", line)
            # New format: MINUTE OPS REPLAYED MATCHED MISMATCHED INFRA_ERR AVGms
            if len(parts) >= 7:
                bucket.append({
                    "minute": parts[0],
                    "ops": int(parts[1]),
                    "replayed": int(parts[2]),
                    "matched": int(parts[3]),
                    "mismatched": int(parts[4]),
                    "infra_err": int(parts[5]),
                    "avg_ms": float(parts[6]),
                })
        timeline[typ] = bucket
    out["timeline"] = timeline

    infra_errors = []
    m = re.search(r"\nINFRASTRUCTURE ERRORS:\n(?P<body>.*?)(?=\nFIDELITY|\nReport file|\Z)",
                  text, re.DOTALL)
    if m:
        for line in m.group("body").splitlines():
            line = line.strip()
            if line.startswith("- "):
                infra_errors.append(line[2:])
    out["infra_errors"] = infra_errors
    out["infra_err_count"] = len(infra_errors)

    fidelity_mismatches = []
    m = re.search(r"\nFIDELITY MISMATCHES[^\n]*:\n(?P<body>.*)", text, re.DOTALL)
    if m:
        for line in m.group("body").splitlines():
            line = line.strip()
            if line.startswith("- "):
                fidelity_mismatches.append(line[2:])
    out["fidelity_mismatches"] = fidelity_mismatches
    out["fidelity_mismatch_count"] = len(fidelity_mismatches)
    return out


def _colon(line: str) -> str:
    return line.split(":", 1)[1].strip() if ":" in line else line


def _parse_table(block: str) -> List[dict]:
    """Parse a TM-header-followed-by-dashes table."""
    rows = block.splitlines()
    if len(rows) < 3:
        return []
    headers = re.split(r"\s+", rows[0].strip())
    sep = rows[1].strip()
    body = [r for r in rows[2:] if r.strip()]
    table = []
    for r in body:
        parts = re.split(r"\s+", r.strip())
        if len(parts) != len(headers):
            continue
        table.append(dict(zip(headers, parts)))
    return table


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    margin: 0; padding: 24px;
    background: #0f172a; color: #e2e8f0;
}
h1, h2, h3 { color: #f8fafc; margin-top: 1.4em; }
h1 { font-size: 1.7em; border-bottom: 1px solid #334155; padding-bottom: 0.3em; }
h2 { font-size: 1.3em; border-bottom: 1px solid #1e293b; padding-bottom: 0.2em; }
h3 { font-size: 1.1em; color: #cbd5e1; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
           gap: 12px; margin: 16px 0; }
.kpi { background: #1e293b; border: 1px solid #334155; border-radius: 8px;
       padding: 14px 16px; }
.kpi .label { font-size: 0.8em; color: #94a3b8; text-transform: uppercase;
              letter-spacing: 0.05em; }
.kpi .value { font-size: 1.6em; font-weight: 600; color: #f1f5f9; margin-top: 4px; }
.kpi.succ   .value { color: #4ade80; }
.kpi.fail   .value { color: #f87171; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 0.9em; }
th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #1e293b; }
th { background: #1e293b; color: #cbd5e1; font-weight: 600; position: sticky; top: 0; }
th.num { text-align: right; }
tr:hover td { background: #1e293b; }
td.num { text-align: right; font-family: ui-monospace, "SF Mono", monospace; }
.bar { display: inline-block; height: 8px; border-radius: 4px;
       background: linear-gradient(90deg, #4ade80, #22d3ee); vertical-align: middle; }
.bar-row { display: flex; align-items: center; gap: 8px; }
.bar-row .label { width: 110px; font-family: ui-monospace, monospace;
                  font-size: 0.85em; color: #94a3b8; }
.bar-row .bar { flex: 1; }
.bar-row .val { width: 70px; text-align: right; font-family: ui-monospace, monospace;
                font-size: 0.85em; }
.chart { background: #1e293b; border: 1px solid #334155; border-radius: 8px;
         padding: 12px; margin: 16px 0; }
.chart svg { width: 100%; height: auto; }
.failure-list { font-family: ui-monospace, monospace; font-size: 0.8em;
                background: #1e293b; border: 1px solid #334155; border-radius: 6px;
                padding: 12px; max-height: 480px; overflow: auto; }
.section { margin: 18px 0; }
.muted { color: #94a3b8; font-size: 0.9em; }
.danger { color: #f87171; }
.ok { color: #4ade80; }
.scroll-x { overflow-x: auto; }
.legend { background: #1e293b; border: 1px solid #475569; border-left: 4px solid #22d3ee;
          border-radius: 8px; padding: 16px 20px; margin: 20px 0; }
.legend h2 { margin-top: 0; }
.legend dl { margin: 0; }
.legend dt { font-weight: 600; color: #f1f5f9; font-family: ui-monospace, "SF Mono", monospace;
             margin-top: 10px; }
.legend dd { margin: 2px 0 0 0; color: #cbd5e1; }
.legend .swatch { display: inline-block; width: 12px; height: 12px; border-radius: 3px;
                  margin-right: 6px; vertical-align: middle; }
.toggle-legend { display: flex; flex-wrap: wrap; gap: 4px 18px; padding: 8px 4px; }
.toggle { display: inline-flex; align-items: center; gap: 6px; font-size: 0.85em;
          cursor: pointer; user-select: none; }
.toggle .swatch { width: 14px; height: 14px; border-radius: 3px;
                  display: inline-block; flex: 0 0 auto; }
.toggle input { accent-color: #22d3ee; }
.topnav { position: sticky; top: 0; z-index: 50; display: flex; flex-wrap: nowrap;
          overflow-x: auto; gap: 2px 8px; align-items: center; padding: 8px 14px; margin: -24px -24px 18px;
          background: #0b1220; border-bottom: 1px solid #334155; font-size: 0.8em;
          white-space: nowrap; scrollbar-width: thin; }
.topnav a { color: #94a3b8; text-decoration: none; padding: 3px 7px; border-radius: 5px; }
.topnav a:hover { background: #1e293b; color: #e2e8f0; }
.topnav a.active { background: #164e63; color: #67e8f9; font-weight: 600; }
.topnav .brand { font-weight: 700; color: #e2e8f0; margin-right: 6px; flex: 0 0 auto; }
.topnav .group { color: #64748b; margin-left: 8px; flex: 0 0 auto; }
.chart { position: relative; }
.chart-tip { display: none; position: absolute; z-index: 60; pointer-events: none;
             background: #0b1220; border: 1px solid #475569; border-radius: 6px;
             padding: 6px 10px; font-size: 0.78em; max-width: 260px;
             box-shadow: 0 4px 12px rgba(0,0,0,.4); }
.chart-tip .tip-title { font-weight: 600; color: #f1f5f9; margin-bottom: 4px; }
.chart-tip .tip-row { color: #cbd5e1; }
.chart-tip .swatch { display: inline-block; width: 9px; height: 9px; border-radius: 2px;
                     margin-right: 5px; vertical-align: middle; }
.report-links { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
                gap: 10px; margin: 10px 0 22px; }
.link-card { background: #0f1a2e; border: 1px solid #24344d; border-radius: 8px; padding: 0; }
.link-card a { display: block; color: #cbd5e1; text-decoration: none; padding: 12px 14px; }
.link-card a:hover { background: #16233d; border-radius: 8px; }
.link-card strong { color: #67e8f9; display: block; margin-bottom: 4px; }
.page-footer { margin-top: 32px; padding-top: 14px; border-top: 1px solid #334155;
               font-size: 0.8em; color: #94a3b8; }
.page-footer a { color: #67e8f9; text-decoration: none; }
.page-footer a:hover { text-decoration: underline; }
@media (prefers-color-scheme: light) {
    .link-card { background: #fff; border-color: #e2e8f0; }
    .link-card a { color: #334155; }
    .link-card strong { color: #0e7490; }
}
@media (prefers-color-scheme: light) {
    .topnav { background: #f1f5f9; border-bottom-color: #e2e8f0; }
    .topnav a { color: #475569; }
    .topnav a:hover { background: #e2e8f0; color: #0f172a; }
    .topnav a.active { background: #cffafe; color: #0e7490; }
    .topnav .brand { color: #0f172a; }
    .chart-tip { background: #fff; border-color: #cbd5e1; }
    .chart-tip .tip-title { color: #0f172a; }
    .chart-tip .tip-row { color: #334155; }
}
@media (prefers-color-scheme: light) {
    body { background: #f8fafc; color: #1e293b; }
    h1, h2, h3 { color: #0f172a; }
    .kpi, .chart, .failure-list, .legend { background: #fff; border-color: #e2e8f0; }
    .kpi .label { color: #64748b; }
    .kpi .value { color: #0f172a; }
    .legend { border-left-color: #0891b2; }
    .legend dt { color: #0f172a; }
    .legend dd { color: #334155; }
    th { background: #f1f5f9; color: #475569; }
    tr:hover td { background: #f1f5f9; }
}
"""


def _escape(t: str) -> str:
    return html.escape(t)


def render_kpis(data: dict) -> str:
    """Build the top KPI strip, oriented toward load and response times.

    `data["global"]` has the form
        "Total: 69694 operations, 0 infra error(s), peak concurrent connections: 12"
    """
    m = data["metrics_by_type"]
    order = ["BIND", "SRCH", "CMP", "UNBIND", "ABANDON"]
    present = sorted({r["TYPE"] for r in m}, key=lambda t: order.index(t) if t in order else len(order))
    counts = {r["TYPE"]: r.get("TOTAL", 0) for r in m}

    def _types_card() -> str:
        if not present:
            return card("Operations by type", "—")
        label = " / ".join(present[:3])
        value = " / ".join(str(counts.get(t, 0)) for t in present[:3])
        if len(present) > 3:
            label += " (+%d more)" % (len(present) - 3)
        return card(label, value)

    infra_err = data["infra_err_count"]

    nums = re.findall(r"\d+", data["global"])
    total = int(nums[0]) if nums else 0
    peak = int(nums[2]) if len(nums) > 2 else 0

    def card(label: str, value: str, klass: str = "") -> str:
        return (
            f'<div class="kpi {klass}"><div class="label">{_escape(label)}</div>'
            f'<div class="value">{_escape(value)}</div></div>'
        )

    avg_ms = _weighted_avg(m)
    p95 = _max_col(m, "p95")
    return (
        '<div class="summary">'
        + card("Total operations", str(total))
        + card("Throughput", _throughput(data["run_duration_raw"]))
        + card("Peak concurrent", str(peak))
        + card("AVGms", avg_ms, "succ")
        + card("p95ms", p95)
        + card("Infra errors", str(infra_err), "fail" if infra_err else "succ")
        + _types_card()
        + card("Run duration", data["run_duration"])
        + "</div>"
    )


def _weighted_avg(rows: List[dict]) -> str:
    total_ops = sum(int(r.get("TOTAL", 0)) for r in rows)
    if not total_ops:
        return "0.0"
    total_lat = sum(int(r.get("TOTAL", 0)) * float(r.get("AVGms", 0)) for r in rows)
    return f"{total_lat / total_ops:.1f}"


def _max_col(rows: List[dict], col: str) -> str:
    vals = [float(r.get(col, 0)) for r in rows if r.get(col)]
    return f"{max(vals):.0f}" if vals else "0"


def _throughput(run_duration: str) -> str:
    m = re.search(r"throughput:\s*([\d.]+)", run_duration)
    return f"{m.group(1)} ops/s" if m else "—"


def render_legend() -> str:
    """Legend explaining every metric and chart colour. Placed near the top of
    the report so it is easy to find when interpreting the curves."""
    return (
        '<div class="legend" id="legend">'
        "<h2>Legend &mdash; how to read this report</h2>"
        "<dl>"
        "<dt>RATE/s</dt>"
        "<dd>Throughput: number of operations completed per second.</dd>"
        "<dt>AVGms</dt>"
        "<dd>Average response time of the LDAP server, in milliseconds.</dd>"
        "<dt>p50 / p95 / p99 (ms)</dt>"
        "<dd>Response time percentiles: the value under which 50% / 95% / 99% "
        "of the operations completed. Example: <code>p95 = 41 ms</code> means "
        "95% of the operations took 41 ms or less. They reveal the tail of the "
        "latency distribution: the gap between p50 and p99 grows when the "
        "server starts to saturate.</dd>"
        "<dt>MAXms</dt>"
        "<dd>Slowest single operation observed.</dd>"
        "<dt>INFRA_ERR</dt>"
        "<dd>Infrastructure errors: operations where LDAP did not reply at all "
        "(network failure, timeout, connection refused). The only real "
        "failures; everything else counts as \u201cLDAP replied\u201d.</dd>"
        "<dt>Transactions per second</dt>"
        "<dd>Throughput of all operations combined (BIND + SRCH + CMP + "
        "UNBIND + ABANDON, i.e. every operation type of the replay): number "
        "of completed transactions per second, bucketed over short intervals. "
        "A plateau means the server cannot go faster.</dd>"
        "<dt>Average transaction response time (ms)</dt>"
        "<dd>Mean response time of all operations per interval. Read it "
        "together with Transactions per second: when throughput plateaus "
        "while this curve rises, the server is saturated.</dd>"
        "<dt>Concurrent connections</dt>"
        "<dd>Number of LDAP connections in flight at the same time (the load "
        "level of the test).</dd>"
"<dt>Transaction summary table</dt>"
        "<dd>Per operation type (BIND, SRCH, CMP, UNBIND, ABANDON): total "
        "count, minimum, average, maximum, standard deviation, 90th "
        "percentile, and the number of passed / failed transactions. The "
        "<code>90%</code> column follows the LoadRunner Transaction Summary "
        "convention; the comparison charts additionally show p95 / p99.</dd>"
        "<dt>Elapsed time on the X axis</dt>"
        "<dd>All charts use the test duration, starting from zero, formatted "
        "as <code>mm:ss</code> (e.g. <code>2:35</code> = 2 minutes 35 seconds "
        "after the start of the test), never the clock time of the logs.</dd>"
        "</dl>"
        "<p>Chart colours (Behaviour over time): "
        '<span class="swatch" style="background:#4ade80"></span>green bars = '
        "operations per minute (load), "
        '<span class="swatch" style="background:#fbbf24"></span>amber dots and '
        "line = average latency (ms), "
        '<span class="swatch" style="background:#f87171"></span>red ticks = '
        "infrastructure errors. Hover a bar for details.</p>"
        "</div>"
    )


def render_metrics_table(data: dict) -> str:
    rows = data["metrics_by_type"]
    if not rows:
        return '<p class="muted">No metrics by type found.</p>'
    headers = [
        "TYPE", "TOTAL", "RATE/s", "AVGms", "p50", "p95", "p99", "MAXms",
        "INFRA_ERR",
    ]
    num_cols = set(headers) - {"TYPE"}
    out = [
        '<div class="scroll-x"><table>',
        "<tr>" + "".join(
            f'<th class="num">{_escape(h)}</th>' if h in num_cols
            else f"<th>{_escape(h)}</th>" for h in headers) + "</tr>",
    ]
    for r in rows:
        cells = []
        for h in headers:
            v = r.get(h, "")
            if h == "TYPE":
                cells.append(f'<td>{_escape(v)}</td>')
            elif h == "INFRA_ERR":
                klass = "danger" if v not in ("0", "") else ""
                cells.append(f'<td class="num {klass}">{_escape(v)}</td>')
            else:
                cells.append(f'<td class="num">{_escape(v)}</td>')
        out.append("<tr>" + "".join(cells) + "</tr>")
    out.append("</table></div>")
    return "\n".join(out)


def render_fidelity_table(data: dict) -> str:
    """Secondary, informational table: how faithful the replay was vs the log."""
    rows = data["fidelity_check"]
    if not rows:
        return '<p class="muted">No fidelity check block found.</p>'
    headers = [
        "TYPE", "TOTAL", "REPLAYED", "MATCHED", "MISMATCHED",
        "ERR_MIS", "CNT_MIS", "DNS_MIS",
    ]
    num_cols = set(headers) - {"TYPE"}
    out = [
        '<p class="muted">Fidelity vs the log is informational: a wrong '
        "password or a missing entry counts as \"LDAP replied\" (see the "
        "primary metrics table).</p>",
        '<div class="scroll-x"><table>',
        "<tr>" + "".join(
            f'<th class="num">{_escape(h)}</th>' if h in num_cols
            else f"<th>{_escape(h)}</th>" for h in headers) + "</tr>",
    ]
    for r in rows:
        cells = []
        for h in headers:
            v = r.get(h, "")
            if h == "TYPE":
                cells.append(f"<td>{_escape(v)}</td>")
            elif h in ("ERR_MIS", "CNT_MIS", "DNS_MIS"):
                klass = "danger" if v not in ("0", "") else ""
                cells.append(f'<td class="num {klass}">{_escape(v)}</td>')
            else:
                cells.append(f'<td class="num">{_escape(v)}</td>')
        out.append("<tr>" + "".join(cells) + "</tr>")
    out.append("</table></div>")
    return "\n".join(out)


def _timeline_labels(buckets: List[dict]) -> List[str]:
    """Relative elapsed-time labels for per-minute buckets: the first bucket
    is 0:00, the second 1:00, ... based on the minute of the original log."""
    from datetime import datetime
    first = None
    labels = []
    for b in buckets:
        try:
            t = datetime.fromisoformat(b["minute"])
        except (ValueError, TypeError):
            labels.append(b["minute"])
            continue
        if first is None:
            first = t
        labels.append(_fmt_elapsed((t - first).total_seconds()))
    return labels


def render_timeline(data: dict) -> str:
    timeline = data["timeline"]
    if not timeline:
        return '<p class="muted">No timeline data.</p>'

    blocks = []
    for typ, buckets in timeline.items():
        if not buckets:
            continue
        width = 1000
        n = len(buckets)
        bar_w = max(2, width // n - 1)
        max_ops = max(b["ops"] for b in buckets) or 1
        max_avg = max(b["avg_ms"] for b in buckets) or 1.0
        height = 280
        chart_h = 220
        rel_labels = _timeline_labels(buckets)
        out = [
            f"<h3>{_escape(typ)} ({n} minutes, {sum(b['ops'] for b in buckets)} ops)</h3>",
            f'<div class="chart"><svg viewBox="0 0 {width} {height}" '
            f'preserveAspectRatio="xMidYMid meet">',
        ]
        for tick in (0, 0.25, 0.5, 0.75, 1.0):
            y = chart_h - chart_h * tick + 10
            out.append(
                f'<line x1="40" y1="{y:.1f}" x2="{width - 10}" y2="{y:.1f}" '
                f'stroke="#334155" stroke-width="0.5"/>'
                f'<text x="36" y="{y + 3:.1f}" fill="#94a3b8" font-size="9" '
                f'text-anchor="end">{int(max_ops * tick)}</text>'
            )
        for i, b in enumerate(buckets):
            x = 40 + i * (width - 50) / n
            ops_h = chart_h * b["ops"] / max_ops
            avg_h = chart_h * b["avg_ms"] / max_avg
            out.append(
                f'<rect x="{x:.1f}" y="{chart_h - ops_h + 10:.1f}" '
                f'width="{bar_w}" height="{ops_h:.1f}" fill="#4ade80" rx="1">'
                f'<title>{_escape(rel_labels[i])} : {b["ops"]} ops / '
                f'AVG={b["avg_ms"]:.1f}ms / {b["infra_err"]} infra_err</title></rect>'
            )
            if b["infra_err"] > 0:
                out.append(
                    f'<rect x="{x:.1f}" y="8" width="{bar_w}" height="4" fill="#f87171" rx="1"/>'
                )
        lat_pts = []
        for i, b in enumerate(buckets):
            x = 40 + i * (width - 50) / n + bar_w / 2
            avg_h = chart_h * b["avg_ms"] / max_avg
            lat_pts.append(f"{x:.1f},{chart_h - avg_h + 10:.1f}")
            out.append(
                f'<circle cx="{x:.1f}" cy="{chart_h - avg_h + 10:.1f}" r="2" fill="#fbbf24">'
                f'<title>{_escape(rel_labels[i])} : AVG={b["avg_ms"]:.1f}ms</title></circle>'
            )
        if len(lat_pts) > 1:
            out.append(
                f'<polyline points="{" ".join(lat_pts)}" fill="none" '
                f'stroke="#fbbf24" stroke-width="1.5"/>'
            )
        label_every = max(1, n // 8)
        for i, b in enumerate(buckets):
            if i % label_every == 0 or i == n - 1:
                x = 40 + i * (width - 50) / n + bar_w / 2
                out.append(
                    f'<text x="{x:.1f}" y="{height - 4:.1f}" '
                    f'fill="#94a3b8" font-size="9" text-anchor="middle">'
                    f'{_escape(rel_labels[i])}</text>'
                )
        out.append("</svg>")
        out.append(
            '<div class="muted" style="font-size:0.8em; margin-top:6px;">'
            '<span class="ok">green</span> = operations (load), '
            '<span style="color:#fbbf24">amber</span> = average latency (ms), '
            '<span class="danger">red</span> = infra error (LDAP did not reply). '
            'X axis = elapsed time since the start of the replayed window. '
            'Hover for detail.'
            "</div>"
        )
        out.append("</div>")
        blocks.append("\n".join(out))
    return "\n".join(blocks)


def render_per_minute_table(data: dict) -> str:
    timeline = data["timeline"]
    if not timeline:
        return ""
    headers = ["ELAPSED", "TYPE", "OPS", "AVGms", "INFRA_ERR", "REPLAYED",
               "MATCHED", "MISMATCHED"]
    num_cols = set(headers) - {"TYPE"}
    out = ['<div class="scroll-x"><table>',
           "<tr>" + "".join(
               f'<th class="num">{_escape(h)}</th>' if h in num_cols
               else f"<th>{_escape(h)}</th>" for h in headers) + "</tr>"]
    for typ, buckets in timeline.items():
        rel_labels = _timeline_labels(buckets)
        for i, b in enumerate(buckets):
            klass = "danger" if b["infra_err"] > 0 else ""
            out.append(
                "<tr>"
                + f'<td class="num">{_escape(rel_labels[i])}</td>'
                + f'<td>{_escape(typ)}</td>'
                + f'<td class="num">{b["ops"]}</td>'
                + f'<td class="num">{b["avg_ms"]:.1f}</td>'
                + f'<td class="num {klass}">{b["infra_err"]}</td>'
                + f'<td class="num">{b["replayed"]}</td>'
                + f'<td class="num">{b["matched"]}</td>'
                + f'<td class="num">{b["mismatched"]}</td>'
                + "</tr>"
            )
    out.append("</table></div>")
    return "\n".join(out)


def render_infra_errors(data: dict) -> str:
    """Infrastructure errors: LDAP did not reply at all (the only real failures)."""
    infra = data["infra_err_count"]
    if infra == 0:
        return (
            '<h3>Infrastructure errors</h3>'
            '<p class="ok">No infrastructure errors: LDAP replied on every operation.</p>'
        )
    parts = [f'<h3>Infrastructure errors ({infra})</h3>']
    max_shown = 200
    shown = data["infra_errors"][:max_shown]
    rows = "\n".join(f"<div>{_escape(f)}</div>" for f in shown)
    extra = max(0, infra - max_shown)
    parts.append(
        f'<p class="muted">Showing first {min(max_shown, infra)} of {infra} '
        f'infrastructure errors:</p>'
        f'<div class="failure-list">{rows}</div>'
        + (f'<p class="muted">... and {extra} more.</p>' if extra else "")
    )
    return "\n".join(parts)


def render_fidelity_mismatches(data: dict) -> str:
    """Fidelity mismatches: LDAP replied but the result differs from the log."""
    mismatch = data["fidelity_mismatch_count"]
    if mismatch == 0:
        return (
            '<h3>Fidelity mismatches</h3>'
            '<p class="ok">All replays matched the log.</p>'
        )
    parts = [f'<h3>Fidelity mismatches ({mismatch})</h3>']
    max_shown = 100
    shown = data["fidelity_mismatches"][:max_shown]
    rows = "\n".join(f"<div>{_escape(f)}</div>" for f in shown)
    extra = max(0, mismatch - max_shown)
    parts.append(
        f'<p class="muted">Showing first {min(max_shown, mismatch)} of {mismatch} '
        f'mismatches (LDAP replied successfully but the result differs from the log):</p>'
        f'<div class="failure-list">{rows}</div>'
        + (f'<p class="muted">... and {extra} more.</p>' if extra else "")
    )
    return "\n".join(parts)


def _mismatch_type(f: str) -> str:
    m = re.search(r"\b(BIND|SRCH|CMP|UNBIND|ABANDON)\b", f)
    return m.group(1) if m else "OTHER"


def render_failure_classification(data: dict) -> str:
    """Classify fidelity mismatches by their first line prefix."""
    classes: dict[str, int] = {}
    for f in data["fidelity_mismatches"]:
        kind = _mismatch_type(f)
        if "EXPECTED" in f:
            reason = f.split("EXPECTED", 1)[1].split(",")[0].strip()
            key = f"{kind} entries mismatch ({reason})"
        elif "without binddn" in f:
            key = f"{kind} anonymous bind (no DN in log)"
        elif "resultCode=" in f:
            code = f.split("resultCode=", 1)[1].split(",")[0].strip()
            key = f"{kind} resultCode={code}"
        elif "restricted" in f.lower():
            key = f"{kind} proxy restriction"
        else:
            key = f"{kind} other"
        classes[key] = classes.get(key, 0) + 1
    if not classes:
        return '<p class="muted ok">No fidelity mismatches.</p>'
    total = sum(classes.values())
    out = [
        '<table>',
        "<tr><th>FIDELITY MISMATCH CLASS</th><th class='num'>Count</th><th class='num'>%</th></tr>",
    ]
    for cls, count in sorted(classes.items(), key=lambda x: -x[1])[:15]:
        pct = 100 * count / total
        out.append(
            f'<tr><td>{_escape(cls)}</td>'
            f'<td class="num">{count}</td>'
            f'<td class="num">{pct:.1f}%</td></tr>'
        )
    out.append("</table>")
    return "\n".join(out)


def parse_host_metrics(path: Path) -> dict:
    from datetime import datetime
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    if not lines:
        return {}
    header = lines[0].split(",")
    cols = {name: [] for name in header}
    times, labels = [], []
    for raw in lines[1:]:
        if not raw.strip():
            continue
        parts = raw.split(",")
        if len(parts) != len(header):
            continue
        for name, val in zip(header, parts):
            try:
                cols[name].append(float(val))
            except ValueError:
                cols[name].append(0.0)
        ts = raw.split(",", 1)[0]
        if "Z." in ts:
            base, frac = ts.split("Z.", 1)
            ts = f"{base}.{frac}+00:00"
        else:
            ts = ts.replace("Z", "+00:00")
        try:
            t = datetime.fromisoformat(ts)
        except ValueError:
            t = None
        times.append(t)
    if times and times[0]:
        labels = [_fmt_elapsed((t - times[0]).total_seconds()) if t else str(i)
                  for i, t in enumerate(times)]
    else:
        labels = [str(i) for i in range(len(times))]
    return {"cols": cols, "times": times, "labels": labels, "n": len(times)}


def _fmt_elapsed(seconds: float) -> str:
    s = int(round(seconds))
    if s < 0:
        s = 0
    m, sec = divmod(s, 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}:{m:02d}:{sec:02d}"
    return f"{m}:{sec:02d}"


def parse_jtl(path: Path) -> dict:
    import csv as _csv
    from datetime import datetime, timezone
    ops = []
    try:
        fh = path.open(encoding="utf-8", errors="replace")
    except OSError:
        return {"ops": [], "t0": None, "t1": None}
    with fh:
        reader = _csv.reader(fh)
        header = next(reader, None)
        if not header:
            return {"ops": [], "t0": None, "t1": None}
        idx_ts = header.index("timeStamp") if "timeStamp" in header else 0
        idx_el = header.index("elapsed") if "elapsed" in header else 1
        idx_ok = header.index("success") if "success" in header else 7
        idx_lbl = header.index("label") if "label" in header else 2
        idx_msg = header.index("responseMessage") if "responseMessage" in header else 4
        for row in reader:
            if len(row) <= max(idx_ts, idx_el, idx_ok):
                continue
            rc = row[3] if len(row) > 3 else ""
            # Operation sub-samples have an empty responseCode; the parent
            # sample (the whole replay) has "200" and must be skipped.
            if rc not in ("", None):
                continue
            try:
                ts_ms = int(row[idx_ts])
                elapsed = float(row[idx_el])
                success = str(row[idx_ok]).strip().lower() == "true"
            except ValueError:
                continue
            msg = row[idx_msg] if idx_msg < len(row) else ""
            label = row[idx_lbl] if idx_lbl < len(row) else ""
            ops.append({
                "t": datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc),
                "elapsed": elapsed,
                "success": success,
                "label": label,
                "type": msg.split(" ", 1)[0] if msg.split(" ", 1)[0]
                        in ("BIND", "SRCH", "CMP", "UNBIND", "ABANDON") else "OTHER",
            })
    ops.sort(key=lambda o: o["t"])
    return {"ops": ops,
            "t0": ops[0]["t"] if ops else None,
            "t1": ops[-1]["t"] if ops else None}


def _col(hm: dict, name: str) -> List[float]:
    return hm["cols"].get(name, [])


def _chart_tip_data(series: List[Tuple[str, str, list]], labels: List[str],
                    x0: float, xspan: float) -> str:
    payload = {
        "x0": x0,
        "xspan": xspan,
        "labels": [str(l) for l in labels],
        "series": [
            {"name": n, "color": c,
             "values": [v if v is not None else None for v in vals]}
            for n, c, vals in series
        ],
    }
    return html.escape(json.dumps(payload), quote=True)


def render_line_chart(title: str, series: List[Tuple[str, str, List[float]]],
                      labels: List[str], unit: str = "",
                      y_fmt: str = "{:.0f}") -> str:
    n = max((len(v) for _, _, v in series), default=0)
    if n == 0:
        return '<p class="muted">No data.</p>'
    width, height, chart_h = 1000, 300, 240
    pad_l, pad_r, pad_b = 46, 12, 26
    x_step = (width - pad_l - pad_r) / max(1, n - 1)
    all_v = [v for _, _, vals in series for v in vals if v == v]
    if not all_v:
        return '<p class="muted">No data.</p>'
    vmax = max(all_v)
    vmin = min(0.0, min(all_v))
    span = (vmax - vmin) or 1.0
    def X(i): return pad_l + i * x_step
    def Y(v): return chart_h - (v - vmin) / span * chart_h + 8
    parts = [f'<h3>{_escape(title)}</h3>',
             f'<div class="chart" data-tip="{_chart_tip_data(series, labels, pad_l, width - pad_l - pad_r)}">'
             f'<svg viewBox="0 0 {width} {height}" '
             f'preserveAspectRatio="xMidYMid meet">']
    for k in range(5):
        v = vmin + span * k / 4
        y = Y(v)
        parts.append(f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width - pad_r}" '
                     f'y2="{y:.1f}" stroke="#334155" stroke-width="0.5"/>')
        parts.append(f'<text x="{pad_l - 6}" y="{y + 3:.1f}" fill="#94a3b8" '
                     f'font-size="9" text-anchor="end">{y_fmt.format(v)}{_escape(unit)}</text>')
    tick_idx = sorted({0, n - 1} | {round(i * (n - 1) / 6) for i in range(1, 6) if i < 6})
    for i in tick_idx:
        if 0 <= i < len(labels):
            parts.append(f'<text x="{X(i):.1f}" y="{height - 8:.1f}" fill="#94a3b8" '
                         f'font-size="9" text-anchor="middle">{_escape(labels[i])}</text>')
    for name, colour, vals in series:
        pts = [(X(i), Y(v)) for i, v in enumerate(vals) if i < len(vals)]
        if len(pts) > 1:
            parts.append(f'<polyline points="{" ".join(f"{x:.1f},{y:.1f}" for x, y in pts)}" '
                         f'fill="none" stroke="{colour}" stroke-width="1.5"/>')
        for x, y in pts:
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2" fill="{colour}"/>')
    parts.append("</svg>")
    legend = " ".join(
        f'<span class="swatch" style="background:{colour}"></span>{_escape(name)}'
        for name, colour, _ in series
    )
    parts.append(f'<div class="muted" style="font-size:0.8em; margin-top:6px;">{legend}</div>')
    parts.append('<div class="chart-tip"></div></div>')
    return "\n".join(parts)


def render_server_resources(hm: dict) -> str:
    if not hm.get("n"):
        return '<p class="muted">No host metrics collected for this step.</p>'
    labels = hm["labels"]
    instances = sorted({
        name.split("_")[1]
        for name in hm["cols"] if name.startswith("slapd_") and name.endswith("_cpu_usr")
    })
    out = []
    out.append(render_line_chart(
        "Host CPU (" + LDAP_HOST_LABEL + ", %)",
        [("user", "#4ade80", _col(hm, "host_cpu_usr")),
         ("system", "#22d3ee", _col(hm, "host_cpu_sys")),
         ("iowait", "#fbbf24", _col(hm, "host_cpu_iowait")),
         ("steal", "#f87171", _col(hm, "host_cpu_steal"))],
        labels, unit="%"))
    out.append(render_line_chart(
        "Host memory (" + LDAP_HOST_LABEL + ", MB)",
        [("used", "#4ade80", _col(hm, "host_mem_used_mb")),
         ("cached", "#22d3ee", _col(hm, "host_mem_cached_mb")),
         ("available", "#fbbf24", _col(hm, "host_mem_avail_mb"))],
        labels, unit=" MB"))
    out.append(render_line_chart(
        "Host swap (" + LDAP_HOST_LABEL + ", MB)",
        [("swap used", "#f87171", _col(hm, "host_swap_used_mb")),
         ("swap total", "#94a3b8", _col(hm, "host_swap_total_mb"))],
        labels, unit=" MB"))
    cpu_series = []
    for inst in instances:
        vals = [u + s for u, s in zip(
            _col(hm, f"slapd_{inst}_cpu_usr"), _col(hm, f"slapd_{inst}_cpu_sys"))]
        cpu_series.append((inst, _colour(inst), vals))
    out.append(render_line_chart("slapd process CPU (user+system, %)", cpu_series,
                                 labels, unit="%"))
    out.append(render_line_chart("slapd process RSS (MB)", [
        (inst, _colour(inst), _col(hm, f"slapd_{inst}_rss_mb")) for inst in instances
    ], labels, unit=" MB"))
    out.append(render_line_chart("slapd LMDB mapping size (MB)", [
        (inst, _colour(inst), _col(hm, f"slapd_{inst}_lmdb_mb")) for inst in instances
    ], labels, unit=" MB"))
    return "\n".join(out)


def render_injector_resources(hm: dict) -> str:
    if not hm.get("n"):
        return '<p class="muted">No host metrics collected for this step.</p>'
    labels = hm["labels"]
    out = [
        render_line_chart("Injector host CPU (" + INJECTOR_HOST_LABEL + ", %)",
                          [("user", "#4ade80", _col(hm, INJECTOR_PREFIX + "_cpu_usr")),
                           ("system", "#22d3ee", _col(hm, INJECTOR_PREFIX + "_cpu_sys")),
                           ("iowait", "#fbbf24", _col(hm, INJECTOR_PREFIX + "_cpu_iowait")),
                           ("steal", "#f87171", _col(hm, INJECTOR_PREFIX + "_cpu_steal"))],
                          labels, unit="%"),
        render_line_chart("Injector host memory (" + INJECTOR_HOST_LABEL + ", MB)",
                          [("used", "#4ade80", _col(hm, INJECTOR_PREFIX + "_mem_used_mb")),
                           ("cached", "#22d3ee", _col(hm, INJECTOR_PREFIX + "_mem_cached_mb")),
                           ("available", "#fbbf24", _col(hm, INJECTOR_PREFIX + "_mem_avail_mb"))],
                          labels, unit=" MB"),
        render_line_chart("Injector host swap + load (" + INJECTOR_HOST_LABEL + ")",
                          [("swap used MB", "#f87171", _col(hm, INJECTOR_PREFIX + "_swap_used_mb")),
                           ("swap total MB", "#94a3b8", _col(hm, INJECTOR_PREFIX + "_swap_total_mb")),
                           ("load1 x100", "#fbbf24",
                            [v * 100 for v in _col(hm, INJECTOR_PREFIX + "_load1")])],
                          labels, y_fmt="{:.0f}"),
        render_line_chart("jMeter JVM CPU (%, user+system)",
                          [("jMeter", "#22d3ee", [u + s for u, s in zip(
                              _col(hm, "jmeter_cpu_usr"), _col(hm, "jmeter_cpu_sys"))])],
                          labels, unit="%"),
        render_line_chart("jMeter JVM RSS (MB)",
                          [("jMeter", "#22d3ee", _col(hm, "jmeter_rss_mb"))],
                          labels, unit=" MB"),
        render_line_chart("jMeter JVM threads",
                          [("threads", "#a78bfa", _col(hm, "jmeter_threads"))],
                          labels),
    ]
    return "\n".join(out)


def _colour(inst: str) -> str:
    palette = ["#4ade80", "#22d3ee", "#fbbf24", "#f87171", "#a78bfa",
               "#34d399", "#60a5fa", "#f472b6"]
    return palette[sum(ord(c) for c in inst) % len(palette)]


def _percentile(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def _align_series(hm: dict, jtl: dict, bucket_s: int = 30) -> dict:
    times = hm.get("times", [])
    ops = jtl.get("ops", [])
    refs = [t for t in (times[0] if times else None, jtl.get("t0")) if t is not None]
    if not refs:
        return {}
    t0 = min(refs)
    ends = [t for t in (times[-1] if times else None, jtl.get("t1")) if t is not None]
    duration_s = max(1.0, max((t - t0).total_seconds() for t in ends))
    n = int(duration_s // bucket_s) + 1
    per = [[] for _ in range(n)]
    for o in ops:
        idx = min(n - 1, int((o["t"] - t0).total_seconds() // bucket_s))
        per[idx].append(o["elapsed"])
    host_cpu_b = [[] for _ in range(n)]
    slapd_cpu_b = [[] for _ in range(n)]
    host_usr = hm["cols"].get("host_cpu_usr", [])
    host_sys = hm["cols"].get("host_cpu_sys", [])
    insts = sorted({name.split("_")[1] for name in hm["cols"]
                    if name.startswith("slapd_") and name.endswith("_cpu_usr")})
    for i, t in enumerate(times):
        if t is None:
            continue
        idx = min(n - 1, int((t - t0).total_seconds() // bucket_s))
        hu = host_usr[i] if i < len(host_usr) else 0.0
        hs = host_sys[i] if i < len(host_sys) else 0.0
        host_cpu_b[idx].append(hu + hs)
        ssum = 0.0
        for inst in insts:
            u = hm["cols"].get(f"slapd_{inst}_cpu_usr", [])
            s = hm["cols"].get(f"slapd_{inst}_cpu_sys", [])
            if i < len(u) and i < len(s):
                ssum += u[i] + s[i]
        slapd_cpu_b[idx].append(ssum)

    def _mean(vals: List[float]) -> float:
        return sum(vals) / len(vals) if vals else None

    tps = [len(b) / bucket_s for b in per]
    p99 = [_percentile(sorted(b), 99.0) if b else None for b in per]
    avg = [_mean(b) for b in per]
    host_cpu = [_mean(b) for b in host_cpu_b]
    slapd_cpu = [_mean(b) for b in slapd_cpu_b]
    labels = [_fmt_elapsed(i * bucket_s) for i in range(n)]
    return {"labels": labels, "tps": tps, "p99": p99, "avg": avg,
            "host_cpu": host_cpu, "slapd_cpu": slapd_cpu, "bucket_s": bucket_s}


def _saturation_episodes(align: dict, cpu_threshold: float = 85.0,
                         latency_factor: float = 3.0) -> List[dict]:
    labels = align["labels"]
    cpu = [c if c is not None else 0.0 for c in (align["host_cpu"] or align["slapd_cpu"])]
    p99 = align["p99"]
    p99_vals = [v for v in p99 if v is not None]
    base = sorted(p99_vals)[len(p99_vals) // 2] if p99_vals else 0.0
    episodes = []
    in_ep = False
    for i in range(len(labels)):
        c = cpu[i] if i < len(cpu) else None
        p = p99[i] if i < len(p99) else None
        sat_cpu = c is not None and c >= cpu_threshold
        sat_lat = p is not None and base > 0 and p >= base * latency_factor
        if sat_cpu or sat_lat:
            if not in_ep:
                episodes.append({"start": labels[i], "end": labels[i],
                                 "peak_cpu": 0.0, "peak_p99": 0.0, "buckets": 0})
                in_ep = True
            ep = episodes[-1]
            ep["end"] = labels[i]
            ep["buckets"] += 1
            if c is not None:
                ep["peak_cpu"] = max(ep["peak_cpu"], c)
            if p is not None:
                ep["peak_p99"] = max(ep["peak_p99"], p)
        else:
            in_ep = False
    return episodes


def _server_stall_episodes(jtl: dict, bucket_s: int = 5) -> List[dict]:
    ops = jtl.get("ops", [])
    t0 = jtl.get("t0")
    if not ops or t0 is None:
        return []
    duration_s = max(1.0, (jtl["t1"] - t0).total_seconds())
    n = int(duration_s // bucket_s) + 1
    counts = [0] * n
    for o in ops:
        idx = min(n - 1, int((o["t"] - t0).total_seconds() // bucket_s))
        counts[idx] += 1
    baseline = sorted(c for c in counts if c > 0)
    median = baseline[len(baseline) // 2] if baseline else 0
    if median <= 0:
        return []
    # A stall = several consecutive buckets with almost no completed
    # operation, surrounded by normal activity (i.e. not the ramp-up start
    # or the run end). Such periods are the signature of the LDAP server
    # stopping to reply (server CPU ~0), not of a client-side JVM GC pause.
    threshold = max(3, median // 10)
    episodes = []
    in_ep = False
    for i in range(n):
        stalled = counts[i] < threshold
        if stalled and not in_ep:
            in_ep = True
            episodes.append({"start": i, "end": i})
        elif stalled:
            episodes[-1]["end"] = i
        else:
            in_ep = False
    result = []
    for ep in episodes:
        s, e = ep["start"], ep["end"]
        if e - s + 1 < 2:
            continue
        prev_ok = s > 0 and counts[s - 1] >= threshold
        next_ok = e + 1 < n and counts[e + 1] >= threshold
        if not (prev_ok and next_ok):
            continue
        result.append({
            "start": _fmt_elapsed(s * bucket_s),
            "end": _fmt_elapsed((e + 1) * bucket_s),
            "duration_s": (e - s + 1) * bucket_s,
            "ops": sum(counts[s:e + 1]),
            "baseline_ops": median,
        })
    return result


def render_server_stall_table(entries: List[tuple]) -> str:
    rows = []
    for conc, jtl in entries:
        if not jtl or not jtl.get("ops"):
            continue
        for ep in _server_stall_episodes(jtl):
            rows.append(
                "<tr>"
                + f'<td class="lbl">{conc}</td>'
                + f'<td class="num">{_escape(ep["start"])}</td>'
                + f'<td class="num">{_escape(ep["end"])}</td>'
                + f'<td class="num">{ep["duration_s"]}</td>'
                + f'<td class="num">{ep["ops"]}</td>'
                + f'<td class="num">{ep["baseline_ops"]}</td>'
                + "</tr>"
            )
    if not rows:
        return ""
    return (
        "<h2>Server non-response episodes</h2>"
        '<div class="scroll-x"><table>'
        "<tr><th>CONCURRENCY</th><th class='num'>Start</th>"
        "<th class='num'>End</th><th class='num'>Duration (s)</th>"
        "<th class='num'>Ops completed</th>"
        "<th class='num'>Baseline ops/bucket</th></tr>"
        + "".join(rows)
        + "</table></div>"
        + '<p class="muted">Periods where the LDAP server stopped '
          'replying: no operation completed for several seconds while '
          'the surrounding load was normal. The server CPU drops to '
          '~0 during these pauses — this is a server-side stall, not '
          'a client-side JVM garbage-collection pause (a GC freeze '
          'would leave the server CPU busy).</p>'
    )


def render_correlation(data: dict) -> str:
    hm = data.get("host_metrics") or {}
    jtl = data.get("jtl") or {}
    if not hm.get("n") or not jtl.get("ops"):
        return '<p class="muted">Correlation needs both host metrics and JTL samples.</p>'
    duration_s = max(1.0, (jtl["t1"] - jtl["t0"]).total_seconds())
    bucket_s = 30 if duration_s > 900 else 10
    align = _align_series(hm, jtl, bucket_s)
    if not align:
        return '<p class="muted">No alignable samples.</p>'
    labels = align["labels"]
    cpu_series = [("host CPU %", "#4ade80",
                   [c if c is not None else 0.0 for c in align["host_cpu"]])]
    if any(v is not None for v in align["slapd_cpu"]):
        cpu_series.append(("slapd CPU %", "#22d3ee",
                           [c if c is not None else 0.0 for c in align["slapd_cpu"]]))
    out = [
        render_toggle_chart("Load (TPS) vs server CPU",
                            [("TPS", "#a78bfa", [round(v, 1) for v in align["tps"]]),
                             ("host CPU %", "#4ade80",
                              [c if c is not None else 0.0 for c in align["host_cpu"]]),
                             *cpu_series[1:]],
                            labels, unit="", y_fmt="{:.1f}"),
        render_toggle_chart("Latency tail (p99) vs server CPU",
                            [("p99 ms", "#f87171",
                              [v if v is not None else 0.0 for v in align["p99"]]),
                             ("AVG ms", "#fbbf24",
                              [v if v is not None else 0.0 for v in align["avg"]]),
                             ("host CPU %", "#4ade80",
                              [c if c is not None else 0.0 for c in align["host_cpu"]]),
                             *cpu_series[1:]],
                            labels, unit="", y_fmt="{:.1f}"),
    ]
    episodes = _saturation_episodes(align)
    if episodes:
        rows = ["<tr><th class='num'>Start</th><th class='num'>End</th>"
                "<th class='num'>Buckets</th><th class='num'>Peak CPU %</th>"
                "<th class='num'>Peak p99 ms</th></tr>"]
        for ep in episodes:
            rows.append(
                "<tr>"
                + f'<td class="num">{_escape(ep["start"])}</td>'
                + f'<td class="num">{_escape(ep["end"])}</td>'
                + f'<td class="num">{ep["buckets"]}</td>'
                + f'<td class="num">{ep["peak_cpu"]:.0f}</td>'
                + f'<td class="num">{ep["peak_p99"]:.0f}</td>'
                + "</tr>"
            )
        out.append(
            '<h3>Saturation episodes</h3><div class="scroll-x"><table>'
            + "".join(rows)
            + "</table></div>"
            + '<p class="muted">A bucket is saturated when the host/slapd CPU '
              'is above 85% or the p99 latency exceeds 3x its median baseline. '
              'These are the periods where the server is close to its limit.</p>'
        )
    else:
        out.append('<p class="muted">No saturation episode detected '
                   '(CPU &lt; 85% and p99 latency &lt; 3x baseline throughout).</p>')
    return "\n".join(out)


def _queue_analysis(jtl: dict, bucket_s: int = 60) -> dict:
    ops = jtl.get("ops", [])
    t0 = jtl.get("t0")
    if not ops or t0 is None:
        return {}
    duration_s = max(1.0, (jtl["t1"] - t0).total_seconds())
    events = []
    for o in ops:
        start = (o["t"] - t0).total_seconds()
        events.append((start, 1))
        events.append((start + o["elapsed"] / 1000.0, -1))
    events.sort()
    steps, running, last_t = [], 0, 0.0
    for t, d in events:
        if t > last_t:
            steps.append((last_t, running, t))
            last_t = t
        running += d
    steps.append((last_t, running, duration_s))
    # Assign each op its in-flight concurrency. `steps` is sorted by start
    # time and contiguous, so bisect gives the matching band in O(log n)
    # instead of scanning every step per op.
    starts = [a for (a, _, _) in steps]
    vals = [v for (_, v, _) in steps]
    for o in ops:
        start = (o["t"] - t0).total_seconds()
        idx = bisect.bisect_right(starts, start) - 1
        o["inflight"] = vals[idx] if idx >= 0 else 0
    infls = sorted(o["inflight"] for o in ops)
    q = [infls[int(len(infls) * k / 4)] for k in range(1, 4)]
    bands = [(0.0, q[0]), (q[0], q[1]), (q[1], q[2]), (q[2], float("inf"))]
    names = ["Q1 (lowest load)", "Q2", "Q3", "Q4 (highest load)"]
    rows = []
    for (lo, hi), name in zip(bands, names):
        if hi == float("inf"):
            sel = [o for o in ops if o["inflight"] >= lo]
            rng = f"\u2265 {lo:.0f}"
        else:
            sel = [o for o in ops if lo <= o["inflight"] < hi]
            rng = f"{lo:.0f}\u2013{hi:.0f}"
        if not sel:
            continue
        el = sorted(o["elapsed"] for o in sel)
        rows.append({
            "band": name, "range": rng, "n": len(el),
            "avg": sum(el) / len(el),
            "p50": _percentile(el, 50), "p95": _percentile(el, 95),
            "p99": _percentile(el, 99), "max": el[-1],
        })
    return {"rows": rows, "bucket_s": bucket_s}


def render_queue_analysis(data: dict) -> str:
    jtl = data.get("jtl") or {}
    if not jtl.get("ops"):
        return '<p class="muted">No JTL samples for queue analysis.</p>'
    qa = _queue_analysis(jtl, 60)
    out = []
    if qa.get("rows"):
        rows = ["<tr><th>Load band</th><th class='num'>In-flight conns</th>"
                "<th class='num'>Ops</th><th class='num'>AVG ms</th>"
                "<th class='num'>p50</th><th class='num'>p95</th>"
                "<th class='num'>p99</th><th class='num'>MAX ms</th></tr>"]
        for r in qa["rows"]:
            rows.append(
                "<tr>"
                + f'<td>{_escape(r["band"])}</td>'
                + f'<td class="num">{_escape(r["range"])}</td>'
                + f'<td class="num">{r["n"]}</td>'
                + f'<td class="num">{r["avg"]:.2f}</td>'
                + f'<td class="num">{r["p50"]:.2f}</td>'
                + f'<td class="num">{r["p95"]:.2f}</td>'
                + f'<td class="num">{r["p99"]:.2f}</td>'
                + f'<td class="num">{r["max"]:.2f}</td>'
                + "</tr>"
            )
        out.append(
            '<h3>Latency by load quartile</h3><div class="scroll-x"><table>'
            + "".join(rows)
            + "</table></div>"
            + '<p class="muted">Operations are grouped by the number of '
              'in-flight connections at their start. A sharp rise of p95/p99 '
              'between Q3 and Q4 is the signature of queueing (the server '
              'starts to make operations wait).</p>'
        )
    t0 = jtl.get("t0")
    ops = jtl.get("ops", [])
    if t0 and ops:
        duration_s = max(1.0, (jtl["t1"] - t0).total_seconds())
        bucket_s = 60
        n = int(duration_s // bucket_s) + 1
        per = [[] for _ in range(n)]
        for o in ops:
            idx = min(n - 1, int((o["t"] - t0).total_seconds() // bucket_s))
            per[idx].append(o["elapsed"])
        labels = [_fmt_elapsed(i * bucket_s) for i in range(n)]
        p99_series = [_percentile(sorted(b), 99.0) if b else None for b in per]
        tps_series = [len(b) / bucket_s for b in per]
        out.append(render_toggle_chart(
            "p99 latency per minute (ms) with throughput",
            [("p99 ms", "#f87171",
              [v if v is not None else 0.0 for v in p99_series]),
             ("TPS", "#a78bfa", [round(v, 1) for v in tps_series])],
            labels, unit="", y_fmt="{:.1f}"))
    return "\n".join(out)


def render_transaction_summary(jtl: dict) -> str:
    import statistics as _stat
    ops = jtl.get("ops", [])
    if not ops:
        return '<p class="muted">No JTL samples for this step.</p>'
    types = ["BIND", "SRCH", "CMP", "UNBIND", "ABANDON"] + sorted(
        {o["type"] for o in ops
         if o["type"] not in ("BIND", "SRCH", "CMP", "UNBIND", "ABANDON")})
    out = ['<div class="scroll-x"><table>',
           "<tr><th>TRANSACTION</th><th class='num'>Total</th><th class='num'>Min</th>"
           "<th class='num'>Avg</th><th class='num'>Max</th><th class='num'>Std Dev</th>"
           "<th class='num'>90%</th><th class='num'>Pass</th><th class='num'>Fail</th></tr>"]
    for typ in types:
        rows = [o for o in ops if o["type"] == typ]
        if not rows:
            continue
        el = sorted(o["elapsed"] for o in rows)
        total = len(el)
        mn, mx = el[0], el[-1]
        avg = _stat.fmean(el)
        std = _stat.pstdev(el) if total > 1 else 0.0
        p90 = el[int(total * 0.9) - 1] if total else 0.0
        passed = sum(1 for o in rows if o["success"])
        failed = total - passed
        out.append(
            "<tr>"
            + f"<td>{_escape(typ)}</td>"
            + f'<td class="num">{total}</td>'
            + f'<td class="num">{mn:.3f}</td>'
            + f'<td class="num">{avg:.3f}</td>'
            + f'<td class="num">{mx:.3f}</td>'
            + f'<td class="num">{std:.3f}</td>'
            + f'<td class="num">{p90:.3f}</td>'
            + f'<td class="num">{passed}</td>'
            + f'<td class="num {"danger" if failed else ""}">{failed}</td>'
            + "</tr>"
        )
    out.append("</table></div>")
    return "\n".join(out)


def render_all_operations(jtl: dict, conc=None) -> str:
    ops = jtl.get("ops", [])
    if not ops:
        return '<p class="muted">No JTL samples for this step.</p>'
    t0 = jtl["t0"]
    duration_s = max(1.0, (jtl["t1"] - t0).total_seconds())
    # Adaptive bucket size: 5s for short runs, 60s for long ones.
    bucket_s = 5 if duration_s <= 300 else 60
    n_buckets = int(duration_s // bucket_s) + 1
    per_bucket = [[] for _ in range(n_buckets)]
    for o in ops:
        idx = min(n_buckets - 1, int((o["t"] - t0).total_seconds() // bucket_s))
        per_bucket[idx].append(o)
    labels = [_fmt_elapsed(i * bucket_s) for i in range(n_buckets)]
    tps = [len(b) / bucket_s for b in per_bucket]
    avg_lat = [sum(o["elapsed"] for o in b) / len(b) if b else 0.0 for b in per_bucket]
    # Build the in-flight concurrency curve from +1/-1 events at each
    # operation start/end, then evaluate it at 1s resolution.
    events = []
    for o in ops:
        start = (o["t"] - t0).total_seconds()
        events.append((start, 1))
        events.append((start + o["elapsed"] / 1000.0, -1))
    events.sort()
    steps, running, last_t = [], 0, 0.0
    for t, d in events:
        if t > last_t:
            steps.append((last_t, running, t))
            last_t = t
        running += d
    steps.append((last_t, running, duration_s))
    sample_t, sample_c = [], []
    for s in range(0, int(duration_s) + 1):
        c = 0
        for (a, v, b) in steps:
            if a <= s < b:
                c = v
        sample_t.append(s)
        sample_c.append(c)
    sample_labels = [_fmt_elapsed(s) for s in sample_t]
    out = [
        render_transaction_summary(jtl),
        render_line_chart("Transactions per second", [("tps", "#4ade80", tps)],
                          labels, unit="/s", y_fmt="{:.1f}"),
        render_line_chart("Average transaction response time (ms)",
                          [("AVGms", "#fbbf24", [round(v, 1) for v in avg_lat])],
                          labels, unit=" ms"),
        render_line_chart("Concurrent connections",
                          [("in flight", "#22d3ee", [float(v) for v in sample_c])],
                          sample_labels),
    ]
    stall_html = render_server_stall_table([(conc, jtl)])
    if stall_html:
        out.append(stall_html)
    return "\n".join(out)


TOGGLE_JS = """
<script>
function toggleSeries(name, checked) {
  var els = document.querySelectorAll('[data-series="' + name + '"]');
  for (var i = 0; i < els.length; i++) {
    els[i].style.display = checked ? '' : 'none';
  }
}
function fmtNum(v) {
  if (v === null || v === undefined) return '';
  var n = Number(v);
  if (!isFinite(n)) return String(v);
  return n.toLocaleString('en-US', {maximumFractionDigits: 3});
}
function bindTooltips() {
  var charts = document.querySelectorAll('.chart[data-tip]');
  for (var c = 0; c < charts.length; c++) {
    (function (chart) {
      var data;
      try { data = JSON.parse(chart.getAttribute('data-tip')); } catch (e) { return; }
      if (!data || !data.series || data.series.length === 0) return;
      if (data.series.length > 10) return;
      if (data.labels.length > 200) return;
      var svg = chart.querySelector('svg');
      var tip = chart.querySelector('.chart-tip');
      if (!svg || !tip) return;
      var span = data.xspan || 0;
      svg.addEventListener('mousemove', function (ev) {
        var rect = svg.getBoundingClientRect();
        var x = (ev.clientX - rect.left) / rect.width * 1000;
        var idx = Math.round((x - data.x0) / (span / Math.max(1, data.labels.length - 1)));
        if (idx < 0) idx = 0;
        if (idx >= data.labels.length) idx = data.labels.length - 1;
        var html = '<div class="tip-title">' + data.labels[idx] + '</div>';
        for (var s = 0; s < data.series.length; s++) {
          var v = data.series[s].values[idx];
          if (v === null || v === undefined) continue;
          html += '<div class="tip-row"><span class="swatch" style="background:' +
                  data.series[s].color + '"></span>' + data.series[s].name +
                  ': ' + fmtNum(v) + '</div>';
        }
        tip.innerHTML = html;
        tip.style.display = 'block';
        var cRect = chart.getBoundingClientRect();
        tip.style.left = (ev.clientX - cRect.left + 14) + 'px';
        tip.style.top = (ev.clientY - cRect.top + 14) + 'px';
      });
      svg.addEventListener('mouseleave', function () { tip.style.display = 'none'; });
    })(charts[c]);
  }
}
document.addEventListener('DOMContentLoaded', bindTooltips);
</script>
"""


def _concat_num(path: Path) -> int:
    m = re.search(r"conc_(\d+)", path.name)
    return int(m.group(1)) if m else 0


def collect_steps(runs_dir: Path) -> List[dict]:
    steps = []
    for rep in sorted(runs_dir.glob("conc_*/replay_report.txt")):
        d = rep.parent
        data = parse_report(rep)
        jtl_path = d / "results.jtl"
        if jtl_path.exists():
            data["jtl"] = parse_jtl(jtl_path)
        steps.append({"conc": _concat_num(d), "dir": d.name, "data": data})
    steps.sort(key=lambda s: s["conc"])
    return steps


def _tx_stats(ops: List[dict], typ: str) -> dict:
    import statistics as _stat
    rows = [o for o in ops if o["type"] == typ]
    el = sorted(o["elapsed"] for o in rows)
    total = len(el)
    if not total:
        return {"total": 0, "min": 0.0, "avg": 0.0, "max": 0.0,
                "std": 0.0, "p90": 0.0, "passed": 0, "failed": 0}
    passed = sum(1 for o in rows if o["success"])
    return {
        "total": total,
        "min": el[0],
        "avg": _stat.fmean(el),
        "max": el[-1],
        "std": _stat.pstdev(el) if total > 1 else 0.0,
        "p90": el[int(total * 0.9) - 1],
        "passed": passed,
        "failed": total - passed,
    }


def _jtl_curves(jtl: dict, bucket_s: int) -> List[dict]:
    ops = jtl.get("ops", [])
    t0 = jtl["t0"]
    duration_s = max(1.0, (jtl["t1"] - t0).total_seconds())
    n_buckets = int(duration_s // bucket_s) + 1
    per = [[] for _ in range(n_buckets)]
    for o in ops:
        idx = min(n_buckets - 1, int((o["t"] - t0).total_seconds() // bucket_s))
        per[idx].append(o)
    events = []
    for o in ops:
        start = (o["t"] - t0).total_seconds()
        events.append((start, 1))
        events.append((start + o["elapsed"] / 1000.0, -1))
    events.sort()
    steps, running, last_t = [], 0, 0.0
    for t, d in events:
        if t > last_t:
            steps.append((last_t, running, t))
            last_t = t
        running += d
    steps.append((last_t, running, duration_s))
    inflight = []
    for s in range(0, int(duration_s) + 1):
        c = 0
        for (a, v, b) in steps:
            if a <= s < b:
                c = v
        inflight.append(c)
    out = []
    for i in range(n_buckets):
        b = per[i]
        s0, s1 = i * bucket_s, min((i + 1) * bucket_s, int(duration_s) + 1)
        seg = inflight[s0:s1]
        out.append({
            "count": len(b),
            "avg_lat": sum(o["elapsed"] for o in b) / len(b) if b else None,
            "avg_inflight": sum(seg) / len(seg) if seg else 0.0,
        })
    return out


def render_toggle_chart(title: str, series: List[Tuple[str, str, list]],
                        labels: List[str], unit: str = "", y_fmt: str = "{:.1f}") -> str:
    maxv = 1.0
    for _, _, vals in series:
        for v in vals:
            if v is not None:
                maxv = max(maxv, v)
    width, height, chart_h = 1000, 300, 230
    out = [f"<h3>{_escape(title)}</h3>", '<div class="toggle-legend">']
    for name, color, _ in series:
        out.append(
            f'<label class="toggle"><input type="checkbox" checked '
            f'onchange="toggleSeries(\'{_escape(name)}\', this.checked)">'
            f'<span class="swatch" style="background:{color}"></span>'
            f"{_escape(name)}</label>"
        )
    out.append("</div>")
    tip_data = _chart_tip_data(series, labels, 40, width - 50)
    out.append(
        f'<div class="chart" data-tip="{tip_data}">'
        f'<svg viewBox="0 0 {width} {height}" '
        f'preserveAspectRatio="xMidYMid meet">'
    )
    for tick in (0, 0.25, 0.5, 0.75, 1.0):
        y = chart_h - chart_h * tick + 10
        out.append(
            f'<line x1="40" y1="{y:.1f}" x2="{width - 10}" y2="{y:.1f}" '
            f'stroke="#334155" stroke-width="0.5"/>'
            f'<text x="36" y="{y + 3:.1f}" fill="#94a3b8" font-size="9" '
            f'text-anchor="end">{maxv * tick:.1f}</text>'
        )
    n = len(labels)
    for name, color, vals in series:
        pts = []
        for i, v in enumerate(vals):
            if v is None:
                continue
            x = 40 + i * (width - 50) / max(1, n - 1)
            y = chart_h - chart_h * v / maxv + 10
            pts.append(f"{x:.1f},{y:.1f}")
            out.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.5" fill="{color}" '
                f'data-series="{_escape(name)}">'
                f"<title>{_escape(name)} : {_escape(labels[i])} : "
                f"{y_fmt.format(v)}{unit}</title></circle>"
            )
        if len(pts) > 1:
            out.append(
                f'<polyline points="{" ".join(pts)}" fill="none" '
                f'stroke="{color}" stroke-width="2" data-series="{_escape(name)}"/>'
            )
    label_every = max(1, n // 10)
    for i, lab in enumerate(labels):
        if i % label_every == 0 or i == n - 1:
            x = 40 + i * (width - 50) / max(1, n - 1)
            out.append(
                f'<text x="{x:.1f}" y="{height - 4:.1f}" fill="#94a3b8" '
                f'font-size="9" text-anchor="middle">{_escape(lab)}</text>'
            )
    out.append("</svg>")
    out.append('<div class="chart-tip"></div></div>')
    return "\n".join(out)


def render_compare_matrix(steps: List[dict], typ: str) -> str:
    out = [f"<h3>{_escape(typ)}</h3>", '<div class="scroll-x"><table>',
           "<tr><th>CONCURRENCY</th><th class='num'>Total</th><th class='num'>Min</th>"
           "<th class='num'>Avg</th><th class='num'>Max</th><th class='num'>Std Dev</th>"
           "<th class='num'>90%</th><th class='num'>Pass</th><th class='num'>Fail</th></tr>"]
    for s in steps:
        jtl = s["data"].get("jtl")
        if not jtl:
            continue
        st = _tx_stats(jtl.get("ops", []), typ)
        out.append(
            "<tr>"
            + f'<td class="lbl"><a href="conc_{s["conc"]}.html">{s["conc"]}</a></td>'
            + f'<td class="num">{st["total"]}</td>'
            + f'<td class="num">{st["min"]:.3f}</td>'
            + f'<td class="num">{st["avg"]:.3f}</td>'
            + f'<td class="num">{st["max"]:.3f}</td>'
            + f'<td class="num">{st["std"]:.3f}</td>'
            + f'<td class="num">{st["p90"]:.3f}</td>'
            + f'<td class="num">{st["passed"]}</td>'
            + f'<td class="num {"danger" if st["failed"] else ""}">{st["failed"]}</td>'
            + "</tr>"
        )
    out.append("</table></div>")
    return "\n".join(out)


def render_compare_latency_table(rows: List[tuple], typ: str) -> str:
    out = [f"<h3>{_escape(typ)}</h3>", '<div class="scroll-x"><table>',
           "<tr><th>CONCURRENCY</th><th class='num'>AVGms</th><th class='num'>p95</th>"
           "<th class='num'>p99</th><th class='num'>MAXms</th></tr>"]
    for conc, r in rows:
        out.append(
            "<tr>"
            + f'<td class="lbl">{conc}</td>'
            + f'<td class="num">{float(r.get("AVGms", 0)):.3f}</td>'
            + f'<td class="num">{float(r.get("p95", 0)):.3f}</td>'
            + f'<td class="num">{float(r.get("p99", 0)):.3f}</td>'
            + f'<td class="num">{float(r.get("MAXms", 0)):.3f}</td>'
            + "</tr>"
        )
    out.append("</table></div>")
    return "\n".join(out)


def render_compare_html(steps: List[dict], runs_dir: Path,
                        injectors: str = "", targets: str = "") -> str:
    conc_colours = {s["conc"]: _colour(f"conc_{s['conc']}") for s in steps}
    conc_labels = [f"conc_{s['conc']}" for s in steps]
    metric_colours = {"AVGms": "#4ade80", "p95": "#fbbf24",
                      "p99": "#f87171", "MAXms": "#a78bfa"}
    conc_list = [s["conc"] for s in steps]
    first = steps[0]["data"] if steps else {}
    intro = render_intro(first, injectors, targets)

    order = ["BIND", "SRCH", "CMP", "UNBIND", "ABANDON"]
    present_types = []
    seen = set()
    for s in steps:
        for r in s["data"].get("metrics_by_type", []):
            t = r["TYPE"]
            if t not in seen:
                seen.add(t)
                present_types.append(t)
    present_types.sort(key=lambda t: order.index(t) if t in order else len(order))
    if not present_types:
        present_types = ["BIND", "SRCH"]

    body = [
        render_nav("compare", conc_list),
        "<h1>Load ramp comparison (concurrency 1 &rarr; 16)</h1>",
        intro,
        f'<p class="muted">Source: <code>{_escape(str(runs_dir))}</code> &middot; '
        f"{len(steps)} steps &middot; all charts use elapsed test time from zero "
        "(mm:ss). Toggle any curve on/off with its checkbox to compare; hover a "
        "chart to see the value of every curve at that instant.</p>",
        "<h2>Transaction summary by concurrency</h2>",
    ]
    for typ in present_types:
        body.append(render_compare_matrix(steps, typ))

    by_type = {}
    for s in steps:
        for r in s["data"].get("metrics_by_type", []):
            by_type.setdefault(r["TYPE"], []).append((s["conc"], r))
    percentile_colours = {"AVGms": "#4ade80", "p95": "#fbbf24", "p99": "#f87171"}
    for typ in present_types:
        rows = by_type.get(typ, [])
        if not rows:
            continue
        # A single step has only one point per metric, so a chart is
        # meaningless: render a table instead. Multi-step runs keep the
        # "vs concurrency" charts.
        if len(rows) < 2:
            body.append(f"<h2>{_escape(typ)} response time vs concurrency (ms)</h2>")
            body.append(render_compare_latency_table(rows, typ))
            continue
        series = []
        for met, col in percentile_colours.items():
            vals = [float(r.get(met, 0)) for _, r in rows]
            series.append((f"{typ} {met}", col, vals))
        labels = [str(c) for c, _ in rows]
        body.append(f"<h2>{_escape(typ)} response time vs concurrency (ms)</h2>")
        body.append(render_toggle_chart(
            f"{typ} AVGms / p95 / p99 vs concurrency", series, labels, unit=" ms"))
        max_series = [(f"{typ} MAXms", metric_colours["MAXms"],
                       [float(r.get("MAXms", 0)) for _, r in rows])]
        body.append(render_toggle_chart(
            f"{typ} MAXms vs concurrency (slowest single operation)",
            max_series, labels, unit=" ms"))

    curves_by_conc = {}
    max_duration_s = 0
    for s in steps:
        jtl = s["data"].get("jtl")
        if not jtl or not jtl.get("ops"):
            continue
        duration_s = max(1.0, (jtl["t1"] - jtl["t0"]).total_seconds())
        max_duration_s = max(max_duration_s, duration_s)
        curves_by_conc[s["conc"]] = _jtl_curves(jtl, 5)
    if curves_by_conc:
        n_buckets = int(max_duration_s // 5) + 1
        time_labels = [_fmt_elapsed(i * 5) for i in range(n_buckets)]

        def align(curves, key):
            vals = []
            for i in range(n_buckets):
                vals.append(curves[i][key] if i < len(curves) else None)
            return vals

        for typ in present_types:
            series = []
            for s in steps:
                jtl = s["data"].get("jtl")
                if not jtl or not jtl.get("ops"):
                    continue
                typed = {"ops": [o for o in jtl["ops"] if o["type"] == typ],
                         "t0": jtl["t0"], "t1": jtl["t1"]}
                cur = _jtl_curves(typed, 5)
                series.append((f"conc_{s['conc']}",
                               conc_colours[s["conc"]],
                               align(cur, "avg_lat")))
            body.append(f"<h2>{_escape(typ)} average response time over time (ms)</h2>")
            body.append(render_toggle_chart(
                f"{typ} AVGms over time", series, time_labels, unit=" ms"))

        series = []
        for s in steps:
            if s["conc"] not in curves_by_conc:
                continue
            series.append((f"conc_{s['conc']}",
                           conc_colours[s["conc"]],
                           [round(curves_by_conc[s["conc"]][i]["count"] / 5.0, 2)
                            if i < len(curves_by_conc[s["conc"]]) else None
                            for i in range(n_buckets)]))
        body.append("<h2>Transactions per second over time</h2>")
        body.append(render_toggle_chart(
            "Transactions per second", series, time_labels, unit="/s", y_fmt="{:.2f}"))

        series = []
        for s in steps:
            if s["conc"] not in curves_by_conc:
                continue
            series.append((f"conc_{s['conc']}",
                           conc_colours[s["conc"]],
                           align(curves_by_conc[s["conc"]], "avg_inflight")))
        body.append("<h2>Concurrent connections over time</h2>")
        body.append(render_toggle_chart(
            "Concurrent connections", series, time_labels, unit=""))

        stall_html = render_server_stall_table(
            [(s["conc"], s["data"].get("jtl")) for s in steps])
        if stall_html:
            body.append(stall_html)

    body.append(render_legend())

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        f"<title>Load ramp comparison</title>"
        f"<style>{CSS}</style></head>"
        f"<body>{''.join(body)}"
        f"{render_footer()}"
        f"{TOGGLE_JS}</body></html>"
    )


def render_master_html(steps: List[dict], runs_dir: Path,
                       injectors: str = "", targets: str = "") -> str:
    conc_list = [s["conc"] for s in steps]
    first = steps[0]["data"] if steps else {}
    intro = render_intro(first, injectors, targets)

    order = ["BIND", "SRCH", "CMP", "UNBIND", "ABANDON"]
    present_types = []
    seen = set()
    for s in steps:
        for r in s["data"].get("metrics_by_type", []):
            t = r["TYPE"]
            if t not in seen:
                seen.add(t)
                present_types.append(t)
    present_types.sort(key=lambda t: order.index(t) if t in order else len(order))
    if not present_types:
        present_types = ["BIND", "SRCH"]

    report_links = ['<div class="report-links">',
                    '<div class="link-card"><a href="compare.html">'
                    "<strong>Compare</strong><br>All concurrency levels in one "
                    "report (toggleable charts)</a></div>"]
    for s in steps:
        n = s["conc"]
        report_links.append(
            f'<div class="link-card"><a href="conc_{n}.html">'
            f"<strong>Load conc {n}</strong><br>Throughput, latency, behaviour "
            "over time, server resources</a></div>"
        )
        report_links.append(
            f'<div class="link-card"><a href="injector_conc_{n}.html">'
            f"<strong>Injector conc {n}</strong><br>Injector resources "
            "(" + INJECTOR_HOST_LABEL + " + jMeter JVM)</a></div>"
        )
        report_links.append(
            f'<div class="link-card"><a href="fidelity_conc_{n}.html">'
            f"<strong>Fidelity conc {n}</strong><br>Replay fidelity check "
            "vs the original log</a></div>"
        )
    report_links.append("</div>")

    body = [
        render_nav("index", conc_list),
        "<h1>LDAP ramp &mdash; report index</h1>",
        intro,
        f'<p class="muted">Runs directory: <code>{_escape(str(runs_dir))}</code> '
        f"&middot; {len(steps)} concurrency steps "
        f"({' &rarr; '.join(str(c) for c in conc_list)}). Use the tabs above or "
        "the cards below to open each report.</p>",
        "<h2>Reports</h2>",
        "".join(report_links),
        "<h2>Transaction summary by concurrency</h2>",
    ]
    for typ in present_types:
        body.append(render_compare_matrix(steps, typ))
    body.append(render_legend())
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        "<title>LDAP ramp &mdash; report index</title>"
        f"<style>{CSS}</style></head>"
        f"<body>{''.join(body)}"
        f"{render_footer()}"
        f"{TOGGLE_JS}</body></html>"
    )


def render_nav(active: str, steps: List[int]) -> str:
    def link(href: str, label: str, key: str) -> str:
        cls = " active" if key == active else ""
        return f'<a href="{href}" class="{cls}">{_escape(label)}</a>'
    parts = ['<nav class="topnav">',
             '<span class="brand">LDAP ramp</span>',
             link("index.html", "Index", "index"),
             link("compare.html", "Compare", "compare"),
             '<span class="group">Load:</span>']
    for n in steps:
        parts.append(link(f"conc_{n}.html", f"conc {n}", f"conc_{n}"))
    parts.append('<span class="group">Injector:</span>')
    for n in steps:
        parts.append(link(f"injector_conc_{n}.html", f"injector {n}", f"injector_{n}"))
    parts.append('<span class="group">Fidelity:</span>')
    for n in steps:
        parts.append(link(f"fidelity_conc_{n}.html", f"fid {n}", f"fidelity_{n}"))
    parts.append("</nav>")
    return "".join(parts)


def render_intro(data: dict, injectors: str, targets: str) -> str:
    source = data.get("source_file", "")
    duration = data.get("run_duration", "")
    m = re.search(r"(\d+)\s+operations", data.get("global", ""))
    total = m.group(1) if m else "?"
    return (
        '<p class="intro">This report was generated by replaying the recorded LDAP '
        f"scenario <code>{_escape(source)}</code> for a test duration of "
        f"<strong>{_escape(duration)}</strong> ({_escape(total)} operations), from "
        f"{_escape(injectors)} to {_escape(targets)}.</p>"
        '<p class="intro cache-note"><strong>Cache note:</strong> the LDAP '
        "instances were not restarted between runs, so their caches were not "
        "primed (they stayed warm). Two consecutive tests should therefore be "
        "identical; monitor this to keep the runs comparable.</p>"
    )


def render_footer() -> str:
    links = " &middot; ".join(
        f'<a href="{_escape(url)}">{_escape(url)}</a>' for url in PROJECT_URLS
    )
    return (
        f'<footer class="page-footer">Generated with '
        f"{_escape(PROJECT_NAME)} v{_escape(PROJECT_VERSION)} &mdash; "
        f"{links}</footer>"
    )


def render_html(data: dict, steps: List[int] = None,
                injectors: str = "", targets: str = "",
                conc: int = None) -> str:
    steps = steps or []
    title = "LDAP replay load report"
    body = (
        render_nav(f"conc_{conc}" if conc is not None else "conc", steps)
        + f"<h1>{_escape(title)}</h1>"
        + render_intro(data, injectors, targets)
        + "<h2>Summary</h2>"
        + render_kpis(data)
        + "<h2>Metrics by type (response times)</h2>"
        + render_metrics_table(data)
    )
    if data.get("jtl"):
        body += "<h2>All operations combined</h2>" + render_all_operations(data["jtl"], conc)
    if data.get("jtl"):
        body += "<h2>Queue analysis</h2>" + render_queue_analysis(data)
    body += (
        "<h2>Behaviour over time (per minute)</h2>"
        + render_timeline(data)
        + "<h2>Per-minute details</h2>"
        + render_per_minute_table(data)
    )
    if data.get("host_metrics") and data.get("jtl"):
        body += ("<h2>Latency / CPU correlation</h2>"
                 + render_correlation(data))
    if data.get("host_metrics"):
        body += ("<h2>Server resources (" + LDAP_HOST_LABEL.lower() + ")</h2>"
                 + render_server_resources(data["host_metrics"]))
    body += render_infra_errors(data)
    body += render_legend()
    return (
        "<!DOCTYPE html>\n"
        f'<html lang="en"><head><meta charset="utf-8">'
        f"<title>{_escape(title)}</title>"
        f"<style>{CSS}</style></head>"
        f"<body>{body}{render_footer()}{TOGGLE_JS}</body></html>"
    )


def render_injector_html(data: dict, steps: List[int] = None,
                       injectors: str = "", targets: str = "",
                       conc: int = None) -> str:
    steps = steps or []
    title = "LDAP replay injector report (" + INJECTOR_HOST_LABEL + ")"
    body = (
        render_nav(f"injector_{conc}" if conc is not None else "injector", steps)
        + f"<h1>{_escape(title)}</h1>"
        + render_intro(data, injectors, targets)
        + "<h2>Summary</h2>"
        + render_kpis(data)
    )
    if data.get("host_metrics"):
        body += ("<h2>Injector resources (" + INJECTOR_HOST_LABEL + " + jMeter JVM)</h2>"
                 + render_injector_resources(data["host_metrics"]))
    body += "<h2>Behaviour over time (per minute)</h2>" + render_timeline(data)
    body += render_legend()
    return (
        "<!DOCTYPE html>\n"
        f'<html lang="en"><head><meta charset="utf-8">'
        f"<title>{_escape(title)}</title>"
        f"<style>{CSS}</style></head>"
        f"<body>{body}{render_footer()}{TOGGLE_JS}</body></html>"
    )


def render_fidelity_html(data: dict, steps: List[int] = None,
                         conc: int = None, injectors: str = "",
                         targets: str = "") -> str:
    steps = steps or []
    title = "LDAP replay fidelity report"
    body = (
        render_nav(f"fidelity_{conc}" if conc is not None else "fidelity", steps)
        + f"<h1>{_escape(title)}</h1>"
        + render_intro(data, injectors, targets)
        + "<h2>Fidelity check</h2>"
        + render_fidelity_table(data)
        + "<h2>Fidelity mismatch classification</h2>"
        + render_failure_classification(data)
        + render_fidelity_mismatches(data)
        + render_legend()
    )
    return (
        "<!DOCTYPE html>\n"
        f'<html lang="en"><head><meta charset="utf-8">'
        f"<title>{_escape(title)}</title>"
        f"<style>{CSS}</style></head>"
        f"<body>{body}{render_footer()}</body></html>"
    )


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("report", type=Path, nargs="?", default=None,
                   help="replay_report.txt path (not needed with --compare)")
    p.add_argument("-o", "--output", type=Path, required=True,
                   help="HTML output path")
    p.add_argument("--host-metrics", type=Path, default=None,
                   help="host_metrics.csv path (adds server/injector curves)")
    p.add_argument("--jtl", type=Path, default=None,
                   help="results.jtl path (adds all-operations combined view)")
    p.add_argument("--fidelity", action="store_true",
                   help="generate a dedicated fidelity report instead of the "
                        "main load report")
    p.add_argument("--injector", action="store_true",
                   help="generate a dedicated injector (" + INJECTOR_HOST_LABEL + ") report")
    p.add_argument("--compare", type=Path, default=None, metavar="RUNS_DIR",
                   help="generate a multi-concurrency comparison report from "
                        "the conc_*/ subdirectories of RUNS_DIR")
    p.add_argument("--master", type=Path, default=None, metavar="RUNS_DIR",
                   help="generate the master index.html for the conc_*/ "
                        "subdirectories of RUNS_DIR")
    p.add_argument("--steps", type=str, default="",
                   help="comma-separated list of concurrency levels for the "
                        "navigation tabs (e.g. 1,2,4,8,16)")
    p.add_argument("--injectors", type=str, default="",
                   help="free-text description of the injector(s), e.g. "
                        "'1 injector (192.0.2.5)'")
    p.add_argument("--targets", type=str, default="",
                   help="free-text description of the target systems, e.g. "
                        "'the LDAP server (ldaps://ldap.example.org:"
                        "11636)'")
    args = p.parse_args()

    def _steps_arg() -> List[int]:
        return [int(x) for x in args.steps.split(",") if x.strip()]

    if args.master is not None:
        steps = collect_steps(args.master)
        if not steps:
            p.error(f"no conc_*/replay_report.txt found under {args.master}")
        page = render_master_html(steps, args.master,
                                  args.injectors, args.targets)
        args.output.write_text(page, encoding="utf-8")
        print(f"OK: {args.output} ({args.output.stat().st_size} bytes, "
              f"{len(steps)} steps)")
        return
    if args.compare is not None:
        steps = collect_steps(args.compare)
        if not steps:
            p.error(f"no conc_*/replay_report.txt found under {args.compare}")
        page = render_compare_html(steps, args.compare,
                                   args.injectors, args.targets)
        args.output.write_text(page, encoding="utf-8")
        print(f"OK: {args.output} ({args.output.stat().st_size} bytes, "
              f"{len(steps)} steps)")
        return
    data = parse_report(args.report)
    if args.host_metrics:
        data["host_metrics"] = parse_host_metrics(args.host_metrics)
    if args.jtl:
        data["jtl"] = parse_jtl(args.jtl)
    nav_steps = _steps_arg()
    conc = None
    m = re.search(r"conc_(\d+)\.html$", args.output.name)
    if m:
        conc = int(m.group(1))
    if args.fidelity:
        page = render_fidelity_html(data, nav_steps, conc,
                                    args.injectors, args.targets)
    elif args.injector:
        page = render_injector_html(data, nav_steps,
                                    args.injectors, args.targets, conc)
    else:
        page = render_html(data, nav_steps, args.injectors, args.targets, conc)
    args.output.write_text(page, encoding="utf-8")
    print(f"OK: {args.output} ({args.output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
