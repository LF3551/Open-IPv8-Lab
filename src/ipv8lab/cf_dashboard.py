# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Performance dashboard with CF (Cost Factor) visualisation.

Provides:
  - CF component breakdown for multiple paths
  - Path comparison with accumulated CF
  - Anomaly detection (physics floor violations)
  - Performance benchmark results
  - JSON API + single-page HTML dashboard

No external dependencies — uses stdlib http.server.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from ipv8lab.benchmark import BenchmarkResult, run_all as run_benchmarks
from ipv8lab.cost_factor import (
    CFComponents,
    accumulate_cf,
    cf_total,
    compute_cf,
    is_cf_anomaly,
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class PathEntry:
    """A path tracked in the dashboard."""

    path_id: str
    origin_asn: int
    as_path: list[int]
    components: CFComponents
    cf_value: int
    hop_cfs: list[int]
    distance_km: float = 0.0
    measured_rtt_ms: float = 0.0

    @property
    def accumulated_cf(self) -> int:
        return accumulate_cf(self.hop_cfs) if self.hop_cfs else self.cf_value

    @property
    def anomaly(self) -> bool:
        if self.distance_km <= 0:
            return False
        return is_cf_anomaly(self.measured_rtt_ms, self.distance_km)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "origin_asn": self.origin_asn,
            "as_path": self.as_path,
            "components": {
                "rtt": self.components.rtt,
                "packet_loss": self.components.packet_loss,
                "congestion": self.components.congestion,
                "stability": self.components.stability,
                "capacity": self.components.capacity,
                "economic": self.components.economic,
                "geographic": self.components.geographic,
            },
            "cf_value": self.cf_value,
            "accumulated_cf": self.accumulated_cf,
            "hop_cfs": self.hop_cfs,
            "distance_km": self.distance_km,
            "measured_rtt_ms": self.measured_rtt_ms,
            "anomaly": self.anomaly,
        }


class CFDashboardState:
    """Dashboard state holding paths, benchmarks and CF data."""

    def __init__(self, intrazone_cf: int = 0) -> None:
        self._paths: dict[str, PathEntry] = {}
        self._intrazone_cf = intrazone_cf
        self._benchmarks: list[BenchmarkResult] | None = None

    @property
    def intrazone_cf(self) -> int:
        return self._intrazone_cf

    @intrazone_cf.setter
    def intrazone_cf(self, value: int) -> None:
        self._intrazone_cf = max(0, min(value, 0xFFFFFFFF))

    def add_path(
        self,
        path_id: str,
        origin_asn: int,
        as_path: list[int],
        components: CFComponents,
        hop_cfs: list[int] | None = None,
        distance_km: float = 0.0,
        measured_rtt_ms: float = 0.0,
    ) -> PathEntry:
        """Add or update a path entry."""
        cf_value = compute_cf(components)
        entry = PathEntry(
            path_id=path_id,
            origin_asn=origin_asn,
            as_path=as_path,
            components=components,
            cf_value=cf_value,
            hop_cfs=hop_cfs if hop_cfs else [cf_value],
            distance_km=distance_km,
            measured_rtt_ms=measured_rtt_ms,
        )
        self._paths[path_id] = entry
        return entry

    def remove_path(self, path_id: str) -> bool:
        if path_id in self._paths:
            del self._paths[path_id]
            return True
        return False

    def get_path(self, path_id: str) -> PathEntry | None:
        return self._paths.get(path_id)

    def list_paths(self) -> list[PathEntry]:
        return list(self._paths.values())

    @property
    def path_count(self) -> int:
        return len(self._paths)

    def best_path(self) -> PathEntry | None:
        """Return path with lowest CF_total."""
        if not self._paths:
            return None
        return min(
            self._paths.values(),
            key=lambda p: cf_total(p.accumulated_cf, self._intrazone_cf),
        )

    def ranked_paths(self) -> list[PathEntry]:
        """Return all paths sorted by CF_total (best first)."""
        return sorted(
            self._paths.values(),
            key=lambda p: cf_total(p.accumulated_cf, self._intrazone_cf),
        )

    def anomalies(self) -> list[PathEntry]:
        return [p for p in self._paths.values() if p.anomaly]

    def run_benchmarks(self, iterations: int = 1000) -> list[BenchmarkResult]:
        self._benchmarks = run_benchmarks(iterations)
        return self._benchmarks

    @property
    def benchmarks(self) -> list[BenchmarkResult] | None:
        return self._benchmarks

    def summary(self) -> dict[str, Any]:
        best = self.best_path()
        return {
            "paths": self.path_count,
            "intrazone_cf": self._intrazone_cf,
            "best_path": best.path_id if best else None,
            "best_cf_total": cf_total(best.accumulated_cf, self._intrazone_cf) if best else None,
            "anomalies": len(self.anomalies()),
            "benchmarks_run": self._benchmarks is not None,
        }

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "summary": self.summary(),
            "paths": [p.to_dict() for p in self.ranked_paths()],
            "anomalies": [p.to_dict() for p in self.anomalies()],
        }
        if self._benchmarks:
            data["benchmarks"] = [
                {
                    "name": b.name,
                    "iterations": b.iterations,
                    "total_seconds": round(b.total_seconds, 6),
                    "ops_per_second": round(b.ops_per_second, 1),
                    "us_per_op": round(b.us_per_op, 2),
                }
                for b in self._benchmarks
            ]
        return data

    def clear(self) -> None:
        self._paths.clear()
        self._benchmarks = None


# ---------------------------------------------------------------------------
# Demo state factory
# ---------------------------------------------------------------------------


def create_demo_state() -> CFDashboardState:
    """Create a demo state with sample paths for visualisation."""
    state = CFDashboardState(intrazone_cf=100)

    state.add_path(
        path_id="direct-64497",
        origin_asn=64497,
        as_path=[64497],
        components=CFComponents(rtt=0.1, packet_loss=0.02, geographic=0.1),
        distance_km=500.0,
        measured_rtt_ms=6.0,
    )

    state.add_path(
        path_id="transit-64498-64497",
        origin_asn=64497,
        as_path=[64498, 64497],
        components=CFComponents(rtt=0.3, packet_loss=0.08, congestion=0.1, geographic=0.3),
        hop_cfs=[200000, 300000],
        distance_km=2000.0,
        measured_rtt_ms=25.0,
    )

    state.add_path(
        path_id="premium-64499",
        origin_asn=64499,
        as_path=[64499],
        components=CFComponents(rtt=0.05, packet_loss=0.01, economic=0.8, geographic=0.05),
        distance_km=300.0,
        measured_rtt_ms=4.0,
    )

    # Anomaly path — claimed RTT faster than light
    state.add_path(
        path_id="anomaly-64500",
        origin_asn=64500,
        as_path=[64500],
        components=CFComponents(rtt=0.01, packet_loss=0.0, geographic=0.5),
        distance_km=10000.0,
        measured_rtt_ms=5.0,  # way too fast for 10000km
    )

    return state


# ---------------------------------------------------------------------------
# HTML dashboard
# ---------------------------------------------------------------------------

_CF_DASHBOARD_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IPv8 Lab — CF Performance Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}
h1{color:#58a6ff;margin-bottom:6px;font-size:1.6rem}
h2{color:#58a6ff;margin:24px 0 12px;font-size:1.2rem}
.subtitle{color:#8b949e;margin-bottom:20px;font-size:.9rem}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px}
.card.best{border-color:#238636}
.card.anomaly{border-color:#f85149}
.card h3{color:#f0f6fc;margin-bottom:8px;font-size:1rem}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.75rem;margin-left:6px;color:#fff}
.badge-best{background:#238636}
.badge-anomaly{background:#f85149}
.badge-rank{background:#1f6feb}
.field{margin:4px 0;font-size:.85rem}
.label{color:#8b949e;margin-right:6px}
.value{color:#c9d1d9;font-family:'SF Mono',monospace}
.bar-container{display:flex;align-items:center;margin:3px 0}
.bar-label{width:90px;font-size:.8rem;color:#8b949e}
.bar-track{flex:1;height:14px;background:#21262d;border-radius:3px;overflow:hidden;position:relative}
.bar-fill{height:100%;border-radius:3px;transition:width .3s}
.bar-value{position:absolute;right:4px;top:0;font-size:.7rem;line-height:14px;color:#c9d1d9}
.cf-rtt{background:#58a6ff}
.cf-loss{background:#f85149}
.cf-cong{background:#d29922}
.cf-stab{background:#a371f7}
.cf-cap{background:#3fb950}
.cf-econ{background:#f778ba}
.cf-geo{background:#79c0ff}
table{width:100%;border-collapse:collapse;margin:8px 0}
th,td{text-align:left;padding:6px 10px;font-size:.85rem;border-bottom:1px solid #21262d}
th{color:#8b949e;font-weight:500}
td{font-family:'SF Mono',monospace}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin:12px 0}
.stat{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;text-align:center}
.stat-value{font-size:1.4rem;font-weight:bold;color:#58a6ff}
.stat-label{font-size:.8rem;color:#8b949e;margin-top:4px}
.controls{margin:16px 0;display:flex;gap:10px;flex-wrap:wrap}
button{background:#238636;color:#fff;border:1px solid #238636;border-radius:6px;padding:8px 16px;cursor:pointer;font-size:.9rem}
button:hover{background:#2ea043}
button.secondary{background:#21262d;border-color:#30363d;color:#c9d1d9}
button.secondary:hover{background:#30363d}
#error{color:#f85149;margin:8px 0;display:none}
</style>
</head>
<body>
<h1>CF Performance Dashboard</h1>
<p class="subtitle">Cost Factor visualisation per draft-thain-ipv8-00 Section 1.6</p>
<div id="error"></div>

<div class="summary-grid" id="summary"></div>

<div class="controls">
  <button onclick="refresh()">Refresh</button>
  <button class="secondary" onclick="runBenchmarks()">Run Benchmarks</button>
</div>

<h2>Path Ranking (by CF_total)</h2>
<div class="grid" id="paths"></div>

<div id="anomaly-section" style="display:none">
<h2>Anomalies</h2>
<div class="grid" id="anomalies"></div>
</div>

<div id="bench-section" style="display:none">
<h2>Performance Benchmarks</h2>
<div class="card" id="benchmarks" style="max-width:700px"></div>
</div>

<script>
const API='';

function pct(v){return Math.round(v*100)}
function fmtCF(v){return v.toLocaleString()}

function makeBar(label,value,cls){
  return `<div class="bar-container">
    <span class="bar-label">${label}</span>
    <div class="bar-track">
      <div class="bar-fill ${cls}" style="width:${pct(value)}%"></div>
      <span class="bar-value">${pct(value)}%</span>
    </div>
  </div>`;
}

function pathCard(p,rank){
  const isBest=rank===1;
  const cls=['card'];
  if(isBest) cls.push('best');
  if(p.anomaly) cls.push('anomaly');
  const badges=[];
  badges.push(`<span class="badge badge-rank">#${rank}</span>`);
  if(isBest) badges.push('<span class="badge badge-best">BEST</span>');
  if(p.anomaly) badges.push('<span class="badge badge-anomaly">ANOMALY</span>');
  const c=p.components;
  return `<div class="${cls.join(' ')}">
    <h3>${p.path_id}${badges.join('')}</h3>
    <div class="field"><span class="label">Origin:</span><span class="value">AS${p.origin_asn}</span></div>
    <div class="field"><span class="label">AS-path:</span><span class="value">[${p.as_path.join(', ')}]</span></div>
    <div class="field"><span class="label">CF value:</span><span class="value">${fmtCF(p.cf_value)}</span></div>
    <div class="field"><span class="label">Accumulated:</span><span class="value">${fmtCF(p.accumulated_cf)}</span></div>
    <div class="field"><span class="label">Distance:</span><span class="value">${p.distance_km} km</span></div>
    <div class="field"><span class="label">RTT:</span><span class="value">${p.measured_rtt_ms} ms</span></div>
    <div style="margin-top:8px">
      ${makeBar('RTT',c.rtt,'cf-rtt')}
      ${makeBar('Loss',c.packet_loss,'cf-loss')}
      ${makeBar('Congestion',c.congestion,'cf-cong')}
      ${makeBar('Stability',c.stability,'cf-stab')}
      ${makeBar('Capacity',c.capacity,'cf-cap')}
      ${makeBar('Economic',c.economic,'cf-econ')}
      ${makeBar('Geographic',c.geographic,'cf-geo')}
    </div>
  </div>`;
}

async function refresh(){
  try{
    const r=await fetch(API+'/api/cf');
    const data=await r.json();
    const s=data.summary;

    document.getElementById('summary').innerHTML=`
      <div class="stat"><div class="stat-value">${s.paths}</div><div class="stat-label">Paths</div></div>
      <div class="stat"><div class="stat-value">${s.best_path||'-'}</div><div class="stat-label">Best Path</div></div>
      <div class="stat"><div class="stat-value">${s.best_cf_total!=null?fmtCF(s.best_cf_total):'-'}</div><div class="stat-label">Best CF_total</div></div>
      <div class="stat"><div class="stat-value">${fmtCF(s.intrazone_cf)}</div><div class="stat-label">Intrazone CF</div></div>
      <div class="stat"><div class="stat-value">${s.anomalies}</div><div class="stat-label">Anomalies</div></div>
    `;

    const pathsDiv=document.getElementById('paths');
    pathsDiv.innerHTML=data.paths.map((p,i)=>pathCard(p,i+1)).join('');

    const anomSec=document.getElementById('anomaly-section');
    if(data.anomalies.length>0){
      anomSec.style.display='block';
      document.getElementById('anomalies').innerHTML=data.anomalies.map((p,i)=>pathCard(p,i+1)).join('');
    } else {
      anomSec.style.display='none';
    }

    if(data.benchmarks){
      document.getElementById('bench-section').style.display='block';
      let html='<table><tr><th>Benchmark</th><th>Iterations</th><th>ops/s</th><th>μs/op</th></tr>';
      data.benchmarks.forEach(b=>{
        html+=`<tr><td>${b.name}</td><td>${b.iterations.toLocaleString()}</td><td>${b.ops_per_second.toLocaleString()}</td><td>${b.us_per_op}</td></tr>`;
      });
      html+='</table>';
      document.getElementById('benchmarks').innerHTML=html;
    }

    hideError();
  }catch(e){
    showError('Failed to load: '+e.message);
  }
}

async function runBenchmarks(){
  try{
    const r=await fetch(API+'/api/benchmarks',{method:'POST'});
    await r.json();
    refresh();
  }catch(e){
    showError('Benchmark failed: '+e.message);
  }
}

function showError(msg){const el=document.getElementById('error');el.textContent=msg;el.style.display='block'}
function hideError(){document.getElementById('error').style.display='none'}

refresh();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------


class _CFDashboardHandler(BaseHTTPRequestHandler):
    """HTTP handler for the CF performance dashboard."""

    state: CFDashboardState

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass

    def do_GET(self) -> None:
        if self.path == "/" or self.path == "/index.html":
            self._respond(200, "text/html", _CF_DASHBOARD_HTML.encode())
        elif self.path == "/api/cf":
            data = self.state.to_dict()
            self._respond(200, "application/json", json.dumps(data).encode())
        elif self.path == "/api/summary":
            data = self.state.summary()
            self._respond(200, "application/json", json.dumps(data).encode())
        else:
            self._respond(404, "text/plain", b"Not Found")

    def do_POST(self) -> None:
        if self.path == "/api/benchmarks":
            results = self.state.run_benchmarks(iterations=1000)
            data = [
                {
                    "name": b.name,
                    "iterations": b.iterations,
                    "ops_per_second": round(b.ops_per_second, 1),
                    "us_per_op": round(b.us_per_op, 2),
                }
                for b in results
            ]
            self._respond(200, "application/json", json.dumps(data).encode())
        elif self.path == "/api/path":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                req = json.loads(body)
                components = CFComponents(**req.get("components", {}))
                entry = self.state.add_path(
                    path_id=req["path_id"],
                    origin_asn=req.get("origin_asn", 0),
                    as_path=req.get("as_path", []),
                    components=components,
                    hop_cfs=req.get("hop_cfs"),
                    distance_km=req.get("distance_km", 0.0),
                    measured_rtt_ms=req.get("measured_rtt_ms", 0.0),
                )
                self._respond(200, "application/json", json.dumps(entry.to_dict()).encode())
            except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
                self._respond(400, "application/json", json.dumps({"error": str(exc)}).encode())
        else:
            self._respond(404, "text/plain", b"Not Found")

    def _respond(self, code: int, content_type: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def make_cf_handler(state: CFDashboardState) -> type[_CFDashboardHandler]:
    """Create a handler class bound to a specific state."""
    return type("BoundCFHandler", (_CFDashboardHandler,), {"state": state})


def run_cf_dashboard(
    state: CFDashboardState,
    host: str = "127.0.0.1",
    port: int = 8719,
) -> None:
    """Start the CF performance dashboard server."""
    handler_cls = make_cf_handler(state)
    server = HTTPServer((host, port), handler_cls)
    print(f"CF Performance Dashboard: http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
