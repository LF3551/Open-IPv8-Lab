# Copyright 2026 Aleksei Aleinikov
# SPDX-License-Identifier: Apache-2.0

"""Minimal web dashboard for IPv8 Lab simulations.

Serves a single-page HTML dashboard with a JSON API.
No external dependencies — uses only stdlib http.server.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from ipv8lab.dump import address_summary
from ipv8lab.simulator import NetworkSimulator

_DASHBOARD_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IPv8 Lab Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}
h1{color:#58a6ff;margin-bottom:20px;font-size:1.6rem}
h2{color:#58a6ff;margin:20px 0 10px;font-size:1.2rem}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px}
.card h3{color:#f0f6fc;margin-bottom:8px;font-size:1rem}
.badge{display:inline-block;background:#238636;color:#fff;padding:2px 8px;border-radius:12px;font-size:.75rem;margin-left:6px}
.field{margin:4px 0;font-size:.9rem}
.label{color:#8b949e;margin-right:6px}
.value{color:#c9d1d9;font-family:'SF Mono',monospace}
.link{color:#8b949e;font-size:.8rem}
.trace{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;margin:10px 0;font-family:'SF Mono',monospace;font-size:.85rem;white-space:pre-wrap;max-height:300px;overflow-y:auto}
.controls{margin:20px 0;display:flex;gap:10px;flex-wrap:wrap;align-items:center}
input,button,select{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;padding:8px 12px;font-size:.9rem}
button{cursor:pointer;background:#238636;border-color:#238636;color:#fff}
button:hover{background:#2ea043}
.status{padding:8px 16px;background:#161b22;border:1px solid #30363d;border-radius:6px;margin:10px 0}
#error{color:#f85149;margin:8px 0;display:none}
</style>
</head>
<body>
<h1>IPv8 Lab Dashboard</h1>
<div class="status" id="status">Loading...</div>
<div id="error"></div>

<h2>Nodes</h2>
<div class="grid" id="nodes"></div>

<h2>Links</h2>
<div id="links" class="card" style="max-width:600px"></div>

<h2>Send Packet</h2>
<div class="controls">
  <select id="src-node"><option>Loading...</option></select>
  <span style="color:#8b949e">→</span>
  <input id="dst-addr" placeholder="Destination address" style="width:220px">
  <input id="payload" placeholder="Payload" style="width:160px" value="hello">
  <button onclick="sendPacket()">Send</button>
</div>
<div class="trace" id="trace" style="display:none"></div>

<script>
const API = '';
async function load() {
  try {
    const r = await fetch(API + '/api/topology');
    const data = await r.json();
    document.getElementById('status').textContent =
      `Nodes: ${data.nodes.length} | Links: ${data.links.length}`;

    const nodesDiv = document.getElementById('nodes');
    nodesDiv.innerHTML = '';
    const sel = document.getElementById('src-node');
    sel.innerHTML = '';
    data.nodes.forEach(n => {
      const card = document.createElement('div');
      card.className = 'card';
      card.innerHTML = `
        <h3>${n.name}<span class="badge">${n.address.asn_notation}</span></h3>
        <div class="field"><span class="label">Full:</span><span class="value">${n.address.full_notation}</span></div>
        <div class="field"><span class="label">Routes:</span><span class="value">${n.route_count}</span></div>
        <div class="field"><span class="label">Inbox:</span><span class="value">${n.inbox_count}</span></div>
      `;
      nodesDiv.appendChild(card);
      const opt = document.createElement('option');
      opt.value = n.name;
      opt.textContent = n.name;
      sel.appendChild(opt);
    });

    const linksDiv = document.getElementById('links');
    if (data.links.length === 0) {
      linksDiv.textContent = 'No links configured.';
    } else {
      linksDiv.innerHTML = data.links.map(l =>
        `<div class="field"><span class="value">${l[0]}</span> <span class="label">↔</span> <span class="value">${l[1]}</span></div>`
      ).join('');
    }
  } catch (e) {
    showError('Failed to load topology: ' + e.message);
  }
}

async function sendPacket() {
  const src = document.getElementById('src-node').value;
  const dst = document.getElementById('dst-addr').value;
  const payload = document.getElementById('payload').value;
  if (!dst) { showError('Enter a destination address'); return; }
  try {
    const r = await fetch(API + '/api/send', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({src, dst, payload})
    });
    const data = await r.json();
    const traceDiv = document.getElementById('trace');
    traceDiv.style.display = 'block';
    traceDiv.textContent = data.trace.join('\\n');
    hideError();
    load();
  } catch (e) {
    showError('Send failed: ' + e.message);
  }
}

function showError(msg) {
  const el = document.getElementById('error');
  el.textContent = msg;
  el.style.display = 'block';
}
function hideError() {
  document.getElementById('error').style.display = 'none';
}

load();
</script>
</body>
</html>
"""


def _topology_json(sim: NetworkSimulator) -> dict[str, Any]:
    """Build topology data for the API."""
    nodes = []
    for name, node in sim.nodes.items():
        addr_info = address_summary(node.address.full_notation)
        nodes.append(
            {
                "name": name,
                "address": addr_info,
                "route_count": len(node.routes.routes),
                "inbox_count": len(node.inbox),
            }
        )
    return {"nodes": nodes, "links": list(sim.links)}


class _DashboardHandler(BaseHTTPRequestHandler):
    """HTTP handler for the dashboard."""

    sim: NetworkSimulator  # set via class factory

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass  # silent by default

    def do_GET(self) -> None:
        if self.path == "/" or self.path == "/index.html":
            self._respond(200, "text/html", _DASHBOARD_HTML.encode())
        elif self.path == "/api/topology":
            data = _topology_json(self.sim)
            self._respond(200, "application/json", json.dumps(data).encode())
        else:
            self._respond(404, "text/plain", b"Not Found")

    def do_POST(self) -> None:
        if self.path == "/api/send":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                req = json.loads(body)
                src = req.get("src", "")
                dst = req.get("dst", "")
                payload = req.get("payload", "")
                if not src or not dst:
                    self._respond(
                        400,
                        "application/json",
                        json.dumps({"error": "src and dst required"}).encode(),
                    )
                    return
                trace = self.sim.send(src, dst, payload)
                self._respond(
                    200,
                    "application/json",
                    json.dumps({"trace": trace}).encode(),
                )
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                self._respond(
                    400,
                    "application/json",
                    json.dumps({"error": str(exc)}).encode(),
                )
        else:
            self._respond(404, "text/plain", b"Not Found")

    def _respond(self, code: int, content_type: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def make_handler(sim: NetworkSimulator) -> type[_DashboardHandler]:
    """Create a handler class bound to a specific simulator."""
    return type("BoundHandler", (_DashboardHandler,), {"sim": sim})


def run_dashboard(sim: NetworkSimulator, host: str = "127.0.0.1", port: int = 8718) -> None:
    """Start the web dashboard server."""
    handler_cls = make_handler(sim)
    server = HTTPServer((host, port), handler_cls)
    print(f"IPv8 Lab Dashboard: http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
