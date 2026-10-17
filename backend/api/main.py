"""Local-first HTTP API and static dashboard for NEXUS Cyber.

Uses only the Python standard library. Intended for localhost development, not
for exposure to an untrusted network without authentication and hardening.
"""
from __future__ import annotations

import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from scenarios.cyber_containment import SCENARIO_ID, build_attack_world, build_initial_world
from simulation.baselines import DoNothingProvider, ScriptedDefensiveProvider
from simulation.experiment import (
    attack_provider_factories, compare_providers, configured_attack_world,
)

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_DIR = ROOT / "dashboard"
MAX_BODY_BYTES = 16_384
MAX_SEEDS = 20
MAX_TICKS = 100


def scenario_payload(seed: int = 7, mode: str = "containment") -> dict[str, Any]:
    """Return the real initial scenario topology, not frontend fixture data."""
    if mode == "active_attack":
        world = build_attack_world(seed)
    elif mode == "containment":
        world = build_initial_world(seed)
    else:
        raise ValueError("mode must be 'containment' or 'active_attack'.")
    state = world.state
    return {
        "scenario_id": state.scenario_id or SCENARIO_ID,
        "seed": seed,
        "tick": state.tick,
        "hosts": [
            {
                "id": host.host_id,
                "hostname": host.hostname,
                "ip": host.ip_address,
                "os": f"{host.os_type} {host.os_version}".strip(),
                "compromised": host.is_compromised,
                "isolated": host.isolated,
                "services": [
                    {"name": name, "running": running}
                    for name, running in sorted(host.running_services.items())
                ],
                "data_stores": list(host.data_stores),
            }
            for host in sorted(state.hosts.values(), key=lambda item: item.host_id)
        ],
        "links": [
            {"source": source, "target": target}
            for source, targets in sorted(state.network.items())
            for target in sorted(targets)
            if source < target
        ],
        "data_stores": [
            {
                "id": store.store_id,
                "name": store.name,
                "host": store.location_host,
                "size_gb": store.size_gb,
                "sensitivity": store.sensitivity_level,
                "exfiltrated": store.is_exfiltrated,
            }
            for store in sorted(state.data_stores.values(), key=lambda item: item.store_id)
        ],
        "agents": [
            {"id": agent.agent_id, "role": agent.role, "host": agent.current_host}
            for agent in sorted(state.agents.values(), key=lambda item: item.agent_id)
        ],
        "resources": dict(state.resource_pool),
    }


def validate_run_request(payload: Any) -> tuple[list[int], int]:
    if not isinstance(payload, dict):
        raise ValueError("Request body must be a JSON object.")
    seeds = payload.get("seeds", [7, 17, 42])
    ticks = payload.get("ticks", 5)
    if not isinstance(seeds, list) or not 1 <= len(seeds) <= MAX_SEEDS:
        raise ValueError(f"seeds must be a list containing 1–{MAX_SEEDS} integers.")
    if any(not isinstance(seed, int) or isinstance(seed, bool) or not 0 <= seed <= 2**31 - 1 for seed in seeds):
        raise ValueError("Each seed must be an integer from 0 to 2147483647.")
    if len(set(seeds)) != len(seeds):
        raise ValueError("Seeds must be unique.")
    if not isinstance(ticks, int) or isinstance(ticks, bool) or not 1 <= ticks <= MAX_TICKS:
        raise ValueError(f"ticks must be an integer from 1 to {MAX_TICKS}.")
    mode = payload.get("mode", "containment")
    if not isinstance(mode, str) or mode not in {"containment", "active_attack"}:
        raise ValueError("mode must be 'containment' or 'active_attack'.")
    return seeds, ticks


def run_experiment(payload: Any) -> dict[str, Any]:
    seeds, ticks = validate_run_request(payload)
    mode = payload.get("mode", "containment")
    if mode == "active_attack":
        factories = attack_provider_factories()
        report = compare_providers(
            factories, seeds=seeds, max_ticks=ticks,
            world_factory=configured_attack_world,
        )
        scenario_id = "nexus_cyber_attack_v1"
        note = (
            "A deterministic simulated attacker follows a fixed in-memory attack sequence. "
            "The defensive policy may interrupt it. This is not real network activity "
            "and is not an LLM/GPU benchmark."
        )
    else:
        factories = [
            (DoNothingProvider.policy_id, DoNothingProvider),
            (ScriptedDefensiveProvider.policy_id, ScriptedDefensiveProvider),
        ]
        report = compare_providers(factories, seeds=seeds, max_ticks=ticks)
        scenario_id = SCENARIO_ID
        note = "This run compares deterministic containment baselines. It is not an LLM/GPU benchmark."
    report["dashboard_metadata"] = {
        "scenario_id": scenario_id,
        "mode": mode,
        "engine": "NEXUS deterministic Python simulation",
        "model_inference_used": False,
        "note": note,
    }
    return report


class NexusRequestHandler(BaseHTTPRequestHandler):
    server_version = "NEXUSDashboard/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        if os.getenv("NEXUS_HTTP_LOG", "0") == "1":
            super().log_message(fmt, *args)

    def _send(self, status: int, body: bytes, content_type: str = "application/json; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, value: Any) -> None:
        body = json.dumps(value, sort_keys=True, allow_nan=False).encode("utf-8")
        self._send(status, body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/health":
            self._json(200, {"status": "ok", "scenario_id": SCENARIO_ID})
        elif path == "/api/scenario":
            mode = parse_qs(parsed.query).get("mode", ["containment"])[0]
            try:
                self._json(200, scenario_payload(mode=mode))
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
        elif path in {"/", "/index.html"}:
            index = DASHBOARD_DIR / "index.html"
            if not index.is_file():
                self._json(500, {"error": "Dashboard asset is missing."})
                return
            self._send(200, index.read_bytes(), "text/html; charset=utf-8")
        else:
            self._json(404, {"error": "Not found."})

    def do_POST(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/api/run":
            self._json(404, {"error": "Not found."})
            return
        raw_length = self.headers.get("Content-Length", "")
        try:
            length = int(raw_length)
        except ValueError:
            self._json(411, {"error": "A valid Content-Length header is required."})
            return
        if length < 1 or length > MAX_BODY_BYTES:
            self._json(413, {"error": f"Request body must be 1–{MAX_BODY_BYTES} bytes."})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            report = run_experiment(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json(400, {"error": "Request body must be valid UTF-8 JSON."})
            return
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
            return
        except Exception:
            # Keep diagnostics on the local server console, never in the HTTP response.
            logging.exception("NEXUS simulation request failed")
            self._json(500, {"error": "Simulation run failed. Check the server console and test suite."})
            return
        self._json(200, report)


def create_app(host: str | None = None, port: int | None = None) -> ThreadingHTTPServer:
    """Create the local dashboard server; call serve_forever() to run it."""
    bind_host = host or os.getenv("NEXUS_HOST", "127.0.0.1")
    bind_port = port if port is not None else int(os.getenv("NEXUS_PORT", "8765"))
    return ThreadingHTTPServer((bind_host, bind_port), NexusRequestHandler)


def main() -> None:
    server = create_app()
    print(f"NEXUS Cyber Dashboard: http://{server.server_address[0]}:{server.server_address[1]}")
    print("Local development server. Do not expose it to an untrusted network.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down NEXUS dashboard...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
