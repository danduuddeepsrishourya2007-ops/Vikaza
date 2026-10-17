"""Regression tests for the local NEXUS dashboard API."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from backend.api.main import create_app, run_experiment, scenario_payload, validate_run_request
from scenarios.cyber_containment import SCENARIO_ID


def test_scenario_payload_comes_from_initial_world():
    data = scenario_payload(23)
    assert data["scenario_id"] == SCENARIO_ID
    assert data["seed"] == 23
    assert {host["id"] for host in data["hosts"]} == {
        "developer_workstation", "application_server", "customer_database"
    }
    assert len(data["links"]) == 2
    assert data["data_stores"][0]["size_gb"] == 50.0
    assert any(host["compromised"] for host in data["hosts"])


@pytest.mark.parametrize("payload", [
    None,
    {"seeds": []},
    {"seeds": [1, 1]},
    {"seeds": [True]},
    {"seeds": [1], "ticks": 0},
    {"seeds": [1], "ticks": 101},
    {"seeds": ["7"]},
    {"seeds": list(range(21))},
])
def test_invalid_run_request_is_rejected(payload):
    with pytest.raises(ValueError):
        validate_run_request(payload)


def test_run_experiment_returns_verified_real_engine_runs():
    report = run_experiment({"seeds": [7], "ticks": 2})
    assert report["scenario_id"] == SCENARIO_ID
    assert len(report["runs"]) == 2
    assert all(run["replay_verified"] for run in report["runs"])
    assert all("metrics" in run and "trace" in run for run in report["runs"])
    assert report["dashboard_metadata"]["model_inference_used"] is False


def test_http_dashboard_health_scenario_and_run_routes():
    server = create_app("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urllib.request.urlopen(base + "/api/health", timeout=3) as response:
            assert json.load(response)["status"] == "ok"
        with urllib.request.urlopen(base + "/api/scenario?mode=active_attack", timeout=3) as response:
            attack_scenario = json.load(response)
        assert attack_scenario["scenario_id"] == "nexus_cyber_attack_v1"
        assert any(agent["role"] == "attacker" for agent in attack_scenario["agents"])
        with urllib.request.urlopen(base + "/", timeout=3) as response:
            assert "Decision Rehearsal Console" in response.read().decode()
        request = urllib.request.Request(
            base + "/api/run",
            data=json.dumps({"seeds": [3], "ticks": 1}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            report = json.load(response)
        assert len(report["runs"]) == 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_http_run_rejects_invalid_json_payload_values():
    server = create_app("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        request = urllib.request.Request(
            base + "/api/run", data=b'{"seeds": [], "ticks": 1}',
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(request, timeout=3)
        assert exc.value.code == 400
        assert "seeds" in json.loads(exc.value.read())["error"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_active_attack_dashboard_mode_runs_real_red_team_scenario():
    report = run_experiment({"seeds": [7], "ticks": 7, "mode": "active_attack"})
    assert report["dashboard_metadata"]["mode"] == "active_attack"
    assert report["dashboard_metadata"]["model_inference_used"] is False
    runs = {run["policy_id"]: run for run in report["runs"]}
    assert runs["do_nothing_v1"]["replay_verified"] is True
    assert runs["do_nothing_v1"]["metrics"]["data_exfiltrated_gb"] == 50.0
    assert runs["scripted_defensive_v1"]["metrics"]["data_exfiltrated_gb"] == 0.0


def test_invalid_scenario_mode_is_rejected():
    with pytest.raises(ValueError, match="mode"):
        validate_run_request({"seeds": [7], "ticks": 5, "mode": "real_network"})


def test_active_attack_scenario_payload_includes_simulated_attacker():
    data = scenario_payload(23, mode="active_attack")
    assert data["scenario_id"] == "nexus_cyber_attack_v1"
    assert any(agent["role"] == "attacker" for agent in data["agents"])

