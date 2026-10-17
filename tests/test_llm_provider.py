import pytest

from scenarios.cyber_containment import build_initial_world, policy_config
from simulation.actions import ActionType, AgentDecision
from simulation.baselines import ScriptedDefensiveProvider
from simulation.llm_provider import FallbackProvider, OpenAICompatibleProvider, ProviderError
from simulation.observations import observe
from simulation.policy import ContainmentStrategy


def configured_world():
    world = build_initial_world(seed=7)
    world.state.active_policy = policy_config("llm_test", ContainmentStrategy.IMMEDIATE)
    return world


def response(content):
    return {"choices": [{"message": {"content": content}}]}


def test_openai_compatible_provider_parses_structured_decision_without_mutating_world():
    seen = {}

    def fake_transport(url, headers, payload, timeout):
        seen.update(url=url, headers=headers, payload=payload, timeout=timeout)
        return response('{"action_type":"ISOLATE_HOST","target":"developer_workstation","rationale":"Contain the known compromised endpoint."}')

    world = configured_world()
    before = repr(world.state)
    view = observe(world, "security_engineer_1")
    provider = OpenAICompatibleProvider(
        "http://localhost:8000/v1", "test-model", api_key="test-only",
        transport=fake_transport,
    )
    decision = provider.decide(view)

    assert decision == AgentDecision(
        agent_id="security_engineer_1", tick=0,
        action_type=ActionType.ISOLATE_HOST, target="developer_workstation",
        rationale="Contain the known compromised endpoint.", source="llm",
    )
    assert seen["url"] == "http://localhost:8000/v1/chat/completions"
    assert seen["headers"]["Authorization"] == "Bearer test-only"
    assert seen["payload"]["temperature"] == 0.0
    assert "known_vulnerabilities" in seen["payload"]["messages"][1]["content"]
    assert repr(world.state) == before
    assert provider.calls == 1
    assert provider.failures == 0


def test_provider_rejects_unknown_action_and_fallback_returns_heuristic():
    primary = OpenAICompatibleProvider(
        "http://localhost:8000/v1", "test-model",
        transport=lambda *args: response('{"action_type":"DELETE_REAL_SYSTEM","target":null,"rationale":"bad"}'),
    )
    provider = FallbackProvider(primary, ScriptedDefensiveProvider())
    world = configured_world()
    decision = provider.decide(observe(world, "security_engineer_1"))
    assert decision.action_type is ActionType.ISOLATE_HOST
    assert decision.target == "developer_workstation"
    assert decision.source == "fallback_heuristic"
    assert "Fallback after provider failure" in decision.rationale
    assert provider.stats.attempts == 1
    assert provider.stats.failed_decisions == 1
    assert provider.stats.fallback_decisions == 1


def test_provider_rejects_malformed_json():
    provider = OpenAICompatibleProvider(
        "http://localhost:8000/v1", "test-model",
        transport=lambda *args: response("not json"),
    )
    with pytest.raises(ProviderError, match="not valid JSON"):
        provider.decide(observe(configured_world(), "security_engineer_1"))
    assert provider.failures == 1


def test_provider_requires_configuration_and_positive_timeout():
    with pytest.raises(ValueError, match="base_url"):
        OpenAICompatibleProvider("", "model")
    with pytest.raises(ValueError, match="timeout_seconds"):
        OpenAICompatibleProvider("http://localhost/v1", "model", timeout_seconds=0)
