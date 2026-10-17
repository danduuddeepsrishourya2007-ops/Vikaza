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


def test_quota_exhaustion_opens_circuit_and_prevents_repeated_requests():
    calls = []

    def exhausted_transport(*args):
        calls.append(args[0])
        raise ProviderError(
            "LLM endpoint returned HTTP 429 (credit_balance_exhausted)",
            category="quota_exhausted",
            status_code=429,
        )

    primary = OpenAICompatibleProvider(
        "https://api.openai.com/v1", "test-model", transport=exhausted_transport,
    )
    provider = FallbackProvider(primary, ScriptedDefensiveProvider())
    world = configured_world()
    view = observe(world, "security_engineer_1")

    first = provider.decide(view)
    second = provider.decide(view)
    third = provider.decide(view)

    assert first.source == second.source == third.source == "fallback_heuristic"
    assert len(calls) == 1
    assert primary.calls == 1
    assert primary.failures == 1
    assert provider.stats.fallback_decisions == 3
    assert provider.stats.failed_decisions == 1
    assert provider.stats.skipped_after_circuit_open == 2
    assert provider.stats.circuit_open is True
    assert provider.stats.last_error_category == "quota_exhausted"
    assert provider.stats.last_error_status_code == 429


def test_http_error_body_classifies_exhausted_quota_without_leaking_raw_message():
    from io import BytesIO
    from urllib.error import HTTPError

    body = b'{"error":{"message":"private billing detail","type":"insufficient_quota","code":"credit_balance_exhausted"}}'
    http_error = HTTPError(
        "https://api.openai.com/v1/chat/completions", 429, "Too Many Requests", {}, BytesIO(body)
    )

    def failing_urlopen(*args, **kwargs):
        raise http_error

    # Exercise the production HTTP transport without making a network request.
    import simulation.llm_provider as module
    original_urlopen = module.urlopen
    module.urlopen = failing_urlopen
    try:
        with pytest.raises(ProviderError) as caught:
            OpenAICompatibleProvider._http_json(
                "https://api.openai.com/v1/chat/completions",
                {"Content-Type": "application/json"},
                {"model": "test-model"},
                1.0,
            )
    finally:
        module.urlopen = original_urlopen

    assert caught.value.category == "quota_exhausted"
    assert caught.value.status_code == 429
    assert "credit_balance_exhausted" in str(caught.value)
    assert "private billing detail" not in str(caught.value)


def test_rate_limit_is_recoverable_and_does_not_open_circuit():
    calls = []

    def limited_transport(*args):
        calls.append(args[0])
        raise ProviderError("temporarily rate limited", category="rate_limited", status_code=429)

    primary = OpenAICompatibleProvider(
        "http://localhost:8000/v1", "test-model", transport=limited_transport,
    )
    provider = FallbackProvider(primary, ScriptedDefensiveProvider())
    view = observe(configured_world(), "security_engineer_1")

    first = provider.decide(view)
    second = provider.decide(view)

    assert first.source == second.source == "fallback_heuristic"
    assert first.failure_reason == second.failure_reason == "rate_limited"
    assert len(calls) == 2
    assert provider.stats.circuit_open is False


def test_unknown_action_error_does_not_echo_untrusted_action_text():
    secret_like_text = "do-not-echo-this-value"
    provider = OpenAICompatibleProvider(
        "http://localhost:8000/v1", "test-model",
        transport=lambda *args: response(
            '{"action_type":"' + secret_like_text + '","target":null,"rationale":"bad"}'
        ),
    )
    with pytest.raises(ProviderError) as caught:
        provider.decide(observe(configured_world(), "security_engineer_1"))
    assert caught.value.category == "unknown_action"
    assert secret_like_text not in str(caught.value)


@pytest.mark.parametrize(
    "content",
    [
        '{"target":"developer_workstation","rationale":"Contain it."}',
        '{"action_type":"ISOLATE_HOST","rationale":"Contain it."}',
        '{"action_type":"ISOLATE_HOST","target":"developer_workstation"}',
    ],
    ids=["missing-action-type", "missing-target", "missing-rationale"],
)
def test_provider_rejects_decisions_missing_required_fields_and_uses_fallback(content):
    primary = OpenAICompatibleProvider(
        "http://localhost:8000/v1", "test-model",
        transport=lambda *args: response(content),
    )
    provider = FallbackProvider(primary, ScriptedDefensiveProvider())
    decision = provider.decide(observe(configured_world(), "security_engineer_1"))

    assert decision.source == "fallback_heuristic"
    assert decision.failure_reason == "invalid_decision"
    assert provider.stats.failed_decisions == 1
    assert provider.stats.fallback_decisions == 1
    assert primary.failures == 1
