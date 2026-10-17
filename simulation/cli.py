"""Command-line entry points for reproducible NEXUS experiments."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from simulation.baselines import (
    AttackScenarioProvider, DoNothingProvider, ScriptedDefensiveProvider,
)
from simulation.experiment import (
    attack_provider_factories, compare_providers, configured_attack_world,
)
from simulation.llm_provider import FallbackProvider, OpenAICompatibleProvider


def _seeds(value: str) -> list[int]:
    try:
        seeds = [int(part.strip()) for part in value.split(",") if part.strip()]
    except ValueError as exc:
        raise argparse.ArgumentTypeError("seeds must be comma-separated integers") from exc
    if not seeds:
        raise argparse.ArgumentTypeError("provide at least one seed")
    if len(set(seeds)) != len(seeds):
        raise argparse.ArgumentTypeError("seeds must be unique")
    return seeds


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run reproducible NEXUS cyber-simulation experiments")
    parser.add_argument("--seeds", type=_seeds, default=[7, 17, 42], help="comma-separated seeds (default: 7,17,42)")
    parser.add_argument("--ticks", type=int, default=5, help="simulation ticks per run (default: 5; use 7+ for full active attack)")
    parser.add_argument("--mode", choices=("containment", "active_attack"), default="containment", help="scenario mode (default: containment)")
    parser.add_argument("--output", type=Path, default=Path("artifacts/nexus-evaluation.json"), help="JSON report path")
    parser.add_argument("--with-llm", action="store_true", help="include an OpenAI-compatible model endpoint")
    parser.add_argument("--timeout", type=float, default=8.0, help="per-decision endpoint timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.ticks < 1:
        raise SystemExit("--ticks must be positive")
    world_factory = None
    if args.mode == "active_attack":
        factories = attack_provider_factories()
        world_factory = configured_attack_world
    else:
        factories = [
            (DoNothingProvider.policy_id, DoNothingProvider),
            (ScriptedDefensiveProvider.policy_id, ScriptedDefensiveProvider),
        ]
    if args.with_llm:
        base_url = os.getenv("NEXUS_LLM_BASE_URL", "").strip()
        model = os.getenv("NEXUS_LLM_MODEL", "").strip()
        if not base_url or not model:
            raise SystemExit(
                "--with-llm requires NEXUS_LLM_BASE_URL and NEXUS_LLM_MODEL. "
                "No model server is started automatically."
            )
        def llm_factory():
            primary = OpenAICompatibleProvider(
                base_url=base_url,
                model=model,
                timeout_seconds=args.timeout,
            )
            provider = FallbackProvider(primary)
            return AttackScenarioProvider(provider) if args.mode == "active_attack" else provider
        factories.append(("openai_compatible_llm_with_fallback_v1", llm_factory))

    report = compare_providers(
        factories, args.seeds, args.ticks, world_factory=world_factory
    )
    report["run_metadata"] = {
        "mode": args.mode,
        "model_inference_requested": args.with_llm,
        "note": (
            "Active attack uses a deterministic in-memory red-team sequence; "
            "no real hosts or networks are contacted."
            if args.mode == "active_attack"
            else "Containment mode compares deterministic response baselines."
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "summaries": report["summaries"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
