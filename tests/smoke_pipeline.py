"""Offline smoke test for the AdverSim repository.

The smoke path deliberately avoids the LLM generation entry points. It runs
the local metrics, v14 validation, and Sigma-rule conversion on a checked-in
20-scenario fixture so the public code path can be tested without an API key.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from core.metrics_engine import analyze_dataset
from mitre_attack_validator import MitreAttackValidator
from sigma_rule_generator import main as generate_sigma_rules


FIXTURE = ROOT / "tests" / "fixtures" / "mini_corpus.json"
STIX_CANDIDATES = [
    ROOT / "mitre" / "enterprise-attack-14.1-active-techniques.json",
]


def load_fixture() -> list[dict]:
    with FIXTURE.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise AssertionError("fixture must be a JSON array")
    if len(data) != 20:
        raise AssertionError(f"expected 20 fixture scenarios, found {len(data)}")
    return data


def write_jsonl(path: Path, scenarios: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for scenario in scenarios:
            f.write(json.dumps(scenario) + "\n")


def validate_against_stix(scenarios: list[dict]) -> None:
    stix_path = next((p for p in STIX_CANDIDATES if p.exists()), None)
    if stix_path is None:
        raise AssertionError("no ATT&CK STIX bundle found for validation")

    validator = MitreAttackValidator(stix_path)
    bad: list[str] = []
    for scenario in scenarios:
        for stage in scenario.get("attack_stages", []):
            for technique in stage.get("techniques", []):
                tid = technique.get("technique_id")
                if tid and not validator.is_valid(tid):
                    bad.append(f"{scenario.get('scenario_id')}:{tid}")
        for tid in scenario.get("mitre_attack_mapping", []):
            if tid and not validator.is_valid(tid):
                bad.append(f"{scenario.get('scenario_id')}:{tid}")
    if bad:
        raise AssertionError("inactive or invalid ATT&CK IDs: " + ", ".join(bad[:10]))


def main() -> int:
    scenarios = load_fixture()
    validate_against_stix(scenarios)

    metrics = analyze_dataset(scenarios)
    if metrics["total_scenarios"] != 20:
        raise AssertionError("metrics did not process all fixture scenarios")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        (tmp_path / "data").mkdir()

        dataset_path = tmp_path / "mini_corpus.jsonl"
        out_dir = tmp_path / "sigma_rules"
        write_jsonl(dataset_path, scenarios)
        summary = generate_sigma_rules(str(dataset_path), str(out_dir), n=20)
        if summary["rules_generated"] == 0:
            raise AssertionError("Sigma generator produced no rules")

    print("smoke ok: fixture metrics, v14 validation, sigma generation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
