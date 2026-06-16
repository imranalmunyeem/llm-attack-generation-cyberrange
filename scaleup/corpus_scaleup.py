"""Generate and validate a scaled AdverSim scenario corpus.

This is the Phase 0.5 runner. It keeps generation defensive and metadata-only,
validates every MITRE ATT&CK ID against an active enterprise STIX bundle, and
writes only small sample/manifest artifacts that are safe to commit.

Full generated corpora are written under data/generated/ by default. That path
is ignored by git and should be uploaded to a citable release/DOI instead.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mitre_attack_validator import MitreAttackValidator  # noqa: E402


ATTACK_TYPES = ["Phishing", "Ransomware", "Insider Threat", "APT"]
ENVIRONMENTS = ["Enterprise Network", "Cloud Infrastructure", "Healthcare", "ICS"]
DIFFICULTIES = ["Easy", "Medium", "Hard"]

THREAT_ACTORS = [
    "Lazarus Group (DPRK, financially motivated)",
    "APT28 / Fancy Bear (Russian GRU, espionage)",
    "APT41 (Chinese dual espionage/cybercrime)",
    "Cozy Bear / APT29 (Russian SVR, stealthy)",
    "Charming Kitten / APT35 (Iranian espionage)",
    "Sandworm (Russian GRU, destructive)",
    "Kimsuky (DPRK, intelligence collection)",
    "Mustang Panda (Chinese, political espionage)",
    "FIN7 (financially motivated, POS targeting)",
    "REvil / Sodinokibi (ransomware-as-a-service)",
    "Conti ransomware group (double extortion)",
    "Evil Corp (financial fraud, banking trojans)",
    "Disgruntled employee with privileged access",
    "Opportunistic criminal using commodity tooling",
]

INDUSTRIES_BY_ENV = {
    "Enterprise Network": [
        "Financial services / retail banking",
        "Government / defence contractor",
        "Retail / e-commerce / payment processing",
        "Telecommunications / ISP",
        "Higher education / research university",
        "Legal services / law firm",
        "Military contractor",
        "Media / broadcasting",
    ],
    "Cloud Infrastructure": [
        "Cloud-native SaaS startup",
        "Managed service provider",
        "Financial services cloud tenant",
        "Healthcare SaaS platform",
        "Government cloud workload",
    ],
    "Healthcare": [
        "Hospital emergency department",
        "Regional healthcare provider",
        "Pharmaceutical / life sciences",
        "Medical billing provider",
        "Clinical research organization",
    ],
    "ICS": [
        "Water treatment facility",
        "Critical infrastructure / power grid",
        "Manufacturing / automotive supply chain",
        "Oil and gas pipeline operator",
        "Building automation environment",
    ],
}

TTP_FOCUS_AREAS = [
    "initial access and credential harvesting",
    "living-off-the-land and defense evasion",
    "lateral movement and domain compromise",
    "data collection and staged exfiltration",
    "persistence and long-term implant deployment",
    "destructive payload delivery and impact",
    "supply-chain compromise and software tampering",
    "cloud service abuse and identity manipulation",
]

CAMPAIGN_OBJECTIVES = [
    "financial theft / business email compromise",
    "intellectual property theft / espionage",
    "ransomware deployment for extortion",
    "destructive attack on critical infrastructure",
    "persistent access for long-term intelligence collection",
    "supply-chain poisoning to reach downstream targets",
]

OPSEC_LEVELS = [
    "high operational security, slow and patient, low-noise",
    "moderate operational security, balanced speed and stealth",
    "low operational security, fast and noisy, time-pressured",
]

COST_PER_1K_INPUT = 0.00015
COST_PER_1K_OUTPUT = 0.00060


@dataclass(frozen=True)
class PlanItem:
    index: int
    attack_type: str
    environment: str
    difficulty: str
    target_industry: str
    threat_actor: str
    ttp_focus: str
    campaign_objective: str
    opsec_level: str


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, str):
                obj = json.loads(obj)
            rows.append(obj)
    return rows


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def output_path(path: str | None) -> Path | None:
    if path is None:
        return None
    parsed = Path(path)
    return parsed if parsed.is_absolute() else ROOT / parsed


def find_stix_bundle(explicit: str | None) -> Path:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.extend(
        [
            ROOT / "data" / "journal_results" / "enterprise-attack-14.1.json",
            ROOT / "data" / "journal_results" / "enterprise-attack.json",
        ]
    )
    for path in candidates:
        if path.exists():
            return path
    raise FileNotFoundError(
        "No ATT&CK STIX bundle found. Pass --stix path/to/enterprise-attack-14.1.json."
    )


def build_balanced_plan(n: int, seed: int) -> list[PlanItem]:
    rng = random.Random(seed)
    combos = [(at, env, diff) for at in ATTACK_TYPES for env in ENVIRONMENTS for diff in DIFFICULTIES]
    plan: list[PlanItem] = []

    actor_offset = rng.randrange(len(THREAT_ACTORS))
    focus_offset = rng.randrange(len(TTP_FOCUS_AREAS))
    objective_offset = rng.randrange(len(CAMPAIGN_OBJECTIVES))
    opsec_offset = rng.randrange(len(OPSEC_LEVELS))
    industry_offsets = {env: rng.randrange(len(industries)) for env, industries in INDUSTRIES_BY_ENV.items()}

    cycle = 0
    while len(plan) < n:
        shuffled = combos[:]
        rng.shuffle(shuffled)
        for attack_type, environment, difficulty in shuffled:
            industries = INDUSTRIES_BY_ENV[environment]
            idx = len(plan)
            plan.append(
                PlanItem(
                    index=idx + 1,
                    attack_type=attack_type,
                    environment=environment,
                    difficulty=difficulty,
                    target_industry=industries[(idx + cycle + industry_offsets[environment]) % len(industries)],
                    threat_actor=THREAT_ACTORS[(idx + cycle + actor_offset) % len(THREAT_ACTORS)],
                    ttp_focus=TTP_FOCUS_AREAS[(idx + focus_offset) % len(TTP_FOCUS_AREAS)],
                    campaign_objective=CAMPAIGN_OBJECTIVES[(idx + objective_offset) % len(CAMPAIGN_OBJECTIVES)],
                    opsec_level=OPSEC_LEVELS[(idx + opsec_offset) % len(OPSEC_LEVELS)],
                )
            )
            if len(plan) >= n:
                break
        cycle += 1
    return plan


def build_prompt(item: PlanItem, correction_hint: str | None = None) -> str:
    prompt = f"""
You are generating defensive cyber range scenario metadata for detection engineering research.

Return ONLY valid JSON. No markdown. No explanations.

Do not include functional exploit code, shell commands, payloads, malware source code,
live infrastructure details, credentials, domains, IP addresses, or operational instructions.

SCENARIO CONTEXT:
- Environment: {item.environment}
- Difficulty: {item.difficulty}
- Attack Type: {item.attack_type}
- Target Industry: {item.target_industry}
- Threat Actor Persona: {item.threat_actor}
- TTP Focus: {item.ttp_focus}
- Campaign Objective: {item.campaign_objective}
- Operational Security Level: {item.opsec_level}

OUTPUT JSON SCHEMA:
{{
  "scenario_id": "string",
  "environment_type": "{item.environment}",
  "difficulty": "{item.difficulty}",
  "attack_type": "{item.attack_type}",
  "threat_actor": "{item.threat_actor}",
  "target_industry": "{item.target_industry}",
  "ttp_focus": "{item.ttp_focus}",
  "campaign_objective": "{item.campaign_objective}",
  "opsec_level": "{item.opsec_level}",
  "realism_score": 0.0,
  "narrative": "2-3 sentence metadata-only campaign description",
  "attack_stages": [
    {{
      "stage_name": "Reconnaissance",
      "description": "metadata-only defensive description",
      "techniques": [
        {{"technique_id": "T1595", "technique_name": "Active Scanning"}}
      ]
    }}
  ],
  "mitre_attack_mapping": ["T1595", "T1566", "T1078"],
  "attack_graph": {{
    "nodes": ["Reconnaissance", "Initial Access"],
    "edges": [["Reconnaissance", "Initial Access"]]
  }}
}}

STRICT RULES:
- Use only active MITRE ATT&CK Enterprise technique IDs.
- Use T#### or T####.### IDs only.
- Include at least 4 attack stages.
- Keep all content defensive and non-operational.
- Match environment_type, difficulty, and attack_type exactly to the context above.
- Use specific, varied techniques that fit the persona and industry.
"""
    if correction_hint:
        prompt += f"\nCORRECTION REQUIRED:\n{correction_hint}\n"
    return prompt


def scenario_tids(scenario: dict[str, Any]) -> list[tuple[str, str]]:
    tids = []
    for si, stage in enumerate(scenario.get("attack_stages", []) or []):
        for ti, technique in enumerate(stage.get("techniques", []) or []):
            tid = str(technique.get("technique_id", "")).strip()
            if tid:
                tids.append((f"attack_stages[{si}].techniques[{ti}]", tid))
    for mi, tid in enumerate(scenario.get("mitre_attack_mapping", []) or []):
        tid = str(tid).strip()
        if tid:
            tids.append((f"mitre_attack_mapping[{mi}]", tid))
    return tids


def validate_scenario(
    scenario: dict[str, Any],
    item: PlanItem,
    validator: MitreAttackValidator,
) -> tuple[bool, list[str], list[dict[str, Any]]]:
    issues = []
    bad_ids = []
    required = [
        "scenario_id",
        "environment_type",
        "difficulty",
        "attack_type",
        "attack_stages",
        "mitre_attack_mapping",
        "attack_graph",
    ]
    for field in required:
        if field not in scenario:
            issues.append(f"Missing field: {field}")

    if scenario.get("environment_type") != item.environment:
        issues.append(f"environment_type must be {item.environment!r}")
    if scenario.get("difficulty") != item.difficulty:
        issues.append(f"difficulty must be {item.difficulty!r}")
    if scenario.get("attack_type") != item.attack_type:
        issues.append(f"attack_type must be {item.attack_type!r}")

    stages = scenario.get("attack_stages") or []
    if not isinstance(stages, list) or len(stages) < 4:
        issues.append("attack_stages must contain at least 4 stages")

    for loc, tid in scenario_tids(scenario):
        cls = validator.classify(tid)
        if cls != "ACTIVE":
            suggestion = validator.suggest(tid)
            bad_ids.append({"location": loc, "technique_id": tid, "class": cls, "suggestion": suggestion})
    if bad_ids:
        issues.append(
            "Non-active ATT&CK IDs: "
            + ", ".join(f"{b['technique_id']}({b['class']})" for b in bad_ids[:12])
        )

    text = json.dumps(scenario, ensure_ascii=False).lower()
    disallowed_markers = ["```", "-----begin", "password=", "api_key=", "private key"]
    found = [marker for marker in disallowed_markers if marker in text]
    if found:
        issues.append("Operational/sensitive marker detected: " + ", ".join(found))

    return len(issues) == 0, issues, bad_ids


def correction_hint(issues: list[str], bad_ids: list[dict[str, Any]], validator: MitreAttackValidator) -> str:
    lines = ["Fix every issue below and return corrected JSON only:"]
    for issue in issues:
        lines.append(f"- {issue}")
    for bad in bad_ids:
        suggestion = bad.get("suggestion")
        if suggestion and validator.technique_meta(suggestion):
            name = validator.technique_meta(suggestion)["name"]
            lines.append(
                f"- Replace {bad['technique_id']} at {bad['location']} with active ID "
                f"{suggestion} ({name}) or another active ID suitable for that stage."
            )
        else:
            lines.append(
                f"- Replace {bad['technique_id']} at {bad['location']} with a valid active "
                "MITRE ATT&CK Enterprise technique ID suitable for that stage."
            )
    return "\n".join(lines)


class ScaleupGenerator:
    def __init__(self, model: str, max_requery: int) -> None:
        from openai import OpenAI

        load_dotenv(ROOT / ".env")
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is missing. Add it to .env or the environment.")
        self.client = OpenAI(api_key=api_key)
        self.model = model
        self.max_requery = max_requery

    def call(self, prompt: str, temperature: float, top_p: float) -> tuple[dict[str, Any], int, int, str]:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You produce defensive cybersecurity scenario metadata as strict JSON. "
                        "Never include executable exploit steps or payload code."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=temperature,
            top_p=top_p,
            response_format={"type": "json_object"},
        )
        raw = response.choices[0].message.content or "{}"
        obj = json.loads(raw)
        if isinstance(obj, str):
            obj = json.loads(obj)
        usage = response.usage
        return obj, int(usage.prompt_tokens), int(usage.completion_tokens), raw

    def generate(
        self,
        item: PlanItem,
        validator: MitreAttackValidator,
        temperature: float,
        top_p: float,
    ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
        started = time.time()
        input_tokens = 0
        output_tokens = 0
        attempts = []
        first_attempt_active = False

        prompt = build_prompt(item)
        scenario: dict[str, Any] | None = None
        final_issues: list[str] = []
        final_bad_ids: list[dict[str, Any]] = []

        for attempt_idx in range(self.max_requery + 1):
            try:
                scenario, in_tok, out_tok, _raw = self.call(prompt, temperature=temperature, top_p=top_p)
                input_tokens += in_tok
                output_tokens += out_tok
                ok, issues, bad_ids = validate_scenario(scenario, item, validator)
            except Exception as exc:
                scenario = None
                ok = False
                issues = [f"Generation/parse error: {exc}"]
                bad_ids = []

            attempts.append(
                {
                    "attempt": attempt_idx + 1,
                    "valid": ok,
                    "issues": issues,
                    "bad_ids": bad_ids,
                }
            )
            if attempt_idx == 0:
                first_attempt_active = ok
            if ok and scenario is not None:
                break

            final_issues = issues
            final_bad_ids = bad_ids
            if attempt_idx < self.max_requery:
                prompt = build_prompt(item, correction_hint(final_issues, final_bad_ids, validator))

        accepted = scenario is not None and attempts[-1]["valid"]
        elapsed = time.time() - started
        cost = input_tokens / 1000 * COST_PER_1K_INPUT + output_tokens / 1000 * COST_PER_1K_OUTPUT
        meta = {
            "plan": asdict(item),
            "accepted": accepted,
            "first_attempt_active": first_attempt_active,
            "attempt_count": len(attempts),
            "attempts": attempts,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "estimated_cost_usd": round(cost, 8),
            "elapsed_sec": round(elapsed, 3),
        }
        if not accepted:
            return None, meta

        assert scenario is not None
        scenario["scaleup_metadata"] = {
            "generated_at": utc_now(),
            "generation_mode": "phase0.5_scaleup",
            "model": self.model,
            "temperature": temperature,
            "top_p": top_p,
            "plan": asdict(item),
        }
        return scenario, meta


def wilson_ci(successes: int, n: int) -> list[float] | None:
    if n == 0:
        return None
    z = 1.96
    p = successes / n
    denom = 1 + z**2 / n
    centre = p + z**2 / (2 * n)
    spread = z * math.sqrt((p * (1 - p) + z**2 / (4 * n)) / n)
    return [round((centre - spread) / denom, 4), round((centre + spread) / denom, 4)]


def summarize_scenarios(
    scenarios: list[dict[str, Any]],
    validator: MitreAttackValidator,
    base_technique_denominator: int,
) -> dict[str, Any]:
    active_ids = set()
    base_ids = set()
    by_combo = Counter()
    by_env = Counter()
    by_attack = Counter()
    by_difficulty = Counter()

    for scenario in scenarios:
        by_combo[
            (
                scenario.get("attack_type", "Unknown"),
                scenario.get("environment_type", "Unknown"),
                scenario.get("difficulty", "Unknown"),
            )
        ] += 1
        by_env[scenario.get("environment_type", "Unknown")] += 1
        by_attack[scenario.get("attack_type", "Unknown")] += 1
        by_difficulty[scenario.get("difficulty", "Unknown")] += 1
        for _loc, tid in scenario_tids(scenario):
            if validator.is_valid(tid):
                active_ids.add(tid)
                base_ids.add(tid.split(".")[0])

    return {
        "scenario_count": len(scenarios),
        "unique_active_v14_ids": len(active_ids),
        "unique_active_v14_ids_list": sorted(active_ids),
        "unique_base_techniques": len(base_ids),
        "base_technique_coverage": round(len(base_ids) / base_technique_denominator, 6)
        if base_technique_denominator
        else None,
        "by_environment": dict(sorted(by_env.items())),
        "by_attack_type": dict(sorted(by_attack.items())),
        "by_difficulty": dict(sorted(by_difficulty.items())),
        "combo_min_count": min(by_combo.values()) if by_combo else 0,
        "combo_max_count": max(by_combo.values()) if by_combo else 0,
    }


def stratified_sample(scenarios: list[dict[str, Any]], sample_n: int, seed: int) -> list[dict[str, Any]]:
    if sample_n <= 0 or len(scenarios) <= sample_n:
        return scenarios[:]
    rng = random.Random(seed)
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for scenario in scenarios:
        groups[
            (
                scenario.get("attack_type", "Unknown"),
                scenario.get("environment_type", "Unknown"),
                scenario.get("difficulty", "Unknown"),
            )
        ].append(scenario)

    sample = []
    per_group = max(1, sample_n // max(1, len(groups)))
    for key in sorted(groups):
        rows = groups[key][:]
        rng.shuffle(rows)
        sample.extend(rows[:per_group])

    if len(sample) < sample_n:
        remaining = [s for s in scenarios if s not in sample]
        rng.shuffle(remaining)
        sample.extend(remaining[: sample_n - len(sample)])
    rng.shuffle(sample)
    return sample[:sample_n]


def write_jsonl(path: Path, scenarios: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for scenario in scenarios:
            f.write(json.dumps(scenario, ensure_ascii=False) + "\n")


def active_base_denominator(validator: MitreAttackValidator) -> int:
    return len({tid for tid in validator.active if "." not in tid})


def run(args: argparse.Namespace) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    plan = build_balanced_plan(args.n, seed=args.seed)
    plan_counts = Counter((p.attack_type, p.environment, p.difficulty) for p in plan)

    if args.dry_run:
        print(f"Dry run: planned {len(plan)} scenarios across {len(plan_counts)} combos")
        print(f"Per-combo count range: {min(plan_counts.values())}..{max(plan_counts.values())}")
        print("First 5 plan rows:")
        for row in plan[:5]:
            print(json.dumps(asdict(row), indent=2))
        return 0

    if not args.run:
        print("Refusing to call the API without --run. Use --dry-run to inspect the plan.")
        return 2

    stix_path = find_stix_bundle(args.stix)
    validator = MitreAttackValidator(stix_path)
    denominator = active_base_denominator(validator)

    out_dir = output_path(args.out) or ROOT / "data" / "generated" / "scaleup"
    out_dir.mkdir(parents=True, exist_ok=True)
    full_path = out_dir / args.full_name
    log_path = out_dir / args.log_name

    existing = load_jsonl(full_path) if args.resume else []
    completed = len(existing)
    if completed:
        print(f"Resuming from {completed} existing accepted scenarios in {full_path}")

    generator = ScaleupGenerator(model=args.model, max_requery=args.max_requery)
    scenarios = existing[:]
    log_entries: list[dict[str, Any]] = []
    if args.resume and log_path.exists():
        with log_path.open(encoding="utf-8") as f:
            log_entries = json.load(f).get("entries", [])

    with full_path.open("a", encoding="utf-8") as fout:
        for item in plan[completed:]:
            print(
                f"[{item.index}/{args.n}] {item.attack_type} | {item.environment} | "
                f"{item.difficulty} | {item.threat_actor[:26]} ...",
                end=" ",
                flush=True,
            )
            scenario, meta = generator.generate(
                item,
                validator,
                temperature=args.temperature,
                top_p=args.top_p,
            )
            log_entries.append(meta)
            if scenario:
                scenarios.append(scenario)
                fout.write(json.dumps(scenario, ensure_ascii=False) + "\n")
                print(
                    f"OK attempts={meta['attempt_count']} "
                    f"first_active={meta['first_attempt_active']} "
                    f"cost=${meta['estimated_cost_usd']:.6f}"
                )
            else:
                print(f"REJECT attempts={meta['attempt_count']}")

            if item.index % args.checkpoint_every == 0:
                write_json(log_path, {"updated_at": utc_now(), "entries": log_entries})

    write_json(log_path, {"updated_at": utc_now(), "entries": log_entries})

    accepted = sum(1 for row in log_entries if row.get("accepted"))
    first_active = sum(1 for row in log_entries if row.get("first_attempt_active"))
    total_input = sum(int(row.get("input_tokens", 0)) for row in log_entries)
    total_output = sum(int(row.get("output_tokens", 0)) for row in log_entries)
    total_cost = total_input / 1000 * COST_PER_1K_INPUT + total_output / 1000 * COST_PER_1K_OUTPUT
    scenario_summary = summarize_scenarios(scenarios, validator, denominator)

    sample = stratified_sample(scenarios, sample_n=args.sample_n, seed=args.seed)
    sample_path = output_path(args.sample_out) if args.sample_out else ROOT / "dataset" / "samples" / args.sample_name
    manifest_path = (
        output_path(args.manifest_out)
        if args.manifest_out
        else ROOT / "dataset" / "manifests" / args.manifest_name
    )
    write_jsonl(sample_path, sample)

    validation = {
        "created_at": utc_now(),
        "model": args.model,
        "n_requested": args.n,
        "n_accepted": accepted,
        "n_rejected": len(log_entries) - accepted,
        "first_attempt_active_rate": round(first_active / max(1, len(log_entries)), 6),
        "first_attempt_active_rate_wilson_95ci": wilson_ci(first_active, len(log_entries)),
        "accepted_rate": round(accepted / max(1, len(log_entries)), 6),
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "estimated_cost_usd": round(total_cost, 6),
        "cost_per_accepted_scenario_usd": round(total_cost / max(1, accepted), 8),
        "stix_bundle": str(stix_path),
        "stix_sha256": sha256_file(stix_path),
        "scenario_summary": scenario_summary,
    }
    validation_path = (
        output_path(args.validation_out)
        if args.validation_out
        else ROOT / "results" / "scaleup_validation.json"
    )
    validation_path.parent.mkdir(exist_ok=True)
    write_json(validation_path, validation)

    manifest = {
        "created_at": utc_now(),
        "release_url": args.release_url,
        "full_corpus": {
            "path": str(full_path),
            "sha256": sha256_file(full_path),
            "record_count": len(scenarios),
            "committed_to_git": False,
        },
        "sample": {
            "path": str(sample_path.relative_to(ROOT) if sample_path.is_relative_to(ROOT) else sample_path),
            "sha256": sha256_file(sample_path),
            "record_count": len(sample),
            "committed_to_git": True,
        },
        "generation_config": {
            "n": args.n,
            "seed": args.seed,
            "model": args.model,
            "temperature": args.temperature,
            "top_p": args.top_p,
            "max_requery": args.max_requery,
            "defensive_scope": "metadata-only; no executable payloads or live targets",
        },
        "validation": validation,
    }
    write_json(manifest_path, manifest)

    print("\nScale-up run complete")
    print(f"Accepted: {accepted}/{args.n}")
    print(f"First-attempt active-v14 rate: {validation['first_attempt_active_rate']}")
    print(f"Full corpus: {full_path} (ignored by git)")
    print(f"Sample: {sample_path}")
    print(f"Manifest: {manifest_path}")
    print(f"Validation: {validation_path}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Phase 0.5 AdverSim corpus scale-up runner")
    parser.add_argument("--n", type=int, default=5000, help="Number of base scenarios to generate")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--model", default="gpt-4o-mini")
    parser.add_argument("--temperature", type=float, default=0.7)
    parser.add_argument("--top-p", type=float, default=0.95)
    parser.add_argument("--max-requery", type=int, default=2)
    parser.add_argument("--out", default="data/generated/scaleup")
    parser.add_argument("--full-name", default="adversim_scaleup_full.jsonl")
    parser.add_argument("--log-name", default="adversim_scaleup_log.json")
    parser.add_argument("--sample-n", type=int, default=240)
    parser.add_argument("--sample-name", default="scaleup_sample.jsonl")
    parser.add_argument("--manifest-name", default="scaleup_MANIFEST.json")
    parser.add_argument("--sample-out", default=None, help="Override sample output path")
    parser.add_argument("--manifest-out", default=None, help="Override manifest output path")
    parser.add_argument("--validation-out", default=None, help="Override validation output path")
    parser.add_argument("--checkpoint-every", type=int, default=25)
    parser.add_argument("--stix", default=None, help="Path to pinned ATT&CK v14.1 enterprise STIX bundle")
    parser.add_argument("--release-url", default=None, help="Zenodo/GitHub Release URL for the full corpus")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="Print the balanced plan without API calls")
    parser.add_argument("--run", action="store_true", help="Required for paid API generation")
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(run(parse_args()))
