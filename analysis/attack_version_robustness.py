"""Cross-ATT&CK-version robustness audit.

This analysis validates an existing AdverSim corpus against multiple MITRE
ATT&CK Enterprise matrix releases without calling any LLM APIs. It reports the
active/deprecated/unrecognised split and a deterministic remediation path:

1. keep IDs already active in the selected matrix;
2. auto-replace deprecated/revoked IDs when an official successor or active
   parent technique is available;
3. mark the remaining scenarios for the existing validate-and-requery loop.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CACHE_DIR = ROOT / "data" / "raw_baselines" / "attack_versions"
RESULTS_PATH = ROOT / "results" / "attack_version_robustness.json"
AUDIT_PATH = ROOT / "results" / "attack_version_robustness_audit.md"

DEFAULT_CORPUS_CANDIDATES = [
    ROOT / "data" / "generated" / "scaleup" / "adversim_scaleup_full.jsonl",
    ROOT / "dataset" / "full_dataset.jsonl",
    ROOT / "full_dataset_v14clean.jsonl",
]

VERSION_URLS = {
    "v13.1": "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v13.1/enterprise-attack/enterprise-attack.json",
    "v14.1": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v14.1/enterprise-attack/enterprise-attack.json",
    "v15.1": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v15.1/enterprise-attack/enterprise-attack.json",
}

TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
TECHNIQUE_SEARCH_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


@dataclass(frozen=True)
class TechniqueRef:
    tid: str
    location: str


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def resolve_corpus(explicit: Path | None) -> Path:
    if explicit:
        path = explicit if explicit.is_absolute() else ROOT / explicit
        if not path.exists():
            raise FileNotFoundError(f"corpus not found: {path}")
        return path

    for path in DEFAULT_CORPUS_CANDIDATES:
        if path.exists():
            return path
    candidates = "\n".join(f"- {display_path(path)}" for path in DEFAULT_CORPUS_CANDIDATES)
    raise FileNotFoundError(f"no default corpus found; checked:\n{candidates}")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if isinstance(obj, str):
                obj = json.loads(obj)
            if not isinstance(obj, dict):
                raise ValueError(f"{path}:{line_no} is not a JSON object")
            rows.append(obj)
    if not rows:
        raise ValueError(f"corpus has no scenarios: {path}")
    return rows


def extract_tid(value: Any) -> str | None:
    match = TECHNIQUE_SEARCH_RE.search(str(value or "").upper())
    return match.group(0).upper() if match else None


def scenario_id(scenario: dict[str, Any], index: int) -> str:
    raw = scenario.get("scenario_id") or scenario.get("id")
    return str(raw) if raw else f"row_{index:06d}"


def scenario_tids(scenario: dict[str, Any]) -> list[TechniqueRef]:
    refs: list[TechniqueRef] = []
    for stage_i, stage in enumerate(scenario.get("attack_stages", []) or []):
        for tech_i, technique in enumerate(stage.get("techniques", []) or []):
            tid = extract_tid(technique.get("technique_id"))
            if tid:
                refs.append(TechniqueRef(tid, f"attack_stages[{stage_i}].techniques[{tech_i}]"))
    for map_i, raw_tid in enumerate(scenario.get("mitre_attack_mapping", []) or []):
        tid = extract_tid(raw_tid)
        if tid:
            refs.append(TechniqueRef(tid, f"mitre_attack_mapping[{map_i}]"))
    return refs


def download_json(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=120) as response:
        return json.loads(response.read().decode("utf-8"))


def technique_id_from_stix(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            tid = str(ref["external_id"]).strip().upper()
            return tid if TECHNIQUE_RE.fullmatch(tid) else None
    return None


def compact_index_from_stix(bundle: dict[str, Any], source_url: str) -> dict[str, Any]:
    active: dict[str, dict[str, Any]] = {}
    deprecated: dict[str, dict[str, Any]] = {}
    stixid_to_tid: dict[str, str] = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        tid = technique_id_from_stix(obj)
        if not tid:
            continue
        stixid_to_tid[obj.get("id", "")] = tid
        meta = {
            "name": obj.get("name", ""),
            "modified": obj.get("modified", ""),
            "revoked": bool(obj.get("revoked", False)),
            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
            "tactics": [
                phase.get("phase_name", "")
                for phase in obj.get("kill_chain_phases", []) or []
                if phase.get("kill_chain_name") == "mitre-attack"
            ],
        }
        if meta["revoked"] or meta["deprecated"]:
            deprecated.setdefault(tid, meta)
        else:
            active[tid] = meta

    successors: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "revoked-by":
            continue
        src = stixid_to_tid.get(obj.get("source_ref", ""))
        dst = stixid_to_tid.get(obj.get("target_ref", ""))
        if src and dst:
            successors[src] = dst

    return {
        "schema_version": 2,
        "source_url": source_url,
        "fetched_at": utc_now(),
        "active": dict(sorted(active.items())),
        "deprecated": dict(sorted(deprecated.items())),
        "successors": dict(sorted(successors.items())),
        "active_count": len(active),
        "deprecated_count": len(deprecated),
    }


def load_or_fetch_index(label: str, url: str, cache_dir: Path, refresh: bool = False) -> dict[str, Any]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / f"{label.replace('.', '_')}_index.json"
    if cache_path.exists() and not refresh:
        index = json.loads(cache_path.read_text(encoding="utf-8"))
        if index.get("schema_version") == 2 and "deprecated" in index:
            return index

    bundle = download_json(url)
    index = compact_index_from_stix(bundle, source_url=url)
    cache_path.write_text(json.dumps(index, indent=2, sort_keys=True), encoding="utf-8")
    return index


def classify_tid(tid: str, index: dict[str, Any]) -> str:
    if not TECHNIQUE_RE.fullmatch(tid):
        return "unrecognised"
    if tid in index["active"]:
        return "active"
    if tid in index["deprecated"]:
        return "deprecated"
    return "unrecognised"


def replacement_for(tid: str, index: dict[str, Any]) -> tuple[str | None, str]:
    successor = index.get("successors", {}).get(tid)
    if successor and successor in index["active"]:
        return successor, "official_successor"

    if "." in tid:
        parent = tid.split(".")[0]
        if parent in index["active"]:
            return parent, "active_parent"

    return None, "matrix_aware_requery"


def counter_to_sorted_dict(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0])))


def evaluate_version(label: str, index: dict[str, Any], scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    occurrence_split: Counter[str] = Counter()
    unique_by_class: dict[str, set[str]] = defaultdict(set)
    tid_occurrences: Counter[str] = Counter()
    tid_scenarios: dict[str, set[str]] = defaultdict(set)
    scenario_rows: list[dict[str, Any]] = []
    requery_scenarios: set[str] = set()
    auto_repaired_scenarios: set[str] = set()

    for row_i, scenario in enumerate(scenarios, start=1):
        sid = scenario_id(scenario, row_i)
        refs = scenario_tids(scenario)
        classes: Counter[str] = Counter()
        non_active: set[str] = set()
        unresolved_after_auto: set[str] = set()
        auto_repaired: set[str] = set()

        for ref in refs:
            cls = classify_tid(ref.tid, index)
            occurrence_split[cls] += 1
            unique_by_class[cls].add(ref.tid)
            tid_occurrences[ref.tid] += 1
            tid_scenarios[ref.tid].add(sid)
            classes[cls] += 1
            if cls == "active":
                continue

            non_active.add(ref.tid)
            replacement, _strategy = replacement_for(ref.tid, index)
            if replacement:
                auto_repaired.add(ref.tid)
            else:
                unresolved_after_auto.add(ref.tid)

        if auto_repaired:
            auto_repaired_scenarios.add(sid)
        if unresolved_after_auto:
            requery_scenarios.add(sid)

        scenario_rows.append(
            {
                "scenario_id": sid,
                "all_ids_active": not non_active,
                "non_active_unique_ids": sorted(non_active),
                "auto_repairable_unique_ids": sorted(auto_repaired),
                "requery_required_unique_ids": sorted(unresolved_after_auto),
                "split": dict(sorted(classes.items())),
            }
        )

    unique_ids = set().union(*unique_by_class.values()) if unique_by_class else set()
    non_active_ids = sorted(unique_by_class["deprecated"] | unique_by_class["unrecognised"])
    remediation_map = {}
    auto_repairable = 0
    requery_required = 0
    for tid in non_active_ids:
        cls = classify_tid(tid, index)
        replacement, strategy = replacement_for(tid, index)
        if replacement:
            auto_repairable += 1
        else:
            requery_required += 1
        remediation_map[tid] = {
            "class": cls,
            "occurrences": tid_occurrences[tid],
            "affected_scenario_count": len(tid_scenarios[tid]),
            "replacement": replacement,
            "strategy": strategy,
        }

    all_active_scenarios = sum(1 for row in scenario_rows if row["all_ids_active"])
    after_auto_valid_scenarios = sum(1 for row in scenario_rows if not row["requery_required_unique_ids"])
    scenario_count = len(scenarios)
    occurrence_total = sum(occurrence_split.values())
    unique_split = {key: len(value) for key, value in sorted(unique_by_class.items())}

    return {
        "version": label,
        "status": "completed",
        "source_url": index.get("source_url"),
        "matrix": {
            "active_technique_count": len(index.get("active", {})),
            "deprecated_or_revoked_technique_count": len(index.get("deprecated", {})),
            "active_base_technique_count": len({tid for tid in index.get("active", {}) if "." not in tid}),
        },
        "corpus": {
            "scenario_count": scenario_count,
            "technique_occurrence_count": occurrence_total,
            "unique_technique_count": len(unique_ids),
        },
        "split": {
            "occurrences": counter_to_sorted_dict(occurrence_split),
            "unique_ids": dict(sorted(unique_split.items())),
            "occurrence_rates": {
                key: round(value / max(1, occurrence_total), 6)
                for key, value in sorted(occurrence_split.items())
            },
            "unique_id_rates": {
                key: round(value / max(1, len(unique_ids)), 6)
                for key, value in sorted(unique_split.items())
            },
        },
        "scenario_validity": {
            "all_ids_active_count": all_active_scenarios,
            "all_ids_active_rate": round(all_active_scenarios / max(1, scenario_count), 6),
            "valid_after_deterministic_auto_repair_count": after_auto_valid_scenarios,
            "valid_after_deterministic_auto_repair_rate": round(after_auto_valid_scenarios / max(1, scenario_count), 6),
            "scenario_count_requiring_requery": len(requery_scenarios),
            "projected_after_requery_rate": 1.0,
        },
        "path_to_100_percent_valid": {
            "step_0_validate_against_matrix": {
                "all_ids_active_scenarios": all_active_scenarios,
                "non_active_unique_ids": len(non_active_ids),
            },
            "step_1_deterministic_auto_repair": {
                "auto_repairable_unique_ids": auto_repairable,
                "affected_scenarios": len(auto_repaired_scenarios),
                "strategies": counter_to_sorted_dict(
                    Counter(entry["strategy"] for entry in remediation_map.values() if entry["replacement"])
                ),
                "valid_scenarios_after_step": after_auto_valid_scenarios,
            },
            "step_2_validate_and_requery": {
                "requery_required_unique_ids": requery_required,
                "requery_required_scenarios": len(requery_scenarios),
                "projected_valid_scenarios_after_successful_requery": scenario_count,
            },
        },
        "top_non_active_ids": sorted(
            remediation_map.items(),
            key=lambda item: (-item[1]["occurrences"], item[0]),
        )[:50],
        "remediation_map": remediation_map,
        "scenario_samples_requiring_requery": [
            row for row in scenario_rows if row["requery_required_unique_ids"]
        ][:25],
    }


def write_audit(results: dict[str, Any], path: Path) -> None:
    lines = [
        "# Cross-ATT&CK-Version Robustness Audit",
        "",
        f"Generated: `{results['generated_at']}`",
        f"Corpus: `{results['corpus']['path']}`",
        f"Corpus SHA-256: `{results['corpus']['sha256']}`",
        f"Scenario count: `{results['corpus']['scenario_count']}`",
        "",
        "This is a zero-API-token matrix-membership audit. It reuses the fixed",
        "corpus and validates every ATT&CK ID against v13.1, v14.1, and v15.1.",
        "",
        "| Version | Active occ. | Deprecated occ. | Unrecognised occ. | Unique active | Unique deprecated | Unique unrecognised | All-active scenarios | After auto-repair | Requery scenarios |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    for row in results["versions"]:
        if row["status"] != "completed":
            lines.append(f"| {row['version']} | - | - | - | - | - | - | - | - | - |")
            continue
        occ = row["split"]["occurrences"]
        uniq = row["split"]["unique_ids"]
        validity = row["scenario_validity"]
        lines.append(
            "| {version} | {active_occ} | {dep_occ} | {unrec_occ} | {active_u} | {dep_u} | {unrec_u} | {all_active:.1%} | {after_auto:.1%} | {requery} |".format(
                version=row["version"],
                active_occ=occ.get("active", 0),
                dep_occ=occ.get("deprecated", 0),
                unrec_occ=occ.get("unrecognised", 0),
                active_u=uniq.get("active", 0),
                dep_u=uniq.get("deprecated", 0),
                unrec_u=uniq.get("unrecognised", 0),
                all_active=validity["all_ids_active_rate"],
                after_auto=validity["valid_after_deterministic_auto_repair_rate"],
                requery=validity["scenario_count_requiring_requery"],
            )
        )

    lines.extend(["", "## Path To 100% Valid", ""])
    for row in results["versions"]:
        if row["status"] != "completed":
            continue
        path_info = row["path_to_100_percent_valid"]
        lines.extend(
            [
                f"### {row['version']}",
                "",
                f"- Step 0 validation: `{path_info['step_0_validate_against_matrix']['all_ids_active_scenarios']}` scenarios already all-active.",
                f"- Step 1 deterministic repair: `{path_info['step_1_deterministic_auto_repair']['auto_repairable_unique_ids']}` unique IDs can be repaired by official successor or active-parent mapping.",
                f"- Step 2 validate-and-requery: `{path_info['step_2_validate_and_requery']['requery_required_scenarios']}` scenarios require matrix-aware requery for remaining unrecognised IDs.",
                f"- Projected successful loop endpoint: `{path_info['step_2_validate_and_requery']['projected_valid_scenarios_after_successful_requery']}` / `{results['corpus']['scenario_count']}` scenarios valid.",
                "",
            ]
        )

    lines.extend(
        [
            "## Interpretation",
            "",
            "The evidence is intentionally framed as temporal robustness of the",
            "validation loop, not as fresh generation. Differences across v13/v14/v15",
            "identify which existing IDs remain active, which can be deterministically",
            "mapped, and which require the same validate-and-requery loop used during",
            "generation.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=None, help="JSONL corpus. Defaults to 5k scale-up if present.")
    parser.add_argument("--cache-dir", type=Path, default=CACHE_DIR)
    parser.add_argument("--out", type=Path, default=RESULTS_PATH)
    parser.add_argument("--audit", type=Path, default=AUDIT_PATH)
    parser.add_argument("--refresh-matrices", action="store_true", help="Re-fetch compact ATT&CK indexes.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    corpus_path = resolve_corpus(args.corpus)
    scenarios = load_jsonl(corpus_path)

    rows: list[dict[str, Any]] = []
    for label, url in VERSION_URLS.items():
        try:
            index = load_or_fetch_index(label, url, args.cache_dir, refresh=args.refresh_matrices)
            rows.append(evaluate_version(label, index, scenarios))
        except Exception as exc:
            rows.append({"version": label, "status": "unavailable_from_source", "source_url": url, "error": str(exc)})

    results = {
        "schema_version": 2,
        "generated_at": utc_now(),
        "method": (
            "Fixed-corpus cross-matrix validation. No LLM calls. Each ATT&CK ID is "
            "classified as active, deprecated/revoked, or unrecognised for each matrix; "
            "non-active IDs are assigned deterministic repair or validate-and-requery."
        ),
        "corpus": {
            "path": display_path(corpus_path),
            "sha256": sha256_file(corpus_path),
            "scenario_count": len(scenarios),
        },
        "versions": rows,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.audit.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    write_audit(results, args.audit)

    print(f"corpus: {display_path(corpus_path)} ({len(scenarios)} scenarios)")
    for row in rows:
        if row["status"] != "completed":
            print(f"{row['version']}: unavailable ({row.get('error', '')})")
            continue
        split = row["split"]["unique_ids"]
        validity = row["scenario_validity"]
        print(
            f"{row['version']}: unique active={split.get('active', 0)}, "
            f"deprecated={split.get('deprecated', 0)}, "
            f"unrecognised={split.get('unrecognised', 0)}, "
            f"all-active={validity['all_ids_active_rate']:.1%}, "
            f"after-auto={validity['valid_after_deterministic_auto_repair_rate']:.1%}, "
            f"requery-scenarios={validity['scenario_count_requiring_requery']}"
        )
    print(f"wrote {display_path(args.out)}")
    print(f"wrote {display_path(args.audit)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
