"""Cross-ATT&CK-version robustness audit.

This script checks whether generated scenarios remain valid as the ATT&CK
Enterprise matrix changes. It fetches official MITRE ATT&CK STIX bundles when
available, caches compact active-ID indices under ignored raw storage, and
commits only aggregate results.
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "full_dataset_v14clean.jsonl"
CACHE_DIR = ROOT / "data" / "raw_baselines" / "attack_versions"
RESULTS_PATH = ROOT / "results" / "attack_version_robustness.json"
AUDIT_PATH = ROOT / "results" / "attack_version_robustness_audit.md"

VERSION_URLS = {
    "v13.1": "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v13.1/enterprise-attack/enterprise-attack.json",
    "v14.1": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v14.1/enterprise-attack/enterprise-attack.json",
    "v15.1": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v15.1/enterprise-attack/enterprise-attack.json",
}

TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            rows.append(json.loads(obj) if isinstance(obj, str) else obj)
    return rows


def extract_tid(value: Any) -> str | None:
    match = TECHNIQUE_RE.search(str(value or "").upper())
    return match.group(0) if match else None


def scenario_tids(scenario: dict[str, Any]) -> list[str]:
    tids = []
    for stage in scenario.get("attack_stages", []) or []:
        for technique in stage.get("techniques", []) or []:
            tid = extract_tid(technique.get("technique_id"))
            if tid:
                tids.append(tid)
    for tid in scenario.get("mitre_attack_mapping", []) or []:
        parsed = extract_tid(tid)
        if parsed:
            tids.append(parsed)
    return tids


def download_stix(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=120) as response:
        return json.loads(response.read().decode("utf-8"))


def active_index_from_stix(bundle: dict[str, Any]) -> dict[str, Any]:
    active = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = None
        for ref in obj.get("external_references", []) or []:
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id")
                break
        if not tid or not TECHNIQUE_RE.fullmatch(tid):
            continue
        active[tid] = {
            "name": obj.get("name"),
            "modified": obj.get("modified"),
        }
    return {"active": active, "active_count": len(active)}


def load_or_fetch_index(label: str, url: str, cache_dir: Path) -> dict[str, Any]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / f"{label.replace('.', '_')}_active.json"
    if cache_path.exists():
        return json.loads(cache_path.read_text(encoding="utf-8"))
    bundle = download_stix(url)
    index = active_index_from_stix(bundle)
    index["source_url"] = url
    cache_path.write_text(json.dumps(index, indent=2, sort_keys=True), encoding="utf-8")
    return index


def evaluate_version(label: str, index: dict[str, Any], scenario_rows: list[dict[str, Any]]) -> dict[str, Any]:
    active = set(index.get("active", {}))
    active_bases = {tid for tid in active if "." not in tid}
    scenario_results = []
    all_tids = []
    for scenario in scenario_rows:
        tids = scenario_tids(scenario)
        all_tids.extend(tids)
        inactive = sorted({tid for tid in tids if tid not in active})
        scenario_results.append(
            {
                "scenario_id": scenario.get("scenario_id"),
                "all_ids_active": not inactive,
                "inactive_ids": inactive,
            }
        )
    unique = sorted(set(all_tids))
    unique_active = sorted({tid for tid in unique if tid in active})
    unique_inactive = sorted(set(unique) - active)
    scenario_all_active = sum(1 for row in scenario_results if row["all_ids_active"])
    return {
        "version": label,
        "status": "completed",
        "source_url": index.get("source_url"),
        "active_technique_count": len(active),
        "active_base_technique_count": len(active_bases),
        "scenario_count": len(scenario_rows),
        "scenario_all_ids_active_count": scenario_all_active,
        "scenario_all_ids_active_rate": round(scenario_all_active / max(1, len(scenario_rows)), 6),
        "unique_ids_in_corpus": len(unique),
        "unique_ids_active_in_version": len(unique_active),
        "unique_ids_inactive_in_version": len(unique_inactive),
        "unique_id_active_rate": round(len(unique_active) / max(1, len(unique)), 6),
        "base_coverage": round(len({tid.split('.')[0] for tid in unique_active}) / max(1, len(active_bases)), 6),
        "inactive_ids_sample": unique_inactive[:40],
    }


def write_audit(results: dict[str, Any], path: Path) -> None:
    lines = [
        "# Cross-ATT&CK-Version Robustness Audit",
        "",
        "This audit validates the committed v14-clean AdverSim corpus against",
        "official MITRE ATT&CK Enterprise STIX bundles for matrix-version shift.",
        "Only compact active-ID indices are cached locally; raw STIX bundles are not committed.",
        "",
        "| Version | Status | Scenario all-active rate | Unique ID active rate | Base coverage | Notes |",
        "|---|---|---:|---:|---:|---|",
    ]
    for row in results["versions"]:
        if row["status"] != "completed":
            lines.append(f"| {row['version']} | {row['status']} | - | - | - | {row.get('error', '')} |")
            continue
        lines.append(
            "| {version} | completed | {scenario:.1%} | {unique:.1%} | {coverage:.1%} | inactive unique IDs: {inactive} |".format(
                version=row["version"],
                scenario=row["scenario_all_ids_active_rate"],
                unique=row["unique_id_active_rate"],
                coverage=row["base_coverage"],
                inactive=row["unique_ids_inactive_in_version"],
            )
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "Use this as temporal-shift evidence for the validation loop. The key",
            "claim is not that every historical matrix is identical, but that active",
            "ID validation can be re-run against a selected ATT&CK release and report",
            "which identifiers require remediation.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS_PATH)
    parser.add_argument("--cache-dir", type=Path, default=CACHE_DIR)
    parser.add_argument("--out", type=Path, default=RESULTS_PATH)
    parser.add_argument("--audit", type=Path, default=AUDIT_PATH)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    scenarios = load_jsonl(args.corpus)
    rows = []
    for label, url in VERSION_URLS.items():
        try:
            index = load_or_fetch_index(label, url, args.cache_dir)
            rows.append(evaluate_version(label, index, scenarios))
        except Exception as exc:
            rows.append({"version": label, "status": "unavailable_from_source", "source_url": url, "error": str(exc)})
    results = {
        "schema_version": 1,
        "corpus": str(args.corpus.relative_to(ROOT) if args.corpus.is_relative_to(ROOT) else args.corpus),
        "method": "Validate every corpus ATT&CK ID against active Enterprise attack-pattern IDs in each available STIX release.",
        "versions": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.audit.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    write_audit(results, args.audit)
    print(f"wrote {args.out}")
    print(f"wrote {args.audit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
