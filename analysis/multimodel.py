"""Phase 5 multi-LLM generalization runner and summarizer.

This wrapper reuses the Phase 0.5 generator/validator so every model is judged
through the same prompt, balanced plan, active-v14 validation, and requery loop.
Full per-model corpora stay under data/generated/ and are ignored by git. The
tracked deliverables are a compact aggregate JSON table and audit note.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODELS = ["gpt-4o-mini", "gpt-4.1-mini"]
DEFAULT_OUT = ROOT / "data" / "generated" / "multimodel"
RESULTS_PATH = ROOT / "results" / "multimodel.json"
AUDIT_PATH = ROOT / "results" / "multimodel_audit.md"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")


def run_subprocess(cmd: list[str]) -> int:
    printable = " ".join(cmd)
    print(f"\n$ {printable}")
    completed = subprocess.run(cmd, cwd=ROOT)
    return completed.returncode


def model_slug(model: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in model).strip("_").lower()


def run_model(
    model: str,
    n: int,
    seed: int,
    temperature: float,
    top_p: float,
    max_requery: int,
    out_dir: Path,
    dry_run: bool,
    run_api: bool,
) -> int:
    slug = model_slug(model)
    model_dir = out_dir / slug
    cmd = [
        sys.executable,
        str(ROOT / "scaleup" / "corpus_scaleup.py"),
        "--n",
        str(n),
        "--seed",
        str(seed),
        "--model",
        model,
        "--temperature",
        str(temperature),
        "--top-p",
        str(top_p),
        "--max-requery",
        str(max_requery),
        "--out",
        str(model_dir),
        "--full-name",
        f"{slug}_scenarios.jsonl",
        "--log-name",
        f"{slug}_generation_log.json",
        "--sample-n",
        str(min(n, 48)),
        "--sample-out",
        str(model_dir / f"{slug}_sample.jsonl"),
        "--manifest-out",
        str(model_dir / f"{slug}_MANIFEST.json"),
        "--validation-out",
        str(model_dir / f"{slug}_validation.json"),
        "--checkpoint-every",
        "5",
    ]
    cmd.append("--dry-run" if dry_run else "--run" if run_api else "--dry-run")
    return run_subprocess(cmd)


def load_model_validation(out_dir: Path, model: str) -> dict[str, Any] | None:
    path = out_dir / model_slug(model) / f"{model_slug(model)}_validation.json"
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    data["_validation_path"] = str(path.relative_to(ROOT))
    return data


def summarize(out_dir: Path, models: list[str]) -> dict[str, Any]:
    rows = []
    union_ids = set()
    for model in models:
        validation = load_model_validation(out_dir, model)
        if not validation:
            rows.append({"model": model, "status": "missing_validation"})
            continue
        summary = validation.get("scenario_summary", {})
        active_ids = set(summary.get("unique_active_v14_ids_list", []))
        union_ids.update(active_ids)
        rows.append(
            {
                "model": model,
                "status": "completed",
                "n_requested": validation.get("n_requested"),
                "n_accepted": validation.get("n_accepted"),
                "accepted_rate": validation.get("accepted_rate"),
                "first_attempt_active_rate": validation.get("first_attempt_active_rate"),
                "first_attempt_active_rate_wilson_95ci": validation.get(
                    "first_attempt_active_rate_wilson_95ci"
                ),
                "unique_active_v14_ids": summary.get("unique_active_v14_ids"),
                "unique_base_techniques": summary.get("unique_base_techniques"),
                "base_technique_coverage": summary.get("base_technique_coverage"),
                "cost_per_accepted_scenario_usd": validation.get(
                    "cost_per_accepted_scenario_usd"
                ),
                "estimated_cost_usd": validation.get("estimated_cost_usd"),
                "validation_path": validation.get("_validation_path"),
            }
        )

    completed = [row for row in rows if row["status"] == "completed"]
    return {
        "schema_version": 1,
        "created_at": utc_now(),
        "models_requested": models,
        "models_completed": [row["model"] for row in completed],
        "replication_n_per_model": completed[0]["n_requested"] if completed else None,
        "union_unique_active_v14_ids": len(union_ids),
        "model_rows": rows,
        "interpretation": {
            "generalization_question": (
                "Whether the validate-and-requery method preserves active-v14 validity "
                "and comparable coverage when the generator model changes."
            ),
            "scope": (
                "Small stratified replication. Use for robustness/generalization framing, "
                "not as a replacement for the full corpus."
            ),
        },
    }


def write_audit(summary: dict[str, Any], path: Path) -> None:
    lines = [
        "# Phase 5 Multi-LLM Generalization Audit",
        "",
        "Phase 5 reuses `scaleup/corpus_scaleup.py` so each model uses the same",
        "balanced plan, defensive metadata-only prompt, active ATT&CK v14 validation,",
        "and validate-and-requery loop.",
        "",
        "Full generated corpora and per-model logs are written under `data/generated/`",
        "and are intentionally not committed.",
        "",
        "## Results",
        "",
        "| Model | n accepted | First-attempt active-v14 | Unique active IDs | Base techniques | Cost/scenario |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in summary["model_rows"]:
        if row["status"] != "completed":
            lines.append(f"| {row['model']} | missing | - | - | - | - |")
            continue
        ci = row.get("first_attempt_active_rate_wilson_95ci") or ["?", "?"]
        lines.append(
            "| {model} | {n_accepted} | {rate:.1%} [{lo}, {hi}] | {uids} | {base} | ${cost:.6f} |".format(
                model=row["model"],
                n_accepted=row.get("n_accepted", 0),
                rate=float(row.get("first_attempt_active_rate") or 0),
                lo=ci[0],
                hi=ci[1],
                uids=row.get("unique_active_v14_ids"),
                base=row.get("unique_base_techniques"),
                cost=float(row.get("cost_per_accepted_scenario_usd") or 0),
            )
        )
    lines.extend(
        [
            "",
            f"Union unique active v14 IDs across completed models: {summary['union_unique_active_v14_ids']}.",
            "",
            "## Paper Framing",
            "",
            "Report this as a small stratified cross-model replication. The central",
            "claim is method robustness: the active-v14 validation and requery loop is",
            "model-agnostic. Do not claim that a 48-scenario replication fully",
            "characterizes any model family.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models", nargs="+", default=DEFAULT_MODELS)
    parser.add_argument("--n", type=int, default=48, help="Scenarios per model")
    parser.add_argument("--seed", type=int, default=515)
    parser.add_argument("--temperature", type=float, default=0.7)
    parser.add_argument("--top-p", type=float, default=0.95)
    parser.add_argument("--max-requery", type=int, default=2)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--results-out", type=Path, default=RESULTS_PATH)
    parser.add_argument("--audit-out", type=Path, default=AUDIT_PATH)
    parser.add_argument("--run", action="store_true", help="Actually call the API")
    parser.add_argument("--dry-run", action="store_true", help="Print plans only")
    parser.add_argument(
        "--summarize-only",
        action="store_true",
        help="Only rebuild results from existing validation files",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.out = args.out if args.out.is_absolute() else ROOT / args.out
    args.results_out = args.results_out if args.results_out.is_absolute() else ROOT / args.results_out
    args.audit_out = args.audit_out if args.audit_out.is_absolute() else ROOT / args.audit_out

    if not args.summarize_only:
        if not args.run and not args.dry_run:
            print("Refusing to call the API without --run. Use --dry-run to inspect plans.")
            return 2
        for model in args.models:
            rc = run_model(
                model=model,
                n=args.n,
                seed=args.seed,
                temperature=args.temperature,
                top_p=args.top_p,
                max_requery=args.max_requery,
                out_dir=args.out,
                dry_run=args.dry_run,
                run_api=args.run,
            )
            if rc != 0:
                return rc
        if args.dry_run:
            return 0

    summary = summarize(args.out, args.models)
    write_json(args.results_out, summary)
    write_audit(summary, args.audit_out)
    print(f"summary: {args.results_out}")
    print(f"audit: {args.audit_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
