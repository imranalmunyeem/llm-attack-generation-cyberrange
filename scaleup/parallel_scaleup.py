"""Parallel Phase 0.5 scale-up orchestration.

This wrapper runs multiple independent balanced shards through
`corpus_scaleup.py`, then merges the accepted scenario corpora and validation
summaries into the canonical Phase 0.5 artifacts. It does not bypass the core
schema, ATT&CK, or validate-and-requery logic.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from corpus_scaleup import (
    ROOT,
    MitreAttackValidator,
    active_base_denominator,
    find_stix_bundle,
    output_path,
    sha256_file,
    stratified_sample,
    summarize_scenarios,
    utc_now,
    wilson_ci,
    write_json,
    write_jsonl,
)


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def shard_sizes(n: int, shards: int) -> list[int]:
    base = n // shards
    extra = n % shards
    return [base + (1 if i < extra else 0) for i in range(shards)]


def run_shard(
    shard_index: int,
    shard_n: int,
    args: argparse.Namespace,
    shard_root: Path,
) -> subprocess.Popen:
    shard_name = f"shard_{shard_index + 1:02d}"
    shard_dir = shard_root / shard_name
    shard_dir.mkdir(parents=True, exist_ok=True)
    log_dir = shard_root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        str(ROOT / "scaleup" / "corpus_scaleup.py"),
        "--n",
        str(shard_n),
        "--seed",
        str(args.seed + shard_index),
        "--model",
        args.model,
        "--temperature",
        str(args.temperature),
        "--top-p",
        str(args.top_p),
        "--max-requery",
        str(args.max_requery),
        "--out",
        str(shard_dir),
        "--full-name",
        f"{shard_name}_full.jsonl",
        "--log-name",
        f"{shard_name}_log.json",
        "--sample-n",
        str(min(shard_n, args.sample_n)),
        "--sample-out",
        str(shard_dir / f"{shard_name}_sample.jsonl"),
        "--manifest-out",
        str(shard_dir / f"{shard_name}_MANIFEST.json"),
        "--validation-out",
        str(shard_dir / f"{shard_name}_validation.json"),
        "--checkpoint-every",
        str(args.checkpoint_every),
        "--release-url",
        args.release_url or "",
        "--resume",
        "--run",
    ]
    stdout = (log_dir / f"{shard_name}_stdout.log").open("a", encoding="utf-8")
    stderr = (log_dir / f"{shard_name}_stderr.log").open("a", encoding="utf-8")
    return subprocess.Popen(cmd, cwd=ROOT, stdout=stdout, stderr=stderr)


def merge_outputs(args: argparse.Namespace, shard_root: Path, sizes: list[int]) -> None:
    stix_path = find_stix_bundle(args.stix)
    validator = MitreAttackValidator(stix_path)
    denominator = active_base_denominator(validator)

    scenarios: list[dict[str, Any]] = []
    validations: list[dict[str, Any]] = []
    for i, expected_n in enumerate(sizes):
        shard_name = f"shard_{i + 1:02d}"
        shard_dir = shard_root / shard_name
        full = shard_dir / f"{shard_name}_full.jsonl"
        validation_path = shard_dir / f"{shard_name}_validation.json"
        if not full.exists() or not validation_path.exists():
            raise FileNotFoundError(f"missing shard output for {shard_name}")
        rows = load_jsonl(full)
        validation = load_json(validation_path)
        if validation.get("n_requested") != expected_n:
            raise ValueError(f"{shard_name} requested n mismatch")
        if validation.get("n_accepted") != len(rows):
            raise ValueError(f"{shard_name} accepted count mismatch")
        scenarios.extend(rows)
        validations.append(validation)

    out_dir = output_path(args.out) or ROOT / "data" / "generated" / "scaleup"
    out_dir.mkdir(parents=True, exist_ok=True)
    full_path = out_dir / args.full_name
    write_jsonl(full_path, scenarios)

    sample_path = output_path(args.sample_out) if args.sample_out else ROOT / "dataset" / "samples" / args.sample_name
    manifest_path = (
        output_path(args.manifest_out)
        if args.manifest_out
        else ROOT / "dataset" / "manifests" / args.manifest_name
    )
    validation_path = (
        output_path(args.validation_out)
        if args.validation_out
        else ROOT / "results" / "scaleup_validation.json"
    )

    sample = stratified_sample(scenarios, sample_n=args.sample_n, seed=args.seed)
    write_jsonl(sample_path, sample)

    n_requested = sum(int(v.get("n_requested", 0)) for v in validations)
    n_accepted = sum(int(v.get("n_accepted", 0)) for v in validations)
    n_rejected = sum(int(v.get("n_rejected", 0)) for v in validations)
    first_active = sum(
        round(float(v.get("first_attempt_active_rate", 0)) * int(v.get("n_requested", 0)))
        for v in validations
    )
    total_input = sum(int(v.get("total_input_tokens", 0)) for v in validations)
    total_output = sum(int(v.get("total_output_tokens", 0)) for v in validations)
    total_cost = sum(float(v.get("estimated_cost_usd", 0)) for v in validations)
    summary = summarize_scenarios(scenarios, validator, denominator)

    validation = {
        "created_at": utc_now(),
        "model": args.model,
        "n_requested": n_requested,
        "n_accepted": n_accepted,
        "n_rejected": n_rejected,
        "first_attempt_active_rate": round(first_active / max(1, n_requested), 6),
        "first_attempt_active_rate_wilson_95ci": wilson_ci(first_active, n_requested),
        "accepted_rate": round(n_accepted / max(1, n_requested), 6),
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "estimated_cost_usd": round(total_cost, 6),
        "cost_per_accepted_scenario_usd": round(total_cost / max(1, n_accepted), 8),
        "stix_bundle": str(stix_path),
        "stix_sha256": sha256_file(stix_path),
        "scenario_summary": summary,
        "shards": [
            {
                "name": f"shard_{i + 1:02d}",
                "n_requested": validations[i].get("n_requested"),
                "n_accepted": validations[i].get("n_accepted"),
                "validation_path": str(
                    (shard_root / f"shard_{i + 1:02d}" / f"shard_{i + 1:02d}_validation.json").relative_to(ROOT)
                ),
            }
            for i in range(len(validations))
        ],
    }
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
            "parallel_shards": args.shards,
            "defensive_scope": "metadata-only; no executable payloads or live targets",
        },
        "validation": validation,
    }
    write_json(manifest_path, manifest)

    print("Parallel scale-up complete")
    print(f"Accepted: {n_accepted}/{n_requested}")
    print(f"Full corpus: {full_path}")
    print(f"Sample: {sample_path}")
    print(f"Manifest: {manifest_path}")
    print(f"Validation: {validation_path}")


def run(args: argparse.Namespace) -> int:
    sizes = shard_sizes(args.n, args.shards)
    shard_root = output_path(args.shard_out) or ROOT / "data" / "generated" / "scaleup_shards"
    shard_root.mkdir(parents=True, exist_ok=True)

    if args.dry_run:
        print(f"Parallel dry run: {args.n} scenarios across {args.shards} shards")
        print("Shard sizes:", ", ".join(str(size) for size in sizes))
        return 0

    if not args.run:
        print("Refusing to call the API without --run. Use --dry-run to inspect the plan.")
        return 2

    procs = [run_shard(i, size, args, shard_root) for i, size in enumerate(sizes)]
    failed = False
    for i, proc in enumerate(procs):
        code = proc.wait()
        if code != 0:
            print(f"shard_{i + 1:02d} failed with exit code {code}", file=sys.stderr)
            failed = True
    if failed:
        return 1

    merge_outputs(args, shard_root, sizes)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=5000)
    parser.add_argument("--shards", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--model", default="gpt-4o-mini")
    parser.add_argument("--temperature", type=float, default=0.7)
    parser.add_argument("--top-p", type=float, default=0.95)
    parser.add_argument("--max-requery", type=int, default=2)
    parser.add_argument("--out", default="data/generated/scaleup")
    parser.add_argument("--shard-out", default="data/generated/scaleup_shards")
    parser.add_argument("--full-name", default="adversim_scaleup_full.jsonl")
    parser.add_argument("--sample-n", type=int, default=240)
    parser.add_argument("--sample-name", default="scaleup_sample.jsonl")
    parser.add_argument("--manifest-name", default="scaleup_MANIFEST.json")
    parser.add_argument("--sample-out", default=None)
    parser.add_argument("--manifest-out", default=None)
    parser.add_argument("--validation-out", default=None)
    parser.add_argument("--checkpoint-every", type=int, default=25)
    parser.add_argument("--stix", default=None)
    parser.add_argument("--release-url", default="")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--run", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(run(parse_args()))
