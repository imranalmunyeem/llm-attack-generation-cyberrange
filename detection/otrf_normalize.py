"""Normalize selected OTRF Security-Datasets ZIPs for Sigma replay.

OTRF atomic datasets label the capture as an ATT&CK technique. The raw JSON
contains the events from that capture window, including background events.
This converter attaches the dataset-level technique label to each event so the
Phase 4 replay can report technique-level coverage for overlapping datasets.
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "data" / "raw_logs" / "phase4_source" / "otrf_selected" / "manifest.json"
DEFAULT_OUT = ROOT / "data" / "raw_logs" / "sigma_replay_events.jsonl"
DEFAULT_SUMMARY = ROOT / "data" / "raw_logs" / "sigma_replay_events_manifest.json"


def parse_json_lines(text: str) -> Iterable[dict[str, Any]]:
    decoder = json.JSONDecoder()
    idx = 0
    length = len(text)
    while idx < length:
        while idx < length and text[idx].isspace():
            idx += 1
        if idx >= length:
            break
        obj, next_idx = decoder.raw_decode(text, idx)
        idx = next_idx
        if isinstance(obj, dict):
            yield obj


def infer_logsource(event: dict[str, Any]) -> dict[str, str]:
    channel = str(event.get("Channel") or event.get("channel") or "").lower()
    source = str(event.get("SourceName") or event.get("Provider") or "").lower()
    event_id = str(event.get("EventID") or event.get("EventId") or "")

    if "sysmon" in channel or "sysmon" in source:
        if event_id == "10":
            return {"category": "process_access", "product": "windows", "service": "sysmon"}
        if event_id in {"11", "15", "23", "26"}:
            return {"category": "file_event", "product": "windows", "service": "sysmon"}
        if event_id in {"12", "13", "14"}:
            return {"category": "registry_event", "product": "windows", "service": "sysmon"}
        if event_id in {"3", "22"}:
            return {"category": "network_connection", "product": "windows", "service": "sysmon"}
        return {"category": "process_creation", "product": "windows", "service": "sysmon"}

    if "powershell" in channel or "powershell" in source:
        return {"category": "process_creation", "product": "windows", "service": "powershell"}

    if event_id in {"4624", "4625", "4648", "4672", "4768", "4769", "4771", "4776"}:
        return {"category": "authentication", "product": "windows", "service": "security"}

    if event_id in {"4688", "1"} or event.get("CommandLine") or event.get("NewProcessName"):
        return {"category": "process_creation", "product": "windows", "service": "security"}

    if event_id in {"4657", "4663"}:
        return {"category": "registry_event", "product": "windows", "service": "security"}

    if event_id in {"5156", "5157"}:
        return {"category": "network_connection", "product": "windows", "service": "security"}

    return {"category": "process_creation", "product": "windows", "service": "security"}


def normalize_event(event: dict[str, Any], item: dict[str, Any], source_member: str) -> dict[str, Any]:
    normalized = dict(event)
    techniques = item.get("techniques") or []
    normalized["technique_ids"] = techniques
    normalized["dataset_id"] = item.get("id")
    normalized["dataset_title"] = item.get("title")
    normalized["dataset_source_file"] = Path(item.get("local_file", "")).name
    normalized["dataset_member"] = source_member
    normalized["label_scope"] = "dataset"
    normalized.setdefault("logsource", infer_logsource(event))
    return normalized


def load_manifest(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as f:
        manifest = json.load(f)
    if not isinstance(manifest, list):
        raise ValueError(f"manifest must be a list: {path}")
    return manifest


def convert(manifest_path: Path, out_path: Path, summary_path: Path) -> dict[str, Any]:
    manifest_path = manifest_path.resolve()
    out_path = out_path.resolve()
    summary_path = summary_path.resolve()
    manifest = load_manifest(manifest_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    total_events = 0
    datasets = []
    with out_path.open("w", encoding="utf-8") as out:
        for item in manifest:
            zip_path = ROOT / item["local_file"]
            if not zip_path.exists():
                raise FileNotFoundError(zip_path)
            dataset_events = 0
            with zipfile.ZipFile(zip_path) as zf:
                json_members = [name for name in zf.namelist() if name.lower().endswith(".json")]
                if not json_members:
                    continue
                for member in json_members:
                    text = zf.read(member).decode("utf-8", "replace")
                    for event in parse_json_lines(text):
                        normalized = normalize_event(event, item, member)
                        out.write(json.dumps(normalized, separators=(",", ":")) + "\n")
                        dataset_events += 1
                        total_events += 1
            datasets.append(
                {
                    "id": item.get("id"),
                    "title": item.get("title"),
                    "techniques": item.get("techniques"),
                    "source_file": item.get("local_file"),
                    "events": dataset_events,
                    "label_scope": "dataset",
                }
            )

    summary = {
        "schema_version": 1,
        "source": "OTRF/Security-Datasets selected atomic host captures",
        "manifest": str(manifest_path.relative_to(ROOT)),
        "output": str(out_path.relative_to(ROOT)),
        "total_events": total_events,
        "datasets": datasets,
        "notes": [
            "OTRF atomic capture labels are dataset-level labels.",
            "Raw normalized events are ignored by git; commit only aggregate replay output.",
        ],
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    summary = convert(args.manifest, args.out, args.summary)
    print("otrf normalize ok")
    print(f"  datasets: {len(summary['datasets'])}")
    print(f"  events: {summary['total_events']}")
    print(f"  output: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
