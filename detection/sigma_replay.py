"""Replay generated Sigma rules against labelled defensive event logs.

The replay path is intentionally offline and detection-side only: it consumes
pre-recorded events and generated Sigma YAML, then reports measured coverage
for the ATT&CK techniques present in the event dataset.

Input events are newline-delimited JSON. Labels can live in any of these
common fields:
  - technique_id, technique_ids
  - attack.technique, attack.technique.id, attack.technique_ids
  - mitre.technique_id, mitre.technique_ids
  - labels.technique_id, labels.technique_ids
  - tags containing attack.t1059 or attack.t1059_001
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULE_DIR = ROOT / "data" / "journal_results" / "sigma_rules"
DEFAULT_EVENTS = ROOT / "data" / "raw_logs" / "sigma_replay_events.jsonl"
DEFAULT_OUT = ROOT / "results" / "sigma_measured.json"

TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)
TAG_TECHNIQUE_RE = re.compile(r"attack\.t(\d{4})(?:[_\.](\d{3}))?", re.IGNORECASE)


@dataclass(frozen=True)
class SigmaRule:
    path: Path
    rule_id: str
    title: str
    logsource: dict[str, str]
    techniques: frozenset[str]
    keywords: tuple[str, ...]


@dataclass(frozen=True)
class Event:
    line_number: int
    raw: dict[str, Any]
    labels: frozenset[str]
    haystack: str
    logsource: dict[str, str]


def normalize_tid(value: str) -> str | None:
    value = value.strip().upper().replace("_", ".")
    match = TECHNIQUE_RE.search(value)
    if not match:
        return None
    return match.group(0).upper()


def flatten_values(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        for item in value.values():
            yield from flatten_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from flatten_values(item)
    else:
        yield value


def get_path(obj: dict[str, Any], dotted_path: str) -> Any:
    cur: Any = obj
    for part in dotted_path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def iter_values(value: Any) -> Iterable[Any]:
    if value is None:
        return
    if isinstance(value, list):
        for item in value:
            yield item
    else:
        yield value


def extract_technique_labels(event: dict[str, Any]) -> frozenset[str]:
    candidates: list[Any] = []
    for path in (
        "technique_id",
        "technique_ids",
        "attack.technique",
        "attack.technique.id",
        "attack.technique_ids",
        "mitre.technique_id",
        "mitre.technique_ids",
        "labels.technique_id",
        "labels.technique_ids",
        "event.technique_id",
        "event.technique_ids",
    ):
        candidates.extend(iter_values(get_path(event, path)))

    for tag in iter_values(get_path(event, "tags")):
        if not isinstance(tag, str):
            continue
        tag_match = TAG_TECHNIQUE_RE.search(tag)
        if tag_match:
            suffix = f".{tag_match.group(2)}" if tag_match.group(2) else ""
            candidates.append(f"T{tag_match.group(1)}{suffix}")

    labels = {
        tid
        for value in candidates
        if isinstance(value, str)
        for tid in [normalize_tid(value)]
        if tid
    }
    return frozenset(sorted(labels))


def extract_rule_techniques(rule: dict[str, Any]) -> frozenset[str]:
    candidates: list[Any] = []
    candidates.extend(iter_values(get_path(rule, "metadata.techniques")))
    candidates.extend(iter_values(get_path(rule, "tags")))

    tids = set()
    for value in candidates:
        if not isinstance(value, str):
            continue
        tag_match = TAG_TECHNIQUE_RE.search(value)
        if tag_match:
            suffix = f".{tag_match.group(2)}" if tag_match.group(2) else ""
            tids.add(f"T{tag_match.group(1).upper()}{suffix}")
            continue
        tid = normalize_tid(value)
        if tid:
            tids.add(tid)
    return frozenset(sorted(tids))


def extract_keywords(rule: dict[str, Any]) -> tuple[str, ...]:
    detection = rule.get("detection", {})
    if not isinstance(detection, dict):
        return ()

    keywords: set[str] = set()
    for key, value in detection.items():
        if key in {"condition", "timeframe"}:
            continue
        for item in flatten_values(value):
            if not isinstance(item, str):
                continue
            cleaned = item.strip().lower()
            if cleaned and cleaned != "*":
                keywords.add(cleaned)
    return tuple(sorted(keywords))


def normalize_logsource(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    normalized: dict[str, str] = {}
    for key in ("category", "product", "service"):
        raw = value.get(key)
        if raw is not None:
            normalized[key] = str(raw).strip().lower()
    return normalized


def extract_event_logsource(event: dict[str, Any]) -> dict[str, str]:
    explicit = normalize_logsource(event.get("logsource"))
    if explicit:
        return explicit

    derived = {}
    for out_key, paths in {
        "category": ("event.category", "category", "EventCategory"),
        "product": ("event.module", "product", "winlog.channel"),
        "service": ("event.provider", "service", "winlog.provider_name", "Provider"),
    }.items():
        for path in paths:
            value = get_path(event, path)
            if value:
                derived[out_key] = str(value).strip().lower()
                break
    return derived


def build_haystack(event: dict[str, Any]) -> str:
    return "\n".join(str(value).lower() for value in flatten_values(event) if value is not None)


def load_rules(rule_dir: Path) -> list[SigmaRule]:
    if not rule_dir.exists():
        raise FileNotFoundError(f"rule directory not found: {rule_dir}")

    rules: list[SigmaRule] = []
    for path in sorted(rule_dir.glob("*.yml")) + sorted(rule_dir.glob("*.yaml")):
        with path.open(encoding="utf-8") as f:
            parsed = yaml.safe_load(f)
        if not isinstance(parsed, dict):
            continue
        rules.append(
            SigmaRule(
                path=path,
                rule_id=str(parsed.get("id") or path.stem),
                title=str(parsed.get("title") or path.stem),
                logsource=normalize_logsource(parsed.get("logsource")),
                techniques=extract_rule_techniques(parsed),
                keywords=extract_keywords(parsed),
            )
        )
    if not rules:
        raise ValueError(f"no Sigma YAML rules found in {rule_dir}")
    return rules


def load_events(events_path: Path) -> list[Event]:
    if not events_path.exists():
        raise FileNotFoundError(f"event JSONL not found: {events_path}")

    events: list[Event] = []
    with events_path.open(encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON on line {line_number}: {exc}") from exc
            if not isinstance(parsed, dict):
                raise ValueError(f"line {line_number} is not a JSON object")
            events.append(
                Event(
                    line_number=line_number,
                    raw=parsed,
                    labels=extract_technique_labels(parsed),
                    haystack=build_haystack(parsed),
                    logsource=extract_event_logsource(parsed),
                )
            )
    if not events:
        raise ValueError(f"no events found in {events_path}")
    return events


def logsource_matches(rule_source: dict[str, str], event_source: dict[str, str]) -> bool:
    if not rule_source or not event_source:
        return True

    for key, rule_value in rule_source.items():
        if rule_value in {"", "any", "*"}:
            continue
        event_value = event_source.get(key)
        if event_value and event_value != rule_value:
            return False
    return True


def rule_matches_event(rule: SigmaRule, event: Event) -> bool:
    if not logsource_matches(rule.logsource, event.logsource):
        return False
    if not rule.keywords:
        return False
    return any(keyword in event.haystack for keyword in rule.keywords)


def replay(rules: list[SigmaRule], events: list[Event]) -> dict[str, Any]:
    labelled_events = [event for event in events if event.labels]
    label_counts = Counter(tid for event in labelled_events for tid in event.labels)
    rule_techniques = set().union(*(rule.techniques for rule in rules)) if rules else set()

    technique_stats: dict[str, dict[str, Any]] = {
        tid: {
            "labelled_events": count,
            "matched_events": 0,
            "matching_rule_ids": set(),
        }
        for tid, count in sorted(label_counts.items())
    }
    alerts: list[dict[str, Any]] = []
    alert_count = 0
    false_positive_alerts = 0

    for event in events:
        for rule in rules:
            if not rule_matches_event(rule, event):
                continue

            overlap = event.labels & rule.techniques
            is_true_positive = bool(overlap)
            if not is_true_positive:
                false_positive_alerts += 1

            alert_count += 1
            if len(alerts) < 200:
                alerts.append(
                    {
                        "event_line": event.line_number,
                        "rule_id": rule.rule_id,
                        "rule_title": rule.title,
                        "event_labels": sorted(event.labels),
                        "rule_techniques": sorted(rule.techniques),
                        "true_positive": is_true_positive,
                    }
                )

            for tid in overlap:
                technique_stats[tid]["matched_events"] += 1
                technique_stats[tid]["matching_rule_ids"].add(rule.rule_id)

    covered = {tid for tid, stats in technique_stats.items() if stats["matched_events"] > 0}
    labelled = set(technique_stats)
    unsupported = sorted(labelled - rule_techniques)

    per_technique = {}
    for tid, stats in technique_stats.items():
        per_technique[tid] = {
            "labelled_events": stats["labelled_events"],
            "matched_events": stats["matched_events"],
            "covered": stats["matched_events"] > 0,
            "matching_rule_ids": sorted(stats["matching_rule_ids"]),
            "has_generated_rule": tid in rule_techniques,
        }

    true_positive_alerts = sum(stats["matched_events"] for stats in technique_stats.values())
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "rule_count": len(rules),
            "event_count": len(events),
            "labelled_event_count": len(labelled_events),
        },
        "measured": {
            "techniques_present": len(labelled),
            "techniques_with_generated_rule": len(labelled & rule_techniques),
            "techniques_detected": len(covered),
            "technique_coverage": round(len(covered) / len(labelled), 6) if labelled else 0.0,
            "event_true_positive_alerts": true_positive_alerts,
            "event_false_positive_alerts": false_positive_alerts,
            "event_alerts_total": alert_count,
            "unsupported_labelled_techniques": unsupported,
        },
        "per_technique": per_technique,
        "alert_examples": alerts,
        "notes": [
            "Coverage is measured only for techniques labelled in the input events.",
            "An alert is true-positive only when the event label overlaps the rule ATT&CK techniques.",
            "Rules with wildcard-only detections are not treated as matches.",
            "Raw logs are intentionally excluded from git; commit only this aggregate JSON output.",
        ],
    }


def write_report(result: dict[str, Any], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULE_DIR, help="Directory of Sigma YAML rules")
    parser.add_argument("--events", type=Path, default=DEFAULT_EVENTS, help="Labelled event JSONL/NDJSON")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Aggregate measured replay report")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    rules = load_rules(args.rules)
    events = load_events(args.events)
    result = replay(rules, events)
    write_report(result, args.out)

    measured = result["measured"]
    print("sigma replay ok")
    print(f"  rules: {result['inputs']['rule_count']}")
    print(f"  events: {result['inputs']['event_count']} ({result['inputs']['labelled_event_count']} labelled)")
    print(
        "  measured technique coverage: "
        f"{measured['techniques_detected']}/{measured['techniques_present']} "
        f"({measured['technique_coverage']:.1%})"
    )
    print(f"  report: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
