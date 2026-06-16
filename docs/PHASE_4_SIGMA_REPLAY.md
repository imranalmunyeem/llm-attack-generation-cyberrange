# Phase 4 - Empirical Sigma Replay Grounding

Phase 4 adds an offline replay harness for measuring generated Sigma-rule
coverage against labelled defensive logs. It does not execute attacks and does
not require an API key.

## What Is Implemented

- `detection/sigma_replay.py` loads Sigma YAML rules and labelled event JSONL.
- The replay computes measured per-technique true-positive coverage for the
  ATT&CK techniques present in the event dataset.
- `results/sigma_measured.json` is reserved for the aggregate measured result.
- Raw logs stay out of git under `data/raw_logs/`, `data/telemetry/`, or
  `data/soc_logs/`.

The current matcher supports the rule subset emitted by
`sigma_rule_generator.py`: `logsource`, `detection.keywords`, `tags`, and
`metadata.techniques`. This is deliberate and auditable. A later SIEM-backed
run can convert the same rules with `sigma-cli`/pySigma when a target backend
is chosen.

## Event JSONL Contract

Each line must be one JSON object. At minimum, include:

```json
{
  "@timestamp": "2026-01-01T00:00:01Z",
  "technique_id": "T1059.001",
  "logsource": {
    "category": "process_creation",
    "product": "windows",
    "service": "powershell"
  },
  "CommandLine": "powershell.exe -enc ..."
}
```

Technique labels can be provided as any of:

- `technique_id` or `technique_ids`
- `attack.technique.id`, `attack.technique`, or `attack.technique_ids`
- `mitre.technique_id` or `mitre.technique_ids`
- `labels.technique_id` or `labels.technique_ids`
- `tags` containing values like `attack.t1059` or `attack.t1059_001`

The script searches all event fields for rule keywords, so source-specific
field names such as `CommandLine`, `Image`, `TargetImage`, `message`, ECS
fields, or Winlogbeat fields are all acceptable.

## Easiest Dataset Path

Use a public labelled dataset first. The easiest options are:

1. `EVTX-ATTACK-SAMPLES`: download or clone it, then export selected EVTX
   files to JSONL with Winlogbeat, Chainsaw, or another EVTX parser. Add
   the technique ID from the folder/metadata as `technique_id`.
2. `OTRF/Security-Datasets` or Mordor: download JSON datasets that already
   carry ATT&CK context, then normalize labels into one of the fields above.
3. Sanitised SOC logs: export only the fields needed for detection plus a
   technique label. Remove hostnames, usernames, IPs, ticket IDs, and customer
   identifiers before sharing.

Place the normalized JSONL here:

```text
data/raw_logs/sigma_replay_events.jsonl
```

That path is ignored by git. Keep the raw dataset local or release it
separately only if licensing and privacy allow it.

## Commands

Generate rules from the scenario corpus, if needed:

```powershell
.\.venv\Scripts\python.exe sigma_rule_generator.py --dataset dataset\dataset.jsonl --out data\journal_results\sigma_rules --n 48
```

Run the checked-in fixture:

```powershell
.\.venv\Scripts\python.exe detection\sigma_replay.py --rules tests\fixtures\sigma_replay\rules --events tests\fixtures\sigma_replay\events.jsonl --out results\sigma_measured_sample.json
```

Run real replay:

```powershell
.\.venv\Scripts\python.exe detection\sigma_replay.py --rules data\journal_results\sigma_rules --events data\raw_logs\sigma_replay_events.jsonl --out results\sigma_measured.json
```

## What To Report In The Paper

Report measured replay only for techniques present in the dataset:

- techniques present in labelled logs
- techniques with generated rules
- techniques detected by replay
- measured technique coverage
- per-technique covered/not-covered table

Keep simulated and measured detection as separate columns. Disagreement is a
methodological result, not a failure: it tells reviewers where the simulator
over- or under-estimates real log visibility.
