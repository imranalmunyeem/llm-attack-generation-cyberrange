# Phase 4 Sigma Replay Audit

## Dataset

The replay uses a selected subset of OTRF Security-Datasets atomic Windows host
captures. The full GitHub archive was not downloaded because browser and
endpoint protection correctly classify some security telemetry as suspicious.
Instead, eight labelled OTRF ZIP assets were fetched directly from
`raw.githubusercontent.com` into the ignored `data/raw_logs/` workspace.

Raw source ZIPs and normalized JSONL are not committed. Only aggregate replay
results are tracked.

## Normalization

`detection/otrf_normalize.py` converts selected OTRF ZIP files to
`data/raw_logs/sigma_replay_events.jsonl`.

Important limitation: OTRF atomic labels are dataset-level technique labels.
They indicate the ATT&CK technique represented by the capture, but they do not
guarantee that every individual event in the capture is malicious. Therefore
the paper should report this replay as technique-level empirical coverage, not
event-level precision.

## Replay Result

Replay command:

```powershell
.\.venv\Scripts\python.exe detection\sigma_replay.py --rules data\journal_results\sigma_rules --events data\raw_logs\sigma_replay_events.jsonl --out results\sigma_measured.json
```

Summary from `results/sigma_measured.json`:

- Generated Sigma rules replayed: 48
- Normalized labelled events: 56,280
- Overlapping labelled techniques present: 6
- Overlapping techniques with generated rules: 6
- Techniques detected by replay: 2
- Measured technique coverage on this subset: 33.3%

Per-technique outcome:

| Technique | Labelled events | Covered by replay | Matching rule IDs |
|---|---:|---|---|
| T1059 | 2,662 | yes | adversim-000033, adversim-000036 |
| T1059.001 | 110 | yes | adversim-000033, adversim-000036 |
| T1210 | 790 | no | - |
| T1218.001 | 1,221 | no | - |
| T1547.001 | 41,226 | no | - |
| T1550.002 | 10,271 | no | - |

## Paper Framing

Recommended wording:

> We replayed the 48 generated Sigma-compatible rules against a selected
> labelled subset of OTRF Security-Datasets atomic Windows host telemetry.
> Among the six ATT&CK techniques that overlapped both the public telemetry
> subset and the generated rule set, replay detected two techniques (33.3%).
> Because OTRF atomic labels are dataset-level labels, this result is reported
> as technique-level empirical coverage rather than event-level precision. The
> gap between simulated detection and replay coverage shows that the current
> Sigma skeletons are useful as detection-engineering scaffolds but require
> backend-specific field mapping and rule refinement before operational use.

This is stronger than the original manuscript state because the paper no
longer claims a detection-engineering pipeline without executing any rules.
