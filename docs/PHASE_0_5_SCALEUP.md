# Phase 0.5 Corpus Scale-Up

This phase is implemented by `scaleup/corpus_scaleup.py`. The runner generates defensive scenario metadata only, validates every ATT&CK ID against an active enterprise STIX bundle, retries invalid generations with correction hints, and writes the full corpus outside git.

## Safety And Data Policy

- Full generated corpora are written under `data/generated/scaleup/`, which is ignored by git.
- Commit only:
  - `dataset/samples/scaleup_sample.jsonl`
  - `dataset/manifests/scaleup_MANIFEST.json`
  - `results/scaleup_validation.json`
- Upload the full corpus to Zenodo or a GitHub Release and record that URL in the manifest with `--release-url`.
- The prompt explicitly forbids exploit code, payloads, live targets, credentials, and operational instructions.

## Dry Run

Inspect the balanced 48-combination plan without calling the API:

```powershell
.\.venv\Scripts\python.exe scaleup\corpus_scaleup.py --n 5000 --dry-run
```

or, where GNU Make is available:

```bash
make scaleup-plan
```

## Paid Generation

Use `--run` to permit API calls. The default target is 5,000 base scenarios, matching the minimum Phase 0.5 acceptance threshold.

```powershell
.\.venv\Scripts\python.exe scaleup\corpus_scaleup.py `
  --n 5000 `
  --run `
  --resume `
  --stix data\journal_results\enterprise-attack-14.1.json `
  --out data\generated\scaleup
```

For a small pilot:

```powershell
.\.venv\Scripts\python.exe scaleup\corpus_scaleup.py `
  --n 20 `
  --run `
  --out data\generated\scaleup_pilot `
  --sample-out data\generated\scaleup_pilot\pilot_sample.jsonl `
  --manifest-out data\generated\scaleup_pilot\pilot_MANIFEST.json `
  --validation-out data\generated\scaleup_pilot\pilot_validation.json
```

The run writes:

- `data/generated/scaleup/adversim_scaleup_full.jsonl`
- `data/generated/scaleup/adversim_scaleup_log.json`
- `dataset/samples/scaleup_sample.jsonl`
- `dataset/manifests/scaleup_MANIFEST.json`
- `results/scaleup_validation.json`

## Current Caveat

The handover asks us to pin official ATT&CK v14.1. This checkout contains a local untracked `data/journal_results/enterprise-attack-14.1.json`, which is intentionally ignored by git because it is larger than the Phase 0 size limit. If that file is absent, the script falls back to the already tracked `enterprise-attack.json`, but that fallback should not be used for paper numbers unless the author confirms it is the intended v14.1 bundle.
