# Phase 8 Reproducibility CI

Phase 8 adds a lightweight CI path that can run without API keys, raw logs, or
the ignored full corpus. It checks that tracked aggregate artifacts are present,
regenerates paper figures from those aggregates, validates the figure manifest,
and runs the offline smoke pipeline.

Local commands:

```powershell
.\.venv\Scripts\python.exe analysis\regenerate_figures.py
.\.venv\Scripts\python.exe scripts\reproducibility_ci.py
```

Make targets:

```powershell
make figures
make reproducibility-ci
```

Tracked figure outputs:

- `paper_assets/figures/phase7_human_validation.png`
- `paper_assets/figures/real_baselines_coverage.png`
- `paper_assets/figures/multimodel_generalization.png`
- `paper_assets/figures/sigma_replay_coverage.png`
- `paper_assets/figures/soc_sensitivity_ranges.png`
- `results/figure_manifest.json`

The GitHub Actions workflow intentionally avoids `.env`, raw logs, and raw human
ratings. It installs `requirements.lock`, runs the reproducibility command, runs
the repository pre-push checks, and fails if regenerated tracked artifacts drift.
