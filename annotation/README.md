# Phase 7 Human Annotation

Use `annotation/harness.py` to prepare the blinded packet and analyze completed
ratings.

Prepare packet:

```powershell
.\.venv\Scripts\python.exe annotation\harness.py prepare --n 150
```

Collect completed CSVs from independent annotators and place them here:

```text
annotation/raw/phase7/
```

The raw folder is ignored by git. Keep one file per annotator, for example:

```text
annotation/raw/phase7/annotator_01.csv
annotation/raw/phase7/annotator_02.csv
annotation/raw/phase7/annotator_03.csv
```

Analyze after at least three completed files:

```powershell
.\.venv\Scripts\python.exe annotation\harness.py analyze
```

The analysis also reads the anonymous aggregate reviewer profile from:

```text
annotation/reviewer_profile_phase7.json
```

Tracked outputs are anonymized aggregates only:

- `results/human_validation.json`
- `results/human_validation_audit.md`
- `results/human_ratings_summary.csv`

Send annotators only these files:

- `annotation/study_packet/phase7_scenarios_blinded.csv`
- `annotation/study_packet/phase7_rating_template.csv`
- `annotation/study_packet/phase7_instructions.md`

Do not send `annotation/study_packet/phase7_blind_key.csv`; it is retained for
reproducible analysis and contains the hidden scenario-to-score mapping.
