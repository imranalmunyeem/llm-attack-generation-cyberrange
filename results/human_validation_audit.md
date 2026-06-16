# Phase 7 Human Realism Validation

Status: awaiting independent human ratings.

Prepared packet:

- `annotation/study_packet/phase7_scenarios_blinded.csv`
- `annotation/study_packet/phase7_rating_template.csv`
- `annotation/study_packet/phase7_instructions.md`

Raw completed annotator files must be placed in `annotation/raw/phase7/`.
That directory is ignored by git. Do not commit raw annotator identities,
comments, or per-person rating sheets.

Current status:

```json
{
  "status": "awaiting_human_ratings",
  "scenario_count": 150,
  "annotators_received": 0,
  "required_annotators_min": 3,
  "recommended_annotators": 5,
  "packet_dir": "annotation\\study_packet",
  "raw_ratings_dir": "annotation\\raw\\phase7",
  "note": "Do not commit completed annotator CSVs; only aggregate outputs should enter git."
}
```
