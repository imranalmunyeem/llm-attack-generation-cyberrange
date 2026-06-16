# AdverSim Phase 7 Annotation Instructions

Thank you for helping evaluate synthetic cyber attack scenario realism.

You will rate 150 blinded scenarios. The study should take about 45-60 minutes.

Files:
- `phase7_scenarios_blinded.csv`: read-only scenario packet.
- `phase7_rating_template.csv`: fill this file and return it.

You should not receive `phase7_blind_key.csv`; that file is reserved for the
research team after ratings are returned.

Rate each scenario from 1 to 5:

- `attck_alignment`: are the ATT&CK technique IDs plausible for the scenario?
- `stage_sequence`: does the attack sequence make operational sense?
- `overall_realism`: could this scenario plausibly occur in a real incident?
- `confidence_1_5`: how confident are you in your rating?

Scale:
- 1 = clearly unrealistic or incorrect
- 2 = mostly weak/questionable
- 3 = mixed or partially plausible
- 4 = mostly realistic
- 5 = highly realistic

Please do not discuss ratings with other annotators. Do not try to infer model
scores; the packet is intentionally blinded.
