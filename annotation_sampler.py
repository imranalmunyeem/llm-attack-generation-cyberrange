"""
annotation_sampler.py
=====================
Samples scenarios for an expanded external annotation study.
Produces a CSV the user emails to 5 external practitioners.

PURPOSE:
  The current paper reports Fleiss' kappa=0.74 from three annotators
  (the author + two colleagues). To defend this at IEEE Access level,
  expanding to 5+ independent external annotators and 100 scenarios
  is strongly recommended.

  Target annotators: anyone with cybersecurity industry/academic
  background. LinkedIn contacts, former colleagues, MSc students with
  security background, CTF participants, etc.

WHAT ANNOTATORS DO:
  Rate each scenario 1-5 on three dimensions:
    (1) ATT&CK Alignment: Are the technique IDs plausible for this attack?
    (2) Stage Sequence:   Does the attack stage order make operational sense?
    (3) Overall Realism:  Would this scenario occur in a real-world incident?

RUN:
  python annotation_sampler.py \
    --dataset dataset/full_dataset.jsonl \
    --out data/journal_results/annotation/ \
    --n 100

OUTPUT:
  annotation_study_scenarios.csv   ← send this to annotators
  annotation_template.csv          ← blank rating sheet for annotators
  instructions.txt                 ← email this with the CSV
"""

import json
import os
import re
import csv
import random
import argparse
from collections import defaultdict

VALID_TID = re.compile(r'^T\d{4}(\.\d{3})?$')
random.seed(42)


def load_scenarios(path):
    scenarios = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, str):
                    obj = json.loads(obj)
                scenarios.append(obj)
            except Exception:
                pass
    return scenarios


def format_for_annotator(scenario, seq_id):
    """Format a scenario into readable text for annotators."""
    attack_type = scenario.get("attack_type", "Unknown")
    environment = scenario.get("environment_type", "Unknown")
    difficulty  = scenario.get("difficulty", "Unknown")
    narrative   = scenario.get("narrative", "No narrative provided.")
    stages      = scenario.get("attack_stages", [])

    stage_text = []
    all_tids   = []
    for i, stage in enumerate(stages):
        stage_name = stage.get("stage_name", f"Stage {i+1}")
        techs = [t.get("technique_id", "") + " (" + t.get("technique_name", "") + ")"
                 for t in stage.get("techniques", [])
                 if VALID_TID.match(t.get("technique_id", ""))]
        all_tids.extend([t.get("technique_id", "") for t in stage.get("techniques", [])
                         if VALID_TID.match(t.get("technique_id", ""))])
        stage_text.append(f"{i+1}. {stage_name}: {', '.join(techs[:2])}")

    return {
        "seq_id":       seq_id,
        "scenario_id":  scenario.get("scenario_id", f"SIM-{seq_id:04d}"),
        "attack_type":  attack_type,
        "environment":  environment,
        "difficulty":   difficulty,
        "narrative":    narrative[:200] + "..." if len(narrative) > 200 else narrative,
        "attack_stages": " → ".join(
            [s.get("stage_name", "") for s in stages]),
        "techniques":   " | ".join(all_tids[:5]),
        "n_stages":     len(stages),
    }


def main(dataset_path, out_dir, n=100):
    os.makedirs(out_dir, exist_ok=True)
    scenarios = load_scenarios(dataset_path)
    print(f"Loaded {len(scenarios)} scenarios")

    # Stratified sample: balanced across attack type × difficulty
    by_group = defaultdict(list)
    for s in scenarios:
        key = (s.get("attack_type", "?"), s.get("difficulty", "?"))
        by_group[key].append(s)

    sample = []
    per_group = max(1, n // len(by_group))
    for key, grp in sorted(by_group.items()):
        sample.extend(random.sample(grp, min(per_group, len(grp))))
    sample = sample[:n]
    random.shuffle(sample)

    # Format for annotators
    formatted = [format_for_annotator(s, i + 1) for i, s in enumerate(sample)]

    # Write scenario display file
    scenario_csv = os.path.join(out_dir, "annotation_study_scenarios.csv")
    fieldnames = ["seq_id", "scenario_id", "attack_type", "environment",
                  "difficulty", "narrative", "attack_stages", "techniques", "n_stages"]
    with open(scenario_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(formatted)
    print(f"Scenarios CSV → {scenario_csv}")

    # Write blank rating template
    rating_csv = os.path.join(out_dir, "annotation_template.csv")
    with open(rating_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "seq_id", "scenario_id", "attack_type",
            "ATT_CK_Alignment_1_5",
            "Stage_Sequence_1_5",
            "Overall_Realism_1_5",
            "Comments_optional"
        ])
        writer.writeheader()
        for row in formatted:
            writer.writerow({
                "seq_id": row["seq_id"],
                "scenario_id": row["scenario_id"],
                "attack_type": row["attack_type"],
                "ATT_CK_Alignment_1_5": "",
                "Stage_Sequence_1_5": "",
                "Overall_Realism_1_5": "",
                "Comments_optional": "",
            })
    print(f"Rating template → {rating_csv}")

    # Write instructions
    instructions_path = os.path.join(out_dir, "instructions.txt")
    instructions = f"""
ANNOTATION STUDY: Cyber Attack Scenario Realism Assessment
============================================================

Thank you for participating in this study. It takes approximately 30-45 minutes.

You will rate {n} synthetic cyber attack scenarios on THREE dimensions.
Each dimension is rated 1-5 using the scale below.

RATING SCALES:
  ATT&CK Alignment (Column C):
    1 = Technique IDs are unrealistic for this attack type / environment
    3 = Some techniques plausible, some questionable
    5 = All technique IDs are realistic and well-chosen

  Stage Sequence (Column D):
    1 = The attack stages are in an implausible order
    3 = Generally sensible but one or two stages seem out of place
    5 = The attack chain follows a realistic operational sequence

  Overall Realism (Column E):
    1 = This scenario would not occur in a real incident
    3 = Partially realistic; some elements would need refinement
    5 = This scenario mirrors a real-world attack pattern I would expect

HOW TO COMPLETE:
  1. Open 'annotation_study_scenarios.csv' to read each scenario
  2. Open 'annotation_template.csv' and fill in your ratings
  3. Use the seq_id to match scenarios to ratings
  4. Add optional comments in Column F

BACKGROUND REQUIRED:
  Basic familiarity with MITRE ATT&CK framework and cybersecurity
  incident response concepts. If you are unfamiliar with specific
  technique IDs, you can look them up at https://attack.mitre.org

RETURN:
  Email your completed 'annotation_template.csv' to:
  munyeem.swe@gmail.com with subject "AdverSim Annotation Study"

Your responses are used only for research purposes. Thank you!
"""
    with open(instructions_path, "w", encoding="utf-8") as f:
        f.write(instructions)
    print(f"Instructions → {instructions_path}")

    print(f"\n=== ACTION REQUIRED ===")
    print(f"Recruit 5 external annotators (LinkedIn, colleagues, CTF community).")
    print(f"Send them both CSV files + instructions.txt.")
    print(f"After receiving ratings, compute Fleiss' kappa with scipy:")
    print(f"  from statsmodels.stats.inter_rater import fleiss_kappa, aggregate_raters")
    print(f"  kappa, p = fleiss_kappa(ratings_matrix)")
    print(f"Add result to paper: 'External annotation (n=5, {n} scenarios): Fleiss kappa=X.XX'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="dataset/full_dataset.jsonl")
    parser.add_argument("--out",     default="data/journal_results/annotation")
    parser.add_argument("--n",       type=int, default=100)
    args = parser.parse_args()
    main(args.dataset, args.out, args.n)
