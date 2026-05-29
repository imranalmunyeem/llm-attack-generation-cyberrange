import json

from core.dataset_loader import load_dataset
from core.paper_analytics import run_paper_analysis

print("\n===== PAPER ANALYTICS =====\n")

scenarios = load_dataset()

print("Loaded scenarios:", len(scenarios))

report = run_paper_analysis(scenarios)

print(json.dumps(report, indent=4))

with open(
    "data/paper_analytics_report.json",
    "w",
    encoding="utf-8"
) as f:

    json.dump(report, f, indent=4)

print("\n✔ Paper analytics saved")
print("✔ Charts saved in /data/")