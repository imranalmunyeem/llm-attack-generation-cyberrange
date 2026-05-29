import json
from core.metrics_engine import analyze_dataset

DATASET_PATH = "data/attack_dataset_20260529_185053.jsonl"


def load_dataset():
    scenarios = []

    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                scenarios.append(json.loads(line))

    return scenarios


if __name__ == "__main__":
    scenarios = load_dataset()

    print("\n===== RESEARCH METRICS ANALYSIS =====\n")

    report = analyze_dataset(scenarios)

    print(json.dumps(report, indent=4))

    with open("data/research_metrics_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("\n✔ Metrics report saved: data/research_metrics_report.json")