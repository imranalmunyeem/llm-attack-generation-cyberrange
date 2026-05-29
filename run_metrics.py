import json
from core.metrics_engine import analyze_dataset

DATASET_PATH = "dataset/dataset.jsonl"


def parse_jsonl():
    scenarios = []

    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            try:
                obj = json.loads(line)

                # 🔥 FIX: double-encoded JSON safety check
                if isinstance(obj, str):
                    obj = json.loads(obj)

                scenarios.append(obj)

            except Exception as e:
                print("Skipping bad line:", e)

    return scenarios


if __name__ == "__main__":
    print("\n===== RESEARCH METRICS ANALYSIS =====\n")

    scenarios = parse_jsonl()

    print(f"Loaded scenarios: {len(scenarios)}")

    report = analyze_dataset(scenarios)

    print(json.dumps(report, indent=4))

    with open("data/research_metrics_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print("\n✔ Metrics report saved: data/research_metrics_report.json")