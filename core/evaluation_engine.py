import json
from collections import defaultdict
import matplotlib.pyplot as plt


class EvaluationEngine:

    def load_dataset(self, path):

        data = []

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    data.append(json.loads(line))

        return data

    def extract_all_techniques(self, dataset):

        all_techniques = []

        for scenario in dataset:

            for stage in scenario.get("attack_stages", []):

                for tech in stage.get("techniques", []):

                    tid = tech.get("technique_id")

                    if tid:
                        all_techniques.append(tid)

        return all_techniques

    def simulate_detection(self, dataset, detection_rules):

        detected = []
        missed = []

        rule_set = set([r["technique"] for r in detection_rules])

        for scenario in dataset:

            for stage in scenario.get("attack_stages", []):

                for tech in stage.get("techniques", []):

                    tid = tech.get("technique_id")

                    if tid in rule_set:
                        detected.append(tid)
                    else:
                        missed.append(tid)

        return detected, missed

    def plot_results(self, detected, missed):

        labels = ["Detected", "Missed"]
        values = [len(detected), len(missed)]

        plt.figure(figsize=(6, 5))
        plt.bar(labels, values)

        plt.title("Detection Coverage vs Missed Attacks")
        plt.tight_layout()

        plt.savefig("data/detection_coverage.png")
        plt.close()

    def run_evaluation(self, dataset_path, detection_rules):

        dataset = self.load_dataset(dataset_path)

        detected, missed = self.simulate_detection(dataset, detection_rules)

        self.plot_results(detected, missed)

        detection_rate = len(detected) / (len(detected) + len(missed) + 1e-6)

        return {
            "total_attacks": len(detected) + len(missed),
            "detected": len(detected),
            "missed": len(missed),
            "detection_rate": round(detection_rate, 3)
        }


if __name__ == "__main__":

    from core.detection_rules import DetectionRuleGenerator

    dataset_path = "dataset/dataset.jsonl"

    # load dataset
    engine = EvaluationEngine()
    dataset = engine.load_dataset(dataset_path)

    # generate detection rules
    generator = DetectionRuleGenerator()
    rules = generator.generate_rules(dataset)

    # run evaluation
    results = engine.run_evaluation(dataset_path, rules)

    print("\nEVALUATION RESULTS:")
    print(json.dumps(results, indent=4))