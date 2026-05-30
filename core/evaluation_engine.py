import json
import random
import matplotlib.pyplot as plt


class EvaluationEngine:

    def load_dataset(self, path):

        data = []

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    data.append(json.loads(line))

        return data

    def extract_techniques(self, dataset):

        techniques = []

        for scenario in dataset:
            for stage in scenario.get("attack_stages", []):
                for tech in stage.get("techniques", []):
                    tid = tech.get("technique_id")
                    if tid:
                        techniques.append(tid)

        return techniques

    def get_detection_probability(self, technique_id):

        # realistic SOC difficulty model
        hard_techniques = ["T1595", "T1203", "T1021", "T1041"]
        medium_techniques = ["T1566", "T1078", "T1486"]

        if technique_id in hard_techniques:
            return 0.4
        elif technique_id in medium_techniques:
            return 0.7
        else:
            return 0.85

    def simulate_detection(self, techniques):

        detected = []
        missed = []

        for tech in techniques:

            prob = self.get_detection_probability(tech)

            if random.random() < prob:
                detected.append(tech)
            else:
                missed.append(tech)

        return detected, missed

    def plot_results(self, detected, missed):

        labels = ["Detected", "Missed"]
        values = [len(detected), len(missed)]

        plt.figure(figsize=(6, 5))
        plt.bar(labels, values)

        plt.title("Realistic Detection vs Missed Attacks")
        plt.tight_layout()

        plt.savefig("data/detection_coverage.png")
        plt.close()

    def run_evaluation(self, dataset_path):

        dataset = self.load_dataset(dataset_path)

        techniques = self.extract_techniques(dataset)

        detected, missed = self.simulate_detection(techniques)

        self.plot_results(detected, missed)

        total = len(detected) + len(missed)
        detection_rate = len(detected) / total if total > 0 else 0

        return {
            "total_attacks": total,
            "detected": len(detected),
            "missed": len(missed),
            "detection_rate": round(detection_rate, 3),
            "unique_techniques": len(set(techniques))
        }


if __name__ == "__main__":

    dataset_path = "dataset/dataset.jsonl"

    engine = EvaluationEngine()

    results = engine.run_evaluation(dataset_path)

    print("\nEVALUATION RESULTS:")
    print(json.dumps(results, indent=4))