import json
import matplotlib.pyplot as plt
from collections import Counter, defaultdict


class ResearchVisualizer:

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

    def build_frequency_map(self, techniques):

        return Counter(techniques)

    def plot_top_techniques(self, freq_map):

        top = freq_map.most_common(15)

        labels = [t[0] for t in top]
        values = [t[1] for t in top]

        plt.figure(figsize=(10, 6))
        plt.bar(labels, values)

        plt.title("Top MITRE ATT&CK Techniques Frequency")
        plt.xticks(rotation=45)

        plt.tight_layout()
        plt.savefig("data/mitre_frequency.png")
        plt.close()

    def plot_detection_vs_miss(self, detected, missed):

        labels = ["Detected", "Missed"]
        values = [len(detected), len(missed)]

        plt.figure(figsize=(6, 5))
        plt.bar(labels, values)

        plt.title("Detection Coverage Analysis")
        plt.tight_layout()

        plt.savefig("data/detection_vs_miss.png")
        plt.close()

    def plot_risk_score(self, freq_map, detection_rate=0.666):

        techniques = list(freq_map.keys())
        scores = []

        for t in techniques:

            freq = freq_map[t]

            # risk = frequency × (1 - detection effectiveness)
            score = freq * (1 - detection_rate)

            scores.append(score)

        # top 10 risky techniques
        combined = list(zip(techniques, scores))
        combined.sort(key=lambda x: x[1], reverse=True)

        top = combined[:10]

        labels = [x[0] for x in top]
        values = [x[1] for x in top]

        plt.figure(figsize=(10, 6))
        plt.bar(labels, values)

        plt.title("Top Risky MITRE Techniques (Risk Score)")
        plt.xticks(rotation=45)

        plt.tight_layout()

        plt.savefig("data/risk_score.png")
        plt.close()

    def run_all(self, dataset_path, detected, missed):

        dataset = self.load_dataset(dataset_path)

        techniques = self.extract_techniques(dataset)

        freq_map = self.build_frequency_map(techniques)

        self.plot_top_techniques(freq_map)
        self.plot_detection_vs_miss(detected, missed)
        self.plot_risk_score(freq_map)


if __name__ == "__main__":

    from core.evaluation_engine import EvaluationEngine

    dataset_path = "dataset/dataset.jsonl"

    # Step 1: run evaluation
    engine = EvaluationEngine()
    results = engine.run_evaluation(dataset_path)

    # Step 2: recompute detected/missed using same logic
    dataset = engine.load_dataset(dataset_path)
    techniques = engine.extract_techniques(dataset)
    detected, missed = engine.simulate_detection(techniques)

    # Step 3: visualization
    viz = ResearchVisualizer()
    viz.run_all(dataset_path, detected, missed)

    print("\nVISUALIZATION COMPLETE")
    print("Generated:")
    print("- data/mitre_frequency.png")
    print("- data/detection_vs_miss.png")
    print("- data/risk_score.png")