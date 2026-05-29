import json
from collections import Counter
import matplotlib.pyplot as plt


class MitreAnalytics:

    def __init__(self):
        pass

    def load_dataset(self, path):

        with open(path, "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f]

    def extract_techniques(self, dataset):

        techniques = []

        for scenario in dataset:

            for stage in scenario.get("attack_stages", []):

                for tech in stage.get("techniques", []):

                    tech_id = tech.get("technique_id")

                    if tech_id:
                        techniques.append(tech_id)

        return techniques

    def plot_top_techniques(self, techniques, output_path):

        counter = Counter(techniques)

        top = counter.most_common(10)

        labels = [t[0] for t in top]
        values = [t[1] for t in top]

        plt.figure(figsize=(10, 6))
        plt.bar(labels, values)

        plt.title("Top MITRE ATT&CK Techniques")
        plt.xticks(rotation=45)

        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()

    def generate_report(self, dataset_path):

        dataset = self.load_dataset(dataset_path)

        techniques = self.extract_techniques(dataset)

        self.plot_top_techniques(
            techniques,
            "data/top_mitre_techniques.png"
        )

        return {
            "total_techniques": len(set(techniques)),
            "total_occurrences": len(techniques),
            "top_10": Counter(techniques).most_common(10)
        }


if __name__ == "__main__":

    dataset_path = "dataset/dataset.jsonl"

    analytics = MitreAnalytics()

    report = analytics.generate_report(dataset_path)

    print("\nMITRE ANALYTICS REPORT:")
    print(json.dumps(report, indent=4))