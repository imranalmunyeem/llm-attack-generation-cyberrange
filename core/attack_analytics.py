import json
import re
from collections import Counter
import matplotlib.pyplot as plt


class MitreAnalytics:

    def __init__(self):
        # Lightweight MITRE keyword mapping (works without structured labels)
        self.mitre_map = {
            "phishing": "T1566",
            "email": "T1566",
            "spear phishing": "T1566.001",
            "credential": "T1078",
            "login": "T1078",
            "ransomware": "T1486",
            "malware": "T1204",
            "execution": "T1203",
            "privilege escalation": "T1068",
            "lateral movement": "T1021",
            "exfiltration": "T1041",
            "exploit": "T1203",
            "vulnerability": "T1203"
        }

    def load_dataset(self, path):
        """Load JSONL dataset safely"""
        dataset = []

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    dataset.append(json.loads(line))

        return dataset

    def map_to_mitre(self, text):
        """Map free-text to MITRE ATT&CK technique IDs"""
        text = text.lower()

        matched = []

        for keyword, technique in self.mitre_map.items():
            if keyword in text:
                matched.append(technique)

        return matched

    def extract_techniques(self, dataset):
        """Extract MITRE techniques from dataset"""

        techniques = []

        for scenario in dataset:

            for stage in scenario.get("attack_stages", []):

                text_blob = ""

                # combine all available text fields
                text_blob += stage.get("stage_name", "") + " "
                text_blob += stage.get("description", "") + " "

                matched = self.map_to_mitre(text_blob)

                techniques.extend(matched)

        return techniques

    def plot_top_techniques(self, techniques, output_path):

        counter = Counter(techniques)
        top = counter.most_common(10)

        if not top:
            print("No MITRE techniques found. Check dataset content.")
            return

        labels = [x[0] for x in top]
        values = [x[1] for x in top]

        plt.figure(figsize=(10, 6))
        plt.bar(labels, values)

        plt.title("Top MITRE ATT&CK Techniques (Extracted)")
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
            "total_scenarios": len(dataset),
            "unique_techniques": len(set(techniques)),
            "total_technique_occurrences": len(techniques),
            "top_10_techniques": Counter(techniques).most_common(10)
        }


if __name__ == "__main__":

    dataset_path = "dataset/dataset.jsonl"

    analytics = MitreAnalytics()

    report = analytics.generate_report(dataset_path)

    print("\nMITRE ANALYTICS REPORT:")
    print(json.dumps(report, indent=4))