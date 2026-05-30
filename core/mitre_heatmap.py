import json
import matplotlib.pyplot as plt
from collections import defaultdict


class MITREHeatmap:

    def load(self, path):
        data = []
        with open(path, "r") as f:
            for line in f:
                if line.strip():
                    data.append(json.loads(line))
        return data

    def build_matrix(self, dataset):

        matrix = defaultdict(int)

        for s in dataset:
            for stage in s.get("attack_stages", []):
                for t in stage.get("techniques", []):
                    tid = t.get("technique_id")
                    matrix[tid] += 1

        return matrix

    def plot(self, matrix):

        top = sorted(matrix.items(), key=lambda x: x[1], reverse=True)[:15]

        labels = [x[0] for x in top]
        values = [x[1] for x in top]

        plt.figure(figsize=(10, 6))
        plt.bar(labels, values)
        plt.xticks(rotation=45)

        plt.title("MITRE ATT&CK Technique Heatmap (Top 15)")
        plt.tight_layout()

        plt.savefig("data/mitre_heatmap.png")
        plt.close()


if __name__ == "__main__":

    m = MITREHeatmap()

    dataset = m.load("dataset/dataset.jsonl")

    matrix = m.build_matrix(dataset)

    m.plot(matrix)

    print("MITRE heatmap saved → data/mitre_heatmap.png")