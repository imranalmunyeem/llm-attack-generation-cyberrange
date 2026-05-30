import json
import networkx as nx
import matplotlib.pyplot as plt


class TechniqueGraphBuilder:

    def load_dataset(self, path=None):
        if path is None:
            path = "dataset/dataset.jsonl"

        data = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    data.append(json.loads(line))
        return data


    def build_graph(self, dataset):

        G = nx.Graph()

        for scenario in dataset:

            stages = scenario.get("attack_stages", [])

            for stage in stages:
                techniques = stage.get("techniques", [])

                tech_ids = [t.get("technique_id") for t in techniques if t.get("technique_id")]

                # connect co-occurring techniques
                for i in range(len(tech_ids)):
                    for j in range(i + 1, len(tech_ids)):

                        a = tech_ids[i]
                        b = tech_ids[j]

                        if G.has_edge(a, b):
                            G[a][b]["weight"] += 1
                        else:
                            G.add_edge(a, b, weight=1)

        return G


    def visualize(self, G, output="data/mitre_cooccurrence_graph.png"):

        plt.figure(figsize=(10, 8))

        pos = nx.spring_layout(G, k=0.5)

        weights = [G[u][v]["weight"] for u, v in G.edges()]

        nx.draw(
            G,
            pos,
            with_labels=True,
            node_size=800,
            width=weights
        )

        plt.title("MITRE Technique Co-occurrence Graph")
        plt.savefig(output)
        plt.close()

        print(f"Graph saved → {output}")


if __name__ == "__main__":

    builder = TechniqueGraphBuilder()

    dataset = builder.load_dataset()

    G = builder.build_graph(dataset)

    builder.visualize(G)