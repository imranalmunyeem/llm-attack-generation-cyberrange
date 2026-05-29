import json
import networkx as nx
import matplotlib.pyplot as plt
from pyvis.network import Network


class AttackGraphBuilder:

    def __init__(self):
        pass

    def build_graph(self, scenario):

        G = nx.DiGraph()

        attack_stages = scenario.get("attack_stages", [])

        if not attack_stages:
            print("No attack stages found in scenario.")
            return G

        previous_stage = None

        for stage in attack_stages:

            stage_name = stage.get("stage_name", "Unknown")

            G.add_node(stage_name)

            if previous_stage:
                G.add_edge(previous_stage, stage_name)

            previous_stage = stage_name

        return G

    def save_graph_image(self, G, output_path):

        plt.figure(figsize=(10, 7))

        pos = nx.spring_layout(G)

        nx.draw(
            G,
            pos,
            with_labels=True,
            node_size=3000,
            font_size=10,
            arrows=True
        )

        plt.title("Attack Scenario Graph")
        plt.savefig(output_path)
        plt.close()

    def save_interactive_graph(self, G, output_html):

        net = Network(
            height="750px",
            width="100%",
            directed=True,
            notebook=False
        )

        net.from_nx(G)

        # FIX: avoid pyvis template.render crash on Windows
        net.write_html(output_html)


def load_first_scenario(dataset_path):

    try:
        with open(dataset_path, "r", encoding="utf-8") as file:
            first_line = file.readline()
            return json.loads(first_line)

    except FileNotFoundError:
        print(f"Dataset not found at: {dataset_path}")
        return None

    except json.JSONDecodeError:
        print("Invalid JSON in dataset file.")
        return None


if __name__ == "__main__":

    # IMPORTANT: update this if your filename changes
    dataset_path = "dataset/dataset.jsonl"

    scenario = load_first_scenario(dataset_path)

    if scenario is None:
        print("No scenario loaded. Exiting.")
        exit()

    builder = AttackGraphBuilder()

    graph = builder.build_graph(scenario)

    if len(graph.nodes) == 0:
        print("Graph is empty. Nothing to render.")
        exit()

    # Save static image
    builder.save_graph_image(
        graph,
        "data/attack_graph.png"
    )

    # Save interactive graph
    builder.save_interactive_graph(
        graph,
        "data/interactive_attack_graph.html"
    )

    print("Attack graph generated successfully.")