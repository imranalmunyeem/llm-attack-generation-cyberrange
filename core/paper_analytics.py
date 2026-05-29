import json
import math
from collections import Counter
from datetime import datetime

import matplotlib.pyplot as plt


# =========================
# BASIC METRICS
# =========================

def calculate_attack_type_distribution(scenarios):

    counter = Counter()

    for s in scenarios:
        attack_type = s.get("attack_type", "Unknown")
        counter[attack_type] += 1

    return dict(counter)


def calculate_environment_distribution(scenarios):

    counter = Counter()

    for s in scenarios:
        env = s.get("environment_type", "Unknown")
        counter[env] += 1

    return dict(counter)


# =========================
# MITRE ANALYSIS
# =========================

def calculate_mitre_distribution(scenarios):

    counter = Counter()

    for s in scenarios:

        mappings = s.get("mitre_attack_mapping", [])

        if isinstance(mappings, dict):
            mappings = list(mappings.keys())

        for t in mappings:
            counter[t] += 1

    return dict(counter)


# =========================
# NOVELTY SCORE
# =========================

def calculate_novelty_score(scenarios):

    unique_narratives = set()

    for s in scenarios:
        narrative = s.get("narrative", "")
        unique_narratives.add(narrative[:200])

    novelty = len(unique_narratives) / len(scenarios)

    return round(novelty, 3)


# =========================
# GRAPH COMPLEXITY
# =========================

def calculate_graph_complexity(scenario):

    graph = scenario.get("attack_graph", {})

    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    node_count = len(nodes)
    edge_count = len(edges)

    complexity = node_count + edge_count

    return complexity


def average_graph_complexity(scenarios):

    values = []

    for s in scenarios:
        values.append(
            calculate_graph_complexity(s)
        )

    return round(sum(values) / len(values), 2)


# =========================
# VISUALIZATION
# =========================

def generate_attack_type_chart(distribution):

    names = list(distribution.keys())
    values = list(distribution.values())

    plt.figure(figsize=(8, 5))

    plt.bar(names, values)

    plt.xlabel("Attack Type")
    plt.ylabel("Count")
    plt.title("Attack Type Distribution")

    plt.tight_layout()

    plt.savefig("data/attack_type_distribution.png")

    plt.close()


def generate_environment_chart(distribution):

    names = list(distribution.keys())
    values = list(distribution.values())

    plt.figure(figsize=(8, 5))

    plt.bar(names, values)

    plt.xlabel("Environment")
    plt.ylabel("Count")
    plt.title("Environment Distribution")

    plt.tight_layout()

    plt.savefig("data/environment_distribution.png")

    plt.close()


def generate_mitre_chart(mitre_distribution):

    top_items = sorted(
        mitre_distribution.items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]

    names = [x[0] for x in top_items]
    values = [x[1] for x in top_items]

    plt.figure(figsize=(10, 5))

    plt.bar(names, values)

    plt.xlabel("MITRE Technique")
    plt.ylabel("Frequency")
    plt.title("Top MITRE ATT&CK Techniques")

    plt.tight_layout()

    plt.savefig("data/mitre_distribution.png")

    plt.close()


# =========================
# FULL ANALYSIS
# =========================

def run_paper_analysis(scenarios):

    attack_dist = calculate_attack_type_distribution(scenarios)

    env_dist = calculate_environment_distribution(scenarios)

    mitre_dist = calculate_mitre_distribution(scenarios)

    novelty = calculate_novelty_score(scenarios)

    avg_complexity = average_graph_complexity(scenarios)

    generate_attack_type_chart(attack_dist)

    generate_environment_chart(env_dist)

    generate_mitre_chart(mitre_dist)

    report = {

        "timestamp": str(datetime.now()),

        "total_scenarios": len(scenarios),

        "attack_type_distribution": attack_dist,

        "environment_distribution": env_dist,

        "top_mitre_techniques": dict(
            sorted(
                mitre_dist.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        ),

        "novelty_score": novelty,

        "average_graph_complexity": avg_complexity
    }

    return report