import json


class AttackQualityEvaluator:

    def score_attack(self, scenario):

        score = 0

        # 1. MITRE mapping quality
        mitre = scenario.get("mitre_attack_mapping", [])
        if len(mitre) >= 3:
            score += 0.3
        elif len(mitre) >= 1:
            score += 0.15

        # 2. Attack stages depth
        stages = scenario.get("attack_stages", [])
        if len(stages) >= 4:
            score += 0.3
        elif len(stages) >= 2:
            score += 0.15

        # 3. Graph structure
        graph = scenario.get("attack_graph", {})
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])

        if len(nodes) > 5:
            score += 0.2

        if len(edges) > 3:
            score += 0.2

        return round(score, 3)


    def evaluate_dataset(self, dataset):

        results = []

        for s in dataset:
            results.append(self.score_attack(s))

        return {
            "avg_quality_score": sum(results) / len(results),
            "min": min(results),
            "max": max(results)
        }


if __name__ == "__main__":

    from core.dataset_loader import load_dataset

    dataset = load_dataset("dataset/dataset.jsonl")

    evaluator = AttackQualityEvaluator()

    report = evaluator.evaluate_dataset(dataset)

    print(json.dumps(report, indent=4))