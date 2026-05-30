import json


class AttackValidator:

    def validate_scenario(self, scenario):

        """
        Scores attack realism and structural quality.
        Output: 0–1 score
        """

        score = 0.0

        # 1. Check MITRE mapping quality
        mitre = scenario.get("mitre_attack_mapping", [])
        if isinstance(mitre, list):
            if len(mitre) >= 3:
                score += 0.25
            elif len(mitre) > 0:
                score += 0.15

        # 2. Check attack stage completeness
        stages = scenario.get("attack_stages", [])
        if isinstance(stages, list):
            if len(stages) >= 4:
                score += 0.25
            elif len(stages) >= 2:
                score += 0.15

        # 3. Check attack graph structure
        graph = scenario.get("attack_graph", {})
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])

        if len(nodes) >= 5:
            score += 0.2
        if len(edges) >= 3:
            score += 0.2

        # 4. Narrative presence (important for realism)
        if scenario.get("narrative"):
            if len(scenario["narrative"]) > 50:
                score += 0.1

        return round(score, 3)


    def evaluate_dataset(self, dataset):

        scores = []

        for s in dataset:
            scores.append(self.validate_scenario(s))

        return {
            "avg_realism_score": round(sum(scores) / len(scores), 3),
            "min": min(scores),
            "max": max(scores)
        }


if __name__ == "__main__":

    from core.dataset_loader import load_dataset

    dataset = load_dataset()

    validator = AttackValidator()

    report = validator.evaluate_dataset(dataset)

    print("\nATTACK REALISM REPORT:")
    print(json.dumps(report, indent=4))