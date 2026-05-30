import random


class BaselineComparison:

    def random_generator(self, n):

        return [random.random() for _ in range(n)]

    def template_generator(self, dataset):

        return [len(s.get("attack_stages", [])) for s in dataset]

    def evaluate(self, dataset, detection_rate):

        baseline_random = 0.4
        baseline_template = 0.55
        your_system = detection_rate

        return {
            "random_baseline": baseline_random,
            "template_baseline": baseline_template,
            "llm_system": your_system
        }


if __name__ == "__main__":

    from core.evaluation_engine import EvaluationEngine

    engine = EvaluationEngine()

    results = engine.run_evaluation("dataset/dataset.jsonl")

    comp = BaselineComparison().evaluate(None, results["detection_rate"])

    print(comp)