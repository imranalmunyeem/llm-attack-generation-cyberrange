import copy
import random
from core.dataset_loader import load_dataset


class AdversarialMutator:

    def mutate(self, scenario):

        """
        Generate 3 independent adversarial variants.
        """

        return [
            self.stealth_variant(copy.deepcopy(scenario)),
            self.obfuscated_variant(copy.deepcopy(scenario)),
            self.expanded_variant(copy.deepcopy(scenario))
        ]

    def stealth_variant(self, scenario):

        scenario["variant"] = "stealth"

        for stage in scenario.get("attack_stages", []):
            stage["description"] += " (low-noise stealth execution)"

        return scenario

    def obfuscated_variant(self, scenario):

        scenario["variant"] = "obfuscated"

        for stage in scenario.get("attack_stages", []):
            stage["description"] = self._shuffle_words(stage["description"])

        return scenario

    def expanded_variant(self, scenario):

        scenario["variant"] = "expanded"

        stages = scenario.get("attack_stages", [])

        stages.append({
            "stage_name": "Persistence",
            "technique_id": "T1547",
            "description": "Long-term persistence mechanism added for extended access"
        })

        scenario["attack_stages"] = stages

        return scenario

    def _shuffle_words(self, text):
        words = text.split()
        random.shuffle(words)
        return " ".join(words)


if __name__ == "__main__":

    dataset = load_dataset()

    mutator = AdversarialMutator()

    sample = dataset[0]

    variants = mutator.mutate(sample)

    for v in variants:
        print("\nVARIANT:")
        print(v["variant"])