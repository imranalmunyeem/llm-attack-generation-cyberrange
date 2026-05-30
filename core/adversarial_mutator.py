import copy
import random


class AdversarialMutator:

    def mutate(self, scenario):

        """
        Generates adversarial variants of attack scenarios:
        - stealth version
        - obfuscated version
        - expanded multi-stage version
        """

        variants = []

        base = copy.deepcopy(scenario)

        variants.append(self.stealth_variant(base))
        variants.append(self.obfuscated_variant(base))
        variants.append(self.expanded_variant(base))

        return variants

    def stealth_variant(self, scenario):

        scenario["variant"] = "stealth"

        for stage in scenario.get("attack_stages", []):
            stage["description"] += " (low-noise, stealth execution)"

        return scenario

    def obfuscated_variant(self, scenario):

        scenario = copy.deepcopy(scenario)
        scenario["variant"] = "obfuscated"

        for stage in scenario.get("attack_stages", []):
            stage["description"] = self._obfuscate(stage["description"])

        return scenario

    def expanded_variant(self, scenario):

        scenario = copy.deepcopy(scenario)
        scenario["variant"] = "expanded"

        # simulate additional stage
        scenario["attack_stages"].append({
            "stage_name": "Persistence",
            "techniques": [{"technique_id": "T1547"}],
            "description": "Added persistence mechanism for long-term access"
        })

        return scenario

    def _obfuscate(self, text):

        words = text.split()
        random.shuffle(words)
        return " ".join(words)


if __name__ == "__main__":

    from core.dataset_loader import load_dataset

    dataset = load_dataset("dataset/dataset.jsonl")

    mutator = AdversarialMutator()

    sample = dataset[0]

    variants = mutator.mutate(sample)

    for v in variants:
        print("\nVARIANT:")
        print(v["variant"])