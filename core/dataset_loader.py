import json

DATASET_PATH = "dataset/dataset.jsonl"


def load_dataset():
    scenarios = []

    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            try:
                obj = json.loads(line)

                # safety check (ensures dict, not string)
                if isinstance(obj, dict):
                    scenarios.append(obj)

            except json.JSONDecodeError:
                continue

    return scenarios


def filter_by_type(scenarios, attack_type=None, difficulty=None, environment=None):
    filtered = scenarios

    if attack_type:
        filtered = [s for s in filtered if s.get("attack_type") == attack_type]

    if difficulty:
        filtered = [s for s in filtered if s.get("difficulty") == difficulty]

    if environment:
        filtered = [s for s in filtered if s.get("environment_type") == environment]

    return filtered