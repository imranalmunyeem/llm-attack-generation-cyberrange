import json

DATASET_PATH = "data/attack_dataset_20260529_185053.jsonl"


def load_dataset():
    scenarios = []

    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        for line in f:
            try:
                scenarios.append(json.loads(line.strip()))
            except:
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