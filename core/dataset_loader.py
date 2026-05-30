import json

def load_dataset(path=None):
    """
    Loads dataset safely.
    If no path is given, uses default dataset location.
    """

    if path is None:
        path = r"dataset/dataset.jsonl"

    dataset = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                dataset.append(json.loads(line))

    return dataset