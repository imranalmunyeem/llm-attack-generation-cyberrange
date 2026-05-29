import json


def load_mitre_data():
    with open("mitre/mitre_data.json", "r") as file:
        return json.load(file)


def map_technique(technique_id):
    data = load_mitre_data()
    return data.get(technique_id, "Unknown Technique")