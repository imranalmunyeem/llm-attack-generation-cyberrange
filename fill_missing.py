import json
from core.llm_generator import generate_attack_scenario

def regenerate_one(output_file):
    print("Regenerating missing scenario...")

    raw = generate_attack_scenario(
        "Enterprise Network",
        "Medium",
        "Ransomware"
    )

    scenario = json.loads(raw)

    with open(output_file, "a") as f:
        f.write(json.dumps(scenario) + "\n")

    print("Added 1 missing scenario")

# CHANGE THIS
output_file = "dataset/attack_dataset_20260529_182200.jsonl"

regenerate_one(output_file)