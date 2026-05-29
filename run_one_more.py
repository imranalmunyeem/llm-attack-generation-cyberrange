import json
import os
from core.llm_generator import generate_attack_scenario

# ---------------- GENERATE ----------------
scenario = generate_attack_scenario(
    "Enterprise Network",
    "Medium",
    "Ransomware"
)

print("Generated scenario:\n")
print(scenario)

# ---------------- SAFE FILE PATH ----------------
DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

DATASET_PATH = os.path.join(DATA_DIR, "attack_dataset_20260529_185053.jsonl")

# ---------------- APPEND ----------------
with open(DATASET_PATH, "a", encoding="utf-8") as f:
    f.write(json.dumps(scenario) + "\n")

print(f"\n✔ Added scenario to: {DATASET_PATH}")