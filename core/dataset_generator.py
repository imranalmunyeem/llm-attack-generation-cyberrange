import json
import os
import time
from datetime import datetime

from core.llm_generator import generate_attack_scenario


DATASET_PATH = "dataset/raw/scenarios.jsonl"


def ensure_file():
    os.makedirs("dataset/raw", exist_ok=True)


def load_existing_count():
    if not os.path.exists(DATASET_PATH):
        return 0

    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        return sum(1 for _ in f)


def save_scenario(scenario):
    with open(DATASET_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(scenario) + "\n")


def generate_dataset(target_size=300):
    ensure_file()

    count = load_existing_count()

    print(f"Starting generation... current = {count}, target = {target_size}")

    while count < target_size:

        try:
            scenario = generate_attack_scenario(
                environment="Enterprise Network",
                difficulty="Medium",
                attack_type="Ransomware"
            )

            # skip invalid outputs
            if isinstance(scenario, dict) and "error" not in scenario:

                scenario["generated_at"] = str(datetime.now())

                save_scenario(scenario)

                count += 1

                print(f"[OK] Generated {count}/{target_size}")

            else:
                print("[SKIP] Invalid scenario")

            time.sleep(1)  # avoid rate limit

        except Exception as e:
            print("[ERROR]", e)
            time.sleep(2)

    print("Dataset generation complete!")