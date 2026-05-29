import os
import json
import time
import random
from datetime import datetime
from core.llm_generator import generate_attack_scenario


ATTACK_TYPES = ["Ransomware", "Phishing", "APT", "Insider Threat"]
DIFFICULTY = ["Easy", "Medium", "Hard"]
ENVIRONMENTS = ["Enterprise Network", "Cloud Infrastructure", "Healthcare", "ICS"]


def create_balanced_seed(i):
    return {
        "environment": random.choice(ENVIRONMENTS),
        "difficulty": random.choice(DIFFICULTY),
        "attack_type": random.choice(ATTACK_TYPES)
    }


def is_duplicate(new_item, existing):
    """Simple dedup based on narrative similarity"""
    for item in existing[-20:]:  # only compare recent 20 for speed
        if item.get("narrative", "")[:80] == new_item.get("narrative", "")[:80]:
            return True
    return False


def generate_dataset(num_samples=500, output_dir="dataset"):
    os.makedirs(output_dir, exist_ok=True)

    output_file = os.path.join(
        output_dir,
        f"attack_dataset_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    )

    dataset = []

    print(f"\n🚀 Generating {num_samples} scenarios...\n")

    for i in range(num_samples):
        seed = create_balanced_seed(i)

        try:
            raw = generate_attack_scenario(
                seed["environment"],
                seed["difficulty"],
                seed["attack_type"]
            )

            scenario = json.loads(raw)

            if not is_duplicate(scenario, dataset):
                dataset.append(scenario)

                with open(output_file, "a") as f:
                    f.write(json.dumps(scenario) + "\n")

            # progress
            if i % 10 == 0:
                print(f"Generated: {i}/{num_samples}")

            time.sleep(0.3)  # rate limit safety

        except Exception as e:
            print(f"Error at {i}: {e}")
            continue

    print("\n✅ Dataset generation complete!")
    print(f"Saved to: {output_file}")

    return output_file