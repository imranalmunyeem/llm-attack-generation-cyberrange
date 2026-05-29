import json

# 👇 CHANGE THIS TO YOUR REAL FILE NAME
DATASET_PATH = "dataset/attack_dataset_20260529_185053.jsonl"

count = 0
valid = 0

last_item = None

with open(DATASET_PATH, "r") as f:
    for line in f:
        count += 1
        try:
            item = json.loads(line)
            last_item = item

            # basic validation
            if "scenario_id" in item and "attack_stages" in item:
                valid += 1

        except Exception as e:
            print("Broken line:", e)

print("\n===== DATASET CHECK =====")
print("Total lines:", count)
print("Valid scenarios:", valid)

if last_item:
    print("\nSample scenario_id:", last_item.get("scenario_id"))
    print("Attack type:", last_item.get("attack_type"))