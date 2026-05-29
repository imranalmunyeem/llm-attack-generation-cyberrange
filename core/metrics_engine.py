import random
from datetime import datetime

# -----------------------------
# METRICS ENGINE (RESEARCH CORE)
# -----------------------------

STAGE_WEIGHTS = {
    "Initial Access": 0.9,
    "Execution": 0.85,
    "Persistence": 0.8,
    "Privilege Escalation": 0.75,
    "Credential Access": 0.7,
    "Lateral Movement": 0.6,
    "Collection": 0.55,
    "Exfiltration": 0.5,
    "Impact": 0.4,
}


def calculate_attack_success(scenario, detected_stage_index):
    stages = scenario.get("attack_stages", [])

    if detected_stage_index is None:
        return 1.0  # fully successful attack

    return detected_stage_index / len(stages)


def simulate_detection(scenario):
    """
    Simulates SOC detection behavior
    """

    difficulty = scenario.get("difficulty", "Medium")

    base_detection = {
        "Easy": 0.75,
        "Medium": 0.55,
        "Hard": 0.35
    }[difficulty]

    stages = scenario.get("attack_stages", [])

    detected_stage_index = None
    mttd = None

    for i, stage in enumerate(stages):
        stage_name = stage.get("stage_name", "")

        detection_chance = base_detection * STAGE_WEIGHTS.get(stage_name, 0.5)

        if random.random() < detection_chance:
            detected_stage_index = i + 1
            mttd = random.randint(5, 60) * (i + 1)
            break

    return detected_stage_index, mttd


def simulate_response(detected_stage_index, total_stages):
    """
    SOC response effectiveness simulation
    """

    if detected_stage_index is None:
        return {
            "contained": False,
            "mttc": None
        }

    containment_probability = 0.3 + (detected_stage_index / total_stages)

    contained = random.random() < containment_probability

    mttc = random.randint(10, 120) if contained else None

    return {
        "contained": contained,
        "mttc": mttc
    }


def analyze_scenario(scenario):
    """
    Full metrics pipeline
    """

    detected_stage_index, mttd = simulate_detection(scenario)

    total_stages = len(scenario.get("attack_stages", []))

    success_rate = calculate_attack_success(scenario, detected_stage_index)

    response = simulate_response(detected_stage_index, total_stages)

    return {
        "scenario_id": scenario.get("scenario_id"),
        "attack_type": scenario.get("attack_type"),
        "difficulty": scenario.get("difficulty"),

        "attack_success_rate": round(success_rate, 2),
        "detected_stage_index": detected_stage_index,
        "mean_time_to_detect": mttd,

        "containment_success": response["contained"],
        "mean_time_to_contain": response["mttc"],

        "timestamp": datetime.utcnow().isoformat()
    }


def analyze_dataset(scenarios):
    """
    Dataset-level statistics for IEEE paper
    """

    results = [analyze_scenario(s) for s in scenarios]

    total = len(results)

    avg_success = sum(r["attack_success_rate"] for r in results) / total

    detection_count = len([r for r in results if r["detected_stage_index"]])
    detection_rate = detection_count / total

    containment_count = len([r for r in results if r["containment_success"]])
    containment_rate = containment_count / total

    mttd_values = [r["mean_time_to_detect"] for r in results if r["mean_time_to_detect"]]
    avg_mttd = sum(mttd_values) / len(mttd_values) if mttd_values else 0

    return {
        "total_scenarios": total,
        "avg_attack_success_rate": round(avg_success, 3),
        "detection_rate": round(detection_rate, 3),
        "containment_rate": round(containment_rate, 3),
        "avg_mttd": round(avg_mttd, 2),
        "results": results
    }