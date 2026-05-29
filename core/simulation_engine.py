import random


def simulate_scenario(scenario):
    print("\n===== SIMULATION START =====")

    print(f"Scenario ID: {scenario['scenario_id']}")
    print(f"Attack Type: {scenario['attack_type']}")
    print(f"Environment: {scenario['environment_type']}\n")

    stages = scenario.get("attack_stages", [])

    score = 0

    for stage in stages:
        success = random.choice([True, True, True, False])  # 75% success rate

        print(f"[{stage['stage_name']}] - {stage['description']}")
        print("Status:", "SUCCESS" if success else "DETECTED ❌")

        if success:
            score += 1
        else:
            break

    success_rate = (score / len(stages)) * 100

    print("\n===== RESULT =====")
    print(f"Attack Completion: {success_rate:.2f}%")

    if success_rate > 80:
        print("Outcome: FULL COMPROMISE")
    elif success_rate > 50:
        print("Outcome: PARTIAL BREACH")
    else:
        print("Outcome: ATTACK BLOCKED")

    return success_rate