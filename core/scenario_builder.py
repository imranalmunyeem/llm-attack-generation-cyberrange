from core.llm_generator import generate_attack_scenario


def build_scenario(
    environment,
    difficulty,
    attack_type
):

    scenario = generate_attack_scenario(
        environment=environment,
        difficulty=difficulty,
        attack_type=attack_type
    )

    return scenario