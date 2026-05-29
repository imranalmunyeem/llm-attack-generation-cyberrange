import os
from openai import OpenAI
from dotenv import load_dotenv

from core.prompt_templates import (
    BASE_SYSTEM_PROMPT,
    SCENARIO_PROMPT_TEMPLATE
)

from core.validator import validate_json

from utils.logger import log_message

load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)


def generate_attack_scenario(
    environment="Enterprise Network",
    difficulty="Medium",
    attack_type="Ransomware"
):
    """
    Generate validated cyber attack scenario.
    """

    user_prompt = SCENARIO_PROMPT_TEMPLATE.format(
        environment=environment,
        difficulty=difficulty,
        attack_type=attack_type
    )

    try:

        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {
                    "role": "system",
                    "content": BASE_SYSTEM_PROMPT
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ],
            temperature=0.9
        )

        content = response.choices[0].message.content

        valid, result = validate_json(content)

        if valid:

            log_message("Scenario generated successfully.")

            return result

        else:

            log_message(f"JSON validation failed: {result}")

            return {
                "error": "Invalid JSON generated",
                "details": result
            }

    except Exception as e:

        log_message(f"Generation error: {e}")

        return {
            "error": str(e)
        }