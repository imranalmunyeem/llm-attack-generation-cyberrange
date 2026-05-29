import os
import json
from openai import OpenAI
from dotenv import load_dotenv

from core.prompt_templates import (
    BASE_SYSTEM_PROMPT,
    SCENARIO_PROMPT_TEMPLATE
)

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
    Generate a cyber attack scenario using OpenAI.
    """

    user_prompt = SCENARIO_PROMPT_TEMPLATE.format(
        environment=environment,
        difficulty=difficulty,
        attack_type=attack_type
    )

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

    return content