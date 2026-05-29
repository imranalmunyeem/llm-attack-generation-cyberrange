import os
import json
from openai import OpenAI
from core.config import OPENAI_API_KEY

client = OpenAI(api_key=OPENAI_API_KEY)


def generate_attack_scenario(environment, difficulty, attack_type):
    prompt = f"""
You are a cybersecurity attack simulation generator.

Generate a realistic multi-stage cyber attack scenario.

Return ONLY valid JSON. No markdown. No backticks. No explanations.

Requirements:
- environment: {environment}
- difficulty: {difficulty}
- attack_type: {attack_type}

Schema:
{{
  "scenario_id": "string",
  "environment_type": "string",
  "difficulty": "string",
  "attack_type": "string",
  "realism_score": number,
  "narrative": "string",
  "attack_stages": [
    {{
      "stage_name": "string",
      "technique_id": "string",
      "description": "string"
    }}
  ],
  "mitre_attack_mapping": ["string"],
  "attack_graph": {{
    "nodes": ["string"],
    "edges": [["string", "string"]]
  }}
}}
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You generate strict JSON cybersecurity datasets."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.8,
        response_format={"type": "json_object"}  # 🔥 THIS FIXES YOUR JSON ERRORS
    )

    return response.choices[0].message.content