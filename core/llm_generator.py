import json
from openai import OpenAI
from core.config import OPENAI_API_KEY

client = OpenAI(api_key=OPENAI_API_KEY)


def generate_attack_scenario(environment, difficulty, attack_type):

    prompt = f"""
You are a cybersecurity attack simulation generator for research and cyber range systems.

Return ONLY valid JSON. No markdown. No explanation.

You MUST generate realistic multi-stage attack scenarios aligned with MITRE ATT&CK.

IMPORTANT REQUIREMENTS:
- Every stage MUST include at least 1–3 MITRE ATT&CK techniques
- Use REAL MITRE technique IDs (example: T1566, T1078, T1041)
- Ensure techniques match the stage logically
- Ensure attack flow is realistic and sequential

INPUTS:
- Environment: {environment}
- Difficulty: {difficulty}
- Attack Type: {attack_type}

OUTPUT JSON SCHEMA:

{{
  "scenario_id": "string",
  "environment_type": "{environment}",
  "difficulty": "{difficulty}",
  "attack_type": "{attack_type}",
  "realism_score": 0.0,

  "narrative": "string",

  "attack_stages": [
    {{
      "stage_name": "Reconnaissance",
      "description": "string",

      "techniques": [
        {{
          "technique_id": "T1595",
          "technique_name": "Active Scanning"
        }}
      ]
    }}
  ],

  "mitre_attack_mapping": [
    "T1595",
    "T1566",
    "T1078"
  ],

  "attack_graph": {{
    "nodes": ["Reconnaissance", "Initial Access"],
    "edges": [["Reconnaissance", "Initial Access"]]
  }}
}}

STRICT RULES:
- Output ONLY JSON
- No extra text
- No missing fields
- Every stage must include techniques array
- Techniques must be valid MITRE ATT&CK IDs
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": "You are a strict cybersecurity dataset generator producing structured MITRE ATT&CK aligned JSON for research."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.7,
        response_format={"type": "json_object"}
    )

    return response.choices[0].message.content