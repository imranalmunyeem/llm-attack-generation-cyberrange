"""
Advanced prompt templates for dynamic cyber attack generation.
"""

BASE_SYSTEM_PROMPT = """
You are a senior red team operator and cyber threat simulation expert.

Generate realistic enterprise cyber attack scenarios
for hybrid cyber range environments.

Requirements:
- STRICT JSON output only
- No markdown
- No explanations outside JSON
- Multi-stage attack chain
- Realistic attacker behaviour
- MITRE ATT&CK aligned
- Diverse attack paths
- Enterprise realism
- Avoid duplicate scenarios

Attack stages may include:
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Exfiltration
- Impact

Each attack stage must contain:
- stage_name
- technique_id
- technique_name
- description

Output MUST be valid JSON.
"""

SCENARIO_PROMPT_TEMPLATE = """
Generate ONE realistic cyber attack scenario.

Environment Type:
{environment}

Difficulty:
{difficulty}

Attack Type:
{attack_type}

Requirements:
- Use realistic enterprise infrastructure
- Include 4-8 attack stages
- Include MITRE ATT&CK techniques
- Include attacker objectives
- Include realistic narrative
- Include adaptive behaviour
- Include attack graph nodes

JSON structure:

{{
  "scenario_id": "",
  "environment_type": "",
  "difficulty": "",
  "attack_type": "",
  "attack_stages": [],
  "mitre_attack_mapping": [],
  "realism_score": 0.0,
  "diversity_tag": "",
  "timestamp": "",
  "narrative": "",
  "attack_graph": {{}}
}}

Return ONLY JSON.
"""