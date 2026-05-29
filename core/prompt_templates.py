"""
Prompt templates for attack scenario generation.
"""

BASE_SYSTEM_PROMPT = """
You are a senior cybersecurity red team expert.

Generate realistic multi-stage cyber attack scenarios
for hybrid cyber range environments.

Requirements:
- Use MITRE ATT&CK techniques
- Include multi-stage attack paths
- Include phishing, privilege escalation,
  lateral movement, persistence, and exfiltration where relevant
- Return STRICT JSON only
- Avoid duplicate scenarios
- Ensure realism
"""

SCENARIO_PROMPT_TEMPLATE = """
Generate ONE realistic cyber attack scenario.

Environment Type:
{environment}

Difficulty:
{difficulty}

Attack Type:
{attack_type}

Return JSON format with:
- scenario_id
- environment_type
- attack_stages
- mitre_attack_mapping
- difficulty
- realism_score
- diversity_tag
- narrative
- attack_graph

Ensure:
- realistic enterprise attack chain
- ATT&CK alignment
- multi-step attack flow
"""