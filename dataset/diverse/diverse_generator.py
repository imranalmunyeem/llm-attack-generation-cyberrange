"""
diverse_generator.py  —  Diversity-Aware Scenario Generator
=============================================================
Generates 510 additional scenarios using diversity-aware prompts,
breaking the technique-vocabulary saturation observed at N=6 with
fixed prompts.

Target: 490 existing + 510 diverse = 1,000 total base scenarios
Projected ATT&CK coverage: ~64% (129/201 techniques)
Cost: ~$0.17 additional
Time: ~60 minutes

Diversity dimensions added:
  1. Threat actor personas (12 named groups + opportunistic)
  2. Specific industry verticals (beyond 4 generic environments)
  3. Explicit TTP focus areas (initial-access-heavy, lateral-movement-heavy, etc.)
  4. Campaign objectives (financial, espionage, disruption, data-theft)
  5. Operational security levels (noisy/fast vs slow/stealthy)

Run:
  python diverse_generator.py --n 510 --out dataset/diverse/

After running, merge with existing dataset:
  cat dataset/dataset.jsonl dataset/diverse/diverse_scenarios.jsonl > dataset/full_dataset.jsonl
  python journal_experiments.py  # re-run all experiments on full dataset
"""

import json
import os
import time
import random
import argparse
from datetime import datetime
from openai import OpenAI
from core.config import OPENAI_API_KEY

client = OpenAI(api_key=OPENAI_API_KEY)

# ─────────────────────────────────────────────
# DIVERSITY DIMENSIONS
# ─────────────────────────────────────────────

THREAT_ACTORS = [
    # Nation-state APT groups
    "Lazarus Group (DPRK, financially motivated)",
    "APT28 / Fancy Bear (Russian GRU, espionage)",
    "APT41 (Chinese dual espionage/cybercrime)",
    "Cozy Bear / APT29 (Russian SVR, stealthy)",
    "Charming Kitten / APT35 (Iranian espionage)",
    "Sandworm (Russian GRU, destructive)",
    "Kimsuky (DPRK, intelligence collection)",
    "Mustang Panda (Chinese, political espionage)",
    # Criminal groups
    "FIN7 (financially motivated, POS targeting)",
    "REvil / Sodinokibi (ransomware-as-a-service)",
    "Conti ransomware group (double extortion)",
    "Evil Corp (financial fraud, banking trojans)",
    # Insider/opportunistic
    "Disgruntled employee with privileged access",
    "Opportunistic criminal using commodity tools",
    "Script kiddie exploiting unpatched systems",
]

INDUSTRY_VERTICALS = [
    # Beyond the 4 base environments
    "Financial services / retail banking",
    "Critical infrastructure / power grid (OT/ICS)",
    "Government / defence contractor",
    "Retail / e-commerce / payment processing",
    "Telecommunications / ISP",
    "Higher education / research university",
    "Legal services / law firm",
    "Manufacturing / automotive supply chain",
    "Pharmaceutical / life sciences",
    "Media / broadcasting",
    # Overlap with existing but with more specificity
    "Hospital emergency department (Healthcare)",
    "Cloud-native SaaS startup (Cloud)",
    "Military contractor (Enterprise)",
    "Water treatment facility (ICS)",
]

TTP_FOCUS_AREAS = [
    "initial access and credential harvesting",
    "living-off-the-land and defence evasion",
    "lateral movement and domain compromise",
    "data collection and staged exfiltration",
    "persistence and long-term implant deployment",
    "destructive payload delivery and impact",
    "supply chain compromise and software tampering",
    "cloud service abuse and identity manipulation",
]

CAMPAIGN_OBJECTIVES = [
    "financial theft / business email compromise",
    "intellectual property theft / espionage",
    "ransomware deployment for extortion",
    "destructive attack on critical infrastructure",
    "persistent access for long-term intelligence collection",
    "supply chain poisoning to reach downstream targets",
]

OPSEC_LEVELS = [
    "high operational security, slow and patient, low-noise",
    "moderate operational security, balanced speed and stealth",
    "low operational security, fast and noisy, time-pressured",
]

ENVIRONMENTS_MAPPING = {
    "Financial services / retail banking": "Enterprise Network",
    "Critical infrastructure / power grid (OT/ICS)": "ICS",
    "Government / defence contractor": "Enterprise Network",
    "Retail / e-commerce / payment processing": "Enterprise Network",
    "Telecommunications / ISP": "Enterprise Network",
    "Higher education / research university": "Enterprise Network",
    "Legal services / law firm": "Enterprise Network",
    "Manufacturing / automotive supply chain": "ICS",
    "Pharmaceutical / life sciences": "Healthcare",
    "Media / broadcasting": "Enterprise Network",
    "Hospital emergency department (Healthcare)": "Healthcare",
    "Cloud-native SaaS startup (Cloud)": "Cloud Infrastructure",
    "Military contractor (Enterprise)": "Enterprise Network",
    "Water treatment facility (ICS)": "ICS",
}

DIFFICULTIES = ["Easy", "Medium", "Hard"]
ATTACK_TYPES  = ["Phishing", "Ransomware", "Insider Threat", "APT"]


# ─────────────────────────────────────────────
# DIVERSE PROMPT BUILDER
# ─────────────────────────────────────────────
def build_diverse_prompt(industry, difficulty, attack_type,
                          threat_actor, ttp_focus,
                          campaign_objective, opsec_level):
    environment = ENVIRONMENTS_MAPPING.get(industry, "Enterprise Network")

    return f"""
You are a cybersecurity attack simulation generator for research and cyber range systems.

Return ONLY valid JSON. No markdown. No explanation.

SCENARIO CONTEXT (use this to select SPECIFIC, REALISTIC MITRE ATT&CK techniques):
- Threat Actor: {threat_actor}
- Target Industry: {industry}
- Attack Type: {attack_type}
- TTP Focus: {ttp_focus}
- Campaign Objective: {campaign_objective}
- Operational Security Level: {opsec_level}
- Difficulty: {difficulty}

IMPORTANT: The scenario context above should drive your technique selection.
Use techniques that this specific threat actor is KNOWN to use in this
type of environment. Do NOT use generic techniques.

OUTPUT JSON SCHEMA:
{{
  "scenario_id": "string",
  "environment_type": "{environment}",
  "difficulty": "{difficulty}",
  "attack_type": "{attack_type}",
  "threat_actor": "{threat_actor}",
  "target_industry": "{industry}",
  "ttp_focus": "{ttp_focus}",
  "realism_score": 0.0,
  "narrative": "string (2-3 sentences describing the attack campaign context)",
  "attack_stages": [
    {{
      "stage_name": "Reconnaissance",
      "description": "string",
      "techniques": [
        {{"technique_id": "T1595", "technique_name": "Active Scanning"}}
      ]
    }}
  ],
  "mitre_attack_mapping": ["T1595", "T1566", "T1078"],
  "attack_graph": {{
    "nodes": ["Reconnaissance", "Initial Access"],
    "edges": [["Reconnaissance", "Initial Access"]]
  }}
}}

STRICT RULES:
- Output ONLY JSON, no extra text
- Every technique_id MUST be a real MITRE ATT&CK ID (T#### or T####.###)
- attack_stages must have at least 4 stages
- Techniques must be specific to the threat actor context above
- Use sub-techniques (e.g. T1566.001) where appropriate for precision
"""


# ─────────────────────────────────────────────
# VALIDATION
# ─────────────────────────────────────────────
import re
VALID_TID_RE = re.compile(r'^T\d{4}(\.\d{3})?$')

def is_valid_tid(tid):
    return bool(VALID_TID_RE.match(str(tid).strip()))

def validate_scenario(s):
    issues = []
    if not s.get("attack_stages"):
        issues.append("Empty attack_stages")
    bad = [t.get("technique_id","") for st in s.get("attack_stages",[])
           for t in st.get("techniques",[])
           if t.get("technique_id") and not is_valid_tid(t["technique_id"])]
    if bad:
        issues.append(f"Invalid TIDs: {bad}")
    return len(issues) == 0, issues


# ─────────────────────────────────────────────
# GENERATION
# ─────────────────────────────────────────────
def generate_diverse_scenario(industry, difficulty, attack_type,
                               threat_actor, ttp_focus,
                               campaign_objective, opsec_level,
                               max_retries=2):
    prompt = build_diverse_prompt(industry, difficulty, attack_type,
                                   threat_actor, ttp_focus,
                                   campaign_objective, opsec_level)
    for attempt in range(max_retries + 1):
        try:
            t0 = time.time()
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system",
                     "content": "You are a strict cybersecurity dataset generator. "
                                "Return only valid JSON conforming exactly to the schema."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.8,   # slightly higher for diversity
                response_format={"type": "json_object"},
            )
            elapsed = time.time() - t0
            content = response.choices[0].message.content
            scenario = json.loads(content)
            if isinstance(scenario, str):
                scenario = json.loads(scenario)

            valid, issues = validate_scenario(scenario)
            if valid:
                scenario["generated_at"] = datetime.now().isoformat()
                scenario["generation_mode"] = "diverse"
                scenario["prompt_diversity"] = {
                    "threat_actor": threat_actor,
                    "target_industry": industry,
                    "ttp_focus": ttp_focus,
                    "campaign_objective": campaign_objective,
                    "opsec_level": opsec_level,
                }
                tok_in  = response.usage.prompt_tokens
                tok_out = response.usage.completion_tokens
                return scenario, elapsed, tok_in, tok_out, None
            elif attempt < max_retries:
                # Re-query with correction
                hint = "Issues: " + "; ".join(issues) + ". Fix and return corrected JSON only."
                prompt = prompt + f"\n\nCORRECTION: {hint}"
        except Exception as e:
            if attempt == max_retries:
                return None, 0, 0, 0, str(e)

    return None, 0, 0, 0, f"Failed after {max_retries+1} attempts: {issues}"


# ─────────────────────────────────────────────
# BALANCED DIVERSE PLAN
# ─────────────────────────────────────────────
def build_diverse_plan(n, seed=42):
    """
    Build a balanced diverse generation plan that maximises parameter coverage.
    Every combination is sampled roughly equally.
    """
    random.seed(seed)
    plan = []

    # Create a pool of all combinations
    pool = []
    for industry in INDUSTRY_VERTICALS:
        for difficulty in DIFFICULTIES:
            for attack_type in ATTACK_TYPES:
                for threat_actor in THREAT_ACTORS[:8]:  # top 8 most distinct
                    pool.append({
                        "industry": industry,
                        "difficulty": difficulty,
                        "attack_type": attack_type,
                        "threat_actor": threat_actor,
                        "ttp_focus": random.choice(TTP_FOCUS_AREAS),
                        "campaign_objective": random.choice(CAMPAIGN_OBJECTIVES),
                        "opsec_level": random.choice(OPSEC_LEVELS),
                    })

    # Shuffle and take n, re-sampling if needed
    random.shuffle(pool)
    while len(plan) < n:
        random.shuffle(pool)
        plan.extend(pool)
    return plan[:n]


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Generate diverse scenarios to break technique-vocabulary saturation.\n\n"
            "Target: 510 diverse + 490 existing = 1,000 total base scenarios\n"
            "Projected ATT&CK coverage: ~64%% (129/201 techniques)\n"
            "Cost: ~$0.17 additional  |  Time: ~60 minutes\n\n"
            "After completion, merge and re-run experiments:\n"
            "  cat dataset/dataset.jsonl dataset/diverse/diverse_scenarios.jsonl \\\n"
            "    > dataset/full_dataset.jsonl\n"
            "  python journal_experiments.py"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--n", type=int, default=510,
                        help="Number of diverse scenarios to generate (default 510)")
    parser.add_argument("--out", type=str, default="dataset/diverse",
                        help="Output directory")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    out_path = os.path.join(args.out, "diverse_scenarios.jsonl")
    log_path = os.path.join(args.out, "diverse_generation_log.json")

    plan = build_diverse_plan(args.n, seed=args.seed)

    print(f"\nAdverSim Diverse Generator")
    print(f"Generating {args.n} diversity-aware scenarios")
    print(f"Target: break saturation → ~64%% ATT&CK coverage")
    print(f"Seed: {args.seed}  |  Output: {out_path}\n")

    accepted = rejected = 0
    total_tokens = 0
    total_cost   = 0.0
    techniques_seen = set()

    log_entries = []

    with open(out_path, "w", encoding="utf-8") as fout:
        for i, params in enumerate(plan):
            industry    = params["industry"]
            difficulty  = params["difficulty"]
            attack_type = params["attack_type"]
            actor       = params["threat_actor"][:30]

            print(f"  [{i+1:3d}/{args.n}] {attack_type:15} | {industry[:22]:22} | {actor[:28]:28} ...",
                  end=" ", flush=True)

            sc, elapsed, tok_in, tok_out, err = generate_diverse_scenario(
                industry=params["industry"],
                difficulty=params["difficulty"],
                attack_type=params["attack_type"],
                threat_actor=params["threat_actor"],
                ttp_focus=params["ttp_focus"],
                campaign_objective=params["campaign_objective"],
                opsec_level=params["opsec_level"],
            )

            if sc:
                fout.write(json.dumps(sc) + "\n")
                accepted += 1
                tok = tok_in + tok_out
                total_tokens += tok
                cost = (tok_in / 1000 * 0.00015 + tok_out / 1000 * 0.00060)
                total_cost += cost

                # Track new techniques
                new_techs = 0
                for stage in sc.get("attack_stages", []):
                    for t in stage.get("techniques", []):
                        tid = t.get("technique_id","")
                        if tid and tid not in techniques_seen:
                            techniques_seen.add(tid)
                            new_techs += 1

                print(f"OK  ({elapsed:.1f}s, {tok}tok, +{new_techs}new_tech)")
                log_entries.append({"i": i+1, "status": "ok", "elapsed": elapsed,
                                    "tokens": tok, "new_techniques": new_techs,
                                    **params})
            else:
                rejected += 1
                print(f"FAIL  ({err})")
                log_entries.append({"i": i+1, "status": "failed", "error": err, **params})

    # Summary
    COST_PER_1K_INPUT  = 0.00015
    COST_PER_1K_OUTPUT = 0.00060

    print(f"\n{'='*65}")
    print(f"  DIVERSE GENERATION COMPLETE")
    print(f"{'='*65}")
    print(f"  Accepted            : {accepted}/{args.n}")
    print(f"  Rejected            : {rejected}")
    print(f"  New unique techniques: {len(techniques_seen)}")
    print(f"  Projected total (490 existing + {accepted} diverse):")
    existing = 83  # from original corpus
    combined = min(201, existing + len(techniques_seen))
    print(f"    Combined coverage  : ~{combined} techniques ({combined/201:.1%})")
    print(f"  Total tokens        : {total_tokens:,}")
    print(f"  Total cost          : ${total_cost:.4f} USD")
    print(f"  Cost per scenario   : ${total_cost/max(accepted,1):.6f} USD")
    print(f"\n  Scenarios saved → {out_path}")
    print(f"\n  NEXT STEPS:")
    print(f"  1. Merge datasets:")
    print(f"     cat dataset/dataset.jsonl {out_path} > dataset/full_dataset.jsonl")
    print(f"  2. Re-run all experiments:")
    print(f"     python journal_experiments.py")
    print(f"  3. Update DATASET_PATH in journal_experiments.py to 'dataset/full_dataset.jsonl'")
    print(f"{'='*65}\n")

    # Save log
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump({"summary": {
            "accepted": accepted, "rejected": rejected,
            "new_techniques_introduced": len(techniques_seen),
            "combined_techniques_projected": combined,
            "projected_coverage": round(combined/201, 4),
            "total_cost_usd": round(total_cost, 6),
        }, "entries": log_entries}, f, indent=2)
    print(f"  Log saved → {log_path}")
