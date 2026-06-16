"""
Generate Sigma-compatible detection rule skeletons from AdverSim scenarios.

Sigma format: https://sigmahq.io/
Each rule is YAML-formatted and maps directly to SIEM query templates.

Example:
  python sigma_rule_generator.py \
    --dataset dataset/full_dataset.jsonl \
    --out data/generated/sigma_rules/ \
    --n 10

Output:
  data/generated/sigma_rules/
    sigma_summary.json
    APT_Enterprise_rule_001.yml
    Ransomware_ICS_rule_002.yml
    ... (n rules)
"""

import json
import os
import re
import yaml
import random
import argparse
from collections import Counter, defaultdict
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VALID_TID = re.compile(r'^T\d{4}(\.\d{3})?$')

# ─────────────────────────────────────────────
# ATT&CK technique → log source / field mapping
# Subset of the full ATT&CK data sources
# ─────────────────────────────────────────────
TECH_TO_LOGSOURCE = {
    # Initial Access
    "T1566":     {"category": "email", "product": "any",    "service": "email_gateway"},
    "T1566.001": {"category": "email", "product": "any",    "service": "email_gateway"},
    "T1566.002": {"category": "email", "product": "any",    "service": "email_gateway"},
    "T1190":     {"category": "webserver", "product": "any","service": "web_application"},
    "T1078":     {"category": "authentication","product": "any","service": "auth"},
    # Execution
    "T1059":     {"category": "process_creation","product": "windows","service": "sysmon"},
    "T1059.001": {"category": "process_creation","product": "windows","service": "powershell"},
    "T1059.003": {"category": "process_creation","product": "windows","service": "cmd"},
    "T1203":     {"category": "process_creation","product": "windows","service": "sysmon"},
    "T1053":     {"category": "process_creation","product": "windows","service": "sysmon"},
    "T1053.005": {"category": "process_creation","product": "windows","service": "sysmon"},
    # Persistence
    "T1547":     {"category": "registry_event", "product": "windows","service": "sysmon"},
    "T1547.001": {"category": "registry_event", "product": "windows","service": "sysmon"},
    "T1136":     {"category": "process_creation","product": "windows","service": "security"},
    "T1098":     {"category": "process_creation","product": "windows","service": "security"},
    # Defense Evasion
    "T1070":     {"category": "process_creation","product": "windows","service": "sysmon"},
    "T1036":     {"category": "process_creation","product": "windows","service": "sysmon"},
    "T1027":     {"category": "file_event",      "product": "windows","service": "sysmon"},
    # Credential Access
    "T1110":     {"category": "authentication",  "product": "any",    "service": "auth"},
    "T1003":     {"category": "process_creation","product": "windows","service": "sysmon"},
    "T1003.001": {"category": "process_access",  "product": "windows","service": "sysmon"},
    # Discovery
    "T1082":     {"category": "process_creation","product": "windows","service": "sysmon"},
    "T1087":     {"category": "process_creation","product": "windows","service": "sysmon"},
    "T1046":     {"category": "network_connection","product":"any",   "service": "firewall"},
    # Lateral Movement
    "T1021":     {"category": "network_connection","product":"windows","service": "security"},
    "T1021.001": {"category": "network_connection","product":"windows","service": "security"},
    # Collection
    "T1560":     {"category": "file_event",      "product": "windows","service": "sysmon"},
    "T1114":     {"category": "email",            "product": "any",   "service": "email_gateway"},
    # C&C
    "T1071":     {"category": "network_connection","product":"any",   "service": "firewall"},
    "T1071.001": {"category": "network_connection","product":"any",   "service": "proxy"},
    "T1095":     {"category": "network_connection","product":"any",   "service": "firewall"},
    # Exfiltration
    "T1041":     {"category": "network_connection","product":"any",   "service": "firewall"},
    "T1048":     {"category": "network_connection","product":"any",   "service": "firewall"},
    # Impact
    "T1486":     {"category": "file_event",      "product": "windows","service": "sysmon"},
    "T1485":     {"category": "file_event",      "product": "windows","service": "sysmon"},
    "T1489":     {"category": "process_creation","product": "windows","service": "sysmon"},
    "T1490":     {"category": "process_creation","product": "windows","service": "sysmon"},
}

SEVERITY_MAP = {
    "Easy": "low",
    "Medium": "medium",
    "Hard": "high",
}

STATUS_MAP = {
    "Phishing": "experimental",
    "Ransomware": "test",
    "Insider Threat": "experimental",
    "APT": "test",
}


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def get_logsource(technique_id):
    base = technique_id.split(".")[0]
    return TECH_TO_LOGSOURCE.get(
        technique_id,
        TECH_TO_LOGSOURCE.get(base,
            {"category": "process_creation", "product": "any", "service": "security"}
        )
    )


def build_detection_keywords(stage):
    """Extract keywords from stage indicators for detection field."""
    keywords = []
    desc = stage.get("description", "")
    techs = stage.get("techniques", [])

    # Add technique names as keywords
    for t in techs:
        name = t.get("technique_name", "")
        if name:
            # Convert to searchable term
            keywords.append(name.lower().replace(" ", "_"))

    # Extract key terms from description
    important_terms = [
        "powershell", "cmd.exe", "wscript", "cscript", "rundll32",
        "regsvr32", "mshta", "certutil", "bitsadmin", "schtasks",
        "net user", "net group", "whoami", "ipconfig", "nmap",
        "mimikatz", "procdump", "ntds.dit", "lsass", "vssadmin",
        "wevtutil", "bcdedit", "wbadmin", "encode", "encoded",
        "base64", "invoke-", "bypass", "hidden", "reflection",
        "ransomware", "encrypt", ".locked", "readme.txt",
    ]
    desc_lower = desc.lower()
    for term in important_terms:
        if term in desc_lower:
            keywords.append(term)

    return list(set(keywords)) if keywords else ["*"]


def scenario_to_sigma(scenario, rule_id):
    """Convert a scenario to a Sigma rule YAML string."""
    attack_type   = scenario.get("attack_type", "Unknown")
    environment   = scenario.get("environment_type", "Unknown")
    difficulty    = scenario.get("difficulty", "Medium")
    stages        = scenario.get("attack_stages", [])
    techniques    = [
        t.get("technique_id", "")
        for stage in stages
        for t in stage.get("techniques", [])
        if VALID_TID.match(t.get("technique_id", ""))
    ]
    scenario_id = scenario.get("scenario_id", f"SIM-{rule_id:04d}")

    if not stages:
        return None

    # Use the highest-risk stage (prefer Execution > Initial Access > others)
    priority_stages = [s for s in stages
                       if s.get("stage_name") in
                       ("Execution", "Command and Control",
                        "Credential Access", "Lateral Movement")]
    focus_stage = priority_stages[0] if priority_stages else stages[0]
    focus_tid   = next(
        (t.get("technique_id") for t in focus_stage.get("techniques", [])
         if VALID_TID.match(t.get("technique_id", ""))),
        "T1059"
    )

    logsource = get_logsource(focus_tid)
    keywords  = build_detection_keywords(focus_stage)

    # ATT&CK tags
    attck_tags = [f"attack.{tid.lower().replace('.', '_')}"
                  for tid in techniques[:5]]
    attck_tags.append(f"attack.{attack_type.lower().replace(' ', '_')}")

    rule = {
        "title": (f"AdverSim - {attack_type} Attack Indicator "
                  f"in {environment} (Scenario {scenario_id})"),
        "id":      f"adversim-{rule_id:06d}",
        "status":  STATUS_MAP.get(attack_type, "experimental"),
        "description": (
            f"Detects indicators associated with a simulated {attack_type} "
            f"scenario targeting {environment} environments. "
            f"ATT&CK stage: {focus_stage.get('stage_name', 'Unknown')}. "
            f"Generated by AdverSim "
            f"(https://github.com/imranalmunyeem/llm-attack-generation-cyberrange)."
        ),
        "references": [
            "https://attack.mitre.org/techniques/" + focus_tid,
            "https://github.com/imranalmunyeem/llm-attack-generation-cyberrange",
        ],
        "author":    "AdverSim (auto-generated)",
        "date":      datetime.now().strftime("%Y/%m/%d"),
        "tags":      attck_tags,
        "logsource": logsource,
        "detection": {
            "keywords": keywords,
            "condition": "keywords",
        },
        "falsepositives": ["Legitimate administrator activity"],
        "level": SEVERITY_MAP.get(difficulty, "medium"),
        "metadata": {
            "scenario_id": scenario_id,
            "attack_type": attack_type,
            "environment": environment,
            "difficulty":  difficulty,
            "techniques":  techniques[:5],
        }
    }

    return yaml.dump(rule, default_flow_style=False,
                     allow_unicode=True, sort_keys=False)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main(dataset_path, out_dir, n=20):
    os.makedirs(out_dir, exist_ok=True)

    # Load scenarios
    scenarios = []
    with open(dataset_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, str):
                    obj = json.loads(obj)
                scenarios.append(obj)
            except Exception:
                pass

    print(f"\n[SIGMA] Loaded {len(scenarios)} scenarios")

    # Sample: stratified across attack types
    random.seed(42)
    by_type = defaultdict(list)
    for s in scenarios:
        by_type[s.get("attack_type", "Unknown")].append(s)

    sample = []
    per_type = max(1, n // len(by_type))
    for at, grp in sorted(by_type.items()):
        sample.extend(random.sample(grp, min(per_type, len(grp))))
    sample = sample[:n]

    # Generate rules
    generated = 0
    log_source_counts = Counter()
    technique_coverage = set()

    for i, scenario in enumerate(sample):
        rule_yaml = scenario_to_sigma(scenario, i + 1)
        if not rule_yaml:
            continue

        at   = scenario.get("attack_type", "Unknown").replace(" ", "_")
        env  = scenario.get("environment_type", "Unknown").replace(" ", "_")
        fname = f"{at}_{env}_rule_{i+1:03d}.yml"
        fpath = os.path.join(out_dir, fname)

        with open(fpath, "w", encoding="utf-8") as f:
            f.write(rule_yaml)

        # Track stats
        rule = yaml.safe_load(rule_yaml)
        ls = rule.get("logsource", {})
        log_source_counts[ls.get("category", "unknown")] += 1
        for tid in rule.get("metadata", {}).get("techniques", []):
            technique_coverage.add(tid)
        generated += 1

    # Summary statistics
    summary = {
        "total_scenarios":       len(scenarios),
        "rules_generated":       generated,
        "log_source_categories": dict(log_source_counts.most_common()),
        "techniques_covered":    len(technique_coverage),
        "technique_ids":         sorted(technique_coverage),
    }

    summary_path = os.path.join(out_dir, "sigma_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\n[SIGMA] Generated {generated} rules → {out_dir}/")
    print(f"\n  Log source breakdown:")
    for cat, count in log_source_counts.most_common():
        print(f"    {cat:25}: {count} rules")
    print(f"\n  Unique techniques covered: {len(technique_coverage)}")
    print(f"\n  Summary saved → {summary_path}")
    print()
    print("  Summary:")
    print(f"    scenarios sampled       : {len(sample)}")
    print(f"    rules generated         : {generated}")
    print(f"    ATT&CK techniques       : {len(technique_coverage)}")
    print(f"    log source categories   : {len(log_source_counts)}")

    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="dataset/full_dataset.jsonl")
    parser.add_argument("--out",     default="data/generated/sigma_rules")
    parser.add_argument("--n",       type=int, default=20)
    args = parser.parse_args()
    main(args.dataset, args.out, args.n)
