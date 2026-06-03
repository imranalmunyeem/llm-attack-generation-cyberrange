"""
core/mitre_validation.py

Production scenario validation against the real MITRE ATT&CK v14 matrix,
for use inside the generation re-query loop. This replaces the old
regex-only `is_valid_tid` / `validate_scenario` in instrumented_generator.py.

Policy: a scenario passes validation only if every technique_id it contains
is an ACTIVE v14 technique. Deprecated, hallucinated (well-formed but absent),
and malformed IDs all FAIL and trigger a re-query whose prompt carries a
correction hint naming the offending IDs and their suggested active successor.

Wire-in (instrumented_generator.py):

    from core.mitre_validation import load_validator, validate_scenario, correction_hint
    VALIDATOR = load_validator("data/official-v14.1.json")
    ...
    ok, issues = validate_scenario(scenario, VALIDATOR)
    ...
    # in the re-query loop, when not ok:
    hint = correction_hint(scenario, VALIDATOR)
    prompt = build_prompt(environment, difficulty, attack_type, correction_hint=hint)
"""

from mitre_attack_validator import MitreAttackValidator


def load_validator(stix_path="data/official-v14.1.json"):
    return MitreAttackValidator(stix_path)


def _scenario_tids(scenario):
    """Yield (location, technique_id) for every ID in the scenario."""
    for si, stage in enumerate(scenario.get("attack_stages", [])):
        for t in stage.get("techniques", []):
            tid = (t.get("technique_id") or "").strip()
            if tid:
                yield (f"stage[{si}]", tid)
    for tid in scenario.get("mitre_attack_mapping", []) or []:
        tid = str(tid).strip()
        if tid:
            yield ("mitre_attack_mapping", tid)


def validate_scenario(scenario, validator):
    """Return (ok, issues). ok requires all technique_ids to be ACTIVE v14."""
    issues = []
    for field in ["scenario_id", "environment_type", "difficulty",
                  "attack_type", "attack_stages", "attack_graph"]:
        if field not in scenario:
            issues.append(f"Missing field: {field}")
    if not scenario.get("attack_stages"):
        issues.append("attack_stages is empty")

    bad = []
    for loc, tid in _scenario_tids(scenario):
        cls = validator.classify(tid)
        if cls != "ACTIVE":
            bad.append((loc, tid, cls, validator.suggest(tid)))
    if bad:
        issues.append("Non-active ATT&CK technique IDs: " +
                      ", ".join(f"{tid}({cls})" for _, tid, cls, _ in bad))
    return (len(issues) == 0), issues


def correction_hint(scenario, validator):
    """Build a re-query instruction listing offending IDs + active successors."""
    lines = []
    for _, tid in _scenario_tids(scenario):
        cls = validator.classify(tid)
        if cls == "ACTIVE":
            continue
        sug = validator.suggest(tid)
        if sug:
            lines.append(f"- '{tid}' is {cls.lower()} in ATT&CK v14; use '{sug}' "
                         f"({validator.technique_meta(sug)['name']}) instead.")
        else:
            lines.append(f"- '{tid}' is {cls.lower()} / not a valid v14 enterprise "
                         f"technique; replace it with a valid active v14 technique "
                         f"appropriate to this stage.")
    if not lines:
        return ""
    return ("CORRECTION REQUIRED — the following technique IDs are not valid "
            "active MITRE ATT&CK v14 enterprise techniques. Regenerate the JSON "
            "using only valid active v14 technique IDs:\n" + "\n".join(lines))
