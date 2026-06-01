"""
instrumented_generator.py
=========================
Drop-in replacement for core/llm_generator.py that tracks:

  - Generation time per scenario (seconds)
  - Token usage (prompt + completion tokens)
  - First-attempt MITRE ID validation failure rate
  - Re-query success / failure rate
  - Scenarios fully rejected (persistent failures)
  - Estimated API cost (USD)

Usage:
  from instrumented_generator import InstrumentedGenerator

  gen = InstrumentedGenerator()
  scenario, meta = gen.generate("Enterprise Network", "Hard", "APT")
  gen.save_report("data/journal_results/hallucination_report.json")

Or run standalone to generate a 20-scenario sample:
  python instrumented_generator.py --n 20 --out data/journal_results/
"""

import json
import os
import re
import time
import argparse
from datetime import datetime
from statistics import mean, stdev

from openai import OpenAI
from core.config import OPENAI_API_KEY

# ─────────────────────────────────────────────
# VALID MITRE ATT&CK TECHNIQUE ID PATTERN
# ─────────────────────────────────────────────
VALID_TID_RE = re.compile(r'^T\d{4}(\.\d{3})?$')

# GPT-4o-mini pricing (USD per 1K tokens) — update if changed
COST_PER_1K_INPUT  = 0.00015
COST_PER_1K_OUTPUT = 0.00060

# ─────────────────────────────────────────────
# VALIDATION HELPERS
# ─────────────────────────────────────────────
def is_valid_tid(tid):
    return bool(VALID_TID_RE.match(str(tid).strip()))


def validate_scenario(scenario):
    """
    Returns (is_valid, list_of_issues).
    Checks: required fields, stages not empty, all technique IDs valid.
    """
    issues = []
    required = ["scenario_id", "environment_type", "difficulty",
                "attack_type", "attack_stages", "mitre_attack_mapping",
                "attack_graph"]
    for field in required:
        if field not in scenario:
            issues.append(f"Missing field: {field}")

    stages = scenario.get("attack_stages", [])
    if not stages:
        issues.append("attack_stages is empty")

    # Collect all technique IDs
    bad_tids = []
    for stage in stages:
        for t in stage.get("techniques", []):
            tid = t.get("technique_id", "")
            if tid and not is_valid_tid(tid):
                bad_tids.append(tid)

    # Also check top-level mapping
    for tid in scenario.get("mitre_attack_mapping", []):
        if tid and not is_valid_tid(str(tid)):
            bad_tids.append(str(tid))

    if bad_tids:
        issues.append(f"Invalid technique IDs: {bad_tids}")

    return len(issues) == 0, issues


# ─────────────────────────────────────────────
# PROMPT BUILDER
# ─────────────────────────────────────────────
def build_prompt(environment, difficulty, attack_type,
                 correction_hint=None):
    base = f"""
You are a cybersecurity attack simulation generator for research and cyber range systems.

Return ONLY valid JSON. No markdown. No explanation.

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
- Output ONLY JSON
- Every technique_id MUST be a real MITRE ATT&CK ID (format: T####  or T####.###)
- Examples of VALID IDs: T1566, T1078, T1041, T1059, T1003, T1486.001
- Examples of INVALID IDs: T999, TXXXX, "phishing", "credential_theft"
- Every stage must include techniques array
- attack_stages must have at least 4 stages
"""
    if correction_hint:
        base += f"\n\nCORRECTION REQUIRED:\n{correction_hint}\n"
    return base


# ─────────────────────────────────────────────
# INSTRUMENTED GENERATOR CLASS
# ─────────────────────────────────────────────
class InstrumentedGenerator:

    def __init__(self, model="gpt-4o-mini", max_requery=2):
        self.client = OpenAI(api_key=OPENAI_API_KEY)
        self.model = model
        self.max_requery = max_requery

        # Accumulated statistics
        self.stats = {
            "total_scenarios_attempted": 0,
            "total_scenarios_accepted": 0,
            "total_scenarios_rejected": 0,
            "first_attempt_pass": 0,
            "first_attempt_fail": 0,
            "requery_success": 0,
            "requery_fail": 0,
            "total_invalid_tids": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "generation_times_sec": [],
            "per_scenario": [],
        }

    def _call_llm(self, prompt):
        """Make one LLM call. Returns (content_str, input_tokens, output_tokens)."""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system",
                 "content": "You are a strict cybersecurity dataset generator "
                             "producing structured MITRE ATT&CK aligned JSON."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.7,
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content
        in_tok  = response.usage.prompt_tokens
        out_tok = response.usage.completion_tokens
        return content, in_tok, out_tok

    def generate(self, environment, difficulty, attack_type):
        """
        Generate one scenario with full instrumentation.
        Returns (scenario_dict | None, metadata_dict).
        """
        self.stats["total_scenarios_attempted"] += 1
        sc_meta = {
            "environment": environment,
            "difficulty": difficulty,
            "attack_type": attack_type,
            "timestamp": datetime.now().isoformat(),
            "first_attempt_valid": None,
            "requery_attempts": 0,
            "requery_success": None,
            "accepted": False,
            "generation_time_sec": None,
            "input_tokens": 0,
            "output_tokens": 0,
            "invalid_tids_found": [],
            "issues": [],
        }

        t_start = time.time()
        total_in_tok = 0
        total_out_tok = 0

        # ── First attempt ──────────────────────────────────────
        try:
            prompt = build_prompt(environment, difficulty, attack_type)
            raw, in_tok, out_tok = self._call_llm(prompt)
            total_in_tok += in_tok
            total_out_tok += out_tok

            scenario = json.loads(raw)
            if isinstance(scenario, str):
                scenario = json.loads(scenario)

            valid, issues = validate_scenario(scenario)
            sc_meta["first_attempt_valid"] = valid
            sc_meta["issues"] = issues

            # Extract bad TIDs for reporting
            bad_tids = [
                t.get("technique_id", "")
                for s in scenario.get("attack_stages", [])
                for t in s.get("techniques", [])
                if t.get("technique_id") and not is_valid_tid(t.get("technique_id"))
            ]
            sc_meta["invalid_tids_found"] = bad_tids
            self.stats["total_invalid_tids"] += len(bad_tids)

        except Exception as e:
            valid = False
            issues = [f"Parse error: {str(e)}"]
            sc_meta["issues"] = issues
            sc_meta["first_attempt_valid"] = False
            scenario = None

        if valid:
            self.stats["first_attempt_pass"] += 1
        else:
            self.stats["first_attempt_fail"] += 1

        # ── Re-query loop ──────────────────────────────────────
        attempt = 0
        while not valid and attempt < self.max_requery:
            attempt += 1
            sc_meta["requery_attempts"] += 1

            hint = "Issues found:\n" + "\n".join(issues) + \
                   "\n\nFix ALL issues. Return ONLY corrected JSON."

            try:
                retry_prompt = build_prompt(environment, difficulty,
                                            attack_type, correction_hint=hint)
                raw, in_tok, out_tok = self._call_llm(retry_prompt)
                total_in_tok  += in_tok
                total_out_tok += out_tok

                scenario = json.loads(raw)
                if isinstance(scenario, str):
                    scenario = json.loads(scenario)

                valid, issues = validate_scenario(scenario)

            except Exception as e:
                valid = False
                issues = [f"Re-query parse error: {str(e)}"]

        # ── Final decision ─────────────────────────────────────
        elapsed = time.time() - t_start
        sc_meta["generation_time_sec"] = round(elapsed, 3)
        sc_meta["input_tokens"]  = total_in_tok
        sc_meta["output_tokens"] = total_out_tok

        self.stats["total_input_tokens"]  += total_in_tok
        self.stats["total_output_tokens"] += total_out_tok
        self.stats["generation_times_sec"].append(elapsed)

        if valid:
            sc_meta["accepted"] = True
            sc_meta["requery_success"] = (sc_meta["requery_attempts"] > 0)
            self.stats["total_scenarios_accepted"] += 1
            if sc_meta["requery_attempts"] > 0:
                self.stats["requery_success"] += 1
        else:
            sc_meta["accepted"] = False
            sc_meta["requery_success"] = False
            self.stats["total_scenarios_rejected"] += 1
            if sc_meta["requery_attempts"] > 0:
                self.stats["requery_fail"] += 1
            scenario = None

        self.stats["per_scenario"].append(sc_meta)
        return scenario, sc_meta

    def get_report(self):
        """Return a clean summary report dict."""
        s = self.stats
        n_attempted = max(s["total_scenarios_attempted"], 1)
        times = s["generation_times_sec"]
        total_tokens = s["total_input_tokens"] + s["total_output_tokens"]
        cost = (s["total_input_tokens"]  / 1000 * COST_PER_1K_INPUT +
                s["total_output_tokens"] / 1000 * COST_PER_1K_OUTPUT)

        return {
            "timestamp": datetime.now().isoformat(),
            "model": self.model,
            "total_attempted": s["total_scenarios_attempted"],
            "total_accepted": s["total_scenarios_accepted"],
            "total_rejected": s["total_scenarios_rejected"],
            "first_attempt_pass_rate": round(
                s["first_attempt_pass"] / n_attempted, 4),
            "first_attempt_fail_rate": round(
                s["first_attempt_fail"] / n_attempted, 4),
            "requery_success_rate": round(
                s["requery_success"] / max(s["first_attempt_fail"], 1), 4),
            "requery_fail_rate": round(
                s["requery_fail"] / max(s["first_attempt_fail"], 1), 4),
            "total_invalid_tids_found": s["total_invalid_tids"],
            "invalid_tids_per_scenario": round(
                s["total_invalid_tids"] / n_attempted, 3),
            "avg_generation_time_sec": round(mean(times), 3) if times else 0,
            "std_generation_time_sec": round(stdev(times), 3) if len(times) > 1 else 0,
            "total_input_tokens": s["total_input_tokens"],
            "total_output_tokens": s["total_output_tokens"],
            "total_tokens": total_tokens,
            "estimated_cost_usd": round(cost, 6),
            "cost_per_scenario_usd": round(cost / n_attempted, 6),
            "tokens_per_scenario": round(total_tokens / n_attempted, 1),
        }

    def save_report(self, path):
        report = self.get_report()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[SAVED] Hallucination report → {path}")
        return report

    def print_summary(self):
        r = self.get_report()
        print("\n" + "="*55)
        print("  LLM GENERATION INSTRUMENTATION REPORT")
        print("="*55)
        print(f"  Scenarios attempted   : {r['total_attempted']}")
        print(f"  Accepted              : {r['total_accepted']}")
        print(f"  Rejected              : {r['total_rejected']}")
        print(f"  First-attempt pass    : {r['first_attempt_pass_rate']*100:.1f}%")
        print(f"  Re-query success rate : {r['requery_success_rate']*100:.1f}%")
        print(f"  Invalid TIDs found    : {r['total_invalid_tids_found']}")
        print(f"  Avg gen. time         : {r['avg_generation_time_sec']}s")
        print(f"  Total tokens          : {r['total_tokens']:,}")
        print(f"  Estimated cost        : ${r['estimated_cost_usd']:.4f} USD")
        print(f"  Cost per scenario     : ${r['cost_per_scenario_usd']:.5f} USD")
        print("="*55)


# ─────────────────────────────────────────────
# STANDALONE: generate N scenarios & report
# ─────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--n",   type=int, default=20,
                        help="Number of scenarios to generate (default 20)")
    parser.add_argument("--out", type=str,
                        default="data/journal_results",
                        help="Output directory")
    args = parser.parse_args()

    ATTACK_TYPES  = ["Phishing", "Ransomware", "Insider Threat", "APT"]
    ENVIRONMENTS  = ["Enterprise Network", "Cloud Infrastructure",
                     "Healthcare", "ICS"]
    DIFFICULTIES  = ["Easy", "Medium", "Hard"]

    import random as _random
    gen = InstrumentedGenerator()

    out_scenarios = os.path.join(args.out, "hallucination_scenarios.jsonl")
    os.makedirs(args.out, exist_ok=True)

    print(f"\nGenerating {args.n} instrumented scenarios...")
    with open(out_scenarios, "w", encoding="utf-8") as fout:
        for i in range(args.n):
            at  = _random.choice(ATTACK_TYPES)
            env = _random.choice(ENVIRONMENTS)
            dif = _random.choice(DIFFICULTIES)

            print(f"  [{i+1}/{args.n}] {at} / {env} / {dif} ...", end=" ")
            sc, meta = gen.generate(env, dif, at)

            if sc:
                fout.write(json.dumps(sc) + "\n")
                print(f"OK  ({meta['generation_time_sec']}s,"
                      f" tokens={meta['input_tokens']+meta['output_tokens']})")
            else:
                print(f"REJECTED  issues={meta['issues']}")

    gen.print_summary()
    gen.save_report(os.path.join(args.out, "hallucination_report.json"))
    print(f"\nScenarios saved → {out_scenarios}")
