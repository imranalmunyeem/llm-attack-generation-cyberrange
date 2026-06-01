"""
instrumented_generator.py  —  v2.0  (journal edition)
======================================================
Drop-in replacement for core/llm_generator.py with full telemetry.

Tracks per-call:
  - Generation time (seconds)
  - Token usage (input + output)
  - First-attempt MITRE ID validation failure rate
  - Re-query success / failure rate
  - Invalid technique IDs found
  - Estimated API cost (USD)
  - Per-dimension breakdown (by attack type, environment, difficulty)

Recommended run for IEEE Access journal statistics:
  python instrumented_generator.py --n 240 --out data/journal_results/

n=240 rationale:
  - 48 parameter combinations (4 types × 4 envs × 3 difficulties)
  - 240 / 48 = 5 samples per combination
  - Wilson score 95% CI lower bound = 0.984 (publishable precision)
  - Cost ≈ $0.082 USD, time ≈ 30 minutes

Usage:
  from instrumented_generator import InstrumentedGenerator
  gen = InstrumentedGenerator()
  scenario, meta = gen.generate("Enterprise Network", "Hard", "APT")
  gen.save_report("data/journal_results/hallucination_report.json")
"""

import json
import os
import re
import time
import argparse
import random
from datetime import datetime
from collections import defaultdict
from statistics import mean, stdev

from openai import OpenAI
from core.config import OPENAI_API_KEY

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────
VALID_TID_RE = re.compile(r'^T\d{4}(\.\d{3})?$')

# GPT-4o-mini pricing (USD per 1K tokens) — update if changed
COST_PER_1K_INPUT  = 0.00015
COST_PER_1K_OUTPUT = 0.00060

ATTACK_TYPES  = ["Phishing", "Ransomware", "Insider Threat", "APT"]
ENVIRONMENTS  = ["Enterprise Network", "Cloud Infrastructure",
                 "Healthcare", "ICS"]
DIFFICULTIES  = ["Easy", "Medium", "Hard"]


# ─────────────────────────────────────────────
# VALIDATION
# ─────────────────────────────────────────────
def is_valid_tid(tid):
    return bool(VALID_TID_RE.match(str(tid).strip()))


def validate_scenario(scenario):
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

    bad_tids = []
    for stage in stages:
        for t in stage.get("techniques", []):
            tid = t.get("technique_id", "")
            if tid and not is_valid_tid(tid):
                bad_tids.append(tid)
    for tid in scenario.get("mitre_attack_mapping", []):
        if tid and not is_valid_tid(str(tid)):
            bad_tids.append(str(tid))

    if bad_tids:
        issues.append(f"Invalid technique IDs: {bad_tids}")

    return len(issues) == 0, issues


# ─────────────────────────────────────────────
# PROMPT
# ─────────────────────────────────────────────
def build_prompt(environment, difficulty, attack_type, correction_hint=None):
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
- Every technique_id MUST be a real MITRE ATT&CK ID (format: T#### or T####.###)
- Examples of VALID IDs: T1566, T1078, T1041, T1059, T1003, T1486.001
- attack_stages must have at least 4 stages
"""
    if correction_hint:
        base += f"\n\nCORRECTION REQUIRED:\n{correction_hint}\n"
    return base


# ─────────────────────────────────────────────
# GENERATOR
# ─────────────────────────────────────────────
class InstrumentedGenerator:

    def __init__(self, model="gpt-4o-mini", max_requery=2):
        self.client = OpenAI(api_key=OPENAI_API_KEY)
        self.model = model
        self.max_requery = max_requery

        self.stats = {
            "total_attempted": 0,
            "total_accepted": 0,
            "total_rejected": 0,
            "first_attempt_pass": 0,
            "first_attempt_fail": 0,
            "requery_success": 0,
            "requery_fail": 0,
            "total_invalid_tids": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "generation_times_sec": [],
            # Per-dimension tracking
            "by_attack_type":  defaultdict(lambda: {"attempted":0,"accepted":0,"first_pass":0,"tokens":0,"time":0.0}),
            "by_environment":  defaultdict(lambda: {"attempted":0,"accepted":0,"first_pass":0,"tokens":0,"time":0.0}),
            "by_difficulty":   defaultdict(lambda: {"attempted":0,"accepted":0,"first_pass":0,"tokens":0,"time":0.0}),
            "per_scenario": [],
        }

    def _call_llm(self, prompt):
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
        self.stats["total_attempted"] += 1
        sc_meta = {
            "environment": environment, "difficulty": difficulty,
            "attack_type": attack_type,
            "timestamp": datetime.now().isoformat(),
            "first_attempt_valid": None,
            "requery_attempts": 0, "requery_success": None,
            "accepted": False,
            "generation_time_sec": None,
            "input_tokens": 0, "output_tokens": 0,
            "invalid_tids_found": [], "issues": [],
        }

        t_start = time.time()
        total_in_tok = total_out_tok = 0

        # ── First attempt ─────────────────────────────
        try:
            prompt = build_prompt(environment, difficulty, attack_type)
            raw, in_tok, out_tok = self._call_llm(prompt)
            total_in_tok += in_tok; total_out_tok += out_tok

            scenario = json.loads(raw)
            if isinstance(scenario, str):
                scenario = json.loads(scenario)

            valid, issues = validate_scenario(scenario)
            sc_meta["first_attempt_valid"] = valid
            sc_meta["issues"] = issues

            bad_tids = [
                t.get("technique_id","")
                for s in scenario.get("attack_stages",[])
                for t in s.get("techniques",[])
                if t.get("technique_id") and not is_valid_tid(t.get("technique_id"))
            ]
            sc_meta["invalid_tids_found"] = bad_tids
            self.stats["total_invalid_tids"] += len(bad_tids)

        except Exception as e:
            valid, issues = False, [f"Parse error: {e}"]
            sc_meta.update({"issues": issues, "first_attempt_valid": False})
            scenario = None

        if valid: self.stats["first_attempt_pass"] += 1
        else:     self.stats["first_attempt_fail"] += 1

        # ── Re-query loop ─────────────────────────────
        attempt = 0
        while not valid and attempt < self.max_requery:
            attempt += 1
            sc_meta["requery_attempts"] += 1
            hint = "Issues found:\n" + "\n".join(issues) + \
                   "\n\nFix ALL issues. Return ONLY corrected JSON."
            try:
                raw, in_tok, out_tok = self._call_llm(
                    build_prompt(environment, difficulty, attack_type,
                                 correction_hint=hint))
                total_in_tok += in_tok; total_out_tok += out_tok
                scenario = json.loads(raw)
                if isinstance(scenario, str): scenario = json.loads(scenario)
                valid, issues = validate_scenario(scenario)
            except Exception as e:
                valid, issues = False, [f"Re-query error: {e}"]

        # ── Final accounting ──────────────────────────
        elapsed = time.time() - t_start
        sc_meta.update({
            "generation_time_sec": round(elapsed, 3),
            "input_tokens": total_in_tok,
            "output_tokens": total_out_tok,
        })
        self.stats["total_input_tokens"]  += total_in_tok
        self.stats["total_output_tokens"] += total_out_tok
        self.stats["generation_times_sec"].append(elapsed)

        if valid:
            sc_meta.update({"accepted": True,
                             "requery_success": sc_meta["requery_attempts"] > 0})
            self.stats["total_accepted"] += 1
            if sc_meta["requery_attempts"] > 0:
                self.stats["requery_success"] += 1
        else:
            sc_meta.update({"accepted": False, "requery_success": False})
            self.stats["total_rejected"] += 1
            if sc_meta["requery_attempts"] > 0:
                self.stats["requery_fail"] += 1
            scenario = None

        # ── Per-dimension update ──────────────────────
        for key, dim in [("by_attack_type", attack_type),
                          ("by_environment", environment),
                          ("by_difficulty", difficulty)]:
            d = self.stats[key][dim]
            d["attempted"] += 1
            d["tokens"] += total_in_tok + total_out_tok
            d["time"]   += elapsed
            if valid:
                d["accepted"] += 1
            if sc_meta["first_attempt_valid"]:
                d["first_pass"] += 1

        self.stats["per_scenario"].append(sc_meta)
        return scenario, sc_meta

    # ─────────────────────────────────────────
    def get_report(self):
        s = self.stats
        n = max(s["total_attempted"], 1)
        times = s["generation_times_sec"]
        total_tokens = s["total_input_tokens"] + s["total_output_tokens"]
        cost = (s["total_input_tokens"]  / 1000 * COST_PER_1K_INPUT +
                s["total_output_tokens"] / 1000 * COST_PER_1K_OUTPUT)

        # Wilson score 95% CI for pass rate
        p_pass = s["first_attempt_pass"] / n
        z = 1.96
        import math
        wilson_lo = (n*p_pass + z**2/2 - z*math.sqrt(n*p_pass*(1-p_pass) + z**2/4)) / (n + z**2)
        wilson_hi = (n*p_pass + z**2/2 + z*math.sqrt(n*p_pass*(1-p_pass) + z**2/4)) / (n + z**2)

        # Per-dimension summaries
        def dim_summary(dim_dict):
            out = {}
            for k, v in dim_dict.items():
                a = max(v["attempted"], 1)
                out[k] = {
                    "attempted": v["attempted"],
                    "accepted": v["accepted"],
                    "first_pass_rate": round(v["first_pass"] / a, 4),
                    "avg_tokens": round(v["tokens"] / a, 1),
                    "avg_time_sec": round(v["time"] / a, 3),
                }
            return out

        return {
            "timestamp": datetime.now().isoformat(),
            "model": self.model,
            "n_attempted": n,
            "n_accepted": s["total_accepted"],
            "n_rejected": s["total_rejected"],
            "first_attempt_pass_rate": round(p_pass, 6),
            "first_attempt_pass_pct":  f"{p_pass*100:.1f}%",
            "wilson_95ci": [round(wilson_lo, 4), round(wilson_hi, 4)],
            "first_attempt_fail_rate": round(s["first_attempt_fail"] / n, 6),
            "requery_success_rate":    round(s["requery_success"] / max(s["first_attempt_fail"],1), 4),
            "total_invalid_tids":      s["total_invalid_tids"],
            "invalid_tids_per_scenario": round(s["total_invalid_tids"] / n, 4),
            "avg_generation_time_sec": round(mean(times), 3) if times else 0,
            "std_generation_time_sec": round(stdev(times), 3) if len(times) > 1 else 0,
            "min_generation_time_sec": round(min(times), 3) if times else 0,
            "max_generation_time_sec": round(max(times), 3) if times else 0,
            "total_input_tokens":  s["total_input_tokens"],
            "total_output_tokens": s["total_output_tokens"],
            "total_tokens": total_tokens,
            "avg_tokens_per_scenario": round(total_tokens / n, 1),
            "estimated_cost_usd":       round(cost, 6),
            "cost_per_scenario_usd":    round(cost / n, 6),
            "estimated_cost_490_corpus": round(cost / n * 490, 4),
            "by_attack_type":  dim_summary(s["by_attack_type"]),
            "by_environment":  dim_summary(s["by_environment"]),
            "by_difficulty":   dim_summary(s["by_difficulty"]),
        }

    def save_report(self, path):
        report = self.get_report()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\n[SAVED] Report → {path}")
        return report

    def print_summary(self):
        r = self.get_report()
        print("\n" + "="*60)
        print("  LLM GENERATION INSTRUMENTATION REPORT")
        print("="*60)
        print(f"  Model                  : {r['model']}")
        print(f"  Scenarios attempted    : {r['n_attempted']}")
        print(f"  Accepted               : {r['n_accepted']}")
        print(f"  Rejected               : {r['n_rejected']}")
        print(f"  First-attempt pass     : {r['first_attempt_pass_pct']}")
        print(f"  Wilson 95% CI          : [{r['wilson_95ci'][0]:.4f}, {r['wilson_95ci'][1]:.4f}]")
        print(f"  Invalid TIDs found     : {r['total_invalid_tids']}")
        print(f"  Avg generation time    : {r['avg_generation_time_sec']}s ± {r['std_generation_time_sec']}s")
        print(f"  Avg tokens / scenario  : {r['avg_tokens_per_scenario']}")
        print(f"  Total cost             : ${r['estimated_cost_usd']:.4f} USD")
        print(f"  Cost per scenario      : ${r['cost_per_scenario_usd']:.6f} USD")
        print(f"  Est. cost 490-corpus   : ${r['estimated_cost_490_corpus']:.4f} USD")
        print()
        print("  Pass rate by attack type:")
        for k, v in r["by_attack_type"].items():
            print(f"    {k:20}: {v['first_pass_rate']*100:.1f}%  ({v['attempted']} scenarios)")
        print()
        print("  Pass rate by environment:")
        for k, v in r["by_environment"].items():
            print(f"    {k:25}: {v['first_pass_rate']*100:.1f}%  ({v['attempted']} scenarios)")
        print()
        print("  Pass rate by difficulty:")
        for k, v in r["by_difficulty"].items():
            print(f"    {k:10}: {v['first_pass_rate']*100:.1f}%  ({v['attempted']} scenarios)")
        print("="*60)


# ─────────────────────────────────────────────
# BALANCED SAMPLING (covers all 48 combos evenly)
# ─────────────────────────────────────────────
def build_balanced_plan(n):
    """Build a balanced list of (attack_type, environment, difficulty) combos."""
    combos = [(at, env, dif)
              for at  in ATTACK_TYPES
              for env in ENVIRONMENTS
              for dif in DIFFICULTIES]      # 48 combinations

    plan = []
    while len(plan) < n:
        random.shuffle(combos)
        plan.extend(combos)
    return plan[:n]


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Instrumented LLM scenario generation with full telemetry.\n"
            "Recommended n=240 for journal-grade statistics:\n"
            "  5 samples per parameter combination (4 types × 4 envs × 3 diffs)\n"
            "  Wilson 95%% CI lower bound ≥ 0.984\n"
            "  Cost ≈ $0.082 USD  |  Time ≈ 30 minutes"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--n",   type=int, default=240,
                        help="Number of scenarios (default 240 for journal quality)")
    parser.add_argument("--out", type=str, default="data/journal_results",
                        help="Output directory")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for reproducibility")
    args = parser.parse_args()

    random.seed(args.seed)
    os.makedirs(args.out, exist_ok=True)

    # Build balanced sampling plan
    plan = build_balanced_plan(args.n)
    gen  = InstrumentedGenerator()

    out_scenarios = os.path.join(args.out, "hallucination_scenarios.jsonl")
    report_path   = os.path.join(args.out, "hallucination_report.json")

    print(f"\nAdverSim Instrumented Generator  —  v2.0")
    print(f"Generating {args.n} scenarios (balanced across 48 parameter combinations)")
    print(f"Model: gpt-4o-mini  |  seed: {args.seed}\n")

    with open(out_scenarios, "w", encoding="utf-8") as fout:
        for i, (at, env, dif) in enumerate(plan):
            print(f"  [{i+1:3d}/{args.n}] {at:15} / {env:22} / {dif:6} ...",
                  end=" ", flush=True)
            sc, meta = gen.generate(env, dif, at)
            if sc:
                fout.write(json.dumps(sc) + "\n")
                tok = meta["input_tokens"] + meta["output_tokens"]
                print(f"OK  ({meta['generation_time_sec']:.1f}s, {tok} tok)")
            else:
                print(f"REJECTED  issues={meta['issues']}")

    gen.print_summary()
    report = gen.save_report(report_path)
    print(f"\nScenarios saved → {out_scenarios}")
    print(f"Report saved    → {report_path}")
    print(f"\nPaste these into Table XI of the paper:")
    print(f"  n                          : {report['n_attempted']}")
    print(f"  First-attempt pass rate    : {report['first_attempt_pass_pct']}")
    print(f"  Wilson 95% CI              : [{report['wilson_95ci'][0]:.4f}, {report['wilson_95ci'][1]:.4f}]")
    print(f"  Avg generation time        : {report['avg_generation_time_sec']}s ± {report['std_generation_time_sec']}s")
    print(f"  Avg tokens / scenario      : {report['avg_tokens_per_scenario']}")
    print(f"  Cost per scenario          : ${report['cost_per_scenario_usd']:.6f}")
    print(f"  Estimated 490-corpus cost  : ${report['estimated_cost_490_corpus']:.4f}")
