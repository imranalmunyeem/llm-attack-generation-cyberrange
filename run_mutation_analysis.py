"""
run_mutation_analysis.py
Re-runs the mutation-impact analysis on the v14-clean corpus, comparing the
faithful Eq.7 embedding obfuscation against the old random.choice() version.
Reuses the paper's exact realism/detection logic (copied verbatim from
journal_experiments.py) so numbers are directly comparable.
"""
import json, random, copy
import numpy as np
from collections import defaultdict
from mitre_attack_validator import MitreAttackValidator
from mutation_engine_v14 import ObfuscationEngine, mutate_obfuscated_random

random.seed(42); np.random.seed(42)

# ---- paper's exact constants + metric functions (from journal_experiments.py) ----
TACTIC_ORDER = {"Reconnaissance":0,"Resource Development":1,"Initial Access":2,"Execution":3,
 "Persistence":4,"Privilege Escalation":5,"Defense Evasion":6,"Credential Access":7,"Discovery":8,
 "Lateral Movement":9,"Collection":10,"Command and Control":11,"Command & Control":11,"C2":11,
 "Exfiltration":12,"Data Exfiltration":12,"Impact":13}
STAGE_DETECTION_WEIGHTS = {"Initial Access":0.90,"Execution":0.85,"Persistence":0.80,
 "Privilege Escalation":0.75,"Credential Access":0.70,"Lateral Movement":0.60,"Collection":0.55,
 "Exfiltration":0.50,"Data Exfiltration":0.50,"Impact":0.40,"Reconnaissance":0.35,"Resource Development":0.30}
DIFFICULTY_BASE = {"Easy":0.75,"Medium":0.55,"Hard":0.35}
W_T,W_G,W_S = 0.40,0.35,0.25

def build_cooc(scenarios):
    m=defaultdict(int); tot=defaultdict(int)
    for s in scenarios:
        st=s.get("attack_stages",[])
        for i in range(len(st)-1):
            ti=[t.get("technique_id") for t in st[i].get("techniques",[])]
            tj=[t.get("technique_id") for t in st[i+1].get("techniques",[])]
            for a in ti:
                for b in tj:
                    if a and b: m[(a,b)]+=1; tot[a]+=1
    return {k:(c/tot[k[0]] if tot[k[0]] else 0.0) for k,c in m.items()}

def score_T(s, V):
    st=s.get("attack_stages",[])
    if not st: return 0.0
    return sum(1 for stg in st if any(V.is_valid(t.get("technique_id","")) for t in stg.get("techniques",[])))/len(st)

def score_G(s, cooc, delta=0.05):
    st=s.get("attack_stages",[]); edges=s.get("attack_graph",{}).get("edges",[])
    smap={x.get("stage_name",""):[t.get("technique_id") for t in x.get("techniques",[])] for x in st}
    if not edges: return 1.0
    pen=0
    for e in edges:
        if not isinstance(e,(list,tuple)) or len(e)<2: continue
        a,b=str(e[0]),str(e[1]); ok=False
        for ti in smap.get(a,[]):
            for tj in smap.get(b,[]):
                if cooc.get((ti,tj),0.0)>=delta: ok=True
        if not ok: pen+=1
    return 1.0-(pen/len(edges))

def score_S(s):
    names=[x.get("stage_name","") for x in s.get("attack_stages",[])]
    if len(names)<2: return 1.0
    rev=pairs=0
    for i in range(len(names)-1):
        a=TACTIC_ORDER.get(names[i],999); b=TACTIC_ORDER.get(names[i+1],999)
        if a!=999 and b!=999:
            pairs+=1
            if b<a: rev+=1
    return 1.0 if pairs==0 else 1.0-(rev/pairs)

def realism(s,cooc,V):
    t,g,sc=score_T(s,V),score_G(s,cooc),score_S(s)
    return W_T*t+W_G*g+W_S*sc

def detect(s, defense=0.671):
    st=s.get("attack_stages",[]); base=DIFFICULTY_BASE.get(s.get("difficulty","Medium"),0.55)
    for i,stg in enumerate(st):
        w=STAGE_DETECTION_WEIGHTS.get(stg.get("stage_name",""),0.50)
        p=min(0.95,max(0.05,base*w*defense))
        if random.random()<p: return True
    return False

def techset(s):
    return {t.get("technique_id") for stg in s.get("attack_stages",[]) for t in stg.get("techniques",[]) if t.get("technique_id")}

def jaccard(a,b):
    a,b=set(a),set(b)
    return len(a&b)/len(a|b) if (a|b) else 1.0

# ---- load ----
V=MitreAttackValidator("data/official-v14.1.json")
scen=[json.loads(l) for l in open("data/full_dataset_v14clean.jsonl") if l.strip()]
cooc=build_cooc(scen)
active_tids=sorted(V.active.keys())
eng=ObfuscationEngine(V, backend="auto")
print(f"embedding backend: {eng.backend}  | active techniques: {len(active_tids)}  | scenarios: {len(scen)}")

# ---- run obfuscation: embedding (Eq7) vs random (old) ----
N_RUNS=5
agg={"base":{"det":[],"real":[]},"emb":{"det":[],"real":[],"jac":[],"cos":[],"cross":[]},
     "rnd":{"det":[],"real":[],"jac":[],"cos":[]}}
all_cos_emb=[]; all_cross=[]
for s in scen:
    base_ts=techset(s)
    emb_s,recs=eng.mutate(s)
    rnd_s=mutate_obfuscated_random(s, active_tids)
    agg["emb"]["jac"].append(jaccard(base_ts,techset(emb_s)))
    agg["rnd"]["jac"].append(jaccard(base_ts,techset(rnd_s)))
    if recs:
        cs=[r["cos"] for r in recs if r["cos"] is not None]
        all_cos_emb+=cs
        all_cross+=[1 if r["cross_tactic"] else 0 for r in recs]
        agg["emb"]["cos"].append(np.mean(cs) if cs else np.nan)
    # random substitution cosine (semantic coherence of random picks)
    rnd_cos=[]
    for stg in s.get("attack_stages",[]):
        for t in stg.get("techniques",[]):
            oid=t.get("technique_id")
            if oid in eng.idx:
                # find what random produced is not tracked per-tech; approximate coherence
                pass
    agg["base"]["real"].append(realism(s,cooc,V))
    agg["emb"]["real"].append(realism(emb_s,cooc,V))
    agg["rnd"]["real"].append(realism(rnd_s,cooc,V))
    d_b=d_e=d_r=0
    for _ in range(N_RUNS):
        d_b+=detect(s); d_e+=detect(emb_s); d_r+=detect(rnd_s)
    agg["base"]["det"].append(d_b/N_RUNS); agg["emb"]["det"].append(d_e/N_RUNS); agg["rnd"]["det"].append(d_r/N_RUNS)

# random-substitution semantic coherence (separate pass: cosine between orig and random pick)
rnd_cos_all=[]
for s in scen:
    for stg in s.get("attack_stages",[]):
        for t in stg.get("techniques",[]):
            oid=t.get("technique_id")
            if oid in eng.idx:
                rid=random.choice([x for x in active_tids if x!=oid])
                rnd_cos_all.append(float(eng.sim[eng.idx[oid]][eng.idx[rid]]))

def m(x): return round(float(np.nanmean(x)),4)
report={
 "embedding_backend":eng.backend,
 "scenarios":len(scen),"substitutions":len(all_cos_emb),
 "obfuscation_embedding_Eq7":{
    "mean_jaccard":m(agg["emb"]["jac"]),
    "mean_substitution_cosine":m(all_cos_emb),
    "pct_cross_tactic":round(100*np.mean(all_cross),1),
    "mean_realism":m(agg["emb"]["real"]),
    "mean_detection_rate":m(agg["emb"]["det"]),
 },
 "obfuscation_random_OLD":{
    "mean_jaccard":m(agg["rnd"]["jac"]),
    "mean_substitution_cosine":m(rnd_cos_all),
    "mean_realism":m(agg["rnd"]["real"]),
    "mean_detection_rate":m(agg["rnd"]["det"]),
 },
 "base":{"mean_realism":m(agg["base"]["real"]),"mean_detection_rate":m(agg["base"]["det"])},
}
json.dump(report, open("mutation_analysis_v14.json","w"), indent=2)

print("\n================ MUTATION ANALYSIS (v14-clean corpus) ================")
print(f"{'metric':32s}{'BASE':>10s}{'Eq7 embed':>12s}{'OLD random':>12s}")
print(f"{'mean Jaccard (vs base)':32s}{'1.000':>10s}{report['obfuscation_embedding_Eq7']['mean_jaccard']:>12.3f}{report['obfuscation_random_OLD']['mean_jaccard']:>12.3f}")
print(f"{'mean substitution cosine':32s}{'-':>10s}{report['obfuscation_embedding_Eq7']['mean_substitution_cosine']:>12.3f}{report['obfuscation_random_OLD']['mean_substitution_cosine']:>12.3f}")
print(f"{'% cross-tactic substitution':32s}{'-':>10s}{report['obfuscation_embedding_Eq7']['pct_cross_tactic']:>11.1f}%{'-':>12s}")
print(f"{'mean realism R(S)':32s}{report['base']['mean_realism']:>10.3f}{report['obfuscation_embedding_Eq7']['mean_realism']:>12.3f}{report['obfuscation_random_OLD']['mean_realism']:>12.3f}")
print(f"{'mean detection rate':32s}{report['base']['mean_detection_rate']:>10.3f}{report['obfuscation_embedding_Eq7']['mean_detection_rate']:>12.3f}{report['obfuscation_random_OLD']['mean_detection_rate']:>12.3f}")
print("\nSaved -> mutation_analysis_v14.json")
