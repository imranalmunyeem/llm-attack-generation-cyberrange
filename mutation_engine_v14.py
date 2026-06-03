"""
mutation_engine_v14.py

Faithful implementation of the ADVERSIM mutation operators that the paper
formalises but the released code only approximated.

Obfuscation (Eq. 7): replace each technique t with
    argmax_{t' in N_k(t)} [ cos(e_t', e_t) - lambda * 1[tactic(t')==tactic(t)] ]
where e_* are technique embeddings, N_k(t) the k nearest neighbours by cosine,
k=5, lambda=0.3. The lambda term penalises same-tactic neighbours, biasing the
substitution toward a semantically-near technique in a *different* tactic
(the evasion intent), rather than the random.choice() the old code used.

Embedding backend: SentenceTransformer (ref [32], all-MiniLM-L6-v2) if
installed; otherwise a fully-offline TF-IDF embedding over the official
ATT&CK v14 technique "name. description" text. The substitution logic is
identical for both; only e_* differs.

Expansion (Eq. 8): insert Poisson(lambda_e=2) new Persistence / Defense-Evasion
stages, with the technique for each new stage sampled *co-occurrence-weighted*
on the preceding stage's technique (not uniform from a hard-coded list).
"""

import copy
import random
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class ObfuscationEngine:
    def __init__(self, validator, k=5, lam=0.3, backend="auto"):
        self.v = validator
        self.k = k
        self.lam = lam
        self.tids = list(validator.active.keys())
        self.idx = {t: i for i, t in enumerate(self.tids)}
        self.tactics = {t: set(validator.active[t]["tactics"]) for t in self.tids}
        self.backend, self.emb = self._build_embeddings(backend)
        # cosine similarity matrix over active techniques
        self.sim = cosine_similarity(self.emb)
        np.fill_diagonal(self.sim, -1.0)  # exclude self

    def _build_embeddings(self, backend):
        docs = [f"{self.v.active[t]['name']}. {self.v.active[t]['description']}"
                for t in self.tids]
        if backend in ("auto", "sbert"):
            try:
                from sentence_transformers import SentenceTransformer
                model = SentenceTransformer("all-MiniLM-L6-v2")
                return "sbert", np.asarray(model.encode(docs, show_progress_bar=False))
            except Exception:
                if backend == "sbert":
                    raise
        vec = TfidfVectorizer(stop_words="english", max_features=4096)
        return "tfidf", vec.fit_transform(docs).toarray()

    def obfuscate_tid(self, tid):
        """Return (new_tid, cosine, cross_tactic) for one technique id."""
        if tid not in self.idx:
            return tid, None, None
        i = self.idx[tid]
        nn = np.argsort(self.sim[i])[::-1][: self.k]   # k nearest neighbours
        best, best_score, best_cos = None, -1e9, None
        for j in nn:
            cos = self.sim[i][j]
            same = 1.0 if (self.tactics[self.tids[i]] & self.tactics[self.tids[j]]) else 0.0
            score = cos - self.lam * same
            if score > best_score:
                best_score, best, best_cos = score, self.tids[j], cos
        cross = bool(not (self.tactics[tid] & self.tactics[best])) if best else None
        return best, best_cos, cross

    def mutate(self, scenario):
        """Eq. 7 obfuscation. Returns (variant, substitution_records)."""
        s = copy.deepcopy(scenario)
        s["variant"] = "obfuscated"
        s["scenario_id"] = s.get("scenario_id", "") + "_obfuscated"
        records = []
        for stage in s.get("attack_stages", []):
            for t in stage.get("techniques", []):
                tid = (t.get("technique_id") or "").strip()
                new, cos, cross = self.obfuscate_tid(tid)
                if new and new != tid:
                    records.append({"orig": tid, "new": new,
                                    "cos": None if cos is None else round(float(cos), 4),
                                    "cross_tactic": cross})
                    t["technique_id"] = new
                    t["technique_name"] = self.v.active[new]["name"]
        return s, records


def mutate_obfuscated_random(scenario, all_active_tids):
    """OLD behaviour, kept for comparison: uniform random.choice substitution."""
    s = copy.deepcopy(scenario)
    s["variant"] = "obfuscated_random"
    for stage in s.get("attack_stages", []):
        for t in stage.get("techniques", []):
            tid = (t.get("technique_id") or "").strip()
            cands = [x for x in all_active_tids if x != tid]
            if cands:
                t["technique_id"] = random.choice(cands)
    return s


def mutate_expanded_cooc(scenario, cooc, validator, lam_e=2):
    """Eq. 8 expansion with co-occurrence-weighted technique sampling."""
    PERSIST = ["T1053", "T1547", "T1098", "T1136", "T1543"]
    EVADE = ["T1070", "T1036", "T1055", "T1027", "T1562"]
    s = copy.deepcopy(scenario)
    s["variant"] = "expanded"
    s["scenario_id"] = s.get("scenario_id", "") + "_expanded"

    last_tids = []
    if s.get("attack_stages"):
        last_tids = [t.get("technique_id") for t in s["attack_stages"][-1].get("techniques", [])]

    def weighted_pick(pool):
        weights = []
        for cand in pool:
            w = sum(cooc.get((lt, cand), 0.0) for lt in last_tids) + 1e-3
            weights.append(w)
        weights = np.array(weights) / sum(weights)
        return np.random.choice(pool, p=weights)

    n_new = max(1, int(np.random.poisson(lam_e)))
    new_stages = []
    for _ in range(n_new):
        if random.random() < 0.5:
            tid = weighted_pick([t for t in PERSIST if validator.is_valid(t)] or PERSIST)
            name, sn = validator.active.get(tid, {}).get("name", tid), "Persistence"
        else:
            tid = weighted_pick([t for t in EVADE if validator.is_valid(t)] or EVADE)
            name, sn = validator.active.get(tid, {}).get("name", tid), "Defense Evasion"
        new_stages.append({"stage_name": sn,
                           "description": f"{sn} technique inserted via co-occurrence-weighted expansion.",
                           "techniques": [{"technique_id": tid, "technique_name": name}]})
    existing = s.get("attack_stages", [])
    at = 1 if len(existing) > 1 else len(existing)
    s["attack_stages"] = existing[:at] + new_stages + existing[at:]
    return s
