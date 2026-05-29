from pydantic import BaseModel
from typing import List, Dict


class AttackStage(BaseModel):
    stage_name: str
    technique_id: str
    technique_name: str
    description: str


class AttackScenario(BaseModel):
    scenario_id: str
    environment_type: str
    attack_stages: List[AttackStage]
    mitre_attack_mapping: List[str]
    difficulty: str
    realism_score: float
    diversity_tag: str
    narrative: str
    attack_graph: Dict