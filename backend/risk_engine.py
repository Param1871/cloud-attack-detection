from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class RiskResult:
    risk: float
    belief: float
    plausibility: float
    level: str

class HierarchicalRisk:
    """Practical DST-inspired evidence aggregation for the project prototype.

    Evidence is represented as mass on {safe}, {attack}, and {safe,attack}.
    Dempster-style combination is used across indicators, then node -> cluster -> global.
    """
    def __init__(self):
        self.base_thresholds = {"local": .55, "cluster": .60, "global": .65}

    def evidence(self, x: float):
        x = min(max(float(x), 0), 1)
        attack = x * .85
        safe = (1-x) * .85
        uncertain = 1 - attack - safe
        return {"safe": safe, "attack": attack, "uncertain": uncertain}

    def combine(self, masses: List[Dict[str, float]]):
        safe, attack, uncertain = 0.0, 0.0, 1.0
        for m in masses:
            s, a, u = m["safe"], m["attack"], m["uncertain"]
            # conflict between safe and attack evidence
            k = safe*a + attack*s
            norm = max(1e-9, 1-k)
            safe, attack, uncertain = ((safe*s + safe*u + uncertain*s)/norm,
                                       (attack*a + attack*u + uncertain*a)/norm,
                                       (uncertain*u)/norm)
        return {"safe": safe, "attack": attack, "uncertain": uncertain}

    def assess(self, values: Dict[str, float], threshold=.55) -> RiskResult:
        m = self.combine([self.evidence(v) for v in values.values()])
        belief = m["attack"]
        plausibility = m["attack"] + m["uncertain"]
        risk = min(1.0, 0.65*belief + 0.35*plausibility)
        level = "CRITICAL" if risk >= .85 else "HIGH" if risk >= threshold else "MEDIUM" if risk >= .35 else "LOW"
        return RiskResult(round(risk,4), round(belief,4), round(plausibility,4), level)

    def hierarchical(self, nodes: List[dict]):
        enriched=[]
        for n in nodes:
            rr=self.assess(n["signals"], self.base_thresholds["local"])
            enriched.append({**n, "risk":rr.risk, "belief":rr.belief, "plausibility":rr.plausibility, "level":rr.level})
        clusters={}
        for n in enriched:
            clusters.setdefault(n.get("cluster","C1"), []).append(n)
        cluster_out=[]
        for cid, members in clusters.items():
            rr=self.assess({f"n{i}":m["risk"] for i,m in enumerate(members)}, self.base_thresholds["cluster"])
            cluster_out.append({"cluster":cid,"risk":rr.risk,"belief":rr.belief,"plausibility":rr.plausibility,"level":rr.level,"nodes":len(members)})
        gr=self.assess({c["cluster"]:c["risk"] for c in cluster_out}, self.base_thresholds["global"])
        thresholds={
            "local":round(self.base_thresholds["local"]*(.6*gr.belief+.4*gr.plausibility),4),
            "cluster":round(self.base_thresholds["cluster"]*(.6*gr.belief+.4*gr.plausibility),4),
            "global":round(self.base_thresholds["global"]*(.6*gr.belief+.4*gr.plausibility),4),
        }
        return enriched, cluster_out, {"risk":gr.risk,"belief":gr.belief,"plausibility":gr.plausibility,"level":gr.level}, thresholds
