from dataclasses import dataclass

@dataclass
class AgentOpinion:
    agent_name: str
    risk_level: str
    recommendation: str
    confidence: float
    reasoning: str
