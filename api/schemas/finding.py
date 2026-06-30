from pydantic import BaseModel


class FindingResponse(BaseModel):

    user: str

    rule_id: str

    title: str

    severity: str

    score: float

    attack_chain: list[str]

    recommendations: list[str]