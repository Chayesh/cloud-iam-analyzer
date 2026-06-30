from pydantic import BaseModel

from app.models.severity import Severity


class RuleMetadata(BaseModel):
    """
    Static information describing a detection rule.
    """

    rule_id: str

    title: str

    description: str

    severity: Severity

    score: float

    recommendations: list[str]

    references: list[str] = []