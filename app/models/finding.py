from pydantic import BaseModel, Field

from app.models.severity import Severity


class Finding(BaseModel):
    """
    Represents a privilege escalation finding.
    """

    user: str

    severity: Severity

    score: float = Field(
        ge=0,
        le=10
    )

    chain: list[str]

    fix: list[str]