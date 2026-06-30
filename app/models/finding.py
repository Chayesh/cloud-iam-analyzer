from pydantic import BaseModel

from app.models.rule_metadata import RuleMetadata


class Finding(BaseModel):
    """
    Dynamic finding produced after a rule matches.
    """

    metadata: RuleMetadata

    user: str

    chain: list[str]