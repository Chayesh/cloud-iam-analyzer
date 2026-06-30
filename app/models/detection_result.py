from pydantic import BaseModel


class DetectionResult(BaseModel):
    """
    Raw output returned by a detection rule.

    The rule only determines whether an attack
    technique exists and provides the attack chain.
    """

    detected: bool

    chain: list[str]