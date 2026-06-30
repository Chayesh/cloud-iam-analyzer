from pydantic import BaseModel

from api.schemas.finding import FindingResponse


class ScanResponse(BaseModel):

    users_scanned: int

    findings: int

    results: list[FindingResponse]