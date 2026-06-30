from fastapi import APIRouter

from app.services.scan_service import ScanService

from api.schemas.scan import ScanResponse
from api.schemas.finding import FindingResponse

router = APIRouter()


@router.get("/")
def home():

    return {
        "application": "Cloud IAM Privilege Escalation Analyzer",
        "version": "1.0.0",
        "status": "running"
    }


@router.get("/health")
def health():

    return {
        "status": "healthy"
    }


@router.post(
    "/scan",
    response_model=ScanResponse,
    summary="Run IAM privilege escalation scan",
    tags=["Scanner"]
)
def scan():

    service = ScanService()

    permissions, findings = service.scan()

    response = []

    for finding in findings:

        response.append(

            FindingResponse(

                user=finding.user,

                rule_id=finding.metadata.rule_id,

                title=finding.metadata.title,

                severity=finding.metadata.severity.value,

                score=finding.metadata.score,

                attack_chain=finding.chain,

                recommendations=finding.metadata.recommendations

            )

        )

    return ScanResponse(

        users_scanned=len(permissions),

        findings=len(response),

        results=response

    )