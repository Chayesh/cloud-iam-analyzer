from fastapi import FastAPI

from api.routes import router

app = FastAPI(
    title="Cloud IAM Privilege Escalation Analyzer",
    description="""
Analyze AWS IAM permissions to detect privilege escalation paths,
visualize attack chains, and assess IAM security risks.
""",
    version="1.0.0",
    contact={
        "name": "Chayesh Kumar"
    },
    license_info={
        "name": "MIT"
    }
)

app.include_router(router)