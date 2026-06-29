from pydantic_settings import BaseSettings
from pydantic import ConfigDict


class Settings(BaseSettings):

    APP_NAME: str = "Cloud IAM Privilege Escalation Analyzer"

    APP_VERSION: str = "2.0"

    AWS_REGION: str = "ap-south-1"

    AWS_PROFILE: str = "default"

    LOG_LEVEL: str = "INFO"

    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=True
    )


settings = Settings()