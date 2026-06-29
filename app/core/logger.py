import logging
import sys

from app.core.config import settings


def setup_logger():

    logging.basicConfig(
        level=settings.LOG_LEVEL,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

    return logging.getLogger("CloudIAMAnalyzer")


logger = setup_logger()