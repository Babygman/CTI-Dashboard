import os

from dotenv import load_dotenv

# Explicit process/service environment variables must take precedence over
# developer .env defaults (also makes isolated migration verification safe).
load_dotenv(override=False)


def _positive_int(name, default):
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _tcp_port(name, default):
    value = _positive_int(name, default)
    return value if value <= 65535 else default


def _bounded_float(name, default, minimum, maximum):
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value if minimum <= value <= maximum else default


class Config:

    SECRET_KEY = os.getenv("SECRET_KEY", "ChangeThisSecretKey")

    SQLALCHEMY_DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI")

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    DEFAULT_COMPANY_NAME = os.getenv(
        "DEFAULT_COMPANY_NAME",
        "Sunstar Chemical (Thailand) Co., Ltd.",
    )
    DEFAULT_COMPANY_SHORT_NAME = os.getenv(
        "DEFAULT_COMPANY_SHORT_NAME",
        "SUNSTAR",
    )
    DEFAULT_DEPARTMENT = os.getenv(
        "DEFAULT_DEPARTMENT",
        "Information Technology Department",
    )
    DEFAULT_CLASSIFICATION = os.getenv(
        "DEFAULT_CLASSIFICATION",
        "ใช้ภายในองค์กร",
    )

    OPERATIONS_DASHBOARD_THREAT_LIMIT = _positive_int(
        "OPERATIONS_DASHBOARD_THREAT_LIMIT", 100
    )

    CTI_HOST = os.getenv("CTI_HOST", "0.0.0.0").strip() or "0.0.0.0"
    CTI_PORT = _tcp_port("CTI_PORT", 8000)
    CTI_THREADS = _positive_int("CTI_THREADS", 8)
    CTI_WORKER_POLL_INTERVAL_SECONDS = _positive_int(
        "CTI_WORKER_POLL_INTERVAL_SECONDS", 30
    )
    CTI_WORKER_LEASE_TIMEOUT_SECONDS = _positive_int(
        "CTI_WORKER_LEASE_TIMEOUT_SECONDS", 300
    )
    CTI_WORKER_HEARTBEAT_INTERVAL_SECONDS = _positive_int(
        "CTI_WORKER_HEARTBEAT_INTERVAL_SECONDS", 30
    )
    CTI_WORKER_RETRY_INTERVAL_SECONDS = _positive_int(
        "CTI_WORKER_RETRY_INTERVAL_SECONDS", 300
    )
    CTI_WORKER_BATCH_SIZE = _positive_int("CTI_WORKER_BATCH_SIZE", 25)
    CTI_CANONICAL_TITLE_SIMILARITY_THRESHOLD = _bounded_float(
        "CTI_CANONICAL_TITLE_SIMILARITY_THRESHOLD", 0.88, 0.0, 1.0
    )
    CTI_CANONICAL_CANDIDATE_LIMIT = _positive_int(
        "CTI_CANONICAL_CANDIDATE_LIMIT", 100
    )
