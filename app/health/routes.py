from flask import current_app, jsonify

from app.extensions import db

from . import health_blueprint


APPLICATION_NAME = "CTI Dashboard"


def _database_available():
    try:
        with db.engine.connect() as connection:
            connection.execute(db.text("SELECT 1"))
        return True
    except Exception as exc:
        current_app.logger.warning(
            "Health database connectivity check failed (%s)",
            type(exc).__name__,
        )
        return False


@health_blueprint.get("/health")
def health():
    if not _database_available():
        return (
            jsonify(
                status="unavailable",
                application=APPLICATION_NAME,
            ),
            503,
        )
    return jsonify(status="ok", application=APPLICATION_NAME)
