from flask import Flask
from datetime import datetime, timezone
from sqlalchemy import event

from config import Config

from .extensions import db


def create_app(config_class=Config):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)

    # Models intentionally use SQL Server's SYSUTCDATETIME server default.
    # Register an equivalent function when running the supported local SQLite
    # workflow so normal browser CRUD behaves the same way.
    if str(app.config.get("SQLALCHEMY_DATABASE_URI", "")).startswith("sqlite"):
        with app.app_context():
            @event.listens_for(db.engine, "connect")
            def _register_sqlite_utc_timestamp(connection, _record):
                connection.create_function(
                    "SYSUTCDATETIME",
                    0,
                    lambda: datetime.now(timezone.utc).replace(tzinfo=None).isoformat(" "),
                )

    from .assets import assets_blueprint
    from .actions import actions_blueprint
    from .auth import auth_blueprint
    from .dashboard import dashboard_blueprint
    from .cves import cves_blueprint
    from .health import health_blueprint
    from .product_catalog import product_catalog_blueprint
    from .threats import threats_blueprint
    from .vendors import vendors_blueprint
    from .awareness import awareness_bp
    from .settings import settings_bp
    from .sources import sources_blueprint
    from .news import news_blueprint

    app.register_blueprint(assets_blueprint)
    app.register_blueprint(actions_blueprint)
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(dashboard_blueprint)
    app.register_blueprint(cves_blueprint)
    app.register_blueprint(health_blueprint)
    app.register_blueprint(product_catalog_blueprint)
    app.register_blueprint(vendors_blueprint)
    app.register_blueprint(threats_blueprint)
    app.register_blueprint(awareness_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(sources_blueprint)
    app.register_blueprint(news_blueprint)

    from .collectors.commands import collector_cli
    from .services.asset_import_commands import import_assets_command
    from .services.commands import normalize_product_command
    from .services.decision_commands import recommend_action_command
    from .services.impact_commands import analyze_impact_command
    from .services.risk_commands import assess_risk_command

    app.cli.add_command(collector_cli)
    app.cli.add_command(import_assets_command)
    app.cli.add_command(normalize_product_command)
    app.cli.add_command(recommend_action_command)
    app.cli.add_command(analyze_impact_command)
    app.cli.add_command(assess_risk_command)

    return app
