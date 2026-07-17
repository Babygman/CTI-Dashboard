from flask import Flask

from config import Config

from .extensions import db


def create_app(config_class=Config):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)

    from .auth import auth_blueprint
    from .dashboard import dashboard_blueprint
    from .threats import threats_blueprint
    from .vendors import vendors_blueprint

    app.register_blueprint(auth_blueprint)
    app.register_blueprint(dashboard_blueprint)
    app.register_blueprint(vendors_blueprint)
    app.register_blueprint(threats_blueprint)

    from .collectors.commands import collector_cli

    app.cli.add_command(collector_cli)

    return app
