from flask import Flask
from sqlalchemy import text

from config import Config

from .extensions import db


def create_app(config_class=Config):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

  

    db.init_app(app)

    with app.app_context():
       
    from .auth import auth_blueprint
    from .dashboard import dashboard_blueprint
    from .threats import threats_blueprint
    from .vendors import vendors_blueprint

    app.register_blueprint(auth_blueprint)
    app.register_blueprint(dashboard_blueprint)
    app.register_blueprint(vendors_blueprint)
    app.register_blueprint(threats_blueprint)

    return app