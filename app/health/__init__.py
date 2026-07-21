from flask import Blueprint


health_blueprint = Blueprint("health", __name__)

from . import routes
