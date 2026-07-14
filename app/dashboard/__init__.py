from flask import Blueprint


dashboard_blueprint = Blueprint("dashboard", __name__)


from . import routes  # noqa: E402, F401
