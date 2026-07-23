from flask import Blueprint


actions_blueprint = Blueprint("actions", __name__, url_prefix="/actions")


from . import routes  # noqa: E402, F401
