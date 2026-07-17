from flask import Blueprint


threats_blueprint = Blueprint("threats", __name__)


from . import routes  # noqa: E402, F401
