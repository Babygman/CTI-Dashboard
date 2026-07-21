from flask import Blueprint


assets_blueprint = Blueprint("assets", __name__)


from . import routes  # noqa: E402, F401
