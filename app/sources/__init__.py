from flask import Blueprint


sources_blueprint = Blueprint("sources", __name__, url_prefix="/sources")


from . import routes  # noqa: E402, F401
