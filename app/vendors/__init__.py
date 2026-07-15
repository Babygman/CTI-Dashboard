from flask import Blueprint


vendors_blueprint = Blueprint("vendors", __name__)


from . import routes  # noqa: E402, F401
