from flask import Blueprint


cves_blueprint = Blueprint("cves", __name__)


from . import routes  # noqa: E402, F401

