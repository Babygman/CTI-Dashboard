from flask import Blueprint

news_blueprint = Blueprint("news", __name__, url_prefix="/news")

from . import routes  # noqa: E402,F401
