from flask import Blueprint


product_catalog_blueprint = Blueprint("product_catalog", __name__)


from . import routes  # noqa: E402, F401
