from flask import render_template

from app.extensions import db
from app.models.vendor import Vendor

from . import vendors_blueprint


@vendors_blueprint.route("/vendors")
def vendor_list():
    vendors = db.session.execute(db.select(Vendor)).scalars().all()
    return render_template("vendors.html", vendors=vendors)
