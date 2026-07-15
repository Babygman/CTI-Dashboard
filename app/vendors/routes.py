from flask import redirect, render_template, request, url_for

from app.extensions import db
from app.models.vendor import Vendor

from . import vendors_blueprint


@vendors_blueprint.route("/vendors")
def vendor_list():
    vendors = db.session.execute(db.select(Vendor)).scalars().all()
    return render_template("vendors.html", vendors=vendors)


@vendors_blueprint.route("/vendors/add", methods=["GET", "POST"])
def add_vendor():
    form_data = {
        "vendor_name": "",
        "category": "",
        "website": "",
        "enabled": True,
    }
    errors = {}

    if request.method == "POST":
        form_data = {
            "vendor_name": request.form.get("vendor_name", "").strip(),
            "category": request.form.get("category", "").strip(),
            "website": request.form.get("website", "").strip(),
            "enabled": "enabled" in request.form,
        }

        if not form_data["vendor_name"]:
            errors["vendor_name"] = "Vendor Name is required."
        elif len(form_data["vendor_name"]) > 100:
            errors["vendor_name"] = "Vendor Name must be 100 characters or fewer."

        if len(form_data["category"]) > 100:
            errors["category"] = "Category must be 100 characters or fewer."

        if len(form_data["website"]) > 255:
            errors["website"] = "Website must be 255 characters or fewer."

        if not errors:
            vendor = Vendor(
                VendorName=form_data["vendor_name"],
                Category=form_data["category"] or None,
                Website=form_data["website"] or None,
                Enabled=form_data["enabled"],
            )
            db.session.add(vendor)
            db.session.commit()
            return redirect(url_for("vendors.vendor_list"))

    return render_template("vendor_add.html", form_data=form_data, errors=errors)
