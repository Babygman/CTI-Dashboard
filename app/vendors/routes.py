from flask import redirect, render_template, request, url_for
from sqlalchemy import func, or_

from app.extensions import db
from app.models.vendor import Vendor

from . import vendors_blueprint


def _vendor_name_exists(vendor_name, excluded_vendor_id=None):
    statement = db.select(Vendor.VendorId).where(
        func.lower(Vendor.VendorName) == vendor_name.lower()
    )
    if excluded_vendor_id is not None:
        statement = statement.where(Vendor.VendorId != excluded_vendor_id)
    return db.session.scalar(statement) is not None


@vendors_blueprint.route("/vendors")
def vendor_list():
    query = request.args.get("q", "").strip()
    statement = db.select(Vendor)

    if query:
        search_pattern = f"%{query}%"
        statement = statement.where(
            or_(
                Vendor.VendorName.ilike(search_pattern),
                Vendor.Category.ilike(search_pattern),
            )
        )

    vendors = db.session.execute(statement).scalars().all()
    return render_template("vendors.html", vendors=vendors, q=query)


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

        if "vendor_name" not in errors and _vendor_name_exists(form_data["vendor_name"]):
            errors["vendor_name"] = "A vendor with this name already exists."

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


@vendors_blueprint.route("/vendors/<int:vendor_id>/edit", methods=["GET", "POST"])
def edit_vendor(vendor_id):
    vendor = db.get_or_404(Vendor, vendor_id)
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

        if "vendor_name" not in errors and _vendor_name_exists(
            form_data["vendor_name"], excluded_vendor_id=vendor.VendorId
        ):
            errors["vendor_name"] = "A vendor with this name already exists."

        if not errors:
            vendor.VendorName = form_data["vendor_name"]
            vendor.Category = form_data["category"] or None
            vendor.Website = form_data["website"] or None
            vendor.Enabled = form_data["enabled"]
            db.session.commit()
            return redirect(url_for("vendors.vendor_list"))
    else:
        form_data = {
            "vendor_name": vendor.VendorName,
            "category": vendor.Category or "",
            "website": vendor.Website or "",
            "enabled": bool(vendor.Enabled),
        }

    return render_template("vendor_edit.html", form_data=form_data, errors=errors)


@vendors_blueprint.route("/vendors/<int:vendor_id>/delete", methods=["POST"])
def delete_vendor(vendor_id):
    vendor = db.get_or_404(Vendor, vendor_id)
    db.session.delete(vendor)
    db.session.commit()
    return redirect(url_for("vendors.vendor_list"))
