from flask import flash, redirect, render_template, request, url_for
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models.threat import Threat
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
    page = request.args.get("page", 1, type=int)
    sort = request.args.get("sort", "vendor_name")
    direction = request.args.get("direction", "asc")

    sort_columns = {
        "vendor_name": Vendor.VendorName,
        "category": Vendor.Category,
        "website": Vendor.Website,
        "enabled": Vendor.Enabled,
    }
    if sort not in sort_columns or direction not in {"asc", "desc"}:
        sort = "vendor_name"
        direction = "asc"
    if page is None or page < 1:
        page = 1

    statement = db.select(Vendor)

    if query:
        search_pattern = f"%{query}%"
        statement = statement.where(
            or_(
                Vendor.VendorName.ilike(search_pattern),
                Vendor.Category.ilike(search_pattern),
            )
        )

    sort_column = sort_columns[sort]
    sort_expression = sort_column.desc() if direction == "desc" else sort_column.asc()
    statement = statement.order_by(sort_expression, Vendor.VendorId.asc())

    pagination = db.paginate(statement, page=page, per_page=10, error_out=False)
    if pagination.pages and page > pagination.pages:
        pagination = db.paginate(
            statement, page=pagination.pages, per_page=10, error_out=False
        )

    return render_template(
        "vendors.html",
        vendors=pagination.items,
        pagination=pagination,
        q=query,
        sort=sort,
        direction=direction,
    )


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
            flash("Vendor added successfully.", "success")
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
            flash("Vendor updated successfully.", "success")
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
    referenced = db.session.scalar(
        db.select(Threat.ThreatId)
        .where(Threat.VendorId == vendor_id)
        .limit(1)
    )
    if referenced is not None:
        flash("Vendor cannot be deleted because it is used by threats.", "warning")
        return redirect(url_for("vendors.vendor_list"))

    try:
        db.session.delete(vendor)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("Vendor cannot be deleted because it is in use.", "warning")
        return redirect(url_for("vendors.vendor_list"))

    flash("Vendor deleted successfully.", "success")
    return redirect(url_for("vendors.vendor_list"))
