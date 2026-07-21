from flask import flash, redirect, render_template, request, url_for
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload

from app.extensions import db
from app.models.asset import Asset
from app.models.catalog_product import CatalogProduct

from . import assets_blueprint


FIELD_LIMITS = {
    "asset_name": 200,
    "vendor": 100,
    "product": 200,
    "version": 100,
    "asset_type": 100,
    "environment": 100,
    "owner": 200,
    "location": 255,
    "status": 50,
}


def _get_catalog_products():
    return db.session.execute(
        db.select(CatalogProduct).order_by(
            CatalogProduct.VendorName.asc(),
            CatalogProduct.ProductName.asc(),
            CatalogProduct.CatalogProductId.asc(),
        )
    ).scalars().all()


def _form_data_from_request():
    return {
        "asset_name": request.form.get("asset_name", "").strip(),
        "vendor": request.form.get("vendor", "").strip(),
        "product": request.form.get("product", "").strip(),
        "version": request.form.get("version", "").strip(),
        "catalog_product_id": request.form.get(
            "catalog_product_id", ""
        ).strip(),
        "asset_type": request.form.get("asset_type", "").strip(),
        "critical": "critical" in request.form,
        "environment": request.form.get("environment", "").strip(),
        "owner": request.form.get("owner", "").strip(),
        "location": request.form.get("location", "").strip(),
        "status": request.form.get("status", "").strip(),
        "notes": request.form.get("notes", "").strip(),
    }


def _validate_form(form_data):
    errors = {}
    if not form_data["asset_name"]:
        errors["asset_name"] = "Asset Name is required."

    labels = {
        "asset_name": "Asset Name",
        "vendor": "Vendor",
        "product": "Product",
        "version": "Version",
        "asset_type": "Asset Type",
        "environment": "Environment",
        "owner": "Owner",
        "location": "Location",
        "status": "Status",
    }
    for field, maximum in FIELD_LIMITS.items():
        if len(form_data[field]) > maximum:
            errors[field] = f"{labels[field]} must be {maximum} characters or fewer."

    if form_data["catalog_product_id"]:
        try:
            catalog_product_id = int(form_data["catalog_product_id"])
        except ValueError:
            errors["catalog_product_id"] = "Select a valid catalog product."
        else:
            if db.session.get(CatalogProduct, catalog_product_id) is None:
                errors["catalog_product_id"] = "Select a valid catalog product."
    return errors


def _apply_form_data(asset, form_data):
    asset.AssetName = form_data["asset_name"]
    asset.Vendor = form_data["vendor"] or None
    asset.Product = form_data["product"] or None
    asset.Version = form_data["version"] or None
    asset.CatalogProductId = (
        int(form_data["catalog_product_id"])
        if form_data["catalog_product_id"]
        else None
    )
    asset.AssetType = form_data["asset_type"] or None
    asset.Critical = form_data["critical"]
    asset.Environment = form_data["environment"] or None
    asset.Owner = form_data["owner"] or None
    asset.Location = form_data["location"] or None
    asset.Status = form_data["status"] or "Active"
    asset.Notes = form_data["notes"] or None


@assets_blueprint.route("/assets")
def asset_list():
    query = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)
    sort = request.args.get("sort", "asset_name")
    direction = request.args.get("direction", "asc")

    sort_columns = {
        "asset_name": Asset.AssetName,
        "vendor": Asset.Vendor,
        "product": Asset.Product,
        "version": Asset.Version,
        "asset_type": Asset.AssetType,
        "environment": Asset.Environment,
        "owner": Asset.Owner,
        "critical": Asset.Critical,
        "status": Asset.Status,
    }
    if sort not in sort_columns or direction not in {"asc", "desc"}:
        sort = "asset_name"
        direction = "asc"
    if page is None or page < 1:
        page = 1

    statement = db.select(Asset).options(joinedload(Asset.catalog_product))
    if query:
        search_pattern = f"%{query}%"
        statement = statement.where(
            or_(
                Asset.AssetName.ilike(search_pattern),
                Asset.Vendor.ilike(search_pattern),
                Asset.Product.ilike(search_pattern),
                Asset.Owner.ilike(search_pattern),
                Asset.Location.ilike(search_pattern),
            )
        )

    sort_column = sort_columns[sort]
    sort_expression = sort_column.desc() if direction == "desc" else sort_column.asc()
    statement = statement.order_by(sort_expression, Asset.AssetId.asc())

    pagination = db.paginate(statement, page=page, per_page=10, error_out=False)
    if pagination.pages and page > pagination.pages:
        pagination = db.paginate(
            statement, page=pagination.pages, per_page=10, error_out=False
        )

    return render_template(
        "assets.html",
        assets=pagination.items,
        pagination=pagination,
        q=query,
        sort=sort,
        direction=direction,
    )


@assets_blueprint.route("/assets/add", methods=["GET", "POST"])
def add_asset():
    form_data = {
        "asset_name": "",
        "vendor": "",
        "product": "",
        "version": "",
        "catalog_product_id": "",
        "asset_type": "",
        "critical": False,
        "environment": "",
        "owner": "",
        "location": "",
        "status": "Active",
        "notes": "",
    }
    errors = {}

    if request.method == "POST":
        form_data = _form_data_from_request()
        errors = _validate_form(form_data)
        if not errors:
            asset = Asset()
            _apply_form_data(asset, form_data)
            db.session.add(asset)
            db.session.commit()
            flash("Asset added successfully.", "success")
            return redirect(url_for("assets.asset_list"))

    return render_template(
        "asset_form.html",
        page_title="Add Asset",
        catalog_products=_get_catalog_products(),
        form_data=form_data,
        errors=errors,
    )


@assets_blueprint.route("/assets/<int:asset_id>/edit", methods=["GET", "POST"])
def edit_asset(asset_id):
    asset = db.get_or_404(Asset, asset_id)
    errors = {}

    if request.method == "POST":
        form_data = _form_data_from_request()
        errors = _validate_form(form_data)
        if not errors:
            _apply_form_data(asset, form_data)
            db.session.commit()
            flash("Asset updated successfully.", "success")
            return redirect(url_for("assets.asset_list"))
    else:
        form_data = {
            "asset_name": asset.AssetName,
            "vendor": asset.Vendor or "",
            "product": asset.Product or "",
            "version": asset.Version or "",
            "catalog_product_id": (
                str(asset.CatalogProductId) if asset.CatalogProductId else ""
            ),
            "asset_type": asset.AssetType or "",
            "critical": bool(asset.Critical),
            "environment": asset.Environment or "",
            "owner": asset.Owner or "",
            "location": asset.Location or "",
            "status": asset.Status or "",
            "notes": asset.Notes or "",
        }

    return render_template(
        "asset_form.html",
        page_title="Edit Asset",
        catalog_products=_get_catalog_products(),
        form_data=form_data,
        errors=errors,
    )


@assets_blueprint.route("/assets/<int:asset_id>/delete", methods=["POST"])
def delete_asset(asset_id):
    asset = db.get_or_404(Asset, asset_id)
    try:
        db.session.delete(asset)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("Asset cannot be deleted because it is in use.", "warning")
        return redirect(url_for("assets.asset_list"))

    flash("Asset deleted successfully.", "success")
    return redirect(url_for("assets.asset_list"))
