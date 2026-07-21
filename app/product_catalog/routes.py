from flask import abort, flash, redirect, render_template, request, url_for
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models.asset import Asset
from app.models.catalog_product import CatalogProduct
from app.models.product_alias import ProductAlias

from . import product_catalog_blueprint


ALIAS_TYPES = (
    "ProductName",
    "Family",
    "Model",
    "OperatingSystem",
    "CPEKeyword",
    "CommonName",
    "Other",
)


def _deduplicated_order_by(sort_column, direction, tie_breaker_columns):
    ordered_columns = [(sort_column, direction)]
    ordered_columns.extend(
        (column, "asc") for column in tie_breaker_columns
    )

    unique_columns = []
    for column, column_direction in ordered_columns:
        column_expression = getattr(column, "expression", column)
        if any(
            column_expression.compare(
                getattr(existing_column, "expression", existing_column)
            )
            for existing_column, _ in unique_columns
        ):
            continue
        unique_columns.append((column, column_direction))

    return [
        column.desc() if column_direction == "desc" else column.asc()
        for column, column_direction in unique_columns
    ]


def _product_name_exists(vendor_name, product_name, excluded_product_id=None):
    statement = db.select(CatalogProduct.CatalogProductId).where(
        func.lower(CatalogProduct.VendorName) == vendor_name.lower(),
        func.lower(CatalogProduct.ProductName) == product_name.lower(),
    )
    if excluded_product_id is not None:
        statement = statement.where(
            CatalogProduct.CatalogProductId != excluded_product_id
        )
    return db.session.scalar(statement) is not None


def _product_form_data():
    return {
        "vendor_name": request.form.get("vendor_name", "").strip(),
        "product_name": request.form.get("product_name", "").strip(),
        "product_family": request.form.get("product_family", "").strip(),
        "technology_category": request.form.get(
            "technology_category", ""
        ).strip(),
        "description": request.form.get("description", "").strip(),
        "active": "active" in request.form,
    }


def _validate_product(form_data, excluded_product_id=None):
    errors = {}
    required_fields = {
        "vendor_name": ("Vendor", 100),
        "product_name": ("Product", 200),
    }
    for field, (label, maximum) in required_fields.items():
        if not form_data[field]:
            errors[field] = f"{label} is required."
        elif len(form_data[field]) > maximum:
            errors[field] = f"{label} must be {maximum} characters or fewer."

    optional_fields = {
        "product_family": ("Product Family", 100),
        "technology_category": ("Technology Category", 100),
    }
    for field, (label, maximum) in optional_fields.items():
        if len(form_data[field]) > maximum:
            errors[field] = f"{label} must be {maximum} characters or fewer."

    if (
        "vendor_name" not in errors
        and "product_name" not in errors
        and _product_name_exists(
            form_data["vendor_name"],
            form_data["product_name"],
            excluded_product_id=excluded_product_id,
        )
    ):
        errors["product_name"] = (
            "This vendor and product combination already exists."
        )
    return errors


def _apply_product_form(product, form_data):
    product.VendorName = form_data["vendor_name"]
    product.ProductName = form_data["product_name"]
    product.ProductFamily = form_data["product_family"] or None
    product.TechnologyCategory = form_data["technology_category"] or None
    product.Description = form_data["description"] or None
    product.Active = form_data["active"]


def _alias_exists(catalog_product_id, alias):
    return db.session.scalar(
        db.select(ProductAlias.ProductAliasId).where(
            ProductAlias.CatalogProductId == catalog_product_id,
            func.lower(ProductAlias.Alias) == alias.lower(),
        )
    ) is not None


@product_catalog_blueprint.route("/product-catalog")
def product_list():
    query = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)
    sort = request.args.get("sort", "vendor")
    direction = request.args.get("direction", "asc")

    alias_counts = (
        db.select(
            ProductAlias.CatalogProductId,
            func.count(ProductAlias.ProductAliasId).label("AliasCount"),
        )
        .group_by(ProductAlias.CatalogProductId)
        .subquery()
    )
    alias_count = func.coalesce(alias_counts.c.AliasCount, 0)
    sort_columns = {
        "vendor": CatalogProduct.VendorName,
        "product": CatalogProduct.ProductName,
        "family": CatalogProduct.ProductFamily,
        "technology_category": CatalogProduct.TechnologyCategory,
        "alias_count": alias_count,
        "active": CatalogProduct.Active,
    }
    if sort not in sort_columns or direction not in {"asc", "desc"}:
        sort = "vendor"
        direction = "asc"
    if page is None or page < 1:
        page = 1

    statement = db.select(CatalogProduct).outerjoin(
        alias_counts,
        CatalogProduct.CatalogProductId == alias_counts.c.CatalogProductId,
    )
    if query:
        pattern = f"%{query}%"
        statement = statement.where(
            or_(
                CatalogProduct.VendorName.ilike(pattern),
                CatalogProduct.ProductName.ilike(pattern),
                CatalogProduct.ProductFamily.ilike(pattern),
                CatalogProduct.TechnologyCategory.ilike(pattern),
            )
        )

    sort_column = sort_columns[sort]
    order_by_expressions = _deduplicated_order_by(
        sort_column,
        direction,
        (
            CatalogProduct.VendorName,
            CatalogProduct.ProductName,
            CatalogProduct.CatalogProductId,
        ),
    )
    statement = statement.order_by(*order_by_expressions)

    pagination = db.paginate(statement, page=page, per_page=10, error_out=False)
    if pagination.pages and page > pagination.pages:
        pagination = db.paginate(
            statement, page=pagination.pages, per_page=10, error_out=False
        )

    product_ids = [
        product.CatalogProductId for product in pagination.items
    ]
    displayed_alias_counts = {}
    if product_ids:
        displayed_alias_counts = dict(
            db.session.execute(
                db.select(
                    ProductAlias.CatalogProductId,
                    func.count(ProductAlias.ProductAliasId),
                )
                .where(ProductAlias.CatalogProductId.in_(product_ids))
                .group_by(ProductAlias.CatalogProductId)
            ).all()
        )
    product_rows = [
        (
            product,
            displayed_alias_counts.get(product.CatalogProductId, 0),
        )
        for product in pagination.items
    ]

    return render_template(
        "catalog_products.html",
        product_rows=product_rows,
        pagination=pagination,
        q=query,
        sort=sort,
        direction=direction,
    )


@product_catalog_blueprint.route("/product-catalog/add", methods=["GET", "POST"])
def add_product():
    form_data = {
        "vendor_name": "",
        "product_name": "",
        "product_family": "",
        "technology_category": "",
        "description": "",
        "active": True,
    }
    errors = {}

    if request.method == "POST":
        form_data = _product_form_data()
        errors = _validate_product(form_data)
        if not errors:
            product = CatalogProduct()
            _apply_product_form(product, form_data)
            db.session.add(product)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                errors["product_name"] = (
                    "This vendor and product combination already exists."
                )
            else:
                flash("Catalog product added successfully.", "success")
                return redirect(
                    url_for(
                        "product_catalog.product_detail",
                        catalog_product_id=product.CatalogProductId,
                    )
                )

    return render_template(
        "catalog_product_form.html",
        page_title="Add Catalog Product",
        form_data=form_data,
        errors=errors,
    )


@product_catalog_blueprint.route(
    "/product-catalog/<int:catalog_product_id>"
)
def product_detail(catalog_product_id):
    product = db.get_or_404(CatalogProduct, catalog_product_id)
    aliases = db.session.execute(
        db.select(ProductAlias)
        .where(ProductAlias.CatalogProductId == catalog_product_id)
        .order_by(ProductAlias.Alias.asc(), ProductAlias.ProductAliasId.asc())
    ).scalars().all()
    linked_asset_count = db.session.scalar(
        db.select(func.count(Asset.AssetId)).where(
            Asset.CatalogProductId == catalog_product_id
        )
    ) or 0
    return render_template(
        "catalog_product_detail.html",
        product=product,
        aliases=aliases,
        linked_asset_count=linked_asset_count,
    )


@product_catalog_blueprint.route(
    "/product-catalog/<int:catalog_product_id>/edit",
    methods=["GET", "POST"],
)
def edit_product(catalog_product_id):
    product = db.get_or_404(CatalogProduct, catalog_product_id)
    errors = {}

    if request.method == "POST":
        form_data = _product_form_data()
        errors = _validate_product(
            form_data, excluded_product_id=catalog_product_id
        )
        if not errors:
            _apply_product_form(product, form_data)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                errors["product_name"] = (
                    "This vendor and product combination already exists."
                )
            else:
                flash("Catalog product updated successfully.", "success")
                return redirect(
                    url_for(
                        "product_catalog.product_detail",
                        catalog_product_id=catalog_product_id,
                    )
                )
    else:
        form_data = {
            "vendor_name": product.VendorName,
            "product_name": product.ProductName,
            "product_family": product.ProductFamily or "",
            "technology_category": product.TechnologyCategory or "",
            "description": product.Description or "",
            "active": bool(product.Active),
        }

    return render_template(
        "catalog_product_form.html",
        page_title="Edit Catalog Product",
        form_data=form_data,
        errors=errors,
    )


@product_catalog_blueprint.route(
    "/product-catalog/<int:catalog_product_id>/delete",
    methods=["POST"],
)
def delete_product(catalog_product_id):
    product = db.get_or_404(CatalogProduct, catalog_product_id)
    linked_asset = db.session.scalar(
        db.select(Asset.AssetId)
        .where(Asset.CatalogProductId == catalog_product_id)
        .limit(1)
    )
    if linked_asset is not None:
        flash(
            "Catalog product cannot be deleted because it is linked to assets.",
            "warning",
        )
        return redirect(
            url_for(
                "product_catalog.product_detail",
                catalog_product_id=catalog_product_id,
            )
        )

    try:
        db.session.delete(product)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("Catalog product cannot be deleted because it is in use.", "warning")
        return redirect(
            url_for(
                "product_catalog.product_detail",
                catalog_product_id=catalog_product_id,
            )
        )

    flash("Catalog product deleted successfully.", "success")
    return redirect(url_for("product_catalog.product_list"))


@product_catalog_blueprint.route(
    "/product-catalog/<int:catalog_product_id>/aliases/add",
    methods=["GET", "POST"],
)
def add_alias(catalog_product_id):
    product = db.get_or_404(CatalogProduct, catalog_product_id)
    form_data = {
        "alias": "",
        "alias_type": "",
        "active": True,
    }
    errors = {}

    if request.method == "POST":
        form_data = {
            "alias": request.form.get("alias", "").strip(),
            "alias_type": request.form.get("alias_type", "").strip(),
            "active": "active" in request.form,
        }
        if not form_data["alias"]:
            errors["alias"] = "Alias is required."
        elif len(form_data["alias"]) > 200:
            errors["alias"] = "Alias must be 200 characters or fewer."

        if len(form_data["alias_type"]) > 50:
            errors["alias_type"] = "Alias Type must be 50 characters or fewer."
        elif (
            form_data["alias_type"]
            and form_data["alias_type"] not in ALIAS_TYPES
        ):
            errors["alias_type"] = "Select a valid alias type."

        if (
            "alias" not in errors
            and _alias_exists(catalog_product_id, form_data["alias"])
        ):
            errors["alias"] = "This alias already exists for the product."

        if not errors:
            alias = ProductAlias(
                CatalogProductId=catalog_product_id,
                Alias=form_data["alias"],
                AliasType=form_data["alias_type"] or None,
                Active=form_data["active"],
            )
            db.session.add(alias)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                errors["alias"] = "This alias already exists for the product."
            else:
                flash("Product alias added successfully.", "success")
                return redirect(
                    url_for(
                        "product_catalog.product_detail",
                        catalog_product_id=catalog_product_id,
                    )
                )

    return render_template(
        "product_alias_form.html",
        product=product,
        alias_types=ALIAS_TYPES,
        form_data=form_data,
        errors=errors,
    )


@product_catalog_blueprint.route(
    "/product-catalog/<int:catalog_product_id>/aliases/"
    "<int:product_alias_id>/delete",
    methods=["POST"],
)
def delete_alias(catalog_product_id, product_alias_id):
    db.get_or_404(CatalogProduct, catalog_product_id)
    alias = db.get_or_404(ProductAlias, product_alias_id)
    if alias.CatalogProductId != catalog_product_id:
        abort(404)

    db.session.delete(alias)
    db.session.commit()
    flash("Product alias deleted successfully.", "success")
    return redirect(
        url_for(
            "product_catalog.product_detail",
            catalog_product_id=catalog_product_id,
        )
    )
