import csv
import logging
from collections import defaultdict
from pathlib import Path

from app.extensions import db
from app.models.asset import Asset
from app.models.catalog_product import CatalogProduct


LOGGER = logging.getLogger(__name__)
MAX_FILE_SIZE = 10 * 1024 * 1024
REQUIRED_HEADERS = (
    "AssetName",
    "AssetType",
    "Environment",
    "Criticality",
    "CatalogVendor",
    "CatalogProduct",
)
OPTIONAL_HEADERS = (
    "IPAddress",
    "Hostname",
    "OperatingSystem",
    "Owner",
    "Location",
    "Description",
    "Enabled",
)
FIELD_LIMITS = {
    "AssetName": 200,
    "AssetType": 100,
    "Environment": 100,
    "CatalogVendor": 100,
    "CatalogProduct": 200,
    "Owner": 200,
    "Location": 255,
}
TRUE_VALUES = {"1", "true", "yes"}
FALSE_VALUES = {"0", "false", "no"}


class AssetImportValidationError(ValueError):
    """A normal file-level validation error safe to show to the user."""


class RowValidationError(ValueError):
    """A normal row-level validation error."""


class AssetImportService:
    """Validate and atomically import Asset inventory from UTF-8 CSV."""

    def __init__(self, session=None):
        self.session = session or db.session

    def import_file(self, file_path, *, dry_run=False):
        path = self._validated_path(file_path)
        transaction = self.session.begin()
        try:
            catalog = self._catalog_index()
            existing_assets = self._asset_index()
            result, plans = self._read_and_plan(
                path,
                catalog,
                existing_assets,
                dry_run=dry_run,
            )
            if dry_run:
                transaction.rollback()
            else:
                self._apply_plan(plans)
                transaction.commit()
            return result
        except Exception:
            self.session.rollback()
            raise

    @staticmethod
    def _validated_path(file_path):
        if not file_path:
            raise AssetImportValidationError("CSV file path is required.")
        path = Path(file_path)
        if not path.exists():
            raise AssetImportValidationError(
                f"CSV file does not exist: {path}"
            )
        if not path.is_file():
            raise AssetImportValidationError(
                f"CSV path is not a file: {path}"
            )
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise AssetImportValidationError(
                f"CSV file cannot be inspected: {path}"
            ) from exc
        if size > MAX_FILE_SIZE:
            raise AssetImportValidationError(
                "CSV file exceeds the 10 MB size limit."
            )
        return path

    def _catalog_index(self):
        products = self.session.execute(
            self._catalog_query()
        ).all()
        index = defaultdict(list)
        for product in products:
            key = self._catalog_key(
                product.VendorName, product.ProductName
            )
            index[key].append(product)
        return index

    @staticmethod
    def _catalog_query():
        return (
            db.select(
                CatalogProduct.CatalogProductId,
                CatalogProduct.VendorName,
                CatalogProduct.ProductName,
            )
            .where(CatalogProduct.Active == True)
            .order_by(CatalogProduct.CatalogProductId.asc())
        )

    def _asset_index(self):
        assets = self.session.execute(
            db.select(Asset).order_by(Asset.AssetId.asc())
        ).scalars().all()
        index = defaultdict(list)
        for asset in assets:
            index[self._key(asset.AssetName)].append(asset)
        return index

    def _read_and_plan(
        self,
        path,
        catalog,
        existing_assets,
        *,
        dry_run,
    ):
        result = {
            "total_rows": 0,
            "valid_rows": 0,
            "created": 0,
            "updated": 0,
            "skipped": 0,
            "errors": 0,
            "dry_run": bool(dry_run),
            "row_errors": [],
        }
        plans = {}
        seen_names = set()

        try:
            handle = path.open(
                "r", encoding="utf-8-sig", newline=""
            )
        except (OSError, UnicodeError) as exc:
            raise AssetImportValidationError(
                f"CSV file cannot be opened as UTF-8: {path}"
            ) from exc

        try:
            with handle:
                reader = csv.DictReader(handle)
                headers = self._validated_headers(reader.fieldnames)
                for row_number, raw_row in enumerate(reader, start=2):
                    row = self._normalized_row(raw_row, headers)
                    if self._blank_row(row):
                        continue
                    result["total_rows"] += 1
                    try:
                        values = self._validated_row(row)
                        product = self._catalog_product(
                            catalog,
                            values["CatalogVendor"],
                            values["CatalogProduct"],
                        )
                        name_key = self._key(values["AssetName"])
                        matching_assets = existing_assets.get(
                            name_key, []
                        )
                        if len(matching_assets) > 1:
                            raise RowValidationError(
                                "multiple existing Assets match AssetName "
                                "case-insensitively"
                            )
                        existing = (
                            matching_assets[0]
                            if matching_assets
                            else None
                        )
                        plan = self._asset_values(values, product)
                        plans[name_key] = (existing, plan)
                        result["valid_rows"] += 1
                        if existing is not None or name_key in seen_names:
                            result["updated"] += 1
                        else:
                            result["created"] += 1
                        seen_names.add(name_key)
                    except RowValidationError as exc:
                        result["skipped"] += 1
                        result["errors"] += 1
                        result["row_errors"].append(
                            {
                                "row_number": row_number,
                                "reason": str(exc),
                            }
                        )
        except UnicodeDecodeError as exc:
            raise AssetImportValidationError(
                "CSV file must be valid UTF-8."
            ) from exc
        except csv.Error as exc:
            raise AssetImportValidationError(
                f"CSV parsing failed: {exc}"
            ) from exc
        return result, plans

    @staticmethod
    def _validated_headers(fieldnames):
        if fieldnames is None:
            raise AssetImportValidationError(
                "CSV file is empty or has no header row."
            )
        headers = [
            header.strip() if header is not None else ""
            for header in fieldnames
        ]
        if any(not header for header in headers):
            raise AssetImportValidationError(
                "CSV contains an empty header name."
            )
        if len(set(headers)) != len(headers):
            raise AssetImportValidationError(
                "CSV contains duplicate header names."
            )
        missing = [
            header for header in REQUIRED_HEADERS if header not in headers
        ]
        if missing:
            raise AssetImportValidationError(
                "CSV is missing required headers: "
                + ", ".join(missing)
            )
        return headers

    @staticmethod
    def _normalized_row(raw_row, headers):
        row = {}
        for original_header, header in zip(
            raw_row.keys(), headers
        ):
            value = raw_row.get(original_header)
            row[header] = value.strip() if value is not None else ""
        return row

    @staticmethod
    def _blank_row(row):
        return not any(value for value in row.values())

    def _validated_row(self, row):
        for field in REQUIRED_HEADERS:
            if not row.get(field, ""):
                raise RowValidationError(f"{field} is required")
        for field, maximum in FIELD_LIMITS.items():
            if len(row.get(field, "")) > maximum:
                raise RowValidationError(
                    f"{field} must be {maximum} characters or fewer"
                )
        values = {
            header: row.get(header, "")
            for header in (*REQUIRED_HEADERS, *OPTIONAL_HEADERS)
        }
        values["Criticality"] = self._boolean(
            values["Criticality"], "Criticality", required=True
        )
        values["Enabled"] = self._boolean(
            values["Enabled"], "Enabled", default=True
        )
        return values

    @staticmethod
    def _boolean(value, field, *, required=False, default=None):
        normalized = (value or "").strip().casefold()
        if not normalized:
            if required:
                raise RowValidationError(f"{field} is required")
            return default
        if normalized in TRUE_VALUES:
            return True
        if normalized in FALSE_VALUES:
            return False
        raise RowValidationError(
            f"{field} must be one of: "
            "true, false, yes, no, 1, 0"
        )

    def _catalog_product(self, catalog, vendor_name, product_name):
        matches = catalog.get(
            self._catalog_key(vendor_name, product_name), []
        )
        if not matches:
            raise RowValidationError(
                "Catalog Product not found for "
                f"{vendor_name} / {product_name}"
            )
        if len(matches) > 1:
            raise RowValidationError(
                "multiple Catalog Products match "
                f"{vendor_name} / {product_name}"
            )
        return matches[0]

    @staticmethod
    def _asset_values(values, product):
        notes = []
        if values["Description"]:
            notes.append(values["Description"])
        metadata = (
            ("IP Address", values["IPAddress"]),
            ("Hostname", values["Hostname"]),
            ("Operating System", values["OperatingSystem"]),
        )
        notes.extend(
            f"{label}: {value}" for label, value in metadata if value
        )
        return {
            "AssetName": values["AssetName"],
            "Vendor": product.VendorName,
            "Product": product.ProductName,
            "AssetType": values["AssetType"],
            "Critical": values["Criticality"],
            "Environment": values["Environment"],
            "Owner": values["Owner"] or None,
            "Location": values["Location"] or None,
            "Status": "Active" if values["Enabled"] else "Disabled",
            "Notes": "\n".join(notes) or None,
            "CatalogProductId": product.CatalogProductId,
        }

    def _apply_plan(self, plans):
        for existing, values in plans.values():
            asset = existing or Asset()
            for attribute, value in values.items():
                setattr(asset, attribute, value)
            if existing is None:
                self.session.add(asset)
        self.session.flush()

    @staticmethod
    def _key(value):
        return (value or "").strip().casefold()

    @classmethod
    def _catalog_key(cls, vendor_name, product_name):
        return cls._key(vendor_name), cls._key(product_name)





