from collections import defaultdict

from app.repositories import (
    CatalogProductRepository,
    ProductAliasRepository,
)


class ProductNormalizer:
    """Resolve a feed vendor/product name to one active catalog product."""

    def __init__(
        self,
        catalog_product_repository=None,
        product_alias_repository=None,
    ):
        self.catalog_product_repository = (
            catalog_product_repository or CatalogProductRepository()
        )
        self.product_alias_repository = (
            product_alias_repository or ProductAliasRepository()
        )
        self._preloaded_indexes = None

    def preload(self):
        """Load the active catalog and alias tables once for batch matching."""
        self._preloaded_indexes = self._load_indexes()
        return self

    def normalize(self, vendor_name, product_name):
        input_vendor = (vendor_name or "").strip()
        input_product = (product_name or "").strip()
        if not input_product:
            return self._unmatched_result(input_vendor, input_product)

        # Dashboard batches use the preloaded indexes. Standalone callers retain
        # fresh-per-call behavior for backward compatibility with mutable data.
        indexes = self._preloaded_indexes or self._load_indexes()
        folded_product = input_product.casefold()
        alias_candidates = indexes["aliases_by_name"].get(
            folded_product, ()
        )
        product_candidates = indexes["products_by_name"].get(
            folded_product, ()
        )

        ordered_matches = (
            (
                self._filter_aliases(
                    alias_candidates,
                    input_vendor,
                    input_product,
                    exact_vendor=True,
                    exact_product=True,
                    require_vendor=True,
                ),
                "Vendor + Exact Alias",
                100,
            ),
            (
                self._filter_aliases(
                    alias_candidates,
                    input_vendor,
                    input_product,
                    exact_vendor=True,
                    exact_product=True,
                    require_vendor=False,
                ),
                "Exact Alias",
                95,
            ),
            (
                self._filter_products(
                    product_candidates,
                    input_vendor,
                    input_product,
                    exact_vendor=True,
                    exact_product=True,
                    require_vendor=True,
                ),
                "Vendor + ProductName",
                100,
            ),
            (
                self._filter_products(
                    product_candidates,
                    input_vendor,
                    input_product,
                    exact_vendor=True,
                    exact_product=True,
                    require_vendor=False,
                ),
                "Exact ProductName",
                95,
            ),
            (
                self._filter_aliases(
                    alias_candidates,
                    input_vendor,
                    input_product,
                    exact_vendor=False,
                    exact_product=False,
                    require_vendor=True,
                ),
                "Case-insensitive Vendor + Alias",
                90,
            ),
            (
                self._filter_aliases(
                    alias_candidates,
                    input_vendor,
                    input_product,
                    exact_vendor=False,
                    exact_product=False,
                    require_vendor=False,
                ),
                "Case-insensitive Alias",
                85,
            ),
            (
                self._filter_products(
                    product_candidates,
                    input_vendor,
                    input_product,
                    exact_vendor=False,
                    exact_product=False,
                    require_vendor=True,
                ),
                "Case-insensitive Vendor + ProductName",
                90,
            ),
            (
                self._filter_products(
                    product_candidates,
                    input_vendor,
                    input_product,
                    exact_vendor=False,
                    exact_product=False,
                    require_vendor=False,
                ),
                "Case-insensitive ProductName",
                85,
            ),
        )

        for candidates, match_type, confidence in ordered_matches:
            match = self._unique_candidate(candidates)
            if match is not None:
                product, alias = match
                return {
                    "matched": True,
                    "catalog_product_id": product.CatalogProductId,
                    "vendor_name": product.VendorName,
                    "product_name": product.ProductName,
                    "match_type": match_type,
                    "matched_alias": alias.Alias if alias is not None else None,
                    "confidence": confidence,
                }

        return self._unmatched_result(input_vendor, input_product)

    def _load_indexes(self):
        products = self.catalog_product_repository.list_active()
        aliases = self.product_alias_repository.list_active()
        products_by_id = {
            product.CatalogProductId: product for product in products
        }
        products_by_name = defaultdict(list)
        aliases_by_name = defaultdict(list)

        # These dictionaries replace the former per-threat SQL lookups.
        for product in products:
            products_by_name[product.ProductName.casefold()].append(product)
        for alias in aliases:
            product = products_by_id.get(alias.CatalogProductId)
            if product is not None:
                aliases_by_name[alias.Alias.casefold()].append(
                    (alias, product)
                )

        return {
            "products_by_name": dict(products_by_name),
            "aliases_by_name": dict(aliases_by_name),
        }

    @classmethod
    def _filter_aliases(
        cls,
        candidates,
        vendor_name,
        product_name,
        *,
        exact_vendor,
        exact_product,
        require_vendor,
    ):
        matches = []
        for alias, product in candidates:
            if not cls._values_match(alias.Alias, product_name, exact_product):
                continue
            if require_vendor:
                if not vendor_name or not cls._values_match(
                    product.VendorName, vendor_name, exact_vendor
                ):
                    continue
            matches.append((product, alias))
        return matches

    @classmethod
    def _filter_products(
        cls,
        candidates,
        vendor_name,
        product_name,
        *,
        exact_vendor,
        exact_product,
        require_vendor,
    ):
        matches = []
        for product in candidates:
            if not cls._values_match(
                product.ProductName, product_name, exact_product
            ):
                continue
            if require_vendor:
                if not vendor_name or not cls._values_match(
                    product.VendorName, vendor_name, exact_vendor
                ):
                    continue
            matches.append((product, None))
        return matches

    @staticmethod
    def _values_match(catalog_value, input_value, exact):
        if exact:
            return catalog_value == input_value
        return catalog_value.casefold() == input_value.casefold()

    @staticmethod
    def _unique_candidate(candidates):
        products = {}
        for product, alias in candidates:
            products.setdefault(product.CatalogProductId, (product, alias))
        if len(products) == 1:
            return next(iter(products.values()))
        return None

    @staticmethod
    def _unmatched_result(vendor_name, product_name):
        return {
            "matched": False,
            "catalog_product_id": None,
            "vendor_name": vendor_name,
            "product_name": product_name,
            "match_type": None,
            "matched_alias": None,
            "confidence": 0,
        }
