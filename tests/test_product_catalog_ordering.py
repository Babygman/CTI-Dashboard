import unittest

from sqlalchemy import func
from sqlalchemy.dialects import mssql

from app.extensions import db
from app.models.catalog_product import CatalogProduct
from app.models.product_alias import ProductAlias
from app.product_catalog.routes import _deduplicated_order_by
from tests.support import create_test_app


class ProductCatalogOrderByTests(unittest.TestCase):
    @staticmethod
    def _compiled_order_clause(sort_column, direction="asc"):
        alias_counts = (
            db.select(
                ProductAlias.CatalogProductId,
                func.count(ProductAlias.ProductAliasId).label("AliasCount"),
            )
            .group_by(ProductAlias.CatalogProductId)
            .subquery()
        )
        statement = db.select(CatalogProduct).outerjoin(
            alias_counts,
            CatalogProduct.CatalogProductId
            == alias_counts.c.CatalogProductId,
        )
        order_by = _deduplicated_order_by(
            sort_column,
            direction,
            (
                CatalogProduct.VendorName,
                CatalogProduct.ProductName,
                CatalogProduct.CatalogProductId,
            ),
        )
        sql = str(
            statement.order_by(*order_by).compile(dialect=mssql.dialect())
        )
        return sql.split("ORDER BY", 1)[1].strip()

    def test_default_sql_server_order_by_has_no_duplicate_vendor(self):
        order_clause = self._compiled_order_clause(
            CatalogProduct.VendorName
        )

        self.assertEqual(
            order_clause,
            "[CatalogProducts].[VendorName] ASC, "
            "[CatalogProducts].[ProductName] ASC, "
            "[CatalogProducts].[CatalogProductId] ASC",
        )
        self.assertEqual(
            order_clause.count("[CatalogProducts].[VendorName]"),
            1,
        )

    def test_selected_tie_breaker_columns_are_not_appended_twice(self):
        cases = (
            (
                CatalogProduct.VendorName,
                "desc",
                "[CatalogProducts].[VendorName] DESC",
            ),
            (
                CatalogProduct.ProductName,
                "asc",
                "[CatalogProducts].[ProductName] ASC",
            ),
            (
                CatalogProduct.CatalogProductId,
                "desc",
                "[CatalogProducts].[CatalogProductId] DESC",
            ),
        )

        for sort_column, direction, first_expression in cases:
            with self.subTest(
                column=sort_column.key,
                direction=direction,
            ):
                order_clause = self._compiled_order_clause(
                    sort_column, direction
                )
                expressions = [
                    expression.strip()
                    for expression in order_clause.split(",")
                ]

                self.assertEqual(expressions[0], first_expression)
                self.assertEqual(len(expressions), len(set(expressions)))
                self.assertEqual(
                    order_clause.count(
                        "[CatalogProducts].[VendorName]"
                    ),
                    1,
                )
                self.assertEqual(
                    order_clause.count(
                        "[CatalogProducts].[ProductName]"
                    ),
                    1,
                )
                self.assertEqual(
                    order_clause.count(
                        "[CatalogProducts].[CatalogProductId]"
                    ),
                    1,
                )


class ProductCatalogPaginationRegressionTests(unittest.TestCase):
    def setUp(self):
        self.app = create_test_app()
        self.context = self.app.app_context()
        self.context.push()
        db.session.add_all(
            [
                CatalogProduct(
                    VendorName=f"Vendor {number:02d}",
                    ProductName=f"Product {number:02d}",
                    Active=True,
                )
                for number in range(12)
            ]
        )
        db.session.commit()

    def tearDown(self):
        engine = db.engine
        db.session.remove()
        self.context.pop()
        engine.dispose()

    def test_default_sorting_and_second_page(self):
        response = self.app.test_client().get(
            "/product-catalog?page=2"
        )
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Vendor 10", body)
        self.assertIn("Vendor 11", body)
        self.assertNotIn("Vendor 00", body)


if __name__ == "__main__":
    unittest.main()