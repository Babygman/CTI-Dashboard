from app import create_app
from app.extensions import db


class TestConfig:
    TESTING = True
    SECRET_KEY = "normalizer-test"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


def create_test_app():
    app = create_app(TestConfig)
    with app.app_context():
        connection = db.engine.raw_connection()
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            """
            CREATE TABLE CatalogProducts (
                CatalogProductId INTEGER PRIMARY KEY AUTOINCREMENT,
                VendorName VARCHAR(100) NOT NULL,
                ProductName VARCHAR(200) NOT NULL,
                ProductFamily VARCHAR(100),
                TechnologyCategory VARCHAR(100),
                Description TEXT,
                Active BOOLEAN NOT NULL DEFAULT 1,
                CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (VendorName, ProductName)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE ProductAliases (
                ProductAliasId INTEGER PRIMARY KEY AUTOINCREMENT,
                CatalogProductId INTEGER NOT NULL,
                Alias VARCHAR(200) NOT NULL,
                AliasType VARCHAR(50),
                Active BOOLEAN NOT NULL DEFAULT 1,
                CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (CatalogProductId)
                    REFERENCES CatalogProducts(CatalogProductId)
                    ON DELETE CASCADE,
                UNIQUE (CatalogProductId, Alias)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE Assets (
                AssetId INTEGER PRIMARY KEY AUTOINCREMENT,
                AssetName VARCHAR(200) NOT NULL,
                Vendor VARCHAR(100),
                Product VARCHAR(200),
                Version VARCHAR(100),
                AssetType VARCHAR(100),
                Quantity INTEGER NOT NULL DEFAULT 1,
                Department VARCHAR(200),
                Critical BOOLEAN NOT NULL DEFAULT 0,
                Environment VARCHAR(100),
                Owner VARCHAR(200),
                Location VARCHAR(255),
                Status VARCHAR(50) NOT NULL DEFAULT 'Active',
                Notes TEXT,
                CreatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UpdatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CatalogProductId INTEGER,
                FOREIGN KEY (CatalogProductId)
                    REFERENCES CatalogProducts(CatalogProductId)
            )
            """
        )
        connection.commit()
        connection.close()
    return app
