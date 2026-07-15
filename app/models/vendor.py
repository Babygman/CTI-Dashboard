from app.extensions import db


class Vendor(db.Model):
    __tablename__ = "Vendors"

    VendorId = db.Column(db.Integer, primary_key=True)
    VendorName = db.Column(db.String(100), nullable=False)
    Category = db.Column(db.String(100))
    Website = db.Column(db.String(255))
    Enabled = db.Column(db.Boolean)
