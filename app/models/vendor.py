from app.extensions import db


class Vendor(db.Model):
    __tablename__ = "Vendors"

    VendorId = db.Column(db.Integer, primary_key=True)
    VendorName = db.Column(db.Unicode(100), nullable=False)
    Category = db.Column(db.Unicode(100))
    Website = db.Column(db.Unicode(255))
    Enabled = db.Column(
        db.Boolean, nullable=True, server_default=db.text("1")
    )
