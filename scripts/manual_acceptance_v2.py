"""Safe, isolated CTI Dashboard v2 acceptance scenario."""
import os
import sys
from datetime import datetime
from pathlib import Path

os.environ["SQLALCHEMY_DATABASE_URI"] = "sqlite:////tmp/cti_dashboard_v2_acceptance.sqlite"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models.awareness_record import AwarenessRecord  # noqa: E402
from app.models.threat import Threat  # noqa: E402


def main():
    app = create_app()
    with app.app_context():
        connection = db.engine.raw_connection()
        connection.create_function(
            "SYSUTCDATETIME", 0, lambda: datetime.utcnow().isoformat(" ")
        )
        connection.close()
        db.drop_all()
        db.create_all()

    client = app.test_client()
    assets = (
        ("FortiGate", "Fortinet", "FortiGate", "Hardware"),
        ("Cisco C9300", "Cisco", "Catalyst C9300", "Hardware"),
        ("Ruckus R650", "Ruckus", "R650", "Hardware"),
        ("Windows 10", "Microsoft", "Windows 10", "Software"),
        ("Windows 11", "Microsoft", "Windows 11", "Software"),
        ("AutoCAD 2024", "Autodesk", "AutoCAD 2024", "Software"),
    )
    for name, vendor, product, asset_type in assets:
        response = client.post(
            "/assets/add",
            data={
                "asset_name": name, "vendor": vendor, "product": product,
                "asset_type": asset_type, "quantity": "1", "status": "Active",
            },
        )
        assert response.status_code == 302

    with app.app_context():
        threat = Threat(
            Title="Cisco Catalyst C9300 IOS XE critical vulnerability",
            Source="Cisco", Severity="Critical", CVE="CVE-2026-9300", KEV=True,
            ReferenceUrl="https://example.test/cisco-c9300",
            Summary="A vulnerability affects Cisco Catalyst C9300 running IOS XE.",
        )
        db.session.add(threat)
        db.session.commit()
        threat_id = threat.ThreatId

    assert client.get("/").status_code == 200
    relevant = client.get("/relevant-threats")
    assert relevant.status_code == 200
    assert b"Cisco C9300" in relevant.data and b"Need Patch" in relevant.data
    response = client.get(f"/awareness/create/threat/{threat_id}")
    assert response.status_code == 302
    with app.app_context():
        record_id = db.session.execute(
            db.select(AwarenessRecord.AwarenessRecordId)
        ).scalar_one()

    preview = client.get(f"/awareness/records/{record_id}/preview")
    assert preview.status_code == 200
    pdf = client.get(f"/awareness/records/{record_id}/pdf")
    png = client.get(f"/awareness/records/{record_id}/png")
    assert pdf.data.startswith(b"%PDF") and png.data.startswith(b"\x89PNG")
    Path("/tmp/cti_v2_acceptance.pdf").write_bytes(pdf.data)
    Path("/tmp/cti_v2_acceptance.png").write_bytes(png.data)
    print("PASS: 6 assets, relevant match, Need Patch, awareness preview, PDF, PNG")
    print("/tmp/cti_v2_acceptance.pdf")
    print("/tmp/cti_v2_acceptance.png")


if __name__ == "__main__":
    main()
