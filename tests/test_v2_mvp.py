from datetime import datetime
from io import BytesIO

from PIL import Image

from app import create_app
from app.extensions import db
from app.models.asset import Asset
from app.models.awareness_record import AwarenessRecord
from app.models.news_item import NewsItem
from app.models.threat import Threat
from app.models.vendor import Vendor
from app.services.relevance import assess_item, news_relevance, recommend


class Config:
    TESTING = True
    SECRET_KEY = "v2-mvp"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


def app_with_schema():
    app = create_app(Config)
    with app.app_context():
        connection = db.engine.raw_connection()
        connection.create_function(
            "SYSUTCDATETIME", 0, lambda: datetime.utcnow().isoformat(" ")
        )
        connection.close()
        db.create_all()
    return app


def test_matching_recommendations_and_phishing_relevance():
    cisco = Asset(AssetName="Core Switch", Vendor="Cisco", Product="Catalyst C9300")
    windows = Asset(AssetName="Laptops", Vendor="Microsoft", Product="Windows 11")
    advisory = Threat(
        Title="Cisco Catalyst C9300 IOS XE vulnerability", Severity="High", KEV=True
    )
    status, reason = assess_item(advisory, cisco)
    assert status == "Affected" and "c9300" in reason.lower()
    assert recommend(advisory, status)[0] == "Need Patch"
    assert assess_item(Threat(Title="Linux kernel vulnerability"), windows)[0] == "Not Affected"
    news = NewsItem(
        Title="Credential phishing campaign", Source="JPCERT",
        ReferenceUrl="https://example.test/phishing",
    )
    assert news_relevance(news, [windows])[0] is True
    assert recommend(news, "Not Affected")[0] == "Need Awareness"


def test_asset_news_crud_and_relevant_filter():
    app = app_with_schema()
    client = app.test_client()
    response = client.post(
        "/assets/add",
        data={
            "asset_name": "Windows fleet", "vendor": "Microsoft",
            "product": "Windows 11", "asset_type": "Software", "quantity": "25",
            "department": "Finance", "status": "Active",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200 and b"Windows fleet" in response.data
    response = client.post(
        "/news/add",
        data={
            "title": "Windows 11 security update", "source": "Microsoft",
            "reference_url": "https://example.test/windows", "severity": "High",
            "threat_type": "Advisory", "summary": "Windows 11 update is required.",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200 and b"Need Patch" in response.data
    assert b"Windows fleet" in response.data
    assert b"Matched asset" in response.data
    with app.app_context():
        db.session.add_all([
            Threat(Title="Windows 11 vulnerability", Severity="High"),
            Threat(Title="Linux-only vulnerability", Severity="High"),
        ])
        db.session.commit()
    response = client.get("/relevant-threats")
    assert b"Windows 11 vulnerability" in response.data
    assert b"Linux-only vulnerability" not in response.data


def test_news_lists_collected_threats_and_preserves_relevance_tabs():
    app = app_with_schema()
    client = app.test_client()
    empty = client.get("/news/")
    assert b"No news or threat records match this view." in empty.data
    with app.app_context():
        db.session.add_all(
            [
                Threat(
                    Title="Credential phishing campaign",
                    Source="NVD",
                    Severity="High",
                    CVE="CVE-2026-1000",
                ),
                Threat(
                    Title="Linux kernel maintenance advisory",
                    Source="NVD",
                    Severity="Low",
                    CVE="CVE-2026-1001",
                ),
            ]
        )
        db.session.commit()

    all_news = client.get("/news/")
    assert all_news.status_code == 200
    assert b"Total records: 2" in all_news.data
    assert b"Credential phishing campaign" in all_news.data
    assert b"Linux kernel maintenance advisory" in all_news.data
    assert b"/threats/" in all_news.data
    assert b"/awareness/create/threat/" in all_news.data

    relevant = client.get("/news/?relevance=relevant")
    assert b"Total records: 1" in relevant.data
    assert b"Credential phishing campaign" in relevant.data
    assert b"Linux kernel maintenance advisory" not in relevant.data

    not_relevant = client.get("/news/?relevance=not-relevant")
    assert b"Total records: 1" in not_relevant.data
    assert b"Linux kernel maintenance advisory" in not_relevant.data
    assert b"Credential phishing campaign" not in not_relevant.data


def test_relevant_threats_paginates_and_preserves_filter_and_page_size():
    app = app_with_schema()
    client = app.test_client()
    with app.app_context():
        db.session.add(
            Asset(
                AssetName="Windows fleet",
                Vendor="Microsoft",
                Product="Windows 11",
                Status="Active",
            )
        )
        db.session.add_all(
            [
                Threat(
                    Title=f"Windows 11 vulnerability {index:03d}",
                    Severity="High",
                    PublishedDate=datetime(2026, 7, 24),
                )
                for index in range(60)
            ]
        )
        db.session.commit()

    first_page = client.get("/relevant-threats?filter=patch")
    assert first_page.status_code == 200
    assert b"Total records: 60" in first_page.data
    assert first_page.data.count(b"Generate Awareness") == 25
    assert b"per_page=25" in first_page.data

    second_page = client.get(
        "/relevant-threats?filter=patch&page=2&per_page=25"
    )
    assert second_page.status_code == 200
    assert second_page.data.count(b"Generate Awareness") == 25
    assert b"filter=patch" in second_page.data

    larger_page = client.get(
        "/relevant-threats?filter=patch&page=1&per_page=50"
    )
    assert larger_page.data.count(b"Generate Awareness") == 50


def test_relevant_threats_search_filters_and_pagination_preserve_query():
    app = app_with_schema()
    client = app.test_client()
    with app.app_context():
        vendor = Vendor(VendorName="Fortinet")
        asset = Asset(
            AssetName="Branch Firewall",
            Vendor="Fortinet",
            Product="FortiGate",
            Status="Active",
        )
        db.session.add_all([vendor, asset])
        db.session.flush()
        db.session.add_all(
            [
                Threat(
                    Title=f"FortiGate security update {index:03d}",
                    VendorId=vendor.VendorId,
                    Source="Fortinet PSIRT",
                    Summary="Fortinet firewall vulnerability",
                    CVE=f"CVE-2026-{2000 + index}",
                    Severity="High",
                )
                for index in range(55)
            ]
            + [
                Threat(
                    Title="Unrelated Linux advisory",
                    Source="NVD",
                    Severity="Low",
                )
            ]
        )
        db.session.commit()
        vendor_id = vendor.VendorId
        asset_id = asset.AssetId

    filtered = client.get(
        "/relevant-threats",
        query_string={
            "filter": "all",
            "q": "FortiGate",
            "vendor_id": vendor_id,
            "severity": "High",
            "recommendation": "Need Patch",
            "impact": "Affected",
            "asset_id": asset_id,
            "page": 2,
            "per_page": 25,
        },
    )
    assert filtered.status_code == 200
    assert b"Total records: 55" in filtered.data
    assert filtered.data.count(b"Generate Awareness") == 25
    for expected in (
        b"q=FortiGate",
        b"severity=High",
        b"recommendation=Need+Patch",
        b"impact=Affected",
        f"vendor_id={vendor_id}".encode(),
        f"asset_id={asset_id}".encode(),
        b"per_page=50",
        b"per_page=100",
    ):
        assert expected in filtered.data

    cve_search = client.get(
        "/relevant-threats",
        query_string={"filter": "all", "q": "CVE-2026-2001"},
    )
    assert b"Total records: 1" in cve_search.data
    assert b"FortiGate security update 001" in cve_search.data

    reset = client.get("/relevant-threats?filter=all")
    assert b"Total records: 56" in reset.data


def test_awareness_edit_preview_pdf_and_png():
    app = app_with_schema()
    client = app.test_client()
    with app.app_context():
        news = NewsItem(
            Title="Phishing alert", Source="JPCERT",
            ReferenceUrl="https://example.test/alert", Severity="High",
            Summary="Fake login messages target employees.", IsRelevant=True,
        )
        db.session.add(news)
        db.session.commit()
        news_id = news.NewsItemId
    assert client.get(f"/awareness/create/news/{news_id}").status_code == 302
    with app.app_context():
        record_id = db.session.execute(
            db.select(AwarenessRecord.AwarenessRecordId)
        ).scalar_one()
    payload = {
        "Title": "ระวังอีเมลปลอม", "ThaiExplanation": "อีเมลปลอมกำลังแพร่ระบาด",
        "WhatHappened": "ผู้โจมตีส่งลิงก์เข้าสู่ระบบปลอม", "WhoAffected": "พนักงานทุกคน",
        "MustDo": "ตรวจสอบผู้ส่ง\nแจ้งฝ่าย IT", "MustNotDo": "ห้ามคลิกลิงก์",
        "ReportToIT": "โทรติดต่อฝ่าย IT", "ReferenceUrl": "https://example.test/alert",
        "Severity": "High", "Status": "Ready", "DocumentVersion": "1.1",
    }
    response = client.post(
        f"/awareness/records/{record_id}/edit", data=payload, follow_redirects=True
    )
    assert "ระวังอีเมลปลอม".encode() in response.data
    pdf = client.get(f"/awareness/records/{record_id}/pdf")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF")
    png = client.get(f"/awareness/records/{record_id}/png")
    with Image.open(BytesIO(png.data)) as image:
        assert image.format == "PNG" and image.size == (1240, 1754)
