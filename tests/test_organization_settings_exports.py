from pathlib import Path

import pytest
from PIL import Image

from app import create_app
from app.exports.infographic_export import InfographicExporter
from app.exports.pdf_export import PDFExporter
from app.extensions import db
from app.models.system_setting import SystemSetting


class OrganizationSettingsTestConfig:
    TESTING = True
    SECRET_KEY = "organization-settings-test"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEFAULT_COMPANY_NAME = "Fallback Organization"
    DEFAULT_COMPANY_SHORT_NAME = "FALLBACK"
    DEFAULT_DEPARTMENT = "Fallback Department"
    DEFAULT_COMPANY_LOGO = ""
    DEFAULT_HEADER_TEXT = "Fallback Header"
    DEFAULT_FOOTER_TEXT = "Fallback Footer"
    DEFAULT_CLASSIFICATION = "ใช้ภายในองค์กร"


@pytest.fixture()
def app():
    application = create_app(OrganizationSettingsTestConfig)
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def threat():
    return {
        "ThreatId": 42,
        "Title": "Microsoft Edge security update",
        "Severity": "High",
        "CVE": "CVE-2026-4242",
        "CVSS": "8.8",
        "Source": "Vendor Advisory",
        "PublishedDate": "2026-07-24",
        "ReferenceUrl": "https://example.test/CVE-2026-4242",
    }


@pytest.fixture()
def infographic_content():
    return {
        "headline": "อัปเดตความปลอดภัย Microsoft Edge",
        "what_happened": "พบช่องโหว่ด้านความปลอดภัยใน Microsoft Edge",
        "why_it_matters": "ผู้โจมตีอาจใช้ช่องโหว่นี้เพื่อเข้าถึงข้อมูล",
        "actions": ["อัปเดตโปรแกรม", "รีสตาร์ตเครื่อง", "แจ้งเหตุผิดปกติ"],
        "avoid": ["อย่าเลื่อนการอัปเดต", "อย่าคลิกลิงก์แปลก", "อย่าปิดระบบป้องกัน"],
        "contact_it": "หากพบสิ่งผิดปกติ โปรดติดต่อฝ่าย IT",
    }


def _save_organization_settings(**overrides):
    values = {
        "CompanyName": "Saved Organization",
        "CompanyShortName": "SAVED",
        "Department": "Saved Technology Department",
        "CompanyLogo": "",
        "HeaderText": "Saved Header",
        "FooterText": "Saved Footer",
        "Classification": "Internal Use",
        "PaperSize": "A4",
        "PrimaryColor": "#0d6efd",
        "SecondaryColor": "#6c757d",
    }
    values.update(overrides)
    for key, value in values.items():
        setting = SystemSetting.query.filter_by(SettingKey=key).first()
        if setting is None:
            setting = SystemSetting(
                SettingKey=key,
                SettingGroup="Organization",
                IsActive=True,
            )
            db.session.add(setting)
        setting.SettingValue = value
    db.session.commit()


def _render_exports(threat, infographic_content):
    pdf, _ = PDFExporter.generate(
        threat=threat,
        executive_summary="สรุปเหตุการณ์สำหรับพนักงาน",
        business_impact=["อาจกระทบต่อข้อมูลและการทำงาน"],
        it_recommendation="โปรดติดตั้งอัปเดตที่ได้รับอนุมัติ",
    )
    png, _ = InfographicExporter.generate(
        threat=threat,
        infographic_content=infographic_content,
    )
    return pdf.getvalue(), png.getvalue()


def test_settings_form_creates_missing_organization_records(app):
    response = app.test_client().post(
        "/settings/",
        data={
            "CompanyName": "Configured Organization",
            "CompanyShortName": "CONFIG",
            "Department": "Configured Department",
            "CompanyLogo": "/static/configured-logo.png",
            "HeaderText": "Configured Header",
            "FooterText": "Configured Footer",
            "Theme": "Default",
            "PrimaryColor": "#0d6efd",
            "SecondaryColor": "#6c757d",
            "Classification": "Internal Use",
            "Language": "TH",
            "PaperSize": "A4",
        },
    )

    assert response.status_code == 302
    saved = {
        setting.SettingKey: setting.SettingValue
        for setting in SystemSetting.query.all()
    }
    assert saved["CompanyName"] == "Configured Organization"
    assert saved["CompanyShortName"] == "CONFIG"
    assert saved["Department"] == "Configured Department"
    assert saved["CompanyLogo"] == "/static/configured-logo.png"
    assert saved["HeaderText"] == "Configured Header"
    assert saved["FooterText"] == "Configured Footer"


def test_exporters_use_config_only_when_no_saved_settings_exist(app):
    settings = InfographicExporter._settings()

    assert settings["CompanyName"] == "Fallback Organization"
    assert settings["CompanyShortName"] == "FALLBACK"
    assert settings["Department"] == "Fallback Department"
    assert PDFExporter._setting(
        PDFExporter._load_settings(),
        "CompanyName",
        "DEFAULT_COMPANY_NAME",
        "",
    ) == "Fallback Organization"


def test_saved_settings_take_priority_for_both_exporters(app):
    _save_organization_settings()

    settings = InfographicExporter._settings()
    assert settings["CompanyName"] == "Saved Organization"
    assert settings["Department"] == "Saved Technology Department"
    assert settings["HeaderText"] == "Saved Header"
    assert settings["FooterText"] == "Saved Footer"
    assert PDFExporter._load_settings()["CompanyName"] == "Saved Organization"
    assert PDFExporter._load_settings()["Department"] == "Saved Technology Department"


@pytest.mark.parametrize(
    ("setting_key", "first_value", "second_value"),
    [
        ("CompanyName", "Organization Alpha", "Organization Beta"),
        ("Department", "Infrastructure Department", "Security Department"),
    ],
)
def test_changing_text_branding_changes_pdf_and_png(
    app,
    threat,
    infographic_content,
    setting_key,
    first_value,
    second_value,
):
    _save_organization_settings(**{setting_key: first_value})
    first_pdf, first_png = _render_exports(threat, infographic_content)

    _save_organization_settings(**{setting_key: second_value})
    second_pdf, second_png = _render_exports(threat, infographic_content)

    assert first_pdf != second_pdf
    assert first_png != second_png


def test_changing_logo_changes_pdf_and_png(
    app,
    threat,
    infographic_content,
    tmp_path,
):
    first_logo = Path(tmp_path) / "first-logo.png"
    second_logo = Path(tmp_path) / "second-logo.png"
    Image.new("RGBA", (120, 60), "#D7263D").save(first_logo)
    Image.new("RGBA", (120, 60), "#118AB2").save(second_logo)

    _save_organization_settings(CompanyLogo=str(first_logo))
    first_pdf, first_png = _render_exports(threat, infographic_content)

    _save_organization_settings(CompanyLogo=str(second_logo))
    second_pdf, second_png = _render_exports(threat, infographic_content)

    assert first_pdf != second_pdf
    assert first_png != second_png
