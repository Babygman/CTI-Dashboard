from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from app.extensions import db
from app.models.system_setting import SystemSetting


settings_bp = Blueprint(
    "settings",
    __name__,
    url_prefix="/settings",
)

SETTING_METADATA = {
    "CompanyName": ("Organization", "Organization name"),
    "CompanyShortName": ("Organization", "Organization short name"),
    "Department": ("Organization", "Department name"),
    "CompanyLogo": ("Organization", "Organization logo path"),
    "HeaderText": ("Organization", "Awareness document header text"),
    "FooterText": ("Organization", "Awareness document footer text"),
    "Theme": ("Branding", "Document theme"),
    "PrimaryColor": ("Branding", "Primary brand color"),
    "SecondaryColor": ("Branding", "Secondary brand color"),
    "Classification": ("Document", "Default document classification"),
    "Language": ("Document", "Default document language"),
    "PaperSize": ("Document", "Default paper size"),
}

SETTING_DEFAULTS = {
    "CompanyName": ("DEFAULT_COMPANY_NAME", ""),
    "CompanyShortName": ("DEFAULT_COMPANY_SHORT_NAME", ""),
    "Department": ("DEFAULT_DEPARTMENT", ""),
    "CompanyLogo": ("DEFAULT_COMPANY_LOGO", ""),
    "HeaderText": ("DEFAULT_HEADER_TEXT", ""),
    "FooterText": ("DEFAULT_FOOTER_TEXT", ""),
    "Theme": (None, "Default"),
    "PrimaryColor": (None, "#0d6efd"),
    "SecondaryColor": (None, "#6c757d"),
    "Classification": ("DEFAULT_CLASSIFICATION", "ใช้ภายในองค์กร"),
    "Language": (None, "TH"),
    "PaperSize": (None, "A4"),
}


@settings_bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        for setting_key, (setting_group, description) in SETTING_METADATA.items():
            setting_value = request.form.get(setting_key, "").strip()

            setting = SystemSetting.query.filter_by(
                SettingKey=setting_key,
            ).first()

            if setting:
                setting.SettingValue = setting_value
                setting.SettingGroup = setting_group
                setting.Description = description
                setting.IsActive = True
            else:
                db.session.add(
                    SystemSetting(
                        SettingKey=setting_key,
                        SettingValue=setting_value,
                        SettingGroup=setting_group,
                        Description=description,
                        IsActive=True,
                    )
                )

        db.session.commit()

        flash(
            "Settings saved successfully.",
            "success",
        )

        return redirect(url_for("settings.index"))

    settings = (
        SystemSetting.query
        .filter_by(IsActive=True)
        .order_by(
            SystemSetting.SettingGroup,
            SystemSetting.SettingKey,
        )
        .all()
    )

    settings_map = {
        setting_key: (
            current_app.config.get(config_key, default)
            if config_key
            else default
        )
        for setting_key, (config_key, default) in SETTING_DEFAULTS.items()
    }
    settings_map.update({
        setting.SettingKey: setting.SettingValue or ""
        for setting in settings
    })

    return render_template(
        "settings/index.html",
        settings=settings_map,
    )
