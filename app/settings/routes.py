from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.extensions import db
from app.models.system_setting import SystemSetting


settings_bp = Blueprint(
    "settings",
    __name__,
    url_prefix="/settings",
)


@settings_bp.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        editable_keys = [
            "CompanyName",
            "CompanyShortName",
            "Department",
            "CompanyLogo",
            "Theme",
            "PrimaryColor",
            "SecondaryColor",
            "Classification",
            "Language",
            "PaperSize",
        ]

        for setting_key in editable_keys:
            setting_value = request.form.get(setting_key, "").strip()

            setting = SystemSetting.query.filter_by(
                SettingKey=setting_key,
                IsActive=True,
            ).first()

            if setting:
                setting.SettingValue = setting_value

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
        setting.SettingKey: setting.SettingValue or ""
        for setting in settings
    }

    return render_template(
        "settings/index.html",
        settings=settings_map,
    )