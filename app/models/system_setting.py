from __future__ import annotations

from datetime import datetime
from typing import Any

from app.extensions import db


class SystemSetting(db.Model):
    __tablename__ = "SystemSettings"

    SettingId = db.Column(
        db.Integer,
        primary_key=True,
        autoincrement=True,
    )

    SettingKey = db.Column(
        db.String(100),
        nullable=False,
        unique=True,
        index=True,
    )

    SettingValue = db.Column(
        db.Text,
        nullable=True,
    )

    SettingGroup = db.Column(
        db.String(50),
        nullable=False,
        default="General",
        index=True,
    )

    Description = db.Column(
        db.String(255),
        nullable=True,
    )

    IsActive = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
    )

    CreatedAt = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.now,
    )

    UpdatedAt = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.now,
        onupdate=datetime.now,
    )

    def __repr__(self) -> str:
        return (
            f"<SystemSetting "
            f"SettingKey={self.SettingKey!r} "
            f"SettingGroup={self.SettingGroup!r}>"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "setting_id": self.SettingId,
            "setting_key": self.SettingKey,
            "setting_value": self.SettingValue,
            "setting_group": self.SettingGroup,
            "description": self.Description,
            "is_active": self.IsActive,
            "created_at": self.CreatedAt,
            "updated_at": self.UpdatedAt,
        }