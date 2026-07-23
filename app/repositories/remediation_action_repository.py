from sqlalchemy import case, func
from sqlalchemy.orm import joinedload, selectinload

from app.extensions import db
from app.models.remediation_action import (
    OPEN_ACTION_STATUSES,
    RemediationAction,
)
from app.models.threat import Threat
from app.models.threat_cve import ThreatCVE


class RemediationActionRepository:
    """Database access for remediation workflow screens."""

    @staticmethod
    def get(action_id):
        return db.session.execute(
            db.select(RemediationAction)
            .options(
                joinedload(RemediationAction.threat),
                joinedload(RemediationAction.history),
            )
            .where(RemediationAction.ActionId == action_id)
        ).unique().scalar_one_or_none()

    @staticmethod
    def list_actions(filters=None):
        filters = filters or {}
        statement = db.select(RemediationAction).options(
            joinedload(RemediationAction.threat)
        )
        if filters.get("status"):
            statement = statement.where(
                RemediationAction.Status == filters["status"]
            )
        if filters.get("priority"):
            statement = statement.where(
                RemediationAction.Priority == filters["priority"]
            )
        if filters.get("owner"):
            statement = statement.where(
                RemediationAction.Owner.ilike(
                    f"%{filters['owner']}%"
                )
            )
        if filters.get("due_date"):
            statement = statement.where(
                RemediationAction.DueDate == filters["due_date"]
            )
        if filters.get("threat_id"):
            statement = statement.where(
                RemediationAction.ThreatId == filters["threat_id"]
            )
        return db.session.execute(
            statement.order_by(
                case(
                    (
                        RemediationAction.Status.in_(
                            OPEN_ACTION_STATUSES
                        ),
                        0,
                    ),
                    else_=1,
                ),
                case(
                    (RemediationAction.DueDate.is_(None), 1),
                    else_=0,
                ),
                RemediationAction.DueDate.asc(),
                RemediationAction.CreatedAt.desc(),
                RemediationAction.ActionId.desc(),
            )
        ).scalars().all()

    @staticmethod
    def list_for_threat(threat_id):
        return db.session.execute(
            db.select(RemediationAction)
            .where(RemediationAction.ThreatId == threat_id)
            .order_by(
                RemediationAction.CreatedAt.desc(),
                RemediationAction.ActionId.desc(),
            )
        ).scalars().all()

    @staticmethod
    def list_open(limit=20):
        return db.session.execute(
            db.select(RemediationAction)
            .options(
                joinedload(RemediationAction.threat)
                .selectinload(Threat.cve_links)
                .joinedload(ThreatCVE.cve),
            )
            .where(RemediationAction.Status.in_(OPEN_ACTION_STATUSES))
            .order_by(
                case(
                    (RemediationAction.DueDate.is_(None), 1),
                    else_=0,
                ),
                RemediationAction.DueDate.asc(),
                RemediationAction.CreatedAt.asc(),
                RemediationAction.ActionId.asc(),
            )
            .limit(limit)
        ).scalars().all()

    @staticmethod
    def duplicate_exists(
        threat_id,
        action_type,
        title,
        *,
        excluded_action_id=None,
    ):
        statement = db.select(RemediationAction.ActionId).where(
            RemediationAction.ThreatId == threat_id,
            RemediationAction.ActionType == action_type,
            func.lower(RemediationAction.Title) == title.lower(),
        )
        if excluded_action_id is not None:
            statement = statement.where(
                RemediationAction.ActionId != excluded_action_id
            )
        return db.session.scalar(statement.limit(1)) is not None

    @staticmethod
    def list_threats():
        return db.session.execute(
            db.select(Threat).order_by(
                Threat.CreatedAt.desc(),
                Threat.ThreatId.desc(),
            )
        ).scalars().all()
