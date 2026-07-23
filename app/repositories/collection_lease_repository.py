from datetime import timedelta

from sqlalchemy import and_, or_, update

from app.extensions import db
from app.models.source import Source


class CollectionLeaseRepository:
    """Atomic persistence operations for scheduled source leases."""

    @staticmethod
    def due_source_ids(now, limit=25):
        statement = (
            db.select(Source.SourceId)
            .where(
                Source.Enabled.is_(True),
                Source.NextRunAt.is_not(None),
                Source.NextRunAt <= now,
                or_(
                    Source.LeaseOwner.is_(None),
                    Source.LeaseExpiresAt.is_(None),
                    Source.LeaseExpiresAt <= now,
                ),
            )
            .order_by(Source.NextRunAt.asc(), Source.SourceId.asc())
            .limit(limit)
        )
        return list(db.session.scalars(statement))

    @staticmethod
    def acquire(
        source_id,
        owner,
        now,
        lease_timeout_seconds,
        *,
        require_due=True,
        require_enabled=True,
    ):
        """Claim a source with one conditional UPDATE.

        The UPDATE predicate is the concurrency control: when workers race,
        SQL Server locks the row and only the first eligible update succeeds.
        """
        conditions = [
            Source.SourceId == source_id,
            or_(
                Source.LeaseOwner.is_(None),
                Source.LeaseExpiresAt.is_(None),
                Source.LeaseExpiresAt <= now,
            ),
        ]
        if require_enabled:
            conditions.append(Source.Enabled.is_(True))
        if require_due:
            conditions.extend(
                (Source.NextRunAt.is_not(None), Source.NextRunAt <= now)
            )

        result = db.session.execute(
            update(Source)
            .where(and_(*conditions))
            .values(
                LeaseOwner=owner,
                LeaseExpiresAt=now
                + timedelta(seconds=lease_timeout_seconds),
                LastHeartbeatAt=now,
                UpdatedAt=Source.UpdatedAt,
            )
        )
        db.session.commit()
        return result.rowcount == 1

    @staticmethod
    def renew(source_id, owner, now, lease_timeout_seconds):
        result = db.session.execute(
            update(Source)
            .where(
                Source.SourceId == source_id,
                Source.LeaseOwner == owner,
                Source.LeaseExpiresAt > now,
            )
            .values(
                LeaseExpiresAt=now
                + timedelta(seconds=lease_timeout_seconds),
                LastHeartbeatAt=now,
                UpdatedAt=Source.UpdatedAt,
            )
        )
        db.session.commit()
        return result.rowcount == 1

    @staticmethod
    def release(source_id, owner, next_run_at):
        result = db.session.execute(
            update(Source)
            .where(
                Source.SourceId == source_id,
                Source.LeaseOwner == owner,
            )
            .values(
                LeaseOwner=None,
                LeaseExpiresAt=None,
                NextRunAt=next_run_at,
                UpdatedAt=Source.UpdatedAt,
            )
        )
        db.session.commit()
        return result.rowcount == 1
