from datetime import timedelta

from sqlalchemy import case, func

from app.collectors import collector_registry
from app.collectors.service import utcnow
from app.extensions import db
from app.models.collection_run import CollectionRun
from app.models.source import Source
from app.models.source_item import SourceItem


class SourceAdministrationService:
    """Read existing source/run data and derive administration health state."""

    @staticmethod
    def collector_available(source):
        return source.SourceType.casefold() in collector_registry.registered_types()

    @staticmethod
    def create_collector(source):
        return collector_registry.create_for_source(source)

    @classmethod
    def list_sources(cls):
        sources = db.session.execute(
            db.select(Source).order_by(
                Source.Priority.desc(),
                Source.SourceName.asc(),
                Source.SourceId.asc(),
            )
        ).scalars().all()
        stats = cls._stats_by_source()
        item_counts = cls._item_counts_by_source()
        latest_runs = cls._latest_runs_by_source()
        latest_errors = cls._latest_errors_by_source()
        return [
            cls._source_view(
                source,
                stats.get(source.SourceId, {}),
                latest_runs.get(source.SourceId),
                latest_errors.get(source.SourceId),
                item_counts.get(source.SourceId, 0),
            )
            for source in sources
        ]

    @classmethod
    def source_detail(cls, source):
        stats = cls._stats_for_source(source.SourceId)
        latest_run = db.session.scalar(
            cls._ordered_runs(source.SourceId).limit(1)
        )
        latest_error = db.session.scalar(
            cls._ordered_runs(source.SourceId)
            .where(CollectionRun.ErrorMessage.is_not(None))
            .limit(1)
        )
        return cls._source_view(
            source,
            stats,
            latest_run,
            latest_error,
            cls._item_count_for_source(source.SourceId),
        )

    @staticmethod
    def collection_history(source_id, page, per_page=20):
        return db.paginate(
            SourceAdministrationService._ordered_runs(source_id),
            page=page,
            per_page=per_page,
            error_out=False,
        )

    @staticmethod
    def latest_run(source_id):
        return db.session.scalar(
            SourceAdministrationService._ordered_runs(source_id).limit(1)
        )

    @staticmethod
    def _ordered_runs(source_id):
        return (
            db.select(CollectionRun)
            .where(CollectionRun.SourceId == source_id)
            .order_by(
                CollectionRun.StartedAt.desc(),
                CollectionRun.CollectionRunId.desc(),
            )
        )

    @staticmethod
    def _stats_query():
        return db.select(
            CollectionRun.SourceId,
            func.count(CollectionRun.CollectionRunId).label("total_count"),
            func.sum(
                case((CollectionRun.Status == "Success", 1), else_=0)
            ).label("success_count"),
            func.sum(
                case((CollectionRun.Status == "Failed", 1), else_=0)
            ).label("failure_count"),
            func.sum(
                case((CollectionRun.Status == "Partial", 1), else_=0)
            ).label("partial_count"),
            func.sum(CollectionRun.ItemsCreated).label("created_count"),
            func.sum(CollectionRun.ItemsUpdated).label("updated_count"),
            func.sum(CollectionRun.ItemsSkipped).label("skipped_count"),
            func.sum(
                case(
                    (CollectionRun.ErrorMessage.is_not(None), 1),
                    else_=0,
                )
            ).label("error_count"),
        ).group_by(CollectionRun.SourceId)

    @classmethod
    def _stats_by_source(cls):
        return {
            row.SourceId: dict(row._mapping)
            for row in db.session.execute(cls._stats_query())
        }

    @classmethod
    def _stats_for_source(cls, source_id):
        row = db.session.execute(
            cls._stats_query().where(
                CollectionRun.SourceId == source_id
            )
        ).first()
        return dict(row._mapping) if row else {}

    @staticmethod
    def _item_counts_by_source():
        return {
            row.SourceId: row.item_count
            for row in db.session.execute(
                db.select(
                    SourceItem.SourceId,
                    func.count(SourceItem.SourceItemId).label("item_count"),
                ).group_by(SourceItem.SourceId)
            )
        }

    @staticmethod
    def _item_count_for_source(source_id):
        return (
            db.session.scalar(
                db.select(func.count(SourceItem.SourceItemId)).where(
                    SourceItem.SourceId == source_id
                )
            )
            or 0
        )

    @staticmethod
    def _ranked_runs(*, errors_only=False):
        statement = db.select(
            CollectionRun.CollectionRunId,
            CollectionRun.SourceId,
            func.row_number()
            .over(
                partition_by=CollectionRun.SourceId,
                order_by=(
                    CollectionRun.StartedAt.desc(),
                    CollectionRun.CollectionRunId.desc(),
                ),
            )
            .label("row_number"),
        )
        if errors_only:
            statement = statement.where(
                CollectionRun.ErrorMessage.is_not(None)
            )
        return statement.subquery()

    @classmethod
    def _latest_runs_by_source(cls):
        ranked = cls._ranked_runs()
        rows = db.session.execute(
            db.select(CollectionRun)
            .join(
                ranked,
                CollectionRun.CollectionRunId
                == ranked.c.CollectionRunId,
            )
            .where(ranked.c.row_number == 1)
        ).scalars()
        return {run.SourceId: run for run in rows}

    @classmethod
    def _latest_errors_by_source(cls):
        ranked = cls._ranked_runs(errors_only=True)
        rows = db.session.execute(
            db.select(CollectionRun)
            .join(
                ranked,
                CollectionRun.CollectionRunId
                == ranked.c.CollectionRunId,
            )
            .where(ranked.c.row_number == 1)
        ).scalars()
        return {run.SourceId: run for run in rows}

    @classmethod
    def _source_view(
        cls,
        source,
        stats,
        latest_run,
        latest_error,
        item_count,
    ):
        next_run = cls._next_run(source, latest_run)
        health, health_class = cls._health(
            source, latest_run, next_run
        )
        return {
            "source": source,
            "latest_run": latest_run,
            "next_run": next_run,
            "status": (
                latest_run.Status
                if latest_run
                else source.LastCollectionStatus or "Never"
            ),
            "success_count": stats.get("success_count", 0) or 0,
            "failure_count": stats.get("failure_count", 0) or 0,
            "partial_count": stats.get("partial_count", 0) or 0,
            "total_count": stats.get("total_count", 0) or 0,
            "records_imported": item_count,
            "new_threats": stats.get("created_count", 0) or 0,
            "updated_count": stats.get("updated_count", 0) or 0,
            "skipped_count": stats.get("skipped_count", 0) or 0,
            "error_count": stats.get("error_count", 0) or 0,
            "last_duration_seconds": cls._duration_seconds(latest_run),
            "last_error": (
                latest_error.ErrorMessage if latest_error else None
            ),
            "health": health,
            "health_class": health_class,
            "collector_available": cls.collector_available(source),
        }

    @staticmethod
    def _duration_seconds(run):
        if run is None or run.FinishedAt is None:
            return None
        return max((run.FinishedAt - run.StartedAt).total_seconds(), 0)

    @staticmethod
    def _next_run(source, latest_run):
        if not source.Enabled:
            return None
        if source.NextRunAt is not None:
            return source.NextRunAt
        if latest_run is None:
            return None
        return latest_run.StartedAt + timedelta(
            minutes=source.CollectionIntervalMinutes
        )

    @staticmethod
    def _health(source, latest_run, next_run):
        if not source.Enabled:
            return "Disabled", "secondary"
        if latest_run is None:
            return "Awaiting First Run", "warning"
        if latest_run.Status == "Running":
            return "Running", "info"
        if latest_run.Status == "Failed":
            return "Unhealthy", "danger"
        if latest_run.Status == "Partial":
            return "Degraded", "warning"
        if next_run is not None and next_run < utcnow():
            return "Stale", "warning"
        return "Healthy", "success"
