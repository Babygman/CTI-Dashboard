from time import perf_counter

import click
from flask import current_app
from flask.cli import AppGroup
from sqlalchemy import func

from app.extensions import db
from app.models.collection_run import CollectionRun
from app.models.source import Source

from . import collector_registry
from .cisa_kev import CISA_KEV_FEED_URL
from .nvd import NVD_MODIFIED_FEED_URL
from .service import run_collector


collector_cli = AppGroup("collector", help="Manage threat collection sources and runs.")


INITIAL_SOURCES = (
    {
        "SourceName": "CISA KEV",
        "SourceType": "CisaKev",
        "BaseUrl": "https://www.cisa.gov",
        "FeedUrl": CISA_KEV_FEED_URL,
    },
    {
        "SourceName": "NVD",
        "SourceType": "Nvd",
        "BaseUrl": "https://nvd.nist.gov",
        "FeedUrl": NVD_MODIFIED_FEED_URL,
    },
    {
        "SourceName": "Microsoft Security Response Center",
        "SourceType": "Microsoft",
        "BaseUrl": "https://msrc.microsoft.com",
    },
    {
        "SourceName": "Fortinet PSIRT",
        "SourceType": "Fortinet",
        "BaseUrl": "https://www.fortiguard.com",
    },
    {
        "SourceName": "Cisco Security Advisories",
        "SourceType": "Cisco",
        "BaseUrl": "https://sec.cloudapps.cisco.com",
    },
    {
        "SourceName": "Veeam Security Advisories",
        "SourceType": "Veeam",
        "BaseUrl": "https://www.veeam.com",
    },
    {
        "SourceName": "Broadcom VMware Advisories",
        "SourceType": "Broadcom",
        "BaseUrl": "https://support.broadcom.com",
    },
)


def _source_by_name(source_name):
    statement = db.select(Source).where(
        func.lower(Source.SourceName) == source_name.lower()
    )
    return db.session.scalar(statement)


@collector_cli.command("seed-sources")
def seed_sources():
    """Insert disabled placeholders for planned live collectors."""
    created = 0
    existing = 0
    for values in INITIAL_SOURCES:
        if _source_by_name(values["SourceName"]) is not None:
            existing += 1
            continue
        db.session.add(
            Source(
                **values,
                Enabled=False,
                CollectionIntervalMinutes=60,
                TimeoutSeconds=30,
            )
        )
        created += 1
    db.session.commit()
    click.echo(f"Source seeding complete: created={created}, existing={existing}")


RUNNABLE_COLLECTORS = {
    "cisa-kev": "CisaKev",
    "nvd": "Nvd",
}
DEFAULT_FEED_URLS = {
    "CisaKev": CISA_KEV_FEED_URL,
    "Nvd": NVD_MODIFIED_FEED_URL,
}


@collector_cli.command("run")
@click.argument(
    "collector_name",
    type=click.Choice(tuple(RUNNABLE_COLLECTORS), case_sensitive=False),
)
def run_named_collector(collector_name):
    """Run a registered production collector by CLI name."""
    source_type = RUNNABLE_COLLECTORS[collector_name.lower()]
    collector_class = collector_registry.get(source_type)
    source = _source_by_name(collector_class.source_name)
    if source is None:
        raise click.ClickException(
            f"{collector_class.source_name} source is not configured. "
            "Run collector seed-sources first."
        )

    collector = collector_registry.create(
        source_type,
        timeout_seconds=source.TimeoutSeconds,
        feed_url=source.FeedUrl or DEFAULT_FEED_URLS[source_type],
    )
    started = perf_counter()
    result = run_collector(
        collector,
        source,
        logger=current_app.logger,
    )
    duration = perf_counter() - started

    click.echo(f"run_id: {result.collection_run_id}")
    click.echo(f"status: {result.status}")
    click.echo(f"fetched: {result.fetched}")
    click.echo(f"created: {result.created}")
    click.echo(f"updated: {result.updated}")
    click.echo(f"skipped: {result.skipped}")
    click.echo(f"errors: {len(result.errors)}")
    click.echo(f"duration_seconds: {duration:.3f}")
    for error in result.errors:
        click.echo(f"  - {error}")

    if result.status == "Failed":
        raise click.exceptions.Exit(1)

@collector_cli.command("run-demo")
def run_demo():
    """Run the local-only demonstration collector."""
    collector = collector_registry.create("Demo", timeout_seconds=30)
    source = _source_by_name(collector.source_name)
    if source is None:
        source = Source(
            SourceName=collector.source_name,
            SourceType=collector.source_type,
            Enabled=False,
            CollectionIntervalMinutes=60,
            TimeoutSeconds=30,
        )
        db.session.add(source)
        db.session.commit()

    result = run_collector(
        collector,
        source,
        logger=current_app.logger,
    )
    click.echo(f"run_id: {result.collection_run_id}")
    click.echo(f"status: {result.status}")
    click.echo(f"fetched: {result.fetched}")
    click.echo(f"created: {result.created}")
    click.echo(f"updated: {result.updated}")
    click.echo(f"skipped: {result.skipped}")
    click.echo(f"errors: {len(result.errors)}")
    for error in result.errors:
        click.echo(f"  - {error}")


@collector_cli.command("status")
def collector_status():
    """Display configured sources and their latest collection status."""
    sources = db.session.scalars(
        db.select(Source).order_by(Source.SourceName.asc())
    ).all()
    if not sources:
        click.echo("No collection sources are configured.")
        return

    for source in sources:
        latest_run = db.session.scalar(
            db.select(CollectionRun)
            .where(CollectionRun.SourceId == source.SourceId)
            .order_by(
                CollectionRun.StartedAt.desc(),
                CollectionRun.CollectionRunId.desc(),
            )
            .limit(1)
        )
        enabled = "yes" if source.Enabled else "no"
        status = latest_run.Status if latest_run else (source.LastCollectionStatus or "Never")
        started = latest_run.StartedAt.isoformat() if latest_run else "-"
        click.echo(
            f"{source.SourceName} | type={source.SourceType} | "
            f"enabled={enabled} | status={status} | latest={started}"
        )
