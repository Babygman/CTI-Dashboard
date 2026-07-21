import logging

import click
from flask.cli import with_appcontext

from .asset_import import (
    AssetImportService,
    AssetImportValidationError,
)


LOGGER = logging.getLogger(__name__)


@click.command("import-assets")
@click.option(
    "--file",
    "file_path",
    required=True,
    type=click.Path(path_type=str),
    help="Path to a UTF-8 Asset Inventory CSV file.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Validate and report changes without writing to the database.",
)
@with_appcontext
def import_assets_command(file_path, dry_run):
    """Import or update Assets from a UTF-8 CSV file."""
    try:
        result = AssetImportService().import_file(
            file_path, dry_run=dry_run
        )
    except AssetImportValidationError as exc:
        raise click.ClickException(str(exc)) from None
    except Exception:
        LOGGER.exception("Fatal Asset CSV import failure")
        raise click.ClickException(
            "Asset import failed; all database changes were rolled back."
        ) from None

    for error in result["row_errors"]:
        click.echo(
            f"Row {error['row_number']}: {error['reason']}",
            err=True,
        )
    click.echo(f"Total rows : {result['total_rows']}")
    click.echo(f"Valid rows : {result['valid_rows']}")
    click.echo(f"Created : {result['created']}")
    click.echo(f"Updated : {result['updated']}")
    click.echo(f"Skipped : {result['skipped']}")
    click.echo(f"Errors : {result['errors']}")
    click.echo(
        f"Dry run status : {'Yes' if result['dry_run'] else 'No'}"
    )
