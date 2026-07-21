import click
from flask.cli import with_appcontext

from .impact_analysis import ImpactAnalysisService


@click.command("analyze-impact")
@click.option(
    "--vendor",
    default="",
    help="Vendor name supplied by the threat source.",
)
@click.option(
    "--product",
    required=True,
    help="Product name supplied by the threat source.",
)
@with_appcontext
def analyze_impact_command(vendor, product):
    """List active Assets affected by a normalized product."""
    result = ImpactAnalysisService().analyze(vendor, product)

    click.echo(f"Matched : {'Yes' if result['matched'] else 'No'}")
    click.echo(
        f"Catalog Product : "
        f"{result['product_name'] if result['matched'] else 'None'}"
    )
    click.echo(f"Affected Assets : {result['affected_asset_count']}")

    for asset in result["affected_assets"]:
        click.echo("")
        click.echo("----------------------")
        click.echo(asset["asset_name"])
        click.echo(f"Owner : {asset['owner'] or '-'}")
        click.echo(f"Environment : {asset['environment'] or '-'}")
        click.echo(f"Critical : {'Yes' if asset['critical'] else 'No'}")
