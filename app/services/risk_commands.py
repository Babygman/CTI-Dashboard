import click
from flask.cli import with_appcontext

from .impact_analysis import ImpactAnalysisService
from .risk_assessment import RiskAssessmentService


@click.command("assess-risk")
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
@click.option(
    "--cvss",
    type=click.FloatRange(0.0, 10.0),
    required=True,
    help="CVSS base score for the threat.",
)
@click.option(
    "--kev",
    is_flag=True,
    help="The threat is in CISA Known Exploited Vulnerabilities.",
)
@click.option(
    "--public-exploit",
    is_flag=True,
    help="A public exploit is available.",
)
@with_appcontext
def assess_risk_command(vendor, product, cvss, kev, public_exploit):
    """Calculate business risk for Assets affected by a product."""
    impact_result = ImpactAnalysisService().analyze(vendor, product)
    threat_context = {
        "cvss_score": cvss,
        "kev": kev,
        "public_exploit": public_exploit,
    }
    result = RiskAssessmentService().assess(
        impact_result, threat_context
    )

    click.echo("Overall Risk")
    click.echo(result["overall_level"])
    click.echo("Score")
    click.echo(result["overall_score"])
    click.echo("Affected Assets")

    if not result["asset_results"]:
        click.echo("None")
        return

    for asset in result["asset_results"]:
        click.echo("")
        click.echo(asset["asset_name"])
        click.echo("Risk")
        click.echo(asset["level"])
        click.echo("Score")
        click.echo(asset["score"])
        click.echo("Reasons")
        for reason in asset["reasons"]:
            click.echo(reason)
