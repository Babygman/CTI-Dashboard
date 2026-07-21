import click
from flask.cli import with_appcontext

from .decision_engine import DecisionEngine
from .impact_analysis import ImpactAnalysisService
from .risk_assessment import RiskAssessmentService


@click.command("recommend-action")
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
@click.option(
    "--notify-users",
    is_flag=True,
    help="Add a user security awareness recommendation.",
)
@click.option(
    "--notification-reason",
    help="Reason users should be notified.",
)
@click.option(
    "--affected-user-group",
    help="User group affected by the threat.",
)
@with_appcontext
def recommend_action_command(
    vendor,
    product,
    cvss,
    kev,
    public_exploit,
    notify_users,
    notification_reason,
    affected_user_group,
):
    """Recommend actions for Assets affected by a product."""
    if notify_users and not (
        notification_reason and notification_reason.strip()
    ):
        raise click.UsageError(
            "--notification-reason must not be empty when "
            "--notify-users is set"
        )

    impact_result = ImpactAnalysisService().analyze(vendor, product)
    risk_result = RiskAssessmentService().assess(
        impact_result,
        {
            "cvss_score": cvss,
            "kev": kev,
            "public_exploit": public_exploit,
        },
    )
    decision = DecisionEngine().recommend(
        risk_result,
        {
            "requires_user_notification": notify_users,
            "notification_reason": notification_reason,
            "affected_user_group": affected_user_group,
        },
    )

    for action in decision["overall_actions"]:
        click.echo("Overall Recommendation")
        click.echo(action["recommendation"])
        click.echo("Action Type")
        click.echo(action["action_type"])
        click.echo("Priority")
        click.echo(action["priority"])
        click.echo("Target")
        click.echo(action["target"])

    if not decision["asset_actions"]:
        click.echo("Affected Asset")
        click.echo("None")

    for action in decision["asset_actions"]:
        click.echo("")
        click.echo("Affected Asset")
        click.echo(action["asset_name"])
        click.echo("Action Type")
        click.echo(action["action_type"])
        click.echo("Recommendation")
        click.echo(action["recommendation"])
        click.echo("Priority")
        click.echo(action["priority"])
        click.echo("Target")
        click.echo(action["target"])
        click.echo("Reasons")
        if action["reasons"]:
            for reason in action["reasons"]:
                click.echo(reason)
        else:
            click.echo("None")

    for action in decision["communication_actions"]:
        click.echo("")
        click.echo("Communication Recommendation")
        click.echo(action["recommendation"])
        click.echo("Action Type")
        click.echo(action["action_type"])
        click.echo("Priority")
        click.echo(action["priority"])
        click.echo("Target")
        click.echo(action["target"])
        click.echo("Affected User Group")
        click.echo(action["affected_user_group"] or "Not Specified")
        click.echo("Reasons")
        for reason in action["reasons"]:
            click.echo(reason)
