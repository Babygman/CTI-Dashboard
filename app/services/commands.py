import click
from flask.cli import with_appcontext

from .product_normalizer import ProductNormalizer


@click.command("normalize-product")
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
def normalize_product_command(vendor, product):
    """Resolve a threat product name to one catalog product."""
    result = ProductNormalizer().normalize(vendor, product)

    click.echo(f"Matched : {'Yes' if result['matched'] else 'No'}")
    click.echo(
        f"Catalog Product : "
        f"{result['product_name'] if result['matched'] else 'None'}"
    )
    click.echo(
        f"Alias : "
        f"{result['matched_alias'] if result['matched_alias'] else 'None'}"
    )
    click.echo(f"Confidence : {result['confidence']}")