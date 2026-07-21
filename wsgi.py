import logging

from app import create_app


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

app = create_app()
app.config["DEBUG"] = False
app.logger.setLevel(logging.INFO)
