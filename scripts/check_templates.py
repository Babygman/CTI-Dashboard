"""Compile every application template without rendering it."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app


class TemplateCheckConfig:
    TESTING = True
    SECRET_KEY = "template-compilation-check"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


def main():
    app = create_app(TemplateCheckConfig)
    templates = sorted(app.jinja_env.list_templates())
    for template_name in templates:
        app.jinja_env.get_template(template_name)
    print(f"Compiled {len(templates)} templates successfully.")


if __name__ == "__main__":
    main()
