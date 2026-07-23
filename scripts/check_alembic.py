"""Fail unless Alembic has exactly one expected migration head."""

from alembic.config import Config
from alembic.script import ScriptDirectory


def main():
    scripts = ScriptDirectory.from_config(Config("alembic.ini"))
    heads = scripts.get_heads()
    if len(heads) != 1:
        raise SystemExit(
            f"Expected exactly one Alembic head; found {len(heads)}: {heads}"
        )
    print(f"Single Alembic head: {heads[0]}")


if __name__ == "__main__":
    main()
