# CTI Dashboard Version 2 MVP

## Local setup and run (Windows / SQL Server)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt
# Set SQLALCHEMY_DATABASE_URI in .env to the existing SQL Server database.
.\.venv\Scripts\alembic upgrade head
.\.venv\Scripts\python app.py
```

Open `http://localhost:5000/`. The Version 2 migration is `20260724_00`; it
adds columns and tables without deleting existing CISA, NVD, canonical threat,
CVE, source, or asset data.

## Test and lint

```powershell
.\.venv\Scripts\python scripts/check_alembic.py
.\.venv\Scripts\pytest -q
.\.venv\Scripts\ruff check .
```

## Manual acceptance test

1. In **My Assets**, add FortiGate, Cisco Catalyst C9300, Ruckus R650,
   Windows 10, Windows 11, and AutoCAD 2024 product-level records.
2. Open **Dashboard / My Environment** and confirm action cards focus on the
   company environment.
3. Open **Relevant Threats**. Its default is **My Assets / Relevant**; **All**
   preserves the research view.
4. Verify a matching advisory shows the asset, reason, impact, and action.
5. In **News**, add and edit a URL/title/source/summary/date. Verify the
   deterministic Thai summary and editable recommendation.
6. Click **Generate Awareness**, edit the content, set **Ready**, and preview.
7. Download PDF and PNG. Confirm the A4 PDF and 1240×1754 PNG open, show
   readable Thai, and have no clipping.
8. Run the existing CISA/NVD collector commands documented in
   `docs/cisa-kev.md` and `docs/nvd-collector.md`.

No paid AI service is required.

An isolated automated version of steps 1–7 is also available:

```powershell
.\.venv\Scripts\python scripts/manual_acceptance_v2.py
```
