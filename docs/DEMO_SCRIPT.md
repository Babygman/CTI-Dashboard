# CTI Dashboard Version 2 — 3-Minute Management Demo

## 0:00–0:25 — The business question

Open **Dashboard / My Environment**.

Say: “The dashboard is designed for one IT Manager. It starts with the four
questions management cares about: what affects our assets, what needs patching,
what needs user awareness, and what needs monitoring. Global threat-feed totals
remain available, but they are secondary.”

## 0:25–0:55 — Our environment

Open **My Assets** and show the Cisco C9300 record.

Say: “This is a product-level inventory, not an individual-device
administration system. We record vendor, model, installed version, quantity,
department, and criticality. That is enough evidence for prioritization without
creating unnecessary administrative work.”

## 0:55–1:30 — News becomes a decision

Open **News**, then open the Cisco IOS XE advisory.

Say: “An IT Manager can add an advisory using its original URL, title, source,
summary, and published date. The dashboard deterministically extracts and
stores the operational fields without requiring a paid AI API.”

Point to **Matched Assets**.

Say: “The advisory matched our headquarters C9300. It is marked ‘Possibly
Affected’ because the source does not prove that installed IOS XE 17.9 is in the
affected range. The reason remains visible, so the manager can verify the
evidence.”

Point to **Need Patch**.

Say: “High severity plus a matching company asset produces an editable ‘Need
Patch’ recommendation.”

## 1:30–2:20 — Generate awareness

Click **Generate Awareness**.

Say: “The system prepares employee-facing content from the selected item. The
manager controls the final message: Thai explanation, affected audience, what
users must do, what they must not do, and how to report to IT.”

Set status to **Ready**, then click **Save & Preview**.

Say: “The preview retains the corporate structure, severity, source,
classification, and document version. Nothing is sent automatically.”

## 2:20–2:50 — Export

Click **Download PDF**, then **Download PNG**.

Say: “The PDF is suitable for formal A4 distribution. The 1240 by 1754 PNG is
optimized for email or Teams. Thai fonts are embedded or selected from
supported system fonts.”

## 2:50–3:00 — Close

Say: “The MVP turns existing threat intelligence into three outcomes: a
company-asset decision, a recommended IT action, and ready-to-review employee
communication—while preserving the current CISA and NVD collection platform.”
