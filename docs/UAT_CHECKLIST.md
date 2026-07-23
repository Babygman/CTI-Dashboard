# CTI Dashboard Version 2 — UAT Checklist

Test date: 24 July 2026  
Role: IT Manager  
Environment: Local Flask application, clean database at migration `20260724_00`

| Step | Result | Screenshot | Notes |
|---|---|---|---|
| Start application | PASS | [01-create-asset.png](uat/01-create-asset.png) | Flask application started on `http://127.0.0.1:5000`; Version 2.0 MVP shell rendered. |
| Create Asset | PASS | [01-create-asset.png](uat/01-create-asset.png) | Created critical hardware asset “Cisco C9300 - Headquarters,” quantity 2, department IT Infrastructure, IOS XE 17.9. |
| Create News | PASS | [02-create-news.png](uat/02-create-news.png) | Created Cisco advisory with URL, source, date, vendor, product, CVE, severity, Thai summary, and impacts. |
| Verify Asset Matching | PASS | [03-verify-asset-matching.png](uat/03-verify-asset-matching.png) | News matched “Cisco C9300 - Headquarters.” Status was “Possibly Affected” because the advisory did not specify the installed 17.9 version. The matching reason was displayed. |
| Verify Decision Recommendation | PASS | [04-verify-decision-recommendation.png](uat/04-verify-decision-recommendation.png) | Recommendation was “Need Patch,” based on the matched company asset and High severity. |
| Generate Awareness | PASS | [05-generate-awareness.png](uat/05-generate-awareness.png) | Generated deterministic draft, edited Thai content, reporting instructions, action/avoidance lists, and set status to Ready. |
| Preview Awareness | PASS | [06-preview-awareness.png](uat/06-preview-awareness.png) | Corporate preview rendered Thai text, severity, source, version, and preserved action line breaks without clipping. |
| Download PDF | PASS | [07-download-pdf.png](uat/07-download-pdf.png) | Browser download event completed; server returned HTTP 200. Automated tests also verified a valid `%PDF` response. |
| Download PNG | PASS | [08-download-png.png](uat/08-download-png.png) | Browser download event completed; server returned HTTP 200. Automated tests verified a valid 1240×1754 PNG. |

## UAT defects found and resolved

1. Asset creation returned HTTP 500 under the supported local SQLite workflow because `SYSUTCDATETIME()` was unavailable. Resolved by registering an equivalent SQLite connection function.
2. News detail did not identify the specific matching asset or explain the match. Resolved by displaying all active matched assets, impact status, and deterministic reason.
3. Application shell displayed Version 1.0.0. Corrected to Version 2.0 MVP.
4. Awareness action lines collapsed in browser preview. Corrected with preserved line breaks.

Final result: **PASS — every required UAT step passed on the final repeat run.**
