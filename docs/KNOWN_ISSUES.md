# CTI Dashboard Version 2 — Known Issues

The following limitations remain after UAT. None blocks the demonstrated MVP
workflow.

1. **Version matching is conservative.** Product and model terms are
   normalized, but vendor-specific semantic version ranges are not evaluated.
   When a product matches and installed-version evidence is incomplete, the
   result is “Possibly Affected.”
2. **Generated Thai copy is deterministic.** It is a safe editable starting
   point, not a contextual translation or AI-authored security analysis. The IT
   Manager must review it before setting the record to Ready.
3. **Dashboard action cards use the existing technical-threat analysis.**
   Relevant manually entered news appears in Recent Relevant News, but news
   recommendations are not added to the legacy technical action-card counts.
4. **PDF/PNG downloads do not display an in-application completion toast.**
   Completion is shown by the browser’s normal download behavior.
5. **Frontend styling libraries are loaded from public CDNs.** A workstation
   without internet access may render the application without Bootstrap icons,
   charts, or full styling. Core server workflows remain available.
6. **No authentication or multi-user workflow was added.** The MVP follows the
   stated single-IT-Manager operating model and relies on the deployment
   environment’s existing access controls.
7. **Legacy Word and PowerPoint exporter routes remain in the codebase.** They
   are not exposed in the Version 2 primary workflow; they were retained to
   avoid removing existing capability.
8. **SQL Server must still be verified in the target UAT environment.** Clean
   migration and browser UAT were performed against isolated SQLite databases;
   automated migration compilation and model behavior remain SQL Server
   compatible.
