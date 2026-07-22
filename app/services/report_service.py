from datetime import datetime
from typing import Any


class ReportGenerator:

    @staticmethod
    def generate(threat: dict[str, Any]) -> dict[str, Any]:
        severity = str(threat.get("Severity") or "Unknown")
        title = str(threat.get("Title") or "No threat title available.")
        cve = str(threat.get("CVE") or "N/A")
        source = str(threat.get("Source") or "N/A")
        summary = str(
            threat.get("Summary")
            or "No threat summary is available."
        )
        recommendation = str(
            threat.get("Recommendation")
            or ReportGenerator._default_recommendation()
        )

        cvss_value = threat.get("CVSS")
        cvss = str(cvss_value) if cvss_value is not None else "N/A"

        report = {
            "threat_id": threat.get("ThreatId"),
            "title": title,
            "cve": cve,
            "severity": severity,
            "severity_level": severity.lower(),
            "cvss": cvss,
            "kev": bool(threat.get("KEV")),
            "source": source,
            "published_date": threat.get("PublishedDate"),
            "reference_url": str(
                threat.get("ReferenceUrl") or ""
            ),
            "original_summary": summary,
            "source_recommendation": recommendation,
            "executive_summary": (
                ReportGenerator._executive_summary(
                    title=title,
                    cve=cve,
                    severity=severity,
                    cvss=cvss,
                    source=source,
                )
            ),
            "business_impact": (
                ReportGenerator._business_impact(severity)
            ),
            "it_recommendation": recommendation,
            "email_subject": (
                ReportGenerator._email_subject(
                    severity=severity,
                    cve=cve,
                )
            ),
            "classification": "Internal Use",
            "generated_time": datetime.now(),
            "generated_time_text": datetime.now().strftime(
                "%d %b %Y %H:%M"
            ),
            "generated_by": "CTI Dashboard",
            "department": "IT Department",
        }

        return report

    @staticmethod
    def _executive_summary(
        title: str,
        cve: str,
        severity: str,
        cvss: str,
        source: str,
    ) -> str:
        return (
            f"A {severity} cybersecurity vulnerability "
            f"has been identified.\n\n"
            f"Threat: {title}\n"
            f"CVE: {cve}\n"
            f"CVSS: {cvss}\n"
            f"Source: {source}\n\n"
            "The IT Department should review affected assets, "
            "confirm exposure and apply the appropriate "
            "remediation actions."
        )

    @staticmethod
    def _business_impact(severity: str) -> list[str]:
        severity_level = severity.lower()

        if severity_level == "critical":
            return [
                "Remote exploitation or system compromise may be possible.",
                "Critical business services may be interrupted.",
                "Immediate containment and remediation are required.",
                "Management visibility and escalation are recommended.",
            ]

        if severity_level == "high":
            return [
                "The vulnerability may create significant operational risk.",
                "Affected systems should be patched as soon as possible.",
                "Security monitoring should be increased.",
            ]

        if severity_level == "medium":
            return [
                "The vulnerability may have limited operational impact.",
                "Patch deployment should be scheduled.",
                "Affected systems should continue to be monitored.",
            ]

        if severity_level == "low":
            return [
                "The vulnerability currently presents low business risk.",
                "Remediation may follow the normal patch cycle.",
                "Continue routine security monitoring.",
            ]

        return [
            "Business impact has not yet been fully determined.",
            "Review affected assets and vendor guidance.",
            "Apply remediation through the standard change process.",
        ]

    @staticmethod
    def _default_recommendation() -> str:
        return (
            "Review affected assets.\n"
            "Validate the vendor advisory.\n"
            "Deploy approved security updates.\n"
            "Monitor for suspicious activity."
        )

    @staticmethod
    def _email_subject(
        severity: str,
        cve: str,
    ) -> str:
        return f"[{severity}] {cve} Security Advisory"