from datetime import datetime


class AwarenessGenerator:

    _INFOGRAPHIC_SUBJECTS = (
        (("microsoft edge", "edge"), "Microsoft Edge"),
        (("windows",), "Windows"),
        (("google chrome", "chrome"), "Google Chrome"),
        (("adobe", "acrobat", "reader"), "Adobe"),
        (("cisco",), "Cisco"),
        (("vmware", "vcenter", "esxi"), "VMware"),
        (("fortinet", "fortigate", "fortios"), "Fortinet"),
        (("microsoft",), "Microsoft"),
    )

    _INFOGRAPHIC_CONTENT = {
        "vulnerability": {
            "headline": "Critical Security Update",
            "what_happened": "A security weakness has been reported{identifier}. The alert concerns {subject}.",
            "why_it_matters": "Attackers could use this weakness to access information, interrupt work, or take control of a device.",
            "actions": [
                "Install the company-approved update when prompted.",
                "Save your work and restart your device if asked.",
                "Tell IT immediately if your device behaves unusually.",
            ],
            "avoid": [
                "Do not keep postponing an approved security update.",
                "Do not download updates from emails or unofficial websites.",
                "Do not try to fix the issue yourself.",
            ],
        },
        "patch_advisory": {
            "headline": "Critical Security Update",
            "what_happened": "A security update is available for {subject}. You may be asked to update or restart your device.",
            "why_it_matters": "Updating promptly helps prevent attackers from using a known security gap.",
            "actions": [
                "Save your work when an update notification appears.",
                "Let the company-approved update finish.",
                "Restart your device when IT asks you to.",
            ],
            "avoid": [
                "Do not cancel or repeatedly postpone the update.",
                "Do not download updates from pop-ups or email links.",
                "Do not power off your device during installation.",
            ],
        },
        "phishing": {
            "headline": "Beware of Phishing",
            "what_happened": "Fake messages are trying to trick people into clicking, opening files, or sharing information. The alert concerns {subject}.",
            "why_it_matters": "One click or reply could expose passwords, company information, or access to company systems.",
            "actions": [
                "Check the sender and message context carefully.",
                "Use the approved reporting option for suspicious messages.",
                "Contact IT through a known channel if uncertain.",
            ],
            "avoid": [
                "Do not click unexpected links or open unknown attachments.",
                "Do not share passwords or verification codes.",
                "Do not reply to confirm whether a message is genuine.",
            ],
        },
        "malware": {
            "headline": "Malware Detected",
            "what_happened": "Harmful software may be spreading through unsafe files, links, websites, or unapproved apps. The alert concerns {subject}.",
            "why_it_matters": "Malware can steal information, damage files, monitor activity, or spread to other company systems.",
            "actions": [
                "Use only company-approved software and websites.",
                "Keep your device connected for security updates.",
                "Report security warnings or unusual behaviour immediately.",
            ],
            "avoid": [
                "Do not run unexpected files or enable unknown macros.",
                "Do not bypass browser or antivirus warnings.",
                "Do not connect unapproved USB devices.",
            ],
        },
        "ransomware": {
            "headline": "Ransomware Alert",
            "what_happened": "Ransomware may lock files or block access to systems and demand payment. The alert concerns {subject}.",
            "why_it_matters": "Ransomware can stop business operations and put company or customer information at risk.",
            "actions": [
                "Report suspicious messages and files immediately.",
                "Keep important work in approved company storage.",
                "Disconnect from the network and call IT if files change unexpectedly.",
            ],
            "avoid": [
                "Do not open unexpected attachments or downloads.",
                "Do not reconnect an affected device without IT approval.",
                "Do not contact attackers or attempt payment.",
            ],
        },
        "general_advisory": {
            "headline": "Security Advisory",
            "what_happened": "A security alert has been issued for {subject}. Follow any instructions shared through an official company channel.",
            "why_it_matters": "Staying alert helps protect company information and prevents avoidable disruption.",
            "actions": [
                "Follow instructions sent through official company channels.",
                "Keep company devices updated and protected.",
                "Report anything unusual to IT promptly.",
            ],
            "avoid": [
                "Do not act on unverified security messages.",
                "Do not share confidential information unnecessarily.",
                "Do not bypass company security controls.",
            ],
        },
    }

    @staticmethod
    def _clean_text(value):
        return " ".join(str(value or "").split())

    @classmethod
    def _short_text(cls, value, maximum=110):
        text = cls._clean_text(value)
        if len(text) <= maximum:
            return text
        shortened = text[: maximum - 1].rsplit(" ", 1)[0]
        return f"{shortened or text[: maximum - 1]}…"

    @classmethod
    def _infographic_threat_type(cls, threat):
        title = cls._clean_text(threat.get("Title")).lower()
        details = " ".join(
            cls._clean_text(threat.get(field)).lower()
            for field in ("Title", "Summary", "Recommendation", "Source")
        )
        if "ransomware" in details:
            return "ransomware"
        if any(term in details for term in ("phishing", "credential theft", "spoofed email")):
            return "phishing"
        if any(term in details for term in ("malware", "trojan", "spyware", "worm")):
            return "malware"
        if any(term in title for term in ("patch", "security update", "hotfix")):
            return "patch_advisory"
        if cls._clean_text(threat.get("CVE")) or "vulnerability" in details:
            return "vulnerability"
        return "general_advisory"

    @classmethod
    def _infographic_subject_name(cls, threat):
        details = " ".join(
            cls._clean_text(threat.get(field)).lower()
            for field in (
                "VendorName",
                "Vendor",
                "Product",
                "Title",
                "Summary",
                "Recommendation",
                "Source",
            )
        )
        for terms, display_name in cls._INFOGRAPHIC_SUBJECTS:
            if any(term in details for term in terms):
                return display_name
        return None

    @classmethod
    def _infographic_headline(cls, threat, threat_type, default):
        subject_name = cls._infographic_subject_name(threat)
        if not subject_name:
            return default
        if threat_type in {"vulnerability", "patch_advisory"}:
            return f"{subject_name} Security Update"
        if threat_type == "general_advisory":
            return f"{subject_name} Security Advisory"
        return default

    @classmethod
    def infographic_content(cls, threat):
        """Build concise employee-awareness copy for the PNG infographic."""
        threat_type = cls._infographic_threat_type(threat)
        content = cls._INFOGRAPHIC_CONTENT[threat_type]
        subject = cls._short_text(threat.get("Title"), maximum=90) or "the reported issue"
        cve = cls._short_text(threat.get("CVE"), maximum=30)
        identifier = f" ({cve})" if cve else ""
        return {
            "threat_type": threat_type,
            "headline": cls._infographic_headline(
                threat, threat_type, content["headline"]
            ),
            "what_happened": content["what_happened"].format(subject=subject, identifier=identifier),
            "why_it_matters": content["why_it_matters"],
            "actions": list(content["actions"]),
            "avoid": list(content["avoid"]),
            "contact_it": (
                "If you notice anything suspicious, stop and contact the IT "
                "Department through an approved company channel."
            ),
        }

    @staticmethod
    def executive_summary(threat):
        severity = threat.get("Severity", "Unknown")
        title = threat.get("Title", "")
        cve = threat.get("CVE", "")
        cvss = threat.get("CVSS")
        source = threat.get("Source", "")

        summary = (
            f"A {severity} cybersecurity vulnerability has been identified.\n\n"
            f"Threat : {title}\n"
            f"CVE : {cve}\n"
            f"CVSS : {cvss}\n"
            f"Source : {source}\n\n"
            f"This issue should be reviewed by the IT Department to determine "
            f"whether company assets are affected."
        )

        return summary

    @staticmethod
    def business_impact(threat):

        severity = (threat.get("Severity") or "").lower()

        if severity == "critical":
            return [
                "Remote Code Execution may be possible.",
                "Production services could be interrupted.",
                "Immediate remediation is recommended.",
                "Executive visibility is required."
            ]

        if severity == "high":
            return [
                "High operational risk.",
                "Patch affected systems quickly.",
                "Monitor for exploitation."
            ]

        if severity == "medium":
            return [
                "Limited operational impact.",
                "Schedule patch deployment.",
                "Continue monitoring."
            ]

        return [
            "Low business impact.",
            "Apply normal patch process."
        ]

    @staticmethod
    def it_recommendation(threat):

        recommendation = threat.get("Recommendation")

        if recommendation:
            return recommendation

        return (
            "Review affected assets.\n"
            "Validate vendor advisory.\n"
            "Deploy security updates.\n"
            "Monitor for suspicious activity."
        )

    @staticmethod
    def email_subject(threat):

        return (
            f"[{threat.get('Severity')}] "
            f"{threat.get('CVE')} Security Advisory"
        )

    @staticmethod
    def generated_time():

        return datetime.now().strftime("%d %b %Y %H:%M")
