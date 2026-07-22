from datetime import datetime


class AwarenessGenerator:

    _INFOGRAPHIC_CONTENT = {
        "vulnerability": {
            "headline": "Security Update Required",
            "what_happened": "A software vulnerability has been reported{identifier}. IT is reviewing which systems may be affected.",
            "why_it_matters": "Attackers may use the weakness to access information, disrupt work, or compromise a device.",
            "actions": [
                "Install company-approved updates when IT prompts you.",
                "Restart your device after updates are installed.",
                "Report unusual device behaviour to IT immediately.",
            ],
            "avoid": [
                "Do not postpone security updates without IT approval.",
                "Do not install patches from emails or unofficial websites.",
                "Do not attempt technical workarounds yourself.",
            ],
        },
        "patch_advisory": {
            "headline": "Install the Approved Security Update",
            "what_happened": "A security update has been released for {subject}. IT will coordinate deployment where required.",
            "why_it_matters": "Applying the approved update helps close known security gaps before they can be exploited.",
            "actions": [
                "Save your work when an update notification appears.",
                "Allow the company update process to complete.",
                "Restart your device if requested by IT.",
            ],
            "avoid": [
                "Do not cancel or repeatedly defer approved updates.",
                "Do not download updates from pop-ups or email links.",
                "Do not power off your device during installation.",
            ],
        },
        "phishing": {
            "headline": "Think Before You Click",
            "what_happened": "A phishing threat is using deceptive messages to trick people into clicking links, opening files, or sharing data.",
            "why_it_matters": "One response can expose passwords, financial information, or company systems to an attacker.",
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
            "headline": "Stop Malware Before It Spreads",
            "what_happened": "Malicious software may be distributed through unsafe files, links, websites, or unauthorized applications.",
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
            "headline": "Protect Company Data from Ransomware",
            "what_happened": "A ransomware threat may encrypt files or block access to systems and demand payment.",
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
            "headline": "Stay Alert to This Security Advisory",
            "what_happened": "A security advisory has been issued for {subject}. IT is reviewing the information and any required response.",
            "why_it_matters": "Following safe working practices helps protect company information and prevents avoidable disruption.",
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
    def infographic_content(cls, threat):
        """Build concise employee-awareness copy for the PNG infographic."""
        threat_type = cls._infographic_threat_type(threat)
        content = cls._INFOGRAPHIC_CONTENT[threat_type]
        subject = cls._short_text(threat.get("Title"), maximum=90) or "the reported issue"
        cve = cls._short_text(threat.get("CVE"), maximum=30)
        identifier = f" ({cve})" if cve else ""
        return {
            "threat_type": threat_type,
            "headline": content["headline"],
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