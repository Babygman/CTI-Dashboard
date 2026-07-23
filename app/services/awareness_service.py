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
            "headline": "ประกาศอัปเดตความปลอดภัยเร่งด่วน",
            "what_happened": "พบช่องโหว่ด้านความปลอดภัย{identifier} ซึ่งเกี่ยวข้องกับ {subject}",
            "why_it_matters": "ผู้ไม่หวังดีอาจใช้ช่องโหว่นี้เพื่อเข้าถึงข้อมูล รบกวนการทำงาน หรือควบคุมอุปกรณ์",
            "actions": [
                "ติดตั้งอัปเดตที่บริษัทอนุมัติเมื่อได้รับแจ้ง",
                "บันทึกงานและรีสตาร์ตอุปกรณ์เมื่อได้รับคำแนะนำ",
                "แจ้งฝ่าย IT ทันทีหากอุปกรณ์ทำงานผิดปกติ",
            ],
            "avoid": [
                "ห้ามเลื่อนการติดตั้งอัปเดตที่ได้รับอนุมัติซ้ำ ๆ",
                "ห้ามดาวน์โหลดอัปเดตจากอีเมลหรือเว็บไซต์ที่ไม่เป็นทางการ",
                "ห้ามพยายามแก้ไขปัญหาด้วยตนเอง",
            ],
        },
        "patch_advisory": {
            "headline": "ประกาศอัปเดตความปลอดภัยเร่งด่วน",
            "what_happened": "มีอัปเดตความปลอดภัยสำหรับ {subject} ผู้ใช้อาจได้รับแจ้งให้อัปเดตหรือรีสตาร์ตอุปกรณ์",
            "why_it_matters": "การอัปเดตโดยเร็วช่วยป้องกันผู้ไม่หวังดีจากการใช้ช่องโหว่ที่ทราบแล้ว",
            "actions": [
                "บันทึกงานเมื่อมีการแจ้งเตือนให้อัปเดต",
                "รอให้อัปเดตที่บริษัทอนุมัติดำเนินการจนเสร็จ",
                "รีสตาร์ตอุปกรณ์เมื่อฝ่าย IT แจ้งให้ดำเนินการ",
            ],
            "avoid": [
                "ห้ามยกเลิกหรือเลื่อนการอัปเดตซ้ำ ๆ",
                "ห้ามดาวน์โหลดอัปเดตจากป๊อปอัปหรือลิงก์ในอีเมล",
                "ห้ามปิดอุปกรณ์ระหว่างการติดตั้ง",
            ],
        },
        "phishing": {
            "headline": "ระวังการหลอกลวงทางออนไลน์",
            "what_happened": "พบข้อความปลอมที่หลอกให้คลิกลิงก์ เปิดไฟล์ หรือเปิดเผยข้อมูล ซึ่งเกี่ยวข้องกับ {subject}",
            "why_it_matters": "การคลิกหรือตอบกลับเพียงครั้งเดียวอาจทำให้รหัสผ่าน ข้อมูลบริษัท หรือสิทธิ์เข้าถึงระบบรั่วไหล",
            "actions": [
                "ตรวจสอบผู้ส่งและบริบทของข้อความอย่างรอบคอบ",
                "รายงานข้อความน่าสงสัยผ่านช่องทางที่บริษัทกำหนด",
                "ติดต่อฝ่าย IT ผ่านช่องทางที่ทราบแน่ชัดเมื่อไม่มั่นใจ",
            ],
            "avoid": [
                "ห้ามคลิกลิงก์ที่ไม่คาดคิดหรือเปิดไฟล์แนบที่ไม่รู้จัก",
                "ห้ามเปิดเผยรหัสผ่านหรือรหัสยืนยัน",
                "ห้ามตอบกลับข้อความเพื่อตรวจสอบว่าเป็นของจริงหรือไม่",
            ],
        },
        "malware": {
            "headline": "ตรวจพบความเสี่ยงจากมัลแวร์",
            "what_happened": "ซอฟต์แวร์อันตรายอาจแพร่ผ่านไฟล์ ลิงก์ เว็บไซต์ หรือแอปที่ไม่ได้รับอนุมัติ ซึ่งเกี่ยวข้องกับ {subject}",
            "why_it_matters": "มัลแวร์สามารถขโมยข้อมูล ทำลายไฟล์ ติดตามกิจกรรม หรือแพร่ไปยังระบบอื่นของบริษัท",
            "actions": [
                "ใช้เฉพาะซอฟต์แวร์และเว็บไซต์ที่บริษัทอนุมัติ",
                "เชื่อมต่ออุปกรณ์ไว้เพื่อรับอัปเดตความปลอดภัย",
                "รายงานคำเตือนหรือการทำงานผิดปกติทันที",
            ],
            "avoid": [
                "ห้ามเปิดไฟล์ที่ไม่คาดคิดหรือเปิดใช้มาโครที่ไม่รู้จัก",
                "ห้ามข้ามคำเตือนจากเบราว์เซอร์หรือโปรแกรมป้องกันไวรัส",
                "ห้ามเชื่อมต่ออุปกรณ์ USB ที่ไม่ได้รับอนุมัติ",
            ],
        },
        "ransomware": {
            "headline": "แจ้งเตือนภัยแรนซัมแวร์",
            "what_happened": "แรนซัมแวร์อาจล็อกไฟล์หรือระบบและเรียกค่าไถ่ ซึ่งเกี่ยวข้องกับ {subject}",
            "why_it_matters": "แรนซัมแวร์อาจหยุดการดำเนินธุรกิจและทำให้ข้อมูลบริษัทหรือลูกค้าตกอยู่ในความเสี่ยง",
            "actions": [
                "รายงานข้อความและไฟล์น่าสงสัยทันที",
                "จัดเก็บงานสำคัญในพื้นที่จัดเก็บที่บริษัทอนุมัติ",
                "ตัดการเชื่อมต่อเครือข่ายและโทรหาฝ่าย IT หากไฟล์เปลี่ยนแปลงผิดปกติ",
            ],
            "avoid": [
                "ห้ามเปิดไฟล์แนบหรือไฟล์ดาวน์โหลดที่ไม่คาดคิด",
                "ห้ามเชื่อมต่ออุปกรณ์ที่ได้รับผลกระทบกลับเข้าระบบโดยไม่ได้รับอนุมัติ",
                "ห้ามติดต่อผู้โจมตีหรือพยายามชำระเงิน",
            ],
        },
        "general_advisory": {
            "headline": "ประกาศด้านความมั่นคงปลอดภัยไซเบอร์",
            "what_happened": "มีประกาศแจ้งเตือนด้านความปลอดภัยสำหรับ {subject} โปรดปฏิบัติตามคำแนะนำจากช่องทางทางการของบริษัท",
            "why_it_matters": "การเฝ้าระวังช่วยปกป้องข้อมูลบริษัทและลดความขัดข้องที่สามารถป้องกันได้",
            "actions": [
                "ปฏิบัติตามคำแนะนำจากช่องทางทางการของบริษัท",
                "อัปเดตและปกป้องอุปกรณ์ของบริษัทอยู่เสมอ",
                "รายงานสิ่งผิดปกติให้ฝ่าย IT โดยเร็ว",
            ],
            "avoid": [
                "ห้ามดำเนินการตามข้อความเตือนที่ยังไม่ผ่านการตรวจสอบ",
                "ห้ามเปิดเผยข้อมูลลับโดยไม่จำเป็น",
                "ห้ามข้ามมาตรการควบคุมความปลอดภัยของบริษัท",
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
            return f"อัปเดตความปลอดภัย {subject_name}"
        if threat_type == "general_advisory":
            return f"ประกาศความปลอดภัย {subject_name}"
        return default

    @classmethod
    def infographic_content(cls, threat):
        """Build concise employee-awareness copy for the PNG infographic."""
        threat_type = cls._infographic_threat_type(threat)
        content = cls._INFOGRAPHIC_CONTENT[threat_type]
        subject = cls._short_text(threat.get("Title"), maximum=90) or "เหตุการณ์ที่ได้รับรายงาน"
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
                "หากพบสิ่งผิดปกติ ให้หยุดดำเนินการและติดต่อฝ่าย IT "
                "ผ่านช่องทางที่บริษัทกำหนดทันที"
            ),
        }

    @staticmethod
    def executive_summary(threat):
        severity = {
            "Critical": "วิกฤต",
            "High": "สูง",
            "Medium": "ปานกลาง",
            "Low": "ต่ำ",
            "Informational": "ข้อมูลทั่วไป",
        }.get(
            str(threat.get("Severity") or "").strip(),
            str(threat.get("Severity") or "ไม่ทราบระดับ"),
        )
        title = threat.get("Title", "")
        cve = threat.get("CVE", "")
        cvss = threat.get("CVSS") or "ไม่ระบุ"
        source = threat.get("Source", "")

        summary = (
            f"พบเหตุการณ์ด้านความมั่นคงปลอดภัยไซเบอร์ ระดับ {severity}\n\n"
            f"เหตุการณ์ : {title}\n"
            f"CVE : {cve}\n"
            f"CVSS : {cvss}\n"
            f"แหล่งข้อมูล : {source}\n\n"
            f"ฝ่าย IT ควรตรวจสอบเหตุการณ์นี้เพื่อพิจารณาว่า "
            f"ทรัพย์สินของบริษัทได้รับผลกระทบหรือไม่"
        )

        return summary

    @staticmethod
    def business_impact(threat):

        severity = (threat.get("Severity") or "").lower()

        if severity == "critical":
            return [
                "อาจเกิดการสั่งรันโค้ดจากระยะไกล",
                "บริการในระบบผลิตอาจหยุดชะงัก",
                "ควรดำเนินการแก้ไขทันที",
                "ควรรายงานให้ผู้บริหารรับทราบ"
            ]

        if severity == "high":
            return [
                "มีความเสี่ยงสูงต่อการดำเนินงาน",
                "ควรอัปเดตระบบที่ได้รับผลกระทบโดยเร็ว",
                "เฝ้าระวังการโจมตีที่ใช้ช่องโหว่นี้"
            ]

        if severity == "medium":
            return [
                "ผลกระทบต่อการดำเนินงานอยู่ในวงจำกัด",
                "กำหนดเวลาติดตั้งอัปเดต",
                "เฝ้าระวังอย่างต่อเนื่อง"
            ]

        return [
            "มีผลกระทบต่อธุรกิจในระดับต่ำ",
            "ดำเนินการตามกระบวนการอัปเดตตามปกติ"
        ]

    @staticmethod
    def it_recommendation(threat):

        recommendation = threat.get("Recommendation")

        if recommendation:
            return recommendation

        return (
            "ตรวจสอบทรัพย์สินที่อาจได้รับผลกระทบ\n"
            "ตรวจสอบประกาศจากผู้ผลิต\n"
            "ติดตั้งอัปเดตความปลอดภัย\n"
            "เฝ้าระวังกิจกรรมที่น่าสงสัย"
        )

    @staticmethod
    def email_subject(threat):

        return (
            f"[{threat.get('Severity')}] "
            f"{threat.get('CVE')} ประกาศด้านความมั่นคงปลอดภัยไซเบอร์"
        )

    @staticmethod
    def generated_time():

        return datetime.now().strftime("%d %b %Y %H:%M")
