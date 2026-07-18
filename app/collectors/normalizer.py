import json
import re
from dataclasses import dataclass
from datetime import date, datetime, time, timezone
from decimal import Decimal, InvalidOperation
from typing import Any


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
SEVERITIES = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}


@dataclass(frozen=True)
class NormalizedItem:
    external_id: str | None
    title: str
    source_url: str | None
    published_date: datetime | None
    source_name: str
    vendor_name: str | None
    severity: str | None
    cve_ids: tuple[str, ...]
    cvss: Decimal | None
    kev: bool
    summary: str | None
    raw_content: str
    recommendation: str | None = None
    product: str | None = None
    known_ransomware_campaign_use: str | None = None
    due_date: datetime | None = None
    notes: str | None = None
    source_modified_date: datetime | None = None
    normalized_metadata: str | None = None


def _text(value: Any, maximum: int | None = None) -> str | None:
    if value is None:
        return None
    result = str(value).strip()
    if not result:
        return None
    if maximum is not None and len(result) > maximum:
        raise ValueError(f"value exceeds maximum length of {maximum}")
    return result


def _published_date(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, date):
        result = datetime.combine(value, time.min)
    elif isinstance(value, str):
        candidate = value.strip()
        if candidate.endswith("Z"):
            candidate = candidate[:-1] + "+00:00"
        try:
            result = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise ValueError("published_date must be ISO-8601") from exc
    else:
        raise ValueError("published_date must be a date, datetime, or ISO-8601 string")

    if result.tzinfo is not None:
        result = result.astimezone(timezone.utc).replace(tzinfo=None)
    return result


def _cvss(value: Any) -> Decimal | None:
    if value is None or value == "":
        return None
    try:
        result = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError("cvss must be numeric") from exc
    if not result.is_finite() or result < Decimal("0.0") or result > Decimal("10.0"):
        raise ValueError("cvss must be between 0.0 and 10.0")
    return result.quantize(Decimal("0.1"))


def _cves(value: Any) -> tuple[str, ...]:
    if value is None:
        values = []
    elif isinstance(value, str):
        values = re.split(r"[,;\s]+", value)
    else:
        try:
            values = list(value)
        except TypeError as exc:
            raise ValueError("cve_ids must be a string or iterable") from exc

    normalized = []
    for candidate in values:
        cve = str(candidate).strip().upper()
        if not cve:
            continue
        if not CVE_PATTERN.fullmatch(cve):
            raise ValueError(f"invalid CVE identifier: {cve}")
        if cve not in normalized:
            normalized.append(cve)
    return tuple(normalized)


def _boolean(value: Any) -> bool:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no", ""}:
            return False
        raise ValueError("kev must be boolean")
    return bool(value)


def normalize_item(item: dict[str, Any], source_name: str) -> NormalizedItem:
    title = _text(item.get("title"), maximum=255)
    if title is None:
        raise ValueError("title is required")

    severity_value = _text(item.get("severity"), maximum=20)
    severity = None
    if severity_value:
        severity = SEVERITIES.get(severity_value.lower())
        if severity is None:
            raise ValueError("severity must be Critical, High, Medium, or Low")

    raw_value = item.get("raw_content")
    if isinstance(raw_value, str):
        raw_content = raw_value
    else:
        raw_content = json.dumps(
            raw_value if raw_value is not None else item,
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        )

    return NormalizedItem(
        external_id=_text(item.get("external_id"), maximum=500),
        title=title,
        source_url=_text(item.get("source_url"), maximum=1000),
        published_date=_published_date(item.get("published_date")),
        source_name=_text(source_name, maximum=100) or "Unknown",
        vendor_name=_text(item.get("vendor_name"), maximum=100),
        severity=severity,
        cve_ids=_cves(item.get("cve_ids")),
        cvss=_cvss(item.get("cvss")),
        kev=_boolean(item.get("kev", False)),
        summary=_text(item.get("summary")),
        raw_content=raw_content,
        recommendation=_text(item.get("recommendation")),
        product=_text(item.get("product"), maximum=500),
        known_ransomware_campaign_use=_text(
            item.get("known_ransomware_campaign_use"), maximum=50
        ),
        due_date=_published_date(item.get("due_date")),
        notes=_text(item.get("notes")),
        source_modified_date=_published_date(item.get("source_modified_date")),
        normalized_metadata=_text(item.get("normalized_metadata")),
    )
