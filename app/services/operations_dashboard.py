import json
import logging
from itertools import islice
from time import perf_counter

from flask import current_app, has_app_context
from sqlalchemy.orm import joinedload, selectinload

from app.extensions import db
from app.models.threat import Threat
from app.models.threat_cve import ThreatCVE

from .decision_engine import DecisionEngine
from .impact_analysis import ImpactAnalysisService
from .risk_assessment import RiskAssessmentService


LOGGER = logging.getLogger(__name__)
DEFAULT_THREAT_LIMIT = 100


class OperationsDashboardService:
    """Build the read-only Security Operations dashboard view model."""

    def __init__(
        self,
        impact_service=None,
        risk_service=None,
        decision_engine=None,
    ):
        self.impact_service = impact_service or ImpactAnalysisService()
        self.risk_service = risk_service or RiskAssessmentService()
        self.decision_engine = decision_engine or DecisionEngine()

    def analyze(self, threats=None, limit=None):
        profiling_enabled = (
            has_app_context() and current_app.debug
        )
        total_started = perf_counter() if profiling_enabled else None
        timings = self._empty_timings() if profiling_enabled else None

        analysis_limit = self._analysis_limit(limit)
        retrieval_started = perf_counter() if profiling_enabled else None
        if threats is None:
            selected_threats = self._recent_threats(analysis_limit)
        else:
            selected_threats = list(islice(threats, analysis_limit))
        if profiling_enabled:
            timings["threat_retrieval_ms"] += self._elapsed_ms(
                retrieval_started
            )

        result = self._empty_result()
        # Preload catalog products, aliases, and assets once. Every threat in
        # this dashboard batch is then normalized and matched in memory.
        preload = getattr(self.impact_service, "preload", None)
        if selected_threats and callable(preload):
            preload_started = perf_counter() if profiling_enabled else None
            try:
                preload()
            except Exception:
                # Preserve the existing per-threat error isolation if a preload
                # fails; standalone analyze() can still use its normal path.
                LOGGER.exception(
                    "Operations dashboard preload failed; "
                    "falling back to per-threat analysis"
                )
            finally:
                if profiling_enabled:
                    timings["data_preload_ms"] += self._elapsed_ms(
                        preload_started
                    )
        for threat in selected_threats:
            try:
                if profiling_enabled:
                    self._analyze_threat_profiled(
                        threat, result, timings
                    )
                else:
                    self._analyze_threat(threat, result)
            except Exception:
                threat_id = getattr(threat, "ThreatId", None)
                LOGGER.exception(
                    "Operations dashboard analysis failed for ThreatId=%s",
                    threat_id,
                )
                result["summary"]["analysis_errors"] += 1
                result["analysis_errors"].append(
                    {
                        "threat_id": threat_id,
                        "threat_identifier": self._threat_identifier(
                            threat
                        ),
                        "message": "Threat analysis failed",
                    }
                )
        if profiling_enabled:
            timings["total_execution_ms"] = self._elapsed_ms(
                total_started
            )
            timings["threat_count"] = len(selected_threats)
            timings["analysis_error_count"] = result["summary"][
                "analysis_errors"
            ]
            LOGGER.debug(
                json.dumps(
                    {
                        "event": "operations_dashboard_profile",
                        "timings": {
                            key: (
                                round(value, 3)
                                if isinstance(value, float)
                                else value
                            )
                            for key, value in timings.items()
                        },
                    },
                    sort_keys=True,
                )
            )
        return result

    @classmethod
    def _recent_threats(cls, limit):
        return db.session.execute(
            cls._recent_threat_query(limit)
        ).scalars().all()

    @staticmethod
    def _recent_threat_query(limit):
        return (
            db.select(Threat)
            .options(
                joinedload(Threat.vendor),
                selectinload(Threat.cve_links).joinedload(ThreatCVE.cve),
            )
            .order_by(
                Threat.CreatedAt.desc(),
                Threat.ThreatId.desc(),
            )
            .limit(limit)
        )

    def _analyze_threat(self, threat, result):
        vendor_name = self._vendor_name(threat)
        product_name = self._product_name(threat)
        impact_result = self.impact_service.analyze(
            vendor_name, product_name
        )
        risk_result = self.risk_service.assess(
            impact_result, self._risk_context(threat)
        )
        decision_result = self.decision_engine.recommend(risk_result)
        self._aggregate_threat_result(
            threat,
            result,
            vendor_name,
            product_name,
            impact_result,
            risk_result,
            decision_result,
        )

    def _analyze_threat_profiled(self, threat, result, timings):
        vendor_name = self._vendor_name(threat)
        product_name = self._product_name(threat)

        if isinstance(self.impact_service, ImpactAnalysisService):
            started = perf_counter()
            normalization = (
                self.impact_service.product_normalizer.normalize(
                    vendor_name, product_name
                )
            )
            timings["product_normalization_ms"] += self._elapsed_ms(
                started
            )

            started = perf_counter()
            impact_result = self.impact_service.analyze_normalized(
                normalization
            )
            timings["impact_analysis_ms"] += self._elapsed_ms(started)
        else:
            # Custom impact services retain their existing interface. Their
            # combined work is reported as impact analysis.
            started = perf_counter()
            impact_result = self.impact_service.analyze(
                vendor_name, product_name
            )
            timings["impact_analysis_ms"] += self._elapsed_ms(started)

        started = perf_counter()
        risk_result = self.risk_service.assess(
            impact_result, self._risk_context(threat)
        )
        timings["risk_assessment_ms"] += self._elapsed_ms(started)

        started = perf_counter()
        decision_result = self.decision_engine.recommend(risk_result)
        timings["decision_engine_ms"] += self._elapsed_ms(started)

        started = perf_counter()
        self._aggregate_threat_result(
            threat,
            result,
            vendor_name,
            product_name,
            impact_result,
            risk_result,
            decision_result,
        )
        timings["dashboard_aggregation_ms"] += self._elapsed_ms(started)

    def _aggregate_threat_result(
        self,
        threat,
        result,
        vendor_name,
        product_name,
        impact_result,
        risk_result,
        decision_result,
    ):
        risk_assets = risk_result.get("asset_results") or []
        for index, action in enumerate(
            decision_result.get("asset_actions") or []
        ):
            risk_asset = (
                risk_assets[index] if index < len(risk_assets) else {}
            )
            item = self._asset_item(
                threat,
                vendor_name,
                impact_result.get("product_name") or product_name,
                risk_asset,
                action,
            )
            destination = self._asset_destination(action)
            if destination is not None:
                result[destination].append(item)
                result["summary"][destination] += 1

        for action in (
            decision_result.get("communication_actions") or []
        ):
            if action.get("action_type") != "NOTIFY_USERS":
                continue
            result["communication_actions"].append(
                self._communication_item(threat, action)
            )
            result["summary"]["notify_users"] += 1

    @staticmethod
    def _elapsed_ms(started):
        return (perf_counter() - started) * 1000

    @staticmethod
    def _empty_timings():
        return {
            "threat_retrieval_ms": 0.0,
            "data_preload_ms": 0.0,
            "product_normalization_ms": 0.0,
            "impact_analysis_ms": 0.0,
            "risk_assessment_ms": 0.0,
            "decision_engine_ms": 0.0,
            "dashboard_aggregation_ms": 0.0,
            "total_execution_ms": 0.0,
        }

    @staticmethod
    def _asset_destination(action):
        mapping = {
            ("REMEDIATE", "P1"): "patch_immediately",
            ("REMEDIATE", "P2"): "patch_this_week",
            ("REMEDIATE", "P3"): "review_and_schedule",
            ("MONITOR", "P4"): "monitor",
        }
        return mapping.get(
            (action.get("action_type"), action.get("priority"))
        )

    @classmethod
    def _asset_item(
        cls,
        threat,
        vendor_name,
        product_name,
        risk_asset,
        action,
    ):
        return {
            "threat_id": getattr(threat, "ThreatId", None),
            "threat_identifier": cls._threat_identifier(threat),
            "asset_name": action.get("asset_name"),
            "vendor": vendor_name,
            "product": product_name,
            "risk_level": risk_asset.get("level"),
            "priority": action.get("priority"),
            "recommendation": action.get("recommendation"),
            "target": action.get("target"),
            "reasons": list(action.get("reasons") or []),
        }

    @classmethod
    def _communication_item(cls, threat, action):
        reasons = list(action.get("reasons") or [])
        return {
            "threat_id": getattr(threat, "ThreatId", None),
            "threat_identifier": cls._threat_identifier(threat),
            "recommendation": action.get("recommendation"),
            "priority": action.get("priority"),
            "target": action.get("target"),
            "affected_user_group": action.get(
                "affected_user_group"
            ),
            "notification_reason": reasons[0] if reasons else None,
            "reasons": reasons,
        }

    @staticmethod
    def _vendor_name(threat):
        vendor = getattr(threat, "vendor", None)
        if vendor is not None:
            return getattr(vendor, "VendorName", None)
        return None

    @staticmethod
    def _product_name(threat):
        for attribute in ("Product", "ProductName"):
            value = getattr(threat, attribute, None)
            if value and str(value).strip():
                return str(value).strip()
        return (getattr(threat, "Title", None) or "").strip()

    @staticmethod
    def _risk_context(threat):
        context = {
            "cvss_score": getattr(threat, "CVSS", None),
            "kev": bool(getattr(threat, "KEV", False)),
        }
        if hasattr(Threat, "PublicExploit"):
            context["public_exploit"] = bool(
                getattr(threat, "PublicExploit", False)
            )
        return context

    @staticmethod
    def _threat_identifier(threat):
        cve = getattr(threat, "primary_cve_code", None)
        if not cve:
            cve = getattr(threat, "CVE", None)
        if cve and str(cve).strip():
            additional = getattr(threat, "additional_cve_count", 0) or 0
            suffix = f" +{additional}" if additional else ""
            return f"{str(cve).strip()}{suffix}"
        threat_id = getattr(threat, "ThreatId", None)
        return f"Threat {threat_id}" if threat_id is not None else "Unknown"

    @staticmethod
    def _analysis_limit(limit):
        configured = (
            current_app.config.get(
                "OPERATIONS_DASHBOARD_THREAT_LIMIT",
                DEFAULT_THREAT_LIMIT,
            )
            if limit is None
            else limit
        )
        try:
            value = int(configured)
        except (TypeError, ValueError):
            LOGGER.warning(
                "Invalid operations dashboard threat limit %r; using %s",
                configured,
                DEFAULT_THREAT_LIMIT,
            )
            return DEFAULT_THREAT_LIMIT
        if value <= 0:
            LOGGER.warning(
                "Non-positive operations dashboard threat limit %r; "
                "using %s",
                configured,
                DEFAULT_THREAT_LIMIT,
            )
            return DEFAULT_THREAT_LIMIT
        return value

    @staticmethod
    def _empty_result():
        return {
            "summary": {
                "patch_immediately": 0,
                "patch_this_week": 0,
                "review_and_schedule": 0,
                "notify_users": 0,
                "monitor": 0,
                "analysis_errors": 0,
            },
            "patch_immediately": [],
            "patch_this_week": [],
            "review_and_schedule": [],
            "communication_actions": [],
            "monitor": [],
            "analysis_errors": [],
        }
