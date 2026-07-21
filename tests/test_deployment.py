import importlib
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app


ROOT = Path(__file__).resolve().parents[1]


class DeploymentTestConfig:
    TESTING = True
    SECRET_KEY = "deployment-test-secret"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class ProductionDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(DeploymentTestConfig)
        self.client = self.app.test_client()

    def test_wsgi_application_import(self):
        module = importlib.import_module("wsgi")

        self.assertEqual(module.app.name, "app")
        self.assertFalse(module.app.debug)
        self.assertFalse(module.app.config["DEBUG"])

    def test_health_returns_200_when_database_check_succeeds(self):
        with patch(
            "app.health.routes._database_available",
            return_value=True,
        ):
            response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {"status": "ok", "application": "CTI Dashboard"},
        )

    def test_health_returns_503_when_database_check_fails(self):
        with patch(
            "app.health.routes._database_available",
            return_value=False,
        ):
            response = self.client.get("/health")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.get_json(),
            {
                "status": "unavailable",
                "application": "CTI Dashboard",
            },
        )

    def test_health_output_contains_no_secrets(self):
        with patch(
            "app.health.routes._database_available",
            return_value=False,
        ):
            response = self.client.get("/health")

        body = response.get_data(as_text=True)
        for forbidden in (
            DeploymentTestConfig.SECRET_KEY,
            DeploymentTestConfig.SQLALCHEMY_DATABASE_URI,
            "password",
            "connection_string",
            "SQLALCHEMY_DATABASE_URI",
            "traceback",
        ):
            self.assertNotIn(forbidden, body)

    def test_required_powershell_scripts_exist(self):
        scripts = (
            "start-cti-dashboard.ps1",
            "install-cti-dashboard-service.ps1",
            "uninstall-cti-dashboard-service.ps1",
            "configure-cti-firewall.ps1",
        )
        for script in scripts:
            with self.subTest(script=script):
                self.assertTrue((ROOT / "scripts" / script).is_file())

    def test_startup_script_uses_waitress_and_production_defaults(self):
        text = (
            ROOT / "scripts" / "start-cti-dashboard.ps1"
        ).read_text(encoding="utf-8-sig")
        for expected in (
            ".venv\\Scripts\\waitress-serve.exe",
            "$env:CTI_HOST",
            "$env:CTI_PORT",
            "$env:CTI_THREADS",
            '"0.0.0.0"',
            "-Default 8000",
            "-Default 8",
            '"--host=$listenHost"',
            '"--port=$listenPort"',
            '"--threads=$threadCount"',
            '"--no-expose-tracebacks"',
            '"wsgi:app"',
        ):
            self.assertIn(expected, text)
        self.assertNotIn("Activate.ps1", text)

    def test_service_script_contains_required_service_and_recovery(self):
        text = (
            ROOT
            / "scripts"
            / "install-cti-dashboard-service.ps1"
        ).read_text(encoding="utf-8-sig")
        for expected in (
            '$serviceName = "CTIDashboard"',
            '$displayName = "CTI Dashboard"',
            '"SERVICE_AUTO_START"',
            '"AppDirectory"',
            '"AppStdout"',
            '"AppStderr"',
            '"AppExit", "Default", "Restart"',
            "restart/5000/restart/5000/restart/5000",
            "The service was not started",
        ):
            self.assertIn(expected, text)
        self.assertNotIn("Start-Service", text)

    def test_firewall_script_is_scoped_and_removable(self):
        text = (
            ROOT / "scripts" / "configure-cti-firewall.ps1"
        ).read_text(encoding="utf-8-sig")
        self.assertIn('"CTI Dashboard TCP 8000"', text)
        self.assertIn("-LocalPort 8000", text)
        self.assertIn("-Protocol TCP", text)
        self.assertIn("-Profile Domain,Private", text)
        self.assertIn("[switch]$Remove", text)
        self.assertNotIn("Public", text)

    def test_uninstall_targets_only_cti_dashboard_service(self):
        text = (
            ROOT
            / "scripts"
            / "uninstall-cti-dashboard-service.ps1"
        ).read_text(encoding="utf-8-sig")
        self.assertIn('$serviceName = "CTIDashboard"', text)
        self.assertIn("Stop-Service -Name $serviceName", text)
        self.assertIn("sc.exe delete $serviceName", text)
        self.assertNotIn("Remove-Item", text)

    def test_requirements_include_pinned_waitress(self):
        requirements = (ROOT / "requirements.txt").read_text(
            encoding="utf-8-sig"
        )
        self.assertIn("waitress==3.0.2", requirements.splitlines())

    def test_logging_directory_and_placeholder_exist(self):
        self.assertTrue((ROOT / "logs").is_dir())
        self.assertTrue((ROOT / "logs" / ".gitkeep").is_file())


if __name__ == "__main__":
    unittest.main()
