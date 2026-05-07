import unittest
from aipt.core.models import Vulnerability, Severity, VulnType, Evidence, ScanResult


class TestModels(unittest.TestCase):
    def test_vulnerability_creation(self):
        vuln = Vulnerability(
            type=VulnType.SQL_INJECTION,
            severity=Severity.HIGH,
            title="Test SQLi",
            description="Test description",
            url="https://example.com"
        )
        self.assertEqual(vuln.type, VulnType.SQL_INJECTION)
        self.assertEqual(vuln.severity, Severity.HIGH)
        self.assertTrue(len(vuln.id) > 0)

    def test_risk_score(self):
        vuln = Vulnerability(
            type=VulnType.SQL_INJECTION,
            severity=Severity.CRITICAL
        )
        self.assertEqual(vuln.risk_score, 10.0)

        vuln2 = Vulnerability(
            type=VulnType.XSS,
            severity=Severity.LOW
        )
        self.assertEqual(vuln2.risk_score, 2.5)

    def test_scan_result_summary(self):
        result = ScanResult(target="https://example.com")
        result.vulnerabilities = [
            Vulnerability(type=VulnType.SQL_INJECTION, severity=Severity.CRITICAL),
            Vulnerability(type=VulnType.XSS, severity=Severity.HIGH),
            Vulnerability(type=VulnType.XSS, severity=Severity.HIGH),
        ]
        
        summary = result.severity_summary
        self.assertEqual(summary['CRITICAL'], 1)
        self.assertEqual(summary['HIGH'], 2)

    def test_vulnerability_to_dict(self):
        vuln = Vulnerability(
            type=VulnType.SQL_INJECTION,
            severity=Severity.HIGH,
            title="Test",
            evidence=Evidence(request="GET /test", response="Error")
        )
        vuln_dict = vuln.to_dict()
        self.assertEqual(vuln_dict['type'], 'SQL Injection')
        self.assertEqual(vuln_dict['severity'], 'HIGH')
        self.assertIn('evidence', vuln_dict)


if __name__ == '__main__':
    unittest.main()
