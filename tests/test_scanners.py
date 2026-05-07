import unittest
from aipt.scanners.vulnerability_scanner import PayloadDatabase, WAFDetector, WAFBypass
from aipt.scanners.js_auditor import JSPatternMatcher, SecretScanner


class TestPayloadDatabase(unittest.TestCase):
    def test_loads_payloads(self):
        db = PayloadDatabase()
        sqli_payloads = db.get_payloads('sqli_error')
        self.assertTrue(len(sqli_payloads) > 0)
        self.assertIn('payload', sqli_payloads[0])

    def test_get_all_categories(self):
        db = PayloadDatabase()
        categories = db.get_all_categories()
        self.assertIn('sqli_error', categories)
        self.assertIn('xss', categories)


class TestWAFDetector(unittest.TestCase):
    def setUp(self):
        self.detector = WAFDetector()

    def test_detects_cloudflare(self):
        class MockResponse:
            headers = {'cf-ray': '1234567890abcdef'}
            text = ''
            status_code = 200

        result = self.detector.detect(MockResponse())
        self.assertEqual(result, 'Cloudflare')

    def test_no_waf(self):
        class MockResponse:
            headers = {}
            text = 'Normal response'
            status_code = 200

        result = self.detector.detect(MockResponse())
        self.assertIsNone(result)


class TestWAFBypass(unittest.TestCase):
    def setUp(self):
        self.bypass = WAFBypass()

    def test_generates_variants(self):
        payload = "<script>alert(1)</script>"
        variants = self.bypass.generate_variants(payload)
        self.assertTrue(len(variants) > 1)
        self.assertIn(payload, variants)


class TestJSPatternMatcher(unittest.TestCase):
    def setUp(self):
        self.matcher = JSPatternMatcher()

    def test_detects_eval(self):
        code = "eval(userInput)"
        findings = self.matcher.analyze(code)
        self.assertTrue(len(findings) > 0)
        self.assertTrue(any('eval' in f.title.lower() for f in findings))

    def test_detects_innerhtml(self):
        code = "element.innerHTML = userData"
        findings = self.matcher.analyze(code)
        self.assertTrue(len(findings) > 0)


class TestSecretScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = SecretScanner()

    def test_detects_aws_key(self):
        # Use a realistic AWS key format (AKIA + 16 alphanumeric chars = 20 total)
        code = 'const key = "AKIAIOSFODNN7EXAMP12"'
        findings = self.scanner.scan(code)
        self.assertTrue(len(findings) > 0)

    def test_false_positive(self):
        code = 'const password = "example_password"'
        findings = self.scanner.scan(code)
        # Should filter out "example" as false positive
        self.assertEqual(len(findings), 0)


if __name__ == '__main__':
    unittest.main()
