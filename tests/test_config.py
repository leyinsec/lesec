import unittest
import os
import tempfile
from aipt.core.config import Config, ScanConfig, AuthConfig


class TestConfig(unittest.TestCase):
    def test_default_config(self):
        config = Config()
        self.assertEqual(config.scan.max_depth, 3)
        self.assertEqual(config.scan.concurrency, 100)
        self.assertFalse(config.auth.enabled)

    def test_from_env(self):
        os.environ['AIPT_CONCURRENCY'] = '200'
        os.environ['AIPT_TIMEOUT'] = '30.0'
        
        config = Config.from_env()
        self.assertEqual(config.scan.concurrency, 200)
        self.assertEqual(config.scan.request_timeout, 30.0)
        
        del os.environ['AIPT_CONCURRENCY']
        del os.environ['AIPT_TIMEOUT']

    def test_to_dict(self):
        config = Config()
        config_dict = config.to_dict()
        self.assertIn('scan', config_dict)
        self.assertIn('auth', config_dict)


if __name__ == '__main__':
    unittest.main()
