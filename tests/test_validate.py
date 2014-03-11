from .utils import TestCase
from dynsupdate.client import validate_ipv4, validate_ipv6, validate_ipv46


class DetectIpTests(TestCase):

    def test_validate_ipv4(self):
        self.assertTrue(validate_ipv4("127.0.0.1"))
        self.assertTrue(validate_ipv4("192.168.1.1"))
        self.assertFalse(validate_ipv4("256.192.0.1"))
        self.assertFalse(validate_ipv4("bad"))
        self.assertFalse(validate_ipv4("...."))

    def test_validate_ipv6(self):
        self.assertTrue(validate_ipv6("::1"))
        self.assertTrue(validate_ipv6("3701:3701:0:42::22:ceef"))
        self.assertFalse(validate_ipv6("127.0.0.1"))
        self.assertFalse(validate_ipv6("bad"))
        self.assertFalse(validate_ipv6("...."))

    def test_validate_ipv46(self):
        self.assertTrue(validate_ipv46("::1"))
        self.assertTrue(validate_ipv46("127.0.0.1"))
        self.assertFalse(validate_ipv46("bad"))
