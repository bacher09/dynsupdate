from .utils import TestCase, skipUnless
from dynsupdate import client
import os


class DnsTests(TestCase):

    @skipUnless(os.getenv("SLOW"), "To slow")
    def test_build_resolver(self):
        domain = 'google-public-dns-a.google.com'
        res = client.NameUpdate.build_resolver(domain)
        self.assertListEqual(res.nameservers, ['8.8.8.8'])
