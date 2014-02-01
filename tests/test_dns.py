from .utils import TestCase, skipUnless, mock
from dynsupdate import client
import os


class DnsTests(TestCase):

    @skipUnless(os.getenv("SLOW"), "To slow")
    def test_build_resolver(self):
        domain = 'google-public-dns-a.google.com'
        res = client.NameUpdate.build_resolver(domain)
        self.assertListEqual(res.nameservers, ['8.8.8.8'])

    @mock.patch('dns.resolver.query')
    @mock.patch('dns.resolver.Resolver')
    def test_build_resolver_fake(self, mock_resolver, mock_query):
        mock_rdata = mock.Mock()
        mock_rdata.address = "127.0.0.1"
        mock_query.return_value = iter([mock_rdata])
        res = client.NameUpdate.build_resolver("ns1.fake.com", port=999)
        mock_query.assert_called_with("ns1.fake.com", "A")
        print(mock_resolver.mock_calls)
        mock_resolver.return_value.nameservers.append \
            .assert_called_with("127.0.0.1")

        self.assertEqual(res.port, 999)
