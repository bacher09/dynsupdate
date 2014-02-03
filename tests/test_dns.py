from .utils import TestCase, skipUnless, mock
from dynsupdate import client
import dns.rdtypes.IN.A
import os


class RealDnsTests(TestCase):

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
        mock_resolver.return_value.nameservers.append \
            .assert_called_with("127.0.0.1")

        self.assertEqual(res.port, 999)

    def get_fake_resolver(self):
        mock_resolver = mock.Mock()
        resolver_answer = dns.rdtypes.IN.A.A(1, 1, '127.0.0.1')
        mock_resolver.query.return_value = iter([resolver_answer])
        return mock_resolver

    def test_check_name(self):
        mock_resolver = self.get_fake_resolver()
        val = client.NameUpdate.check_name('test.com', mock_resolver)
        self.assertEqual(val, "127.0.0.1")
        mock_resolver.query.assert_called_with('test.com', 'A')

        with mock.patch('dns.resolver.get_default_resolver') as getdef_mock:
            getdef_mock.return_value = mock_resolver
            val = client.NameUpdate.check_name('test.com')
            self.assertIsNone(val)

    def test_determine_master_server(self):
        answer_params = ['mname', 'rname', 'serial', 'refresh', 'retry']
        mock_answer = mock.Mock(spec_set=answer_params)
        mock_answer.mname.to_text.return_value = "master.server"
        mock_resolver = mock.Mock()
        mock_resolver.query.return_value = iter([mock_answer])
        with mock.patch('dns.resolver.get_default_resolver') as getdef_mock:
            getdef_mock.return_value = mock_resolver
            val = client.NameUpdate.determine_server('test.com')
            self.assertEqual(val, "master.server")

        # empty list, return None
        mock_resolver.query.return_value = iter([])
        val = client.NameUpdate.determine_server('test.com', mock_resolver)
        self.assertIsNone(val)
