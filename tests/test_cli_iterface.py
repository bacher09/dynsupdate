from .utils import TestCase, mock, StringIO, skip
from dynsupdate import client
import dns.rdtypes.IN.A
import dns.resolver
import dns.name
import argparse
import logging


KEY_TEXT = """
key "test" {
    algorithm hmac-sha256;
    secret "po+SV3VXzzcWgsl+kUwscaFIroLtkzdq2Sp72MhXvDw=";
};
"""


class CliParseTest(TestCase):

    def test_comma_separated_list(self):
        my_types = client.comma_separated_list(['http', 'https'])
        good = my_types('http')
        self.assertSetEqual(good, set(['http']))
        good2 = my_types('http,https')
        self.assertSetEqual(good2, set(['http', 'https']))

        self.assertRaises(argparse.ArgumentTypeError, my_types, "http,bad")
        # TODO: Maybe tests arguments in uppercase to


class CliIterfaceTest(TestCase):

    def setUp(self):
        self.patch_stdout()
        self.patch_urlopen()
        self.patch_argparse()
        self.patch_dnslib_resolver()
        self.patch_dnslib_query()

    def patch_stdout(self):
        stdout_patch = mock.patch('sys.stdout', new_callable=StringIO)
        self.stdout_mock = stdout_patch.start()
        self.addCleanup(stdout_patch.stop)

    def patch_urlopen(self):
        urlopen_patch = mock.patch('dynsupdate.client.urlopen',
                                   spec=client.urlopen)

        self.urlopen_mock = urlopen_patch.start()
        self.addCleanup(urlopen_patch.stop)

    def patch_argparse(self):

        filetype_patch = mock.patch('argparse.FileType')
        self.filetype_mock = filetype_patch.start()
        self.addCleanup(filetype_patch.stop)
        self.keyfile_mock_factory = mock.mock_open(read_data=KEY_TEXT)

        def keyfile_sideeffect(filename):
            if filename == "keyname.key":
                return self.keyfile_mock_factory()
            raise IOError()

        self.filetype_mock.return_value.side_effect = keyfile_sideeffect

    def patch_dnslib_resolver(self):
        self.resolver_mock = mock.Mock(spec=dns.resolver.Resolver)
        self.zone_for_name_mock = mock.Mock(spec=[])

        resolvers_patch = mock.patch.multiple(
            'dns.resolver',
            query=self.resolver_mock.return_value.query,
            Resolver=self.resolver_mock,
            zone_for_name=self.zone_for_name_mock
        )

        resolvers_patch.start()
        self.addCleanup(resolvers_patch.stop)

        soa_params = ['mname', 'rname', 'serial', 'refresh', 'retry']
        self.response_soa_mock = mock.Mock(spec_set=soa_params)
        self.response_soa_mock.mname.to_text.return_value = "master.server"

        def query_effect(name, type):
            master = dns.name.from_text('master.server')
            check_name = dns.name.from_text('name.zone.com')
            if isinstance(name, str):
                name = dns.name.from_text(name)

            if name == master and type == 'A':
                yield dns.rdtypes.IN.A.A(1, 1, '127.0.0.2')
            elif type == "A" and name == check_name:
                yield dns.rdtypes.IN.A.A(1, 1, '127.0.0.1')
            elif type == "SOA":
                yield self.response_soa_mock
            raise dns.resolver.NXDOMAIN("Bad arguments")

        def zone_for_name_effect(name):
            if isinstance(name, str):
                name = dns.name.from_text(name)
            zone = dns.name.from_text('zone.com')
            if name.is_subdomain(zone):
                return zone
            raise ValueError("Bad arguments")

        self.resolver_mock.return_value.query.side_effect = query_effect
        self.zone_for_name_mock.side_effect = zone_for_name_effect

    def patch_dnslib_query(self):
        self.query_mock = mock.Mock(spec=[])
        patch_query = mock.patch.multiple('dns.query', tcp=self.query_mock,
                                          udp=self.query_mock)

        patch_query.start()
        self.addCleanup(patch_query.stop)

    def test_interface_checkip(self):
        response_mock = mock.mock_open(read_data="127.0.0.1\n")
        self.urlopen_mock.side_effect = response_mock
        prog = client.Program()
        prog.run("checkip".split(), log=False)
        ret_value = self.stdout_mock.getvalue()
        self.assertIn('127.0.0.1', ret_value)

    def test_interface_update(self):
        response_mock = mock.mock_open(read_data="127.0.0.6\n")
        self.urlopen_mock.side_effect = response_mock
        prog = client.Program()
        prog.run("update -k keyname.key name.zone.com".split(), log=False)
        self.query_mock.assert_called_with(
            mock.ANY, "master.server", timeout=mock.ANY, port=53
        )
        args, kwargs = self.query_mock.call_args
        updater = args[0]
        self.assertEqual(updater.origin.to_text(), "zone.com.")
        # look to KEY_TEXT
        self.assertEqual(updater.keyname.to_text(), "test.")
        self.assertEqual(updater.keyalgorithm, "hmac-sha256")
        msg_text = updater.to_text()

        self.assertIn("127.0.0.6", msg_text)
        self.assertIn("name", msg_text)

    def test_interface_update2(self):
        self.urlopen_mock.side_effect = mock.mock_open(read_data="127.0.0.7\n")
        prog = client.Program()
        prog.run("update -k keyname.key other.zone.com".split(), log=False)

        args, kwargs = self.query_mock.call_args
        updater = args[0]
        msg_text = updater.to_text()
        self.assertIn("other", msg_text)
        self.assertIn("127.0.0.7", msg_text)
        self.assertNotIn("name", msg_text)
