from .utils import TestCase, mock, StringIO, skip
from dynsupdate import client
import dns.rdtypes.IN.A
import dns.resolver
import dns.name
import dns.exception
import argparse
import logging


KEY_TEXT = """
key "test" {
    algorithm hmac-sha256;
    secret "po+SV3VXzzcWgsl+kUwscaFIroLtkzdq2Sp72MhXvDw=";
};
"""


BAD_KEY = "Bad data"


class ExitException(Exception):
    pass


class CliParseTest(TestCase):

    def test_comma_separated_list(self):
        my_types = client.comma_separated_list(['http', 'https'])
        good = my_types('http')
        self.assertSetEqual(good, set(['http']))
        good2 = my_types('http,https')
        self.assertSetEqual(good2, set(['http', 'https']))

        self.assertRaises(argparse.ArgumentTypeError, my_types, "http,bad")
        # TODO: Maybe tests arguments in uppercase to

    def test_validate_int(self):
        positive_int = client.integer_range(min=0)
        self.assertRaises(argparse.ArgumentTypeError, positive_int, "bad")
        self.assertRaises(argparse.ArgumentTypeError, positive_int, "-2")
        self.assertRaises(argparse.ArgumentTypeError, positive_int, "-1")
        self.assertEqual(positive_int("0"), 0)

        int_range = client.integer_range(min=3, max=6)
        self.assertRaises(argparse.ArgumentTypeError, int_range, "7")
        self.assertRaises(argparse.ArgumentTypeError, int_range, "2")
        self.assertEqual(int_range("3"), 3)
        self.assertEqual(int_range("6"), 6)
        self.assertEqual(int_range("5"), 5)

        float_range = client.integer_range(min=0.2, max=7.6, num_type=float)
        self.assertRaises(argparse.ArgumentTypeError, float_range, "0")
        self.assertRaises(argparse.ArgumentTypeError, float_range, "0.1")
        self.assertRaises(argparse.ArgumentTypeError, float_range, "8")
        self.assertRaises(argparse.ArgumentTypeError, float_range, "7.7")
        self.assertEqual(float_range("0.3"), 0.3)


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
        self.arg_exit_mock = mock.Mock(spec=[])
        self.arg_error_mock = mock.Mock(spec=[])
        self.arg_exit_mock.side_effect = ExitException
        self.arg_error_mock.side_effect = ExitException
        argparse_patch = mock.patch.multiple(
            'argparse.ArgumentParser',
            exit=self.arg_exit_mock,
            error=self.arg_error_mock
        )
        argparse_patch.start()
        self.addCleanup(argparse_patch.stop)

        filetype_patch = mock.patch('argparse.FileType')
        self.filetype_mock = filetype_patch.start()
        self.addCleanup(filetype_patch.stop)
        self.keyfile_mock_factory = mock.mock_open(read_data=KEY_TEXT)
        badkeyfile_factory = mock.mock_open(read_data=BAD_KEY)
        empty_factory = mock.mock_open(read_data="")

        def keyfile_sideeffect(filename):
            if filename == "keyname.key":
                return self.keyfile_mock_factory()
            elif filename == "badkey.key":
                return badkeyfile_factory()
            elif filename == "empty.key":
                return empty_factory()
            else:
                raise ValueError()

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

    def test_interface_checkip_bad_num(self):
        self.urlopen_mock.side_effect = mock.mock_open(read_data="127.0.0.1\n")
        prog = client.Program()
        with self.assertRaises(ExitException):
            prog.run("checkip -n -2".split(), log=False)

        with self.assertRaises(ExitException):
            prog.run("checkip -n 0".split(), log=False)

        with self.assertRaises(ExitException):
            prog.run("checkip --timeout -1".split(), log=False)

        with self.assertRaises(ExitException):
            prog.run("checkip --timeout -0.1".split(), log=False)

    def test_interface_checkip_bad_fetch(self):
        self.urlopen_mock.side_effect = client.URLError("timeout")
        prog = client.Program()

        with self.assertRaises(ExitException):
            prog.run("checkip".split(), log=False)

        self.arg_exit_mock.assert_called_with(69, mock.ANY)

    def test_interface_checkip_bad_services(self):
        prog = client.Program()

        with self.assertRaises(ExitException):
            prog.run("checkip -t https --services curlmyip".split(), log=False)

        self.assertTrue(self.arg_error_mock.called)

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

    def test_interface_update_bad_key(self):
        self.urlopen_mock.side_effect = mock.mock_open(read_data="127.0.0.7\n")
        prog = client.Program()
        with self.assertRaises(ExitException):
            prog.run("update -k badkey.key other.zone.com".split(), log=False)

        with self.assertRaises(ExitException):
            prog.run(
                "update -k keyname.key --keyname bad other.zone.com".split(),
                log=False
            )

        with self.assertRaises(ExitException):
            prog.run("update -k empty.key other.zone.com".split(), log=False)

    def test_interface_update_timeout(self):
        self.urlopen_mock.side_effect = mock.mock_open(read_data="127.0.0.7\n")
        self.resolver_mock.return_value.query \
            .side_effect = dns.exception.Timeout
        prog = client.Program()
        with self.assertRaises(ExitException):
            prog.run("update -k keyname.key test.zone.com".split(), log=False)

        self.zone_for_name_mock.side_effect = dns.exception.Timeout

        with self.assertRaises(ExitException):
            prog.run("update -k keyname.key test.zone.com".split(), log=False)

    def test_interface_update_bad_fetch(self):
        self.urlopen_mock.side_effect = client.URLError("timeout")
        prog = client.Program()
        with self.assertRaises(ExitException):
            prog.run("update -k keyname.key test.zone.com".split(), log=False)

    @mock.patch('dynsupdate.client.Program.checkip_command')
    @mock.patch('dynsupdate.client.logger', spec=logging.Logger)
    def test_interface_set_verbosity(self, logger_mock, checkip_mock):
        logger_mock.configure_mock(handlers=[])
        prog = client.Program()
        prog.run("-vvv checkip".split(), log=True)

        logger_mock.setLevel.assert_called_with(logging.DEBUG)
        logger_mock.addHandler.assert_called_with(mock.ANY)

        prog.run("-vv checkip".split(), log=True)
        logger_mock.setLevel.assert_called_with(logging.INFO)

        prog.run("-v checkip".split(), log=True)
        logger_mock.setLevel.assert_called_with(logging.WARNING)

        prog.run("-vvvvv checkip".split(), log=True)
        logger_mock.setLevel.assert_called_with(logging.DEBUG)
