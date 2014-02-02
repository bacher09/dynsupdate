from .utils import TestCase, mock, StringIO
from dynsupdate import client
import argparse


class CliIterfaceTest(TestCase):

    def test_comma_separated_list(self):
        my_types = client.comma_separated_list(['http', 'https'])
        good = my_types('http')
        self.assertSetEqual(good, set(['http']))
        good2 = my_types('http,https')
        self.assertSetEqual(good2, set(['http', 'https']))

        self.assertRaises(argparse.ArgumentTypeError, my_types, "http,bad")
        # TODO: Maybe tests arguments in uppercase to

    @mock.patch('sys.stdout', new_callable=StringIO)
    @mock.patch('dynsupdate.client.urlopen', spec=client.urlopen)
    def test_interface_checkip(self, urlopen_mock, stdout_mock):
        response_mock = mock.mock_open(read_data="127.0.0.1\n")
        urlopen_mock.side_effect = response_mock
        prog = client.Program()
        prog.run("checkip".split())
        ret_value = stdout_mock.getvalue()
        self.assertTrue('127.0.0.1' in ret_value)
