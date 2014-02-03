from .utils import TestCase, skipUnless, mock, StringIO
from dynsupdate import client
from itertools import cycle
import socket
import os


class DetectIpTests(TestCase):

    def setUp(self):
        self.services = client.HTTP_IP_SERVICES + client.HTTPS_IP_SERVICES
        self.ip_get = client.SimpleIpGetter(self.services)
        self.small_services = (
            ('test', 'http://testurl.com'),
            ('another', 'http://anotherurl.com'),
            ('yetanother', 'http://yetanother.com')
        )

    @skipUnless(os.getenv("SLOW"), "To slow")
    def test_real_services(self):
        services_ips = {}
        for service in self.ip_get.service_names:
            services_ips[service] = self.ip_get.query_service(service)

        self.assertTrue(
            len(set(services_ips.values())) == 1,
            "Some service return bad result {0}".format(str(services_ips))
        )

    @mock.patch('dynsupdate.client.urlopen', spec=client.urlopen)
    def test_services(self, urlopen_mock):
        def fake_urlopen(url, *args, **kwargs):
            return StringIO("127.0.0.1\n")

        urlopen_mock.side_effect = fake_urlopen

        for service in self.ip_get.service_names:
            self.assertEqual(self.ip_get.query_service(service), "127.0.0.1")

    @mock.patch('dynsupdate.client.urlopen', spec=client.urlopen)
    def test_services_bad_response(self, urlopen_mock):
        urlopen_mock.side_effect = mock.mock_open(read_data="bad response")

        for service in self.ip_get.service_names:
            resp = self.ip_get.query_service(service)
            self.assertIsNone(resp, 'Bad response {1!r} of service "{0}"'
                              .format(service, resp))

    @mock.patch('dynsupdate.client.urlopen', spec=client.urlopen)
    def test_bad_query_services(self, urlopen_mock):
        self.assertRaises(ValueError, self.ip_get.query_service, 'bad')

    def test_bad_create_ip_getter(self):
        self.assertRaises(ValueError, client.SimpleIpGetter, [])

    @mock.patch('dynsupdate.client.urlopen', spec=client.urlopen)
    def test_network_issues(self, urlopen_mock):
        urlopen_mock.side_effect = cycle([client.URLError("Bad url"),
                                          socket.error])
        for service in self.ip_get.service_names:
            self.assertEqual(self.ip_get.query_service(service), None)

    @mock.patch('random.randrange')
    def test_iter_random_service(self, randrange_mock):
        randrange_mock.return_value = 0
        ip_get = client.SimpleIpGetter(self.small_services)
        rand_services = tuple(ip_get.iter_rand_service(7))
        result = tuple(ip_get.service_names * 2 + (ip_get.service_names[0],))
        self.assertTupleEqual(rand_services, result)

    @mock.patch('random.randrange')
    def test_iter_random_service(self, randrange_mock):
        randrange_mock.return_value = 0
        ip_get = client.SimpleIpGetter(self.small_services)
        with mock.patch.object(ip_get, 'query_service') as query_mock:
            query_mock.return_value = None
            self.assertRaises(client.IpFetchError, ip_get.get, timeout=10)
            calls = [mock.call(n, timeout=10) for n in ip_get.service_names]
            query_mock.assert_has_calls(calls)

    def test_filter_services(self):
        TEST_SERVICES = (
            ('http:test', 'http://test.com/'),
            ('https:test', 'https://test.com/'),
            ('http:other', 'http://other.com/'),
            ('http:service', 'http://sercice.com/')
        )

        http_services = client.SimpleIpGetter \
            .filter_services(TEST_SERVICES, types=['http'])

        https_services = client.SimpleIpGetter \
            .filter_services(TEST_SERVICES, types=['https'])

        self.assertTupleEqual(tuple(http_services), (
            ('http:test', 'http://test.com/'),
            ('http:other', 'http://other.com/'),
            ('http:service', 'http://sercice.com/')
        ))

        self.assertTupleEqual(tuple(https_services), (
            ('https:test', 'https://test.com/'),
        ))

        tests_services = client.SimpleIpGetter \
            .filter_services(TEST_SERVICES, names=['test'])

        self.assertTupleEqual(tuple(tests_services), (
            ('http:test', 'http://test.com/'),
            ('https:test', 'https://test.com/'),
        ))

        tests2_services = client.SimpleIpGetter \
            .filter_services(TEST_SERVICES, types=['http'], names=['test'])

        self.assertTupleEqual(tuple(tests2_services), (
            ('http:test', 'http://test.com/'),
        ))
