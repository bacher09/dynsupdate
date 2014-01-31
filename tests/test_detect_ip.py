from .utils import TestCase, skip, mock, StringIO
from dynsupdate import client
from itertools import cycle
import socket


class DetectIpTests(TestCase):

    def setUp(self):
        self.services = client.HTTP_IP_SERVICES + client.HTTPS_IP_SERVICES
        self.ip_get = client.SimpleIpGetter(self.services)
        self.small_services = (
            ('test', 'http://testurl.com'),
            ('another', 'http://anotherurl.com'),
            ('yetanother', 'http://yetanother.com')
        )

    @skip("To slow")
    def test_real_services(self):
        services_ips = {}
        for service in self.ip_get.service_names:
            services_ips[service] = self.ip_get.query_service(service)

        self.assertTrue(
            len(set(services_ips.values())) == 1,
            "Some service return bad result {0}".format(str(services_ips))
        )

    @skip("To slow")
    def test_build_resolver(self):
        res = client.build_resolver('google-public-dns-a.google.com')
        self.assertListEqual(res.nameservers, ['8.8.8.8'])

    @mock.patch('dynsupdate.client.urlopen', spec=client.urlopen)
    def test_services(self, urlopen_mock):
        def fake_urlopen(url, *args, **kwargs):
            return StringIO("127.0.0.1\n")

        urlopen_mock.side_effect = fake_urlopen

        for service in self.ip_get.service_names:
            self.assertEqual(self.ip_get.query_service(service), "127.0.0.1")

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
            self.assertRaises(client.IpFetchError, ip_get.get)
            calls = [mock.call(n) for n in ip_get.service_names]
            query_mock.assert_has_calls(calls)
