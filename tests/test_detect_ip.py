from .utils import TestCase, skip, mock, StringIO
from dynsupdate import client


class DetectIpTests(TestCase):

    def setUp(self):
        self.services = client.HTTP_IP_SERVICES + client.HTTPS_IP_SERVICES
        self.ip_get = client.SimpleIpGetter(self.services)

    @skip("To slow")
    def test_real_services(self):
        services_ips = {}
        for service in self.ip_get.service_names:
            services_ips[service] = self.ip_get.query_service(service)

        self.assertTrue(len(set(services_ips.values())) == 1,
            "Some service return bad result {0}".format(str(services_ips)))

    @mock.patch('urllib2.urlopen')
    def test_services(self, urlopen_mock):
        def fake_urlopen(url, *args, **kwargs):
            return StringIO("127.0.0.1\n")

        urlopen_mock.side_effect = fake_urlopen

        for service in self.ip_get.service_names:
            self.assertEqual(self.ip_get.query_service(service), "127.0.0.1")
