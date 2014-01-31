import re
import urllib2
import socket
import contextlib


MAX_RESPONSE_DATA = 8192
# TODO: Support IPv6 too
SIMPLE_IPV4_RE = re.compile("(?:\d{1,3}\.){3}\d{1,3}")


def ip_from_dyndns(data):
    for m in SIMPLE_IPV4_RE.finditer(data):
        return m.group()


# TODO: support dig +short myip.opendns.com @resolver1.opendns.com
HTTPS_IP_SERVICES = (
    ('https_icanhazip', 'https://icanhazip.com/'),
)


HTTP_IP_SERVICES = (
    ('dyndns', 'http://checkip.dyndns.com/', ip_from_dyndns),
    ('icanhazip', 'http://icanhazip.com/'),
    ('curlmyip', 'http://curlmyip.com/'),
    ('ifconfigme', 'http://ifconfig.me/ip'),
    ('ip.appspot.com', 'http://ip.appspot.com'),
    ('ipinfo', 'http://ipinfo.io/ip'),
    ('externalip', 'http://api.externalip.net/ip'),
    ('trackip', 'http://www.trackip.net/ip')
)


def simple_ip_fetch(url, extract_fun=lambda x: x.strip(), timeout=5):
    try:
        with contextlib.closing(urllib2.urlopen(url, timeout=timeout)) as resp:
            # Limit response size
            data = resp.read(MAX_RESPONSE_DATA)
    except (urllib2.URLError, socket.error) as e:
        return None
    else:
        return extract_fun(data)


class SimpleIpGetter(object):

    def __init__(self, services, timeout=5):
        self.services = {}
        for service in services:
            name = service[0]
            self.services[name] = service[1:]

        self.service_names = tuple(self.services.keys())
        self.timeout = timeout

    def query_service(self, service_name):
        if service_name not in self.services:
            raise ValueError("Bad service_name '{0}'".format(service_name))

        args = self.services[service_name]
        return simple_ip_fetch(*args, timeout=self.timeout)
