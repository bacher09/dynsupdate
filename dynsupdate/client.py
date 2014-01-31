import re
import socket
import contextlib
import sys
import random
import dns.resolver


PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3


if PY2:
    from urllib2 import urlopen, URLError
else:
    from urllib.request import urlopen
    from urllib.error import URLError




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
        with contextlib.closing(urlopen(url, timeout=timeout)) as resp:
            # Limit response size
            data = resp.read(MAX_RESPONSE_DATA)
    except (URLError, socket.error) as e:
        return None
    else:
        return extract_fun(data)


class IpFetchError(Exception):
    pass


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

    def iter_rand_service(self, num):
        l = len(self.service_names)
        for i in range(num):
            if i % l == 0:
                el = random.randrange(l)
                yield self.service_names[el] 
                next_array = list(self.service_names)
                del next_array[el]
                k = l
            else:
                k -= 1
                el = random.randrange(k)
                yield next_array[el] 
                del next_array[el]
                
    def get(self, tries=3):
        for service in self.iter_rand_service(tries):
            res = self.query_service(service)
            if res is not None:
                return res

        raise IpFetchError("Can't fetch ip address")


def build_resolver(server):
    for rdata in dns.resolver.query(server, 'A'):
        new_resolver = dns.resolver.Resolver(configure=False)
        new_resolver.nameservers.append(rdata.address)
        return new_resolver


class BadToken(Exception):
    pass


class KeyConfig(object):

    WHITE_SPACE_RE = re.compile("\s+")
    KEYWORD_RE = re.compile("[a-z]+[a-z\d\-]*[a-z\d]+", re.I)
    STRING_RE = re.compile('"([^"]*)"')
    BLOCK_BEGIN_RE = re.compile('{')
    BLOCK_END_RE = re.compile('}')
    END_COMMAND_RE = re.compile(';');

    class Tokens(object):
        SPACE = 0
        KEYWORD = 1
        STRING = 2
        BLOCK_BEGIN = 3
        BLOCK_END = 4
        END_COMMAND = 5

    TOKENS_DATA = (
        (WHITE_SPACE_RE, Tokens.SPACE),
        (KEYWORD_RE, Tokens.KEYWORD),
        (STRING_RE, Tokens.STRING),
        (BLOCK_BEGIN_RE, Tokens.BLOCK_BEGIN),
        (BLOCK_END_RE, Tokens.BLOCK_END),
        (END_COMMAND_RE, Tokens.END_COMMAND)
    )

    @classmethod
    def get_current_token(cls, data, start_pos=0):
        for token_re, token_id in cls.TOKENS_DATA:
            m = token_re.match(data, start_pos)
            if m is not None:
                return (m, token_id)

        raise BadToken("Unknown token")

    @classmethod
    def tokenize(cls, data):
        pos, l = 0, len(data)
        while pos < l:
            m, token_id = cls.get_current_token(data, pos)
            yield (m, token_id)
            pos = m.end()
