import re
import socket
import contextlib
import sys
import random
import argparse
import logging
from collections import namedtuple
from functools import partial
import dns.resolver
import dns.update
import dns.tsigkeyring
import dns.query


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
logger = logging.getLogger(__name__)


def ip_from_dyndns(data):
    for m in SIMPLE_IPV4_RE.finditer(data):
        return m.group()


# TODO: support dig +short myip.opendns.com @resolver1.opendns.com
HTTPS_IP_SERVICES = (
    ('https:icanhazip', 'https://icanhazip.com/'),
)


HTTP_IP_SERVICES = (
    ('http:dyndns', 'http://checkip.dyndns.com/', ip_from_dyndns),
    ('http:icanhazip', 'http://icanhazip.com/'),
    ('http:curlmyip', 'http://curlmyip.com/'),
    ('http:ifconfigme', 'http://ifconfig.me/ip'),
    ('http:ip.appspot.com', 'http://ip.appspot.com'),
    ('http:ipinfo', 'http://ipinfo.io/ip'),
    ('http:externalip', 'http://api.externalip.net/ip'),
    ('http:trackip', 'http://www.trackip.net/ip')
)


ALL_IP_SERVICES = HTTP_IP_SERVICES + HTTPS_IP_SERVICES


def validate_ipv4(ip_text):
    try:
        socket.inet_aton(ip_text)
    except socket.error:
        return False
    else:
        return True


def simple_ip_fetch(url, extract_fun=lambda x: x.strip(), timeout=5):
    logger.debug('fetching url "{0}"'.format(url))
    try:
        with contextlib.closing(urlopen(url, timeout=timeout)) as resp:
            # Limit response size
            data = resp.read(MAX_RESPONSE_DATA)
    except (URLError, socket.error) as e:
        logger.warn('couldn\'t fetch url "{0}" with timeout {1:.4g}'
                    .format(url, timeout))
        return None
    else:
        ip = extract_fun(data)
        if ip and validate_ipv4(ip):
            return ip


class IpFetchError(Exception):
    pass


class SimpleIpGetter(object):

    DEFAULT_TIMEOUT = 5
    DEFAULT_TRIES = 3
    ALL_SERVICES = ALL_IP_SERVICES

    def __init__(self, services):
        self.services = {}
        if not services:
            raise ValueError("At least one service should exist")

        for service in services:
            name = service[0]
            self.services[name] = service[1:]

        self.service_names = tuple(self.services.keys())

    def query_service(self, service_name, timeout=DEFAULT_TIMEOUT):
        logger.info('query service "{0}"'.format(service_name))
        if service_name not in self.services:
            raise ValueError("Bad service_name '{0}'".format(service_name))

        args = self.services[service_name]
        ip = simple_ip_fetch(*args, timeout=timeout)
        logger.debug('service "{0}" return such ip "{1}"'
                     .format(service_name, ip))
        return ip

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

    def get(self, tries=DEFAULT_TRIES, timeout=DEFAULT_TIMEOUT):
        logger.debug('try determine ip address')
        for service in self.iter_rand_service(tries):
            res = self.query_service(service, timeout=timeout)
            if res is not None:
                return res

        logger.debug('can\'t determine ip address')
        raise IpFetchError("Can't fetch ip address")

    @staticmethod
    def get_service_info(servicename):
        return servicename.split(':', 1)

    @classmethod
    def service_info_iterator(cls, services):
        for service in services:
            servicename = service[0]
            service_type, name = cls.get_service_info(servicename)
            yield (service_type, name, service)

    @classmethod
    def get_types_and_names(cls):
        types, names = [], []
        for stype, name, _ in cls.service_info_iterator(cls.ALL_SERVICES):
            types.append(stype)
            names.append(name)

        return frozenset(types), frozenset(names)

    @classmethod
    def filter_services(cls, services, types=None, names=None):
        if types is not None:
            types = frozenset(types)
        if names is not None:
            names = frozenset(names)

        for type, name, service in cls.service_info_iterator(services):
            if types is None or type in types:
                if names is None or name in names:
                    yield service

    @classmethod
    def create_new_ip_getter(cls, types=None, names=None):
        service_iter = cls.filter_services(cls.ALL_SERVICES, types, names)
        return cls(service_iter)


#set types and names
SimpleIpGetter.SERVICE_TYPES, SimpleIpGetter.SERVICE_NAMES = \
    SimpleIpGetter.get_types_and_names()


class BadToken(Exception):
    pass


class ParseError(Exception):
    pass


class NoKeysError(Exception):
    pass


KeyData = namedtuple("KeyData", ["name", "algorithm", "key"])


class KeyConfigParser(object):

    ALGORITHMS = frozenset([
        "hmac-md5", "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384",
        "hmac-sha512"
    ])

    def __init__(self):
        self.keys = {}
        self.states = list()
        self.keys_names = []

        self.current_key_name = None
        self.current_key_algorithm = None
        self.current_key_data = None

    def get_space(self, match):
        pass

    def get_keyword(self, match):
        text = match.group().lower()
        if text == "key" and self.state is None:
            self.state = "keyname"
        elif text == "algorithm" and self.state == "keyblock":
            self.states.append('algorithm')
        elif text == "secret" and self.state == "keyblock":
            self.states.append('secret')
        elif self.state == "algorithm":
            if text in self.ALGORITHMS:
                self.current_key_algorithm = text
                self.state = "waitend"
            else:
                raise ParseError('Bad algorithm type "{0}"'.format(text))
        else:
            raise ParseError(
                'Bad keyword "{0}" with state "{1}"'
                .format(text, str(self.state))
            )

    def get_string(self, match):
        value, = match.groups()
        if self.state == "keyname":
            self.state = "waitblock"
            if value not in self.keys:
                # get keyname
                self.current_key_name = value
            else:
                raise ParseError('Key "{0}" already exists'.format(value))
        elif self.state == "secret":
            self.current_key_data = value
            self.state = "waitend"
        else:
            raise ParseError('Bad string {0}'.format(value))

    def get_block_begin(self, match):
        if self.state == "waitblock":
            self.state = "keyblock"
        else:
            raise ParseError("Bad block")

    def get_block_end(self, match):
        keys_data = [
            self.current_key_name, self.current_key_algorithm,
            self.current_key_data
        ]
        if None in keys_data:
            raise ParseError("Bad key data {0}".format(str(keys_data)))

        self.get_new_key(self.current_key_name, self.current_key_algorithm,
                         self.current_key_data)
        self.state = "waitend"

    def get_end(self, match):
        if self.state == "waitend":
            self.states.pop()
        else:
            raise ParseError("Bad end statement")

    def get_new_key(self, key_name, algorithm, key_data):
        key = KeyData(key_name, algorithm, key_data)
        self.keys[key_name] = key
        self.keys_names.append(key_name)

    @property
    def state(self):
        if not self.states:
            return None
        return self.states[-1]

    @state.setter
    def state(self, val):
        if self.states:
            self.states.pop()
        self.states.append(val)

    def get_key(self, key_name=None):
        if not self.keys_names:
            raise NoKeysError("No keys")

        if key_name is None:
            key_name = self.keys_names[0]

        return self.keys[key_name]

    @classmethod
    def parse_keys(cls, data):
        parser = cls()
        KeyConfig.parse(data, parser)
        return parser


class KeyConfig(object):

    WHITE_SPACE_RE = re.compile("\s+")
    KEYWORD_RE = re.compile("[a-z]+[a-z\d\-]*[a-z\d]+", re.I)
    STRING_RE = re.compile('"([^"]*)"')
    BLOCK_BEGIN_RE = re.compile('{')
    BLOCK_END_RE = re.compile('}')
    END_COMMAND_RE = re.compile(';')

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

        message_data = data[start_pos:start_pos + 40]
        raise BadToken('Unknown token "{0}"'.format(message_data))

    @classmethod
    def tokenize(cls, data):
        pos, l = 0, len(data)
        while pos < l:
            m, token_id = cls.get_current_token(data, pos)
            yield (m, token_id)
            pos = m.end()

    @classmethod
    def parse(cls, data, parser):
        tokens_methods = {
            cls.Tokens.SPACE: 'get_space',
            cls.Tokens.KEYWORD: 'get_keyword',
            cls.Tokens.STRING: 'get_string',
            cls.Tokens.BLOCK_BEGIN: 'get_block_begin',
            cls.Tokens.BLOCK_END: 'get_block_end',
            cls.Tokens.END_COMMAND: 'get_end'
        }
        for m, token_id in cls.tokenize(data):
            method = tokens_methods.get(token_id)
            if method is None:
                raise BadToken('Uknown token "{0}"'.format(token_id))

            getattr(parser, method)(m)

    @staticmethod
    def get_keyring(key_name, key_data):
        return dns.tsigkeyring.from_text({key_name: key_data})


class NameUpdate(object):

    DEFAULT_TTL = 600

    def __init__(self, server, zone, key, keyname=None, port=53):
        self.server = server
        self.zone = zone
        if isinstance(key, KeyData):
            self.key = key
        else:
            self.key = self.key_from_file(key, keyname)
        self.port = 53

    def get_updater(self):
        return self.build_updater(self.zone, self.key)

    def send(self, update, timeout=7):
        logger.info('send update message to server "%s",port %d, timeout %d',
                    self.server, self.port, timeout)
        dns.query.tcp(update, self.server, timeout=timeout, port=self.port)

    def update_a(self, domain, ip, resolver, ttl=DEFAULT_TTL, timeout=7):
        try:
            old_ip = self.check_name(domain, resolver)
        except dns.resolver.NXDOMAIN:
            logger.debug('domain "{0!s}" not exists'.format(domain))
            updater = self.get_updater()
            updater.add(domain.relativize(self.zone), ttl, 'A', ip)
            self.send(updater, timeout=timeout)
            return True
        else:
            logger.debug('domain "{0}" A: "{1}", new ip "{2}"'
                         .format(domain.to_text(), old_ip, ip))
            if ip != old_ip:
                updater = self.get_updater()
                updater.replace(domain.relativize(self.zone), ttl, 'A', ip)
                self.send(updater, timeout=timeout)
                return True
            return False

    @staticmethod
    def build_updater(zone, key):
        keyring = KeyConfig.get_keyring(key.name, key.key)
        return dns.update.Update(zone, keyring=keyring,
                                 keyalgorithm=key.algorithm)

    @staticmethod
    def build_resolver(server, port=53):
        logger.debug('build resolver for server "%s"', server)
        for rdata in dns.resolver.query(server, 'A'):  # pragma: no branch
            new_resolver = dns.resolver.Resolver(configure=False)
            new_resolver.nameservers.append(rdata.address)
            new_resolver.port = port
            return new_resolver

    @staticmethod
    def key_from_file(filename, keyname=None):
        if hasattr(filename, "read"):
            data = filename.read()
        else:
            with open(filename, 'rb') as f:
                data = f.read()

        return KeyConfigParser.parse_keys(data).get_key(keyname)

    @staticmethod
    def determine_server(zone, resolver=None):
        if resolver is None:
            resolver = dns.resolver.get_default_resolver()
        for rdata in resolver.query(zone, 'SOA'):
            return rdata.mname.to_text()

    @staticmethod
    def check_name(name, resolver=None):
        if resolver is None:
            resolver = dns.resolver.get_default_resolver()
        logger.info('try resolve A record of {0!s}'.format(name))
        for rdata in resolver.query(name, 'A'):
            return rdata.address


def comma_separated_list(values):
    check_values = frozenset(values)

    def parse(input_str):
        res = frozenset(input_str.split(','))
        diff = res - check_values
        if diff:
            raise argparse.ArgumentTypeError(
                "Bad input {0}".format(str(tuple(diff)))
            )

        return res

    return parse


def integer_range(min=None, max=None, num_type=int):

    def validate_int(value):
        try:
            res = num_type(value)
        except ValueError:
            raise argparse.ArgumentTypeError('Invalid integer "%s"' % value)
        else:
            if min is not None and res < min:
                raise argparse.ArgumentTypeError(
                    'Value "{val}" is smaller than "{min}"'
                    .format(val=res, min=min)
                )
            elif max is not None and res > max:
                raise argparse.ArgumentTypeError(
                    'Value "{val}" is bigger than "{max}"'
                    .format(val=res, max=min)
                )

            return res

    return validate_int


class Program(object):

    COMMANDS = {
        'checkip': 'checkip_command',
        'update': 'update_command'
    }

    VERBOSITY = (
        logging.ERROR,
        logging.WARNING,
        logging.INFO,
        logging.DEBUG,
    )

    SERVICE_TYPES = frozenset(['http', 'https'])

    def __init__(self):
        self.parser = self.build_parser()

    def run(self, args=None, log=True):
        if log and not logger.handlers:
            self.set_loghandler()

        namespace = self.parser.parse_args(args)
        self.execute(namespace, log=log)

    def set_verbosity(self, verbosity):
        count = len(self.VERBOSITY)
        if verbosity >= count:
            verbosity = count - 1

        logger.setLevel(self.VERBOSITY[verbosity])

    def set_loghandler(self):
        logger.addHandler(logging.StreamHandler())

    def execute(self, namespace, log=True):
        exec_command = self.COMMANDS.get(namespace.command)
        if exec_command is not None:
            if log:
                self.set_verbosity(namespace.verbose)
                logger.debug('args namespace "%s"' % str(namespace))

            kwargs = vars(namespace)
            del kwargs['command']
            del kwargs['verbose']
            getattr(self, exec_command)(**kwargs)
        else:
            raise ValueError("Bad command {0}".format(namespace.command))

    def checkip_command(self, *args, **kwargs):
        ip_fun = self.ip_fun(*args, **kwargs)
        try:
            print(ip_fun())
        except IpFetchError as e:
            self.service_error(e.message)

    def update_command(self, name, keyfile, keyname, zone=None, server=None,
                       tries=5, timeout=5, types=None, services=None,
                       ttl=NameUpdate.DEFAULT_TTL, **kwargs):
        ip_fun = self.ip_fun(tries=tries, timeout=timeout, types=types,
                             services=services)

        name = dns.name.from_text(name)
        if zone is None:
            # could raise Timeout
            zone = dns.resolver.zone_for_name(name)
            logger.info('determine zone by name: zone "{0}" name "{1}"'
                        .format(zone.to_text(), name.to_text()))
        else:
            zone = dns.name.from_text(zone)

        if server is None:
            server = NameUpdate.determine_server(zone)
            logger.info('determine server by zone: server "{0}" zone "{1}"'
                        .format(server, zone.to_text()))

        try:
            ip = ip_fun()
        except IpFetchError:
            pass
        else:
            resolver = NameUpdate.build_resolver(server)
            nu = NameUpdate(server, zone, keyfile, keyname=keyname)
            nu.update_a(name, ip, resolver, ttl)

    def service_error(self, message):
        self.parser.exit(69, message + '\n')

    @classmethod
    def ip_fun(cls, tries=5, timeout=5, types=None, services=None):
        ip_get = SimpleIpGetter.create_new_ip_getter(types, services)
        return partial(ip_get.get, tries=tries, timeout=timeout)

    @classmethod
    def ip_arguments(cls, parser):
        tries_type = integer_range(min=1)
        timeout_type = integer_range(min=0, num_type=float)
        types_type = comma_separated_list(SimpleIpGetter.SERVICE_TYPES)
        services_type = comma_separated_list(SimpleIpGetter.SERVICE_NAMES)
        parser.add_argument('-n', '--tries', dest="tries", type=tries_type,
                            default=5)
        parser.add_argument('-t', '--types', dest="types", type=types_type,
                            default=None)
        parser.add_argument('--services', dest="services", type=services_type,
                            default=None)
        parser.add_argument('--timeout', dest="timeout", type=timeout_type,
                            default=5)

    @classmethod
    def build_parser(cls):
        file_type = argparse.FileType('rb')
        parser = argparse.ArgumentParser(description="dynamic dns update")
        parser.add_argument('-v', '--verbose', action='count', dest='verbose',
                            default=0)
        subparsers = parser.add_subparsers(dest="command")
        checkip_parser = subparsers.add_parser('checkip', help="return ip")
        cls.ip_arguments(checkip_parser)
        update_parser = subparsers.add_parser('update', help="update record")
        update_parser.add_argument('-k', '--key', type=file_type,
                                   required=True, dest='keyfile')
        update_parser.add_argument('--keyname', type=str, dest='keyname',
                                   default=None)
        update_parser.add_argument('--ttl', type=int, dest='ttl', default=600)
        update_parser.add_argument('-s', '--server', type=str, dest='server',
                                   default=None)
        update_parser.add_argument('-z', '--zone', type=str, dest='zone',
                                   default=None)
        update_parser.add_argument('name', type=str)
        cls.ip_arguments(update_parser)
        return parser


def main():  # pragma: no cover
    Program().run()


if __name__ == "__main__":  # pragma: no cover
    main()
