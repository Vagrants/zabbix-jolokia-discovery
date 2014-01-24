#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

__version__ = '0.1.0'

import collections
import json
import optparse
import re
import sys

# pylint: disable=import-error, no-name-in-module
try:
    from urlparse import urlsplit
except ImportError:
    from urllib.parse import urlsplit

try:
    from urlparse import urlunsplit
except ImportError:
    from urllib.parse import urlunsplit

try:
    from urllib2 import HTTPError
except ImportError:
    from urllib.error import HTTPError

try:
    from urllib2 import Request
except ImportError:
    from urllib.request import Request

try:
    from urllib2 import URLError
except ImportError:
    from urllib.error import URLError

try:
    from urllib2 import urlopen
except ImportError:
    from urllib.request import urlopen
# pylint: enable=import-error, no-name-in-module


PARAMETERS = collections.namedtuple(
    'PARAMETERS',
    [
        'jolokia_url',
        'mbean_pattern',
        'lld_macro_name',
        'jmx_host',
        'jmx_port',
        'jmx_user',
        'jmx_pass',
    ],
)


class JolokiaStatusError(Exception):
    pass


class OptionParserError(Exception):
    def __init__(self, message, status=2):
        super(OptionParserError, self).__init__()
        self.message = message
        self.status = status

    def __str__(self):
        return repr(self.message)


class NonExitOptionParser(optparse.OptionParser):
    #pylint: disable=too-many-public-methods
    def exit(self, status=0, msg=None):
        raise OptionParserError(msg, status)


def build_arguments(argv):
    usage = (
        '''%prog [options] "jolokia_url" "mbean_pattern" "lld_macro_name"'''
    )
    version = '%%prog %s' % __version__
    description = 'Zabbix Low Level Discovery with Jolokia.'

    option_parser = NonExitOptionParser(
        usage=usage,
        version=version,
        description=description,
    )
    option_parser.add_option(
        '-H', '--jmx-host', help='Hostname of JMX remote',
    )
    option_parser.add_option(
        '-P', '--jmx-port', type='int', help='Port number of JMX remote',
    )
    option_parser.add_option(
        '-u', '--jmx-user', help='Username of JMX remote user',
    )
    option_parser.add_option(
        '-p', '--jmx-pass', help='Password of JMX remote user',
    )

    arguments = option_parser.parse_args(argv)

    return arguments


def build_parameters(arguments):
    (option_args, positional_args) = arguments

    validate_option_args(option_args)

    try:
        validate_jolokia_url(positional_args[0])
        validate_mbean_pattern(positional_args[1])
        validate_lld_macro_name(positional_args[2])
    except IndexError:
        raise OptionParserError(
            'Insufficient number of positional arguments was specified.'
        )

    parameters = PARAMETERS(
        jolokia_url=positional_args[0],
        mbean_pattern=positional_args[1],
        lld_macro_name=positional_args[2],
        jmx_host=option_args.jmx_host,
        jmx_port=option_args.jmx_port,
        jmx_user=option_args.jmx_user,
        jmx_pass=option_args.jmx_pass,
    )

    return parameters


def validate_option_args(option_args):
    def with_jmx_host():
        if not option_args.jmx_port:
            raise OptionParserError(
                'Cannot specify jmx_host unless jmx_port was also specified.'
            )

        if option_args.jmx_user and not option_args.jmx_pass:
            raise OptionParserError(
                'Cannot specify jmx_user unless jmx_pass was also specified.'
            )

        if option_args.jmx_pass and not option_args.jmx_user:
            raise OptionParserError(
                'Cannot specify jmx_pass unless jmx_user was also specified.'
            )

    def without_jmx_host():
        if option_args.jmx_port:
            raise OptionParserError(
                'Cannot specify jmx_port unless jmx_host was also specified.'
            )

        if option_args.jmx_user:
            raise OptionParserError(
                'Cannot specify jmx_user unless jmx_host was also specified.'
            )

        if option_args.jmx_pass:
            raise OptionParserError(
                'Cannot specify jmx_pass unless jmx_host was also specified.'
            )

    if option_args.jmx_host:
        with_jmx_host()
    else:
        without_jmx_host()


def validate_jolokia_url(url):
    if not url:
        raise OptionParserError(
            'Empty string was specified for Jolokia URL.'
        )

    # pylint: disable=line-too-long
    regex = re.compile(
        r'^(?:[a-z0-9\.\-]*)://'  # scheme is validated separately
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$',
        re.IGNORECASE
    )
    # pylint: enable=line-too-long
    schemes = ['http']

    if url.split('://')[0].lower() not in schemes:
        raise OptionParserError(
            'Invalid scheme was specified for Jolokia URL.'
        )

    if not regex.search(url):
        scheme, netloc, path, query, fragment = urlsplit(url)

        try:
            netloc = netloc.encode('idna').decode('ascii')  # IDN -> ACE
        except UnicodeError:  # invalid domain part
            raise OptionParserError(
                'Invalid domain part was specified for Jolokia URL.'
            )

        url = urlunsplit((scheme, netloc, path, query, fragment))

        if not regex.search(url):
            raise OptionParserError(
                'Invalid Jolokia URL was specified.'
            )


def validate_mbean_pattern(mbean_pattern):
    if not mbean_pattern:
        raise OptionParserError(
            'Empty string was specified for MBean pattern.'
        )


def validate_lld_macro_name(lld_macro_name):
    if not lld_macro_name:
        raise OptionParserError(
            'Empty string was specified for LLD macro name.'
        )

    regex = re.compile(r'^[.0-9A-Z_]{1,63}$')

    if not regex.match(lld_macro_name):
        raise OptionParserError(
            'Invalid LLD macro name was specified.'
        )


def build_request(parameters):
    request = Request(parameters.jolokia_url)

    query_dict = {}
    query_dict['type'] = 'search'
    query_dict['mbean'] = parameters.mbean_pattern

    if parameters.jmx_host:
        query_dict['target'] = {}
        query_dict['target']['url'] = (
            'service:jmx:rmi:///jndi/rmi://{0}:{1}/jmxrmi'
            ''.format(parameters.jmx_host, parameters.jmx_port)
        )

    if parameters.jmx_user:
        query_dict['target']['user'] = parameters.jmx_user
        query_dict['target']['password'] = parameters.jmx_pass

    query_json = json.dumps(query_dict).encode('utf-8')

    request.add_data(query_json)

    return request


def query_jolokia(request):
    result = urlopen(request)
    result_dict = json.load(result)

    if result_dict['status'] == 200:
        return result_dict
    else:
        raise JolokiaStatusError(
            'Invalid status code returned from Jolokia.'
        )


def show_lld_item(parameters, result_dict):
    lld_item_dict = {}
    lld_item_dict['data'] = []

    for value in result_dict['value']:
        lld_item_dict['data'].append(
            {'{{#{0}}}'.format(parameters.lld_macro_name): value}
        )

    lld_item_json = json.dumps(lld_item_dict)
    print(lld_item_json)


def main(argv=None):
    if argv is None:
        argv = sys.argv

    try:
        arguments = build_arguments(argv[1:])
        parameters = build_parameters(arguments)
        request = build_request(parameters)
        result_dict = query_jolokia(request)
        show_lld_item(parameters, result_dict)
    except (JolokiaStatusError, HTTPError, URLError) as error:
        print(str(error), file=sys.stderr)
        return 1
    except OptionParserError as error:
        if error.message:
            print(str(error.message), file=sys.stderr)
        return error.status
    else:
        return 0


if __name__ == '__main__':
    sys.exit(main())
