#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

__version__ = '0.1.0'

import collections
import json
import optparse
import sys

# pylint: disable=import-error, no-name-in-module
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


def build_arguments(argv):
    usage = (
        '''%prog [options] "jolokia_url" "mbean_pattern" "lld_macro_name"'''
    )
    version = '%%prog %s' % __version__
    description = 'Zabbix Low Level Discovery with Jolokia.'

    option_parser = optparse.OptionParser(
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
    (option_arguments, positional_arguments) = arguments

    jolokia_url = positional_arguments[0]
    mbean_pattern = positional_arguments[1]
    lld_macro_name = positional_arguments[2]
    jmx_host = option_arguments.jmx_host
    jmx_port = option_arguments.jmx_port
    jmx_user = option_arguments.jmx_user
    jmx_pass = option_arguments.jmx_pass

    parameters = PARAMETERS(
        jolokia_url,
        mbean_pattern,
        lld_macro_name,
        jmx_host,
        jmx_port,
        jmx_user,
        jmx_pass,
    )

    return parameters


def build_request(parameters):
    request = Request(parameters.jolokia_url)

    query_dict = {}
    query_dict['type'] = 'search'
    query_dict['mbean'] = parameters.mbean_pattern
    query_dict['target'] = {}
    query_dict['target']['url'] = (
        'service:jmx:rmi:///jndi/rmi://{0}:{1}/jmxrmi'
        ''.format(parameters.jmx_host, parameters.jmx_port)
    )
    query_dict['target']['user'] = parameters.jmx_user
    query_dict['target']['password'] = parameters.jmx_pass
    query_json = json.dumps(query_dict).encode('utf-8')

    request.add_data(query_json)

    return request


def query_jolokia(request):
    try:
        result = urlopen(request)
        result_dict = json.load(result)

        if result_dict['status'] == 200:
            return result_dict
        else:
            print('Invalid status code.', file=sys.stderr)
            return None
    except HTTPError as http_error:
        print(http_error, file=sys.stderr)
        return None
    except URLError as url_error:
        print(url_error, file=sys.stderr)
        return None


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

    arguments = build_arguments(argv[1:])
    parameters = build_parameters(arguments)
    request = build_request(parameters)
    result_dict = query_jolokia(request)
    show_lld_item(parameters, result_dict)

    return 0


if __name__ == '__main__':
    sys.exit(main())
