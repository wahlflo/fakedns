from cli_formatter.output_formatting import warning, info, error

from fakedns.config import (
    OperatingSystemNotDetected,
    DefaultConfigFileNotFound,
    FileAlreadyExists,
    ConfigLoadError,
    InvalidConfig,
    Configuration,
)
from fakedns.library import FakeDnsServer
from fakedns.docopt import docopt
import time
import argparse

usage = 'fakedns [OPTIONS...]'

description = "fakedns is a script which mimicks DNS resolution"

version = """
fakedns-config (from fakedns version 1.0)

developed by Florian Wahl (https://www.linkedin.com/in/florian-wahl-security-expert/)

see for more information  https://github.com/wahlflo/fakedns
"""


def main():
    argument_parser = argparse.ArgumentParser(usage=usage, description=description)
    argument_parser.add_argument('-c', '--config', dest='config', help="path to config file (if not set the default global one is used)", type=str)
    argument_parser.add_argument('--log-query-only-once', dest='log_query_only_once', action='store_true', default=False, help="prevents that the same query is logged multiple times")
    argument_parser.add_argument('--log-domain-only-once', dest='log_domain_only_once', action='store_true', default=False, help="prevents that the same domain name is logged multiple times")
    argument_parser.add_argument('--nxdomain-response', dest='nxdomain_response', action='store_true', default=False, help="respond to all queries with an nxdomain response (overrides settings from the config)")
    argument_parser.add_argument('--no-response', dest='no_response', action='store_true', default=False, help="do not respond to any queries (overrides settings from the config)")
    argument_parser.add_argument('--proxy', dest='proxy', action='store_true', default=False, help="proxy all incoming queries (overrides settings from the config)")
    argument_parser.add_argument('--verbose', dest='verbose', action='store_true', default=False, help="logs more details of each queries")
    argument_parser.add_argument('--version', dest='version', action='store_true', default=False, help="shows version info")
    arguments = argument_parser.parse_args()

    if arguments.version:
        print(version)
        exit()

    try:
        config = Configuration()
        if arguments.config is not None:
            config.load(user_input_path_to_configuration_file=arguments.config)
        else:
            config.load()
    except InvalidConfig as exception:
        error('invalid configuration file: {}'.format(exception.message))
        return
    except ConfigLoadError as exception:
        error('configuration could not be loaded: {}'.format(exception.message))
        return
    except FileAlreadyExists as exception:
        error('configuration file could not be created since file already exists: {}'.format(exception.path))
        return
    except OperatingSystemNotDetected as exception:
        error('the operating system could not be created: {}'.format(exception.platform_name))
        return
    except DefaultConfigFileNotFound as exception:
        error('the default config file was not found: {}  - try generate it with the "fakedns-config" command'.format(exception.path))
        return

    if arguments.no_response and arguments.nxdomain_response:
        error(message="only one of the options '--nxdomain-response' and '--no-response' can be set. ")

    if arguments.log_query_only_once and arguments.log_domain_only_once:
        error(message="only one of the options '--log-query-only-once' and '--log-domain-only-once' can be set. ")

    server = FakeDnsServer(configuration=config, log_query_only_once=arguments.log_query_only_once, log_domain_only_once=arguments.log_domain_only_once,
                           nxdomain_response=arguments.nxdomain_response, no_response=arguments.no_response, verbose=arguments.verbose,
                           proxy_queries=arguments.proxy)
    server.start()
    while True:
        try:
            time.sleep(500)
        except KeyboardInterrupt:
            print()
            warning('received keyboard interrupt')
            info('DNS server will be stopped...')
            server.stop()
            info('DNS server successfully stopped')
            break
