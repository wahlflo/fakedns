import time

from fakedns.config.configuration import Configuration
from cli_formatter.output_formatting import colorize_string, Color, warning, info

from fakedns.library.baseline_creation_server import BaselineCreationServer
from fakedns.docopt import docopt, DocoptExit


description = """fakedns-config

Description:
fakedns-config is a script for easy editing and manipulating config files used
by the fakedns script.

Usage:
  fakedns-config help
                        > displays the help page with detailed command descriptions

  fakedns-config edit [<path_to_config>]
                        > opens a text editor to edit the config file manually

  fakedns-config init [<path_to_config>]
                        > create a new default config

  fakedns-config fork [<path_to_new_config_file>]
                        > copies the global config file and saves it at the
                        > given location. Useful if config has to be temporarily
                        > customized for a special use case

  fakedns-config pattern add [<path_to_config>]
                        > a new pattern is added to the config interactively
                        > so that the config has not to be changed manually

  fakedns-config pattern show [<path_to_config>]
                        > lists all patterns which the config file contains
                        > in a table format which makes it suitable to quickly
                        > check the correctness of the used patterns and their
                        > attributes

  fakedns-config pattern baseline [<path_to_config>]
                        > listens to incoming queries and whitelists all received
                        > query patterns in the selected config file until the
                        > user aborts the process via Strg + C.
                        > This command makes it easy to create a baseline
                        > and filter out the "normal" noise from a machine of interest
                        > (e.g. baseline the DNS-requests made from a Windows machine
                        > in a laboratory environment before executing malware on the
                        > machine - in this way only requests are shown which were
                        > triggered by the malware)


Note:
If no path to config is given the default location of the global config is used, which is
/etc/fakedns/global.conf in Linux or %ProgramData%\\fakedns\\global.conf under Windows
"""

version = """
fakedns-config (from fakedns version 1.0)

developed by Florian Wahl (https://www.linkedin.com/in/florian-wahl-security-expert/)

see for more information  https://github.com/wahlflo/fakedns
"""


def print_usage() -> None:
    colored_lines = list()
    for line in description.split('Usage:')[1].split('Note:')[0].split('\n'):
        if line.startswith('  fakedns-config'):
            colored_lines.append(line)
    print('Usage: \n' + '\n'.join(colored_lines))


def print_help() -> None:
    colored_lines = list()
    for line in description.split('\n', 2)[2].split('\n'):
        if line.startswith('Note:') or line.startswith('Description:') or line.startswith('Usage:'):
            colored_lines.append(colorize_string(text=line, color=Color.CYAN))
        elif line.startswith('  fakedns-config'):
            colored_lines.append(colorize_string(text=line, color=Color.BLUE))
        else:
            colored_lines.append(line)
    print('\n'.join(colored_lines), end='')


def main():
    try:
        arguments: dict = docopt(help=False, doc=description, version=version)
    except DocoptExit:
        print_usage()
        return

    if arguments['help']:
        print_help()
        return

    if arguments['edit']:
        path_to_config = arguments['<path_to_config>'] if isinstance(arguments['<path_to_config>'], str) else None
        Configuration.command_edit(path=path_to_config)
        return

    if arguments['init']:
        path_to_config = arguments['<path_to_config>'] if isinstance(arguments['<path_to_config>'], str) else None
        Configuration.command_init(path=path_to_config)
        return

    if arguments['fork']:
        Configuration.command_fork(destination_path=arguments['<path_to_new_config_file>'])
        return

    if arguments['pattern']:
        if arguments['add']:
            path_to_config = arguments['<path_to_config>'] if isinstance(arguments['<path_to_config>'], str) else None
            config = Configuration()
            config.load(user_input_path_to_configuration_file=path_to_config)
            config.command_add_pattern()
        if arguments['show']:
            path_to_config = arguments['<path_to_config>'] if isinstance(arguments['<path_to_config>'], str) else None
            config = Configuration()
            config.load(user_input_path_to_configuration_file=path_to_config)
            config.command_list_patterns()
        if arguments['baseline']:
            path_to_config = arguments['<path_to_config>'] if isinstance(arguments['<path_to_config>'], str) else None
            config = Configuration()
            config.load(user_input_path_to_configuration_file=path_to_config)

            info('Set the values of the new baseline patterns:')

            value_str = input("answer incoming queries using the default pattern [Y/n] ").strip()
            if value_str == 'Y' or value_str == 'y' or value_str == '':
                answer_queries_value = True
            elif value_str == 'N' or value_str == 'n':
                answer_queries_value = False
            else:
                warning('Abort')
                return

            server = BaselineCreationServer(configuration=config, answer_queries=answer_queries_value)
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
                    info('{} baseline patterns were added to the config file'.format(server.get_number_of_added_patterns()))
                    break
