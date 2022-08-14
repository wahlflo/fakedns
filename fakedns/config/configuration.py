import json
from sys import platform
import shutil
import os
import socket
import ipaddress
from typing import List, Iterator, Tuple
from cli_formatter.table_builder import TableBuilderClassic
from cli_formatter.output_formatting import colorize_string, Color, info
from dns_messages import Question, RRType

from .add_pattern_interactively import add_pattern_interactively
from .domain_pattern import DomainPattern


class OperatingSystemNotDetected(Exception):
    def __init__(self, platform_name: str):
        self.platform_name = platform_name


class DefaultConfigFileNotFound(Exception):
    def __init__(self, path: str):
        self.path = path


class FileAlreadyExists(Exception):
    def __init__(self, path: str):
        self.path = path


class ConfigLoadError(Exception):
    def __init__(self, message: str):
        self.message = message


class InvalidConfig(Exception):
    def __init__(self, message: str):
        self.message = message


class Configuration:
    def __init__(self):
        self._path_to_configuration_file: str or None = None

        self._default_ipv4 = None
        self._default_ipv6 = None
        self._server_port = 53
        self._server_ip = None
        self._log_format = '%DATETIME% - %RR_TYPE% - %DOMAIN_NAME% => %RESPONSE%'
        self._log_format_of_response = 'TTL: %TTL% - %RR_VALUE%'
        self._domain_patterns: List[DomainPattern] = list()
        self._dns_proxy_address = None

    @staticmethod
    def _determine_path_to_config_file(user_input_path_to_configuration_file: str or None, create_file: bool = False) -> str:
        # if the user specified a specific config file to load then load this file
        if user_input_path_to_configuration_file is not None:
            return user_input_path_to_configuration_file

        # if the user has no config file specified then user the global one
        if platform == "linux" or platform == "linux2" or platform == "darwin":
            path_to_config_folder = '/etc/fakedns'
        elif platform == "win32":
            path_to_config_folder = os.getenv('ProgramData') + os.sep + 'fakedns'
        else:
            raise OperatingSystemNotDetected(platform_name=platform)

        path_to_file = path_to_config_folder + os.sep + 'global.conf'

        if not os.path.exists(path_to_config_folder):
            if create_file:
                os.mkdir(path_to_config_folder)
            else:
                raise DefaultConfigFileNotFound(path=path_to_file)
        elif not os.path.isdir(path_to_config_folder):
            raise ConfigLoadError('"{}" is not a directory, thus the config which is expected to be in this directory could not be loaded'.format(path_to_config_folder))

        if not os.path.exists(path_to_file) and not create_file:
            raise DefaultConfigFileNotFound(path=path_to_file)
        elif os.path.exists(path_to_file) and create_file:
            raise FileAlreadyExists(path=path_to_file)
        elif os.path.isdir(path_to_file):
            raise ConfigLoadError('"{}" is a directory and not a config file, thus the config could not be loaded'.format(path_to_file))

        return path_to_file

    def load(self, user_input_path_to_configuration_file: str or None = None) -> None:
        self._load_config_file(user_input_path_to_configuration_file=user_input_path_to_configuration_file)

    def _load_config_file(self, user_input_path_to_configuration_file: str) -> None:
        self._path_to_configuration_file: str = Configuration._determine_path_to_config_file(user_input_path_to_configuration_file=user_input_path_to_configuration_file)

        section_list = list()
        current_section = dict()
        section_name = None
        with open(self._path_to_configuration_file, mode='r', encoding='utf-8') as input_file:
            for line_number, line in enumerate(input_file.readlines()):
                line = line.strip()

                # ignore empty lines and comment lines
                if len(line) == 0 or line[0] == '#':
                    continue

                # start of a new section
                if line[0] == '[':
                    # store old section
                    if len(current_section) > 0:
                        section_list.append({'name': section_name, 'data': current_section})
                    current_section = dict()
                    section_name = line[1:-1]
                else:
                    if '=' not in line:
                        raise InvalidConfig(message='Missing "=" in line {}:  "{}"'.format(line_number, line))

                    (key, value) = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    current_section[key] = value

            if len(current_section) > 0:
                if section_name is None:
                    raise InvalidConfig(message='There are values without a specified section')
                section_list.append({'name': section_name, 'data': current_section})

        self._process_config_section_list(section_list=section_list)

    def _process_config_section_list(self, section_list: List[dict]) -> None:
        # the Settings section must be parsed at first since the pattern for example accesses attributes parsed in Settings sections
        self._process_config_settings_section(section_list=section_list)
        self._process_config_output_section(section_list=section_list)
        self._process_config_pattern_entries(section_list=section_list)

    @staticmethod
    def _get_section_by_name(section_name: str, section_list: List[dict]) -> dict:
        for section in section_list:
            if section['name'] == section_name:
                return section['data']
        return dict()

    @staticmethod
    def _get_sections_by_name(section_name: str, section_list: List[dict]) -> Iterator[dict]:
        section: dict
        for section in section_list:
            if section['name'] == section_name:
                yield section['data']

    def _process_config_settings_section(self, section_list: List[dict]) -> None:
        section_dict = Configuration._get_section_by_name(section_name='Settings', section_list=section_list)

        ip_of_this_machine = Configuration._ip_of_this_machine()

        # Load Default IPv4 Address
        if 'DefaultIPv4' in section_dict:
            self._default_ipv4 = section_dict['DefaultIPv4']
        else:
            if isinstance(ip_of_this_machine, ipaddress.IPv4Address):
                self._default_ipv4 = str(ip_of_this_machine)

        # Load Default IPv6 Address
        if 'DefaultIPv6' in section_dict:
            self._default_ipv6 = section_dict['DefaultIPv6']
        else:
            if isinstance(ip_of_this_machine, ipaddress.IPv6Address):
                self._default_ipv6 = str(ip_of_this_machine)

        if 'ListenOnPort' in section_dict:
            self._server_port = int(section_dict['ListenOnPort'])

        if 'ListenOnIP' in section_dict:
            self._server_ip = section_dict['ListenOnIP']
        else:
            if ip_of_this_machine is None:
                raise ConfigLoadError(message='Could not load the IP of this machine, please specify the IP of the fake dns server in the config file')
            else:
                self._server_ip = str(ip_of_this_machine)

        if 'DnsProxyIP' in section_dict:
            dns_proxy_address_ip = section_dict['DnsProxyIP']
        else:
            dns_proxy_address_ip = '8.8.8.8'

        if 'DnsProxyPort' in section_dict:
            dns_proxy_address_port = int(section_dict['DnsProxyPort'])
        else:
            dns_proxy_address_port = 53

        self._dns_proxy_address = (dns_proxy_address_ip, dns_proxy_address_port)

    @staticmethod
    def _ip_of_this_machine() -> ipaddress.IPv4Address or ipaddress.IPv6Address or None:
        try:
            hostname = socket.gethostname()
            return ipaddress.ip_address(socket.gethostbyname(hostname))
        except Exception:
            return None

    def _process_config_output_section(self, section_list: List[dict]) -> None:
        section_dict = Configuration._get_section_by_name(section_name='Output', section_list=section_list)
        if 'format' in section_dict:
            self._log_format = section_dict['format']
        if 'response_format' in section_dict:
            self._log_format_of_response = section_dict['response_format']

    def _process_config_pattern_entries(self, section_list: List[dict]) -> None:
        for section in Configuration._get_sections_by_name(section_name='DomainPattern', section_list=section_list):
            pattern_entry = self._process_config_pattern_entry(config=section)
            self._domain_patterns.append(pattern_entry)

        if len(self._domain_patterns) == 0:
            self._domain_patterns.append(self._get_default_domain_pattern())

        self._domain_patterns = sorted(self._domain_patterns, key=lambda x: x.priority)

    def _process_config_pattern_entry(self, config: dict) -> DomainPattern:
        name_pattern = config.get('name_pattern', '*')
        priority = int(config.get('priority', 99999))

        type_filter = list()
        if 'type_filter' in config:
            for rr_type in config['type_filter'].split(','):
                rr_type = rr_type.strip()
                if len(rr_type) > 0:
                    type_filter.append(RRType[rr_type])

        log_request = config.get('log_request', 'yes') == 'yes'
        proxy_queries = config.get('proxy_queries', 'no') == 'yes'
        not_existing_domain = config.get('not_existing_domain', 'no') == 'yes'
        ttl = int(config.get('ttl', 3600))

        answer_dict = dict()

        answer_A = config.get('answer_A', 'DefaultIPv4')
        if answer_A == 'DefaultIPv4':
            answer_dict['A'] = self.get_default_IPv4()
        else:
            answer_dict['A'] = answer_A

        answer_AAAA = config.get('answer_AAAA', 'DefaultIPv6')
        if answer_AAAA == 'DefaultIPv6':
            answer_dict['AAAA'] = self.get_default_IPv6()
        else:
            answer_dict['AAAA'] = answer_AAAA

        answer_PTR = config.get('answer_PTR', None)
        if answer_PTR is not None:
            answer_dict['PTR'] = answer_PTR

        answer_TXT = config.get('answer_TXT', None)
        if answer_TXT is not None:
            text_lines = json.loads(answer_TXT)
            if not isinstance(text_lines, list):
                raise InvalidConfig('value of "answer_TXT" key must be a list of string in json format')
            answer_dict['TXT'] = [x.encode('ascii') for x in text_lines]

        return DomainPattern(priority=priority, name_pattern=name_pattern, type_filter=type_filter, proxy_queries=proxy_queries,
                             not_existing_domain=not_existing_domain, log_request=log_request, answer_dict=answer_dict, ttl=ttl)

    def _get_default_domain_pattern(self) -> DomainPattern:
        answer_dict = {'TXT': ['FAKE_DNS_TXT'.encode('ascii')]}
        if self.get_default_IPv4() is not None:
            answer_dict['A'] = self.get_default_IPv4()
        if self.get_default_IPv6() is not None:
            answer_dict['AAAA'] = self.get_default_IPv6()
        return DomainPattern(priority=9999, name_pattern='*', type_filter=None, log_request=True, proxy_queries=False, not_existing_domain=False, answer_dict=answer_dict, ttl=3600)

    def get_default_IPv4(self) -> str or None:
        return self._default_ipv4

    def get_default_IPv6(self) -> str or None:
        return self._default_ipv6

    def get_log_format(self) -> str:
        return self._log_format

    def get_log_format_response(self) -> str:
        return self._log_format_of_response

    def get_dns_server_ip(self) -> str:
        return self._server_ip

    def get_dns_server_port(self) -> int:
        return self._server_port

    def get_dns_proxy_address(self) -> Tuple[str, int]:
        return self._dns_proxy_address

    def get_domain_patterns(self) -> List[DomainPattern]:
        return self._domain_patterns

    @staticmethod
    def command_init(path: str or None = None):
        path_to_default_config = os.path.dirname(__file__) + os.sep + 'default_config.config'
        path_to_config = Configuration._determine_path_to_config_file(user_input_path_to_configuration_file=path, create_file=True)
        shutil.copyfile(path_to_default_config, path_to_config)

    @staticmethod
    def command_edit(path: str or None = None):
        path = Configuration._determine_path_to_config_file(user_input_path_to_configuration_file=path)
        try:
            if platform == "win32":
                os.system('notepad "{}"'.format(path))
            else:   # linux
                os.system('sensible-editor "{}"'.format(path))
        except KeyboardInterrupt:
            pass

    @staticmethod
    def command_fork(destination_path: str):
        original_path = Configuration._determine_path_to_config_file(user_input_path_to_configuration_file=None)
        shutil.copyfile(original_path, destination_path)

    def command_list_patterns(self):
        entry: DomainPattern
        number_of_entries = 0
        data = list()
        for entry in self.get_domain_patterns():
            number_of_entries += 1

            if entry.log_request:
                log_request = colorize_string(text='yes', color=Color.GREEN)
            else:
                log_request = colorize_string(text='no', color=Color.RED)

            if entry.type_filter is None:
                type_filter = '-'
            else:
                type_filter = colorize_string(text=', '.join(entry.type_filter), color=Color.CYAN)

            if entry.proxy_queries:
                proxy_queries = colorize_string(text='proxy', color=Color.YELLOW)
            else:
                proxy_queries = ''

            if entry.not_existing_domain:
                not_existing_domain = colorize_string(text='nxdomain', color=Color.RED)
            else:
                not_existing_domain = ''

            data.append([str(entry.priority), entry.original_name_pattern, type_filter, log_request, proxy_queries, not_existing_domain, str(entry.ttl)])

        header = ['Priority', 'Pattern', 'RR Filter', 'Logging', 'Queries are Proxied', 'NxDomain', 'TTL']
        classic_builder = TableBuilderClassic()
        classic_builder.build_table(header=header, data=data)
        print('config files contains {} patterns'.format(number_of_entries))

    @staticmethod
    def command_add_pattern(path: str or None = None):
        try:
            config = Configuration()
            config.load(user_input_path_to_configuration_file=path)
            new_pattern = add_pattern_interactively()
            config._add_pattern_to_config(pattern=new_pattern)
        except KeyboardInterrupt:
            pass

    def add_new_baseline_pattern(self, question: Question, default_pattern: DomainPattern or None) -> DomainPattern:
        if default_pattern is None:
            new_domain_pattern = DomainPattern(priority=0, name_pattern=question.name, type_filter=[question.rr_type],
                                               proxy_queries=False, not_existing_domain=False, log_request=False,
                                               ttl=3600, answer_dict={
                    RRType.A: self.get_default_IPv4(),
                    RRType.AAAA: self.get_default_IPv6()
                })
        else:
            new_domain_pattern = DomainPattern(priority=0, name_pattern=question.name, type_filter=[question.rr_type],
                                               proxy_queries=default_pattern.proxy_queries,
                                               not_existing_domain=default_pattern.not_existing_domain, log_request=False,
                                               ttl=default_pattern.ttl, answer_dict=default_pattern.answer_dict)

        self._domain_patterns.append(new_domain_pattern)
        self._domain_patterns = sorted(self._domain_patterns, key=lambda x: x.priority)

        self._add_pattern_to_config(pattern=new_domain_pattern)

        return new_domain_pattern

    def _add_pattern_to_config(self, pattern: DomainPattern):
        with open(self._path_to_configuration_file, mode='a') as config_file:
            config_file.write('\n')
            config_file.write('[DomainPattern]\n')
            config_file.write('priority = {}\n'.format(pattern.priority))
            config_file.write('name_pattern = {}\n'.format(pattern.original_name_pattern))

            if len(pattern.type_filter) > 0:
                config_file.write('type_filter = {}\n'.format(','.join([x.name for x in pattern.type_filter])))

            if pattern.log_request:
                config_file.write('log_request = yes\n')
            else:
                config_file.write('log_request = no\n')

            if pattern.proxy_queries:
                config_file.write('proxy_queries = yes\n')

            if pattern.not_existing_domain:
                config_file.write('not_existing_domain = yes\n')

            if pattern.not_existing_domain:
                config_file.write('ttl = {}\n'.format(pattern.ttl))

            for r in pattern.answer_dict:
                if r == 'A' and pattern.answer_dict[r] != self.get_default_IPv4():
                    config_file.write('answer_A = {}\n'.format(pattern.answer_dict[r]))
                if r == 'AAAA' and pattern.answer_dict[r] != self.get_default_IPv6():
                    config_file.write('answer_AAAA = {}\n'.format(pattern.answer_dict[r]))
                if r == 'TXT':
                    config_file.write('answer_TXT = {}\n'.format(pattern.answer_dict[r]))
                if r == 'PTR':
                    config_file.write('answer_PTR = {}\n'.format(pattern.answer_dict[r]))

