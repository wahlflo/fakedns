import ipaddress

from dns_messages import RRType

from fakedns.config import DomainPattern
from cli_formatter.output_formatting import warning, error, info
from typing import List


def add_pattern_interactively() -> DomainPattern:
    name_pattern = input('name pattern > ').strip()
    if len(name_pattern) == 0:
        error(message='pattern can not be empty')

    priority = _cli_input_integer(text='priority', default_value=10)
    type_filter = _cli_input_type_filter()
    log_request = _cli_input_boolean(text='log request', default_value=True)
    proxy_queries = _cli_input_boolean(text='proxy queries', default_value=False)
    not_existing_domain = _cli_input_boolean(text='respond with nxdomain error', default_value=False)
    ttl = _cli_input_integer(text='TTL in seconds', default_value=3600)

    answer_dict = {
        'A': _cli_input_ipv4_address(),
        'AAAA': _cli_input_ipv6_address(),
    }

    answer_PTR = _cli_input_PTR()
    if answer_PTR is not None:
        answer_dict['PTR'] = answer_PTR

    answer_TXT = _cli_input_TXT()
    if answer_TXT is not None:
        answer_dict['TXT'] = answer_TXT

    return DomainPattern(priority=priority, name_pattern=name_pattern, type_filter=type_filter, proxy_queries=proxy_queries,
                         not_existing_domain=not_existing_domain, log_request=log_request, answer_dict=answer_dict, ttl=ttl)


def _cli_input_type_filter() -> List[RRType]:
    value = input('apply pattern only to queries regarding specific RR types (comma separated list) [default=None] > ').strip()
    if len(value) == 0:
        return list()

    type_filter = list()
    for part in value.split(','):
        part = part.strip()
        try:
            type_filter.append(RRType[part])
        except AttributeError:
            error(message='RR type "{}" does not exist'.format(part))
            exit()
    return type_filter


def _cli_input_ipv4_address() -> str:
    value = input('value of A record [DefaultIPv4 / IPv4 Address] > ').strip().lower()
    if len(value) == 0 or value == 'defaultipv4':
        return 'DefaultIPv4'
    try:
        ipaddress.IPv4Address(value)
    except AttributeError:
        error('input is not a valid IPv4 address')
        exit()
    return value


def _cli_input_ipv6_address() -> str or None:
    value = input('value of A record [DefaultIPv6 / IPv6 Address] > ').strip().lower()
    if len(value) == 0 or value == 'defaultipv6':
        return 'DefaultIPv6'
    try:
        ipaddress.IPv6Address(value)
    except AttributeError:
        error('input is not a valid IPv6 address')
        exit()
    return value


def _cli_input_PTR() -> str or None:
    value = input('value of PTR record [default=None] > ').strip().lower()
    if len(value) == 0 or value == 'none':
        return None
    return value


def _cli_input_TXT() -> List[bytes] or None:
    value = input('value of TXT record (lines separated with ";") [default=None] > ').strip().lower()
    if len(value) == 0 or value == 'none':
        return None
    return [x.encode('ascii') for x in value.split(';')]


def _cli_input_integer(text: str, default_value: int) -> int:
    default_str = ' [default={}]'.format(default_value)
    value = input('{}{} > '.format(text, default_str)).strip()
    if len(value) == 0:
        return default_value
    try:
        return int(value)
    except AttributeError:
        error(message="input has to be a integer")
        exit()


def _cli_input_boolean(text: str, default_value: bool) -> bool:
    default_str = ' [Y/n]' if default_value else ' [N/y]'
    value = input('{}{} > '.format(text, default_str)).strip().lower()
    if len(value) == 0:
        return default_value
    if value == 'y':
        return True
    if value == 'n':
        return False
    error(message='input is not valid - only "y" or "n" are accepted')
    exit()

