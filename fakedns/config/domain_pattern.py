import re
from typing import List, Set
from dns_messages import DnsMessage, Question, RRType


class DomainPattern:
    def __init__(self, priority: int, name_pattern: str, type_filter: Set[RRType] or None, proxy_queries: bool, not_existing_domain: bool, log_request: bool, ttl: int, answer_dict: dict):
        self.priority = priority
        self.type_filter = type_filter
        self.proxy_queries = proxy_queries
        self.ttl = ttl
        self.not_existing_domain = not_existing_domain
        self.log_request = log_request
        self.answer_dict = answer_dict

        self.original_name_pattern = name_pattern
        name_pattern = name_pattern.replace('.', r'\.')
        name_pattern = name_pattern.replace('*', r'.*')
        self.name_pattern = re.compile(name_pattern)

    def __str__(self) -> str:
        return 'DomainPattern[{}]'.format(self.name_pattern)

    def does_pattern_match(self, question: Question) -> bool:
        if len(self.type_filter) > 0 and question.rr_type not in self.type_filter:
            return False
        return self.name_pattern.match(question.name) is not None
