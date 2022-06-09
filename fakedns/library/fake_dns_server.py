import ipaddress
from datetime import datetime

from dns_messages import DnsMessage, DnsServer, Question, OPCODE, RRClass, A, TXT, RCODE, RRType, AAAA, PTR, ResourceRecord, DnsPacketParsingException, CNAME, MX
from abc import abstractmethod
from cli_formatter.output_formatting import info, warning, error

from fakedns.config.configuration import Configuration
from fakedns.config.domain_pattern import DomainPattern
import socket
from typing import Tuple


class FakeDnsServer(DnsServer):
    def __init__(self, configuration: Configuration, log_query_only_once: bool = False, log_domain_only_once: bool = False,
                 nxdomain_response: bool = False, no_response: bool = False, verbose: bool = False, proxy_queries: bool = False):
        server_ip = configuration.get_dns_server_ip()
        server_port = configuration.get_dns_server_port()
        super().__init__(ip_address=server_ip, port=server_port)
        info(message='fakedns starts listening on {}:{}'.format(server_ip, server_port))

        self._configuration = configuration

        self._proxy_queries = proxy_queries
        self._log_query_only_once = log_query_only_once
        self._log_domain_only_once = log_domain_only_once
        self._nxdomain_response = nxdomain_response
        self._no_response = no_response
        self._verbose = verbose

        self._logged_queries = set()

    @abstractmethod
    def _handle_received_message(self, message: DnsMessage, remote_ip: str, remote_port: int) -> None:
        if self._verbose:
            FakeDnsServer._log_incoming_message_verbose(message=message, remote_ip=remote_ip, remote_port=remote_port)

        if not message.is_query():
            return

        if len(message.questions) == 0:
            if self._verbose:
                info(message='received a DNS query from {} without a question'.format(remote_ip))

        question: Question = message.questions[0]

        # check if message is already ignored by a existing pattern
        for domain_pattern in self._configuration.get_domain_patterns():
            if domain_pattern.does_pattern_match(question=question):
                self._answer_query_with_pattern(message=message, question=question, pattern=domain_pattern, remote_ip=remote_ip, remote_port=remote_port)
                return

    @staticmethod
    def _log_incoming_message_verbose(message: DnsMessage, remote_ip: str, remote_port: int) -> None:
        print('\treceived a DNS message from {}:{}'.format(remote_ip, remote_port))

        if message.is_query():
            query_str = 'yes'
        else:
            query_str = 'no '
        print('\tMessageID: {}   -   Query: {}   -   OPCODE: {}'.format(str(message.message_id).ljust(5, ' '), query_str, message.op_code.name))

        if len(message.questions) > 0:
            print('\t\tquestions:')
            question: Question
            for question in message.questions:
                print('\t\t\t - {} - {} - {}'.format(question.rr_class.name.ljust(4, ' '), question.rr_type.name.ljust(4, ' '), question.name))

        def _log_rr(rr: ResourceRecord):
            print('\t\t\t - {} - {} - {} - TTL: {}'.format(rr.rr_class.name.ljust(4, ' '), rr.get_RR_type().name.ljust(4, ' '), rr.name, rr.ttl))
            if isinstance(rr, A) or isinstance(rr, AAAA):
                print('\t\t\t   IP: {}'.format(rr.ip_address))
            if isinstance(rr, TXT):
                for i, line in enumerate(rr.text_lines):
                    if i == 0:
                        print('\t\t\t   TXT: {}'.format(line))
                    else:
                        print('\t\t\t        {}'.format(line))

        if len(message.answers_RRs) > 0:
            print('\t\tanswers:')
            resource_record: ResourceRecord
            for resource_record in message.answers_RRs:
                _log_rr(rr=resource_record)

        if len(message.authority_RRs) > 0:
            print('\t\tauthority RRs:')
            resource_record: ResourceRecord
            for resource_record in message.authority_RRs:
                _log_rr(rr=resource_record)

        if len(message.additional_RRs) > 0:
            print('\t\tadditional RRs:')
            resource_record: ResourceRecord
            for resource_record in message.additional_RRs:
                _log_rr(rr=resource_record)

        print(30 * '-')

    def _answer_query_with_pattern(self, message: DnsMessage, question: Question, pattern: DomainPattern, remote_ip: str, remote_port: int) -> DnsMessage or None:
        answer_message = self._generate_answer_from_pattern(message=message, question=question, pattern=pattern)
        if answer_message is not None:
            self.send_message(message=answer_message, remote_ip=remote_ip, remote_port=remote_port)
        self._log_query(answer_message=answer_message, question=question, pattern=pattern, remote_ip=remote_ip, remote_port=remote_port)
        return answer_message

    def _log_query(self, answer_message: DnsMessage, question: Question, pattern: DomainPattern, remote_ip: str, remote_port: int) -> None:
        if not pattern.log_request:
            return

        if self._log_query_only_once:
            question_as_string: str = question.__str__()
            if question_as_string in self._logged_queries:
                return
            self._logged_queries.add(question_as_string)

        if self._log_domain_only_once:
            if question.name in self._logged_queries:
                return
            self._logged_queries.add(question.name)

        log_line = self._configuration.get_log_format()
        log_line = log_line.replace('%DATETIME%', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        log_line = log_line.replace('%RR_TYPE%', question.rr_type.name.ljust(4, ' '))
        log_line = log_line.replace('%RR_CLASS%', question.rr_class.name.ljust(4, ' '))
        log_line = log_line.replace('%DOMAINNAME%', question.name.ljust(35, ' '))
        log_line = log_line.replace('%REMOTE_IP%', remote_ip.ljust(15, ' '))
        log_line = log_line.replace('%REMOTE_PORT%', str(remote_port).rjust(5, ' '))

        proxy_text = ' (from Proxy)' if pattern.proxy_queries or self._proxy_queries else ''

        if answer_message is None:
            log_line = log_line.replace('%RESPONSE%', 'No response')
        elif answer_message.rcode == RCODE.non_existing_domain:
            log_line = log_line.replace('%RESPONSE%', 'Response{}: NXDOMAIN'.format(proxy_text))
        elif len(answer_message.answers_RRs) > 0:
            answer: ResourceRecord = answer_message.answers_RRs[0]
            log_line_response = self._configuration.get_log_format_response()
            log_line_response = log_line_response.replace('%TTL%', '{}'.format(answer.ttl))
            if isinstance(answer, A) or isinstance(answer, AAAA):
                log_line_response = log_line_response.replace('%RR_VALUE%', str(answer.ip_address))
            elif isinstance(answer, TXT):
                log_line_response = log_line_response.replace('%RR_VALUE%', '{}'.format(answer.text_lines))
            elif isinstance(answer, PTR):
                log_line_response = log_line_response.replace('%RR_VALUE%', '{}'.format(answer.domain_name))
            elif isinstance(answer, CNAME):
                log_line_response = log_line_response.replace('%RR_VALUE%', 'CNAME: {}'.format(answer.domain_name))
            elif isinstance(answer, MX):
                log_line_response = log_line_response.replace('%RR_VALUE%', 'MX: {}'.format(answer.exchange))

            log_line = log_line.replace('%RESPONSE%', 'Response{}: '.format(proxy_text) + log_line_response)
        else:
            log_line = log_line.replace('%RESPONSE%', 'Response{}: No Record'.format(proxy_text))

        info(log_line)

    def _generate_answer_from_pattern(self, message: DnsMessage, question: Question, pattern: DomainPattern) -> DnsMessage or None:
        answer = DnsMessage(message_id=message.message_id, qr=1)
        answer.questions.append(question)

        if pattern.not_existing_domain or self._nxdomain_response:
            answer.rcode = RCODE.non_existing_domain
            return answer

        if self._no_response:
            return None

        if pattern.proxy_queries or self._proxy_queries:
            return self._proxy_dns_query(message=message)

        rrtype: RRType = RRType[question.rr_type.name]
        answer_value = pattern.answer_dict.get(rrtype.name, None)
        if answer_value is None:
            return answer

        if rrtype == RRType.A:
            rr = A(name=question.name, rr_class=RRClass.IN, ip_address=ipaddress.IPv4Address(answer_value), ttl=pattern.ttl)
        elif rrtype == RRType.AAAA:
            rr = AAAA(name=question.name, rr_class=RRClass.IN, ip_address=ipaddress.IPv6Address(answer_value), ttl=pattern.ttl)
        elif rrtype == RRType.PTR:
            rr = PTR(name=question.name, rr_class=RRClass.IN, domain_name=answer_value, ttl=pattern.ttl)
        elif rrtype == RRType.TXT:
            rr = TXT(name=question.name, rr_class=RRClass.IN, text_lines=answer_value, ttl=pattern.ttl)
        else:
            warning('Answer to RR Type "{}" is currently not supported'.format(rrtype.name))
            return None

        answer.answers_RRs.append(rr)
        return answer

    def _proxy_dns_query(self, message: DnsMessage) -> DnsMessage or None:
        proxy_address = self._configuration.get_dns_proxy_address()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        try:
            sock.sendto(message.to_bytes(), proxy_address)
        except Exception as exception:
            error(message='message could not be forwarded to dns server {}:{} - error: {}'.format(proxy_address[0], proxy_address[1], exception))
            return

        try:
            raw_bytes, _ = sock.recvfrom(1024)
        except Exception as exception:
            error(message='error while receiving answer from proxy server: {}'.format(exception))
            return

        try:
            return DnsMessage.from_bytes(raw_bytes=raw_bytes)
        except DnsPacketParsingException as exception:
            error(message='error while parsing dns answer from proxy server: {}'.format(exception))
            return


