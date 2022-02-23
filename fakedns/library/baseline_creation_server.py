
from dns_messages import DnsMessage, DnsServer, Question, OPCODE, RRClass, A, TXT
from abc import abstractmethod
from cli_formatter.output_formatting import info

from fakedns.config.configuration import Configuration
from fakedns.library.fake_dns_server import FakeDnsServer


class BaselineCreationServer(FakeDnsServer):
    def __init__(self, configuration: Configuration, answer_queries: bool):
        super().__init__(configuration)
        info(message='incoming queries will be added to the config file as patterns with deactivated logging')
        self._number_of_added_patterns = 0
        self._answer_queries = answer_queries

    @abstractmethod
    def _handle_received_message(self, message: DnsMessage, remote_ip: str, remote_port: int) -> None:
        if not message.is_query() and len(message.questions) > 0:
            return

        question: Question = message.questions[0]

        # check if message is already ignored by a existing pattern
        for domain_pattern in self._configuration.get_domain_patterns():
            if not domain_pattern.log_request and domain_pattern.does_pattern_match(question=question):
                self._answer_query_with_pattern(message=message, question=question, pattern=domain_pattern, remote_ip=remote_ip, remote_port=remote_port)
                return

        # answer question with default pattern
        default_pattern = None
        if self._answer_queries:
            for domain_pattern in self._configuration.get_domain_patterns():
                if domain_pattern.does_pattern_match(question=question):
                    default_pattern = domain_pattern

        # generate a new pattern and add it to the config file
        new_baseline_pattern = self._configuration.add_new_baseline_pattern(question=question, default_pattern=default_pattern)
        self._number_of_added_patterns += 1
        info('added new pattern to baseline:  {}  -  {}'.format(question.rr_type.name.ljust(4, ' '), question.name))

        self._answer_query_with_pattern(message=message, question=question, pattern=new_baseline_pattern, remote_ip=remote_ip, remote_port=remote_port)

    def get_number_of_added_patterns(self) -> int:
        return self._number_of_added_patterns
