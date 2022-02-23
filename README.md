# FakeDNS
A fake DNS server for malware analysis written in Python3.

In contrast to other fakedns scripts, this one supports not only answering all requests with the same IP as answer.
It is flexible and configurable to fit the needs of an analyst, and includes the following features:
* Supported RR Types: A, AAAA, PTR, TXT
* Respond to incoming queries based on a predefined configuration which allows pattern matching on domain names
* Proxy DNS queries to a predefined DNS server
* A CLI-tool which simplifies config editing (in particular a baseline script which allows ignoring noise in further analysis)

This fakedns script is implemented on basis of the Python3 package [``dns-messages ``](https://github.com/wahlflo/dns-messages)
which implements parsing and generating DNS packages. 

## Installation

Install the package with pip:

    pip3 install fakedns

## Setup & Configuration with ```fakedns-config```
The fakedns script requires a config file for running. 
If you don't specify a config file, fakedns tries to load the global config from one of the following two locations (depending on your OS):
* %ProgramData%\fakedns\global.conf (Windows)
* /etc/fakedns/global.conf (Linux)

The ```fakedns-config``` CLI-tool simplifies the creation and editing config files for fakedns. It accepts the following commands and parameters:
```
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
If no path to config file is given the default location of the global config is used, which is
/etc/fakedns/global.conf (in Linux) or %ProgramData%\fakedns\global.conf (in Windows)
```

By entering ```fakedns-config init``` a default config is created in the default location mentioned above.

To view the existing patterns in this new config use ```fakedns-config pattern show```.

Adding a new pattern manually can either be done by editing the config file directly or by executing ```fakedns-config pattern add```.

### Structure of a pattern in the config 
A section of a pattern in the config starts with the ``[DomainPattern]`` tag followed by the specified options.

Possible options:
* ``priority`` the lower the priority the earlier the pattern will be checked for a match. If one pattern matches, all the following patterns will not be checked. So the priority for the default pattern should be a high number, and for patterns of a baseline it should be a low number. 
* ``name_pattern`` pattern to match an incoming domain name of a query. ``*`` can be used as wildcard.
* ``log_request`` defines if a query should be logged. Possible values are ``yes`` and ``no``. This option is useful to suppress noise from baseline patterns in the logs while enabling logging for a default (catch-all) pattern
* ``type_filter`` a list of query types this pattern should match; should be comma-separated, e.g. ``A,AAAA`` matches only queries for ``A`` and ``AAAA`` records - other types are ignored
* ``proxy_queries`` proxy this query to a predefined DNS server. Possible values are ``yes`` and ``no``.
* ``not_existing_domain`` respond to queries with an ``nxdomain`` error. Possible values are ``yes`` and ``no``.
* ``ttl`` time to live for the RR of an answer, in seconds
* ``answer_A`` IP address of the ``A`` record. The default value is ``DefaultIPv4`` whose value is defined in the config file.   
* ``answer_AAAA`` IP address of the ``AAAA`` record. The default value is ``DefaultIPv6`` whose value is defined in the config file.
* ``answer_PTR`` domain name of the ``PTR`` record

### Output formatting
It is also possible to configure the output of ``fakedns`` in the config file.

The attribute ``format`` defines the general structure of one log line. ``response_format`` defines the output if an answer contains a RR within the ``%RESPONSE%`` log. 

The possible placeholders are: 
```
# defines the output of fakedns 
# available placeholders are:
# - %DATETIME%
# - %RR_TYPE%    (from the query)
# - %RR_CLASS%   (from the query)
# - %DOMAINNAME% (from the query)
# - %RESPONSE%   
# - %TTL%  (from the response)
format = %DATETIME% - %RR_TYPE% - %DOMAINNAME% => %RESPONSE%

# - %TTL%
# - %RR_VALUE%
response_format = %RR_VALUE%
```

An example for log lines produced by ```fakedns``` using the default config:
```
[+] 2022-02-20 08:17:58 - PTR  - 1.96.18.172.in-addr.arpa            => Response: fakedns.com
[+] 2022-02-20 08:17:58 - AAAA - example.com                         => Response: No Record
[+] 2022-02-20 08:24:40 - AAAA - google.com                          => Response (from Proxy): 2a00:1450:4016:809::200e
```

### Creating a baseline 
To create a baseline type ``fakedns-config pattern baseline``. 
Then you can specify how the generated patterns should be handled.

For example, it could be useful to proxy all baseline patterns or not respond to them at all, depending on your needs.


## Start ``fakedns``
To start the fakedns script just type ``fakedns`` :smiley:

The following excerpt from the help page shows all CLI argument options:
```
usage: fakedns [OPTIONS...]

fakedns is a script which mimicks DNS resolution

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        path to config file (if not set the default global one is used)
  --log-query-only-once
                        prevents that the same query is logged multiple times
  --log-domain-only-once
                        prevents that the same domain name is logged multiple times
  --nxdomain-response   respond to all queries with an nxdomain response (overrides settings from the config)
  --no-response         do not respond to any queries (overrides settings from the config)
  --proxy               proxy all incoming queries (overrides settings from the config)
  --verbose             logs more details of each queries
  --version             shows version info
```


```console
foo@bar:~$ fakedns
[+] fakedns starts listening on 172.18.96.1:53
[+] 2022-02-20 08:17:58 - PTR  - 1.96.18.172.in-addr.arpa            => Response: fakedns.com
[+] 2022-02-20 08:17:58 - A    - example.com                         => Response: 172.18.96.1
[+] 2022-02-20 08:17:58 - AAAA - example.com                         => Response: No Record
[+] 2022-02-20 08:18:00 - TXT  - example.com                         => Response: No Record
[+] 2022-02-20 08:24:40 - A    - google.com                          => Response (from Proxy): 142.251.36.206
[+] 2022-02-20 08:24:40 - AAAA - google.com                          => Response (from Proxy): 2a00:1450:4016:809::200e
```
