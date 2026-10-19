# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : iptables.py
# Descricao   : Parser de ``iptables-save`` / ``ip6tables-save`` e de
#               ``ipset save`` para o modelo comum de firewall.
# Author      : Jose Edson Moreno Jr.
# Email       : edson.moreno@gmail.com
# Versao      : 0.1
# Data        : 2026-10-19
# copyright   : (c) 2026 by Edson Moreno
# Parametros  :
# Opcoes      :
#
# Retorno     :
#
# CHANGELOG   :
#
############################################################################

"""
Parser iptables.

Usa a saida de ``iptables-save`` (formato estavel e completo) em vez de
``iptables -L``. Opcoes nao reconhecidas sao registradas em
``Rule.unknown`` para que o avaliador as trate de forma conservadora.
"""

import shlex

from exposure_audit.collector.firewall.model import (
    ACCEPT, CONTINUE, DNAT, DROP, GOTO, JUMP, REDIRECT, REJECT, RETURN, UNKNOWN,
    AddressMatch, Chain, IfaceMatch, Rule, Table)
from exposure_audit.netutils import range_to_networks

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"

_BUILTIN_HOOKS: dict[str, dict[str, tuple[str, int]]] = {
    "filter": {"INPUT": ("input", 0), "FORWARD": ("forward", 0), "OUTPUT": ("output", 0)},
    "nat": {"PREROUTING": ("prerouting", -100), "INPUT": ("input", 100),
            "OUTPUT": ("output", -100), "POSTROUTING": ("postrouting", 100)},
    "mangle": {"PREROUTING": ("prerouting", -150), "INPUT": ("input", -150),
               "FORWARD": ("forward", -150), "OUTPUT": ("output", -150),
               "POSTROUTING": ("postrouting", -150)},
    "raw": {"PREROUTING": ("prerouting", -300), "OUTPUT": ("output", -300)},
    "security": {"INPUT": ("input", 50), "FORWARD": ("forward", 50), "OUTPUT": ("output", 50)},
}

_NON_TERMINAL_TARGETS = frozenset({
    "LOG", "NFLOG", "ULOG", "MARK", "CONNMARK", "CT", "TCPMSS", "TRACE", "SET",
    "AUDIT", "NOTRACK", "CLASSIFY", "DSCP", "TOS", "TTL", "HL", "CHECKSUM",
    "SNAT", "MASQUERADE", "CONNSECMARK", "SECMARK", "IDLETIMER", "LED", "RATEEST",
})
_RATE_MODULES = frozenset({"limit", "hashlimit", "recent", "connlimit"})
_IGNORED_MODULES = frozenset({"comment", "tcp", "udp", "multiport", "conntrack", "state",
                              "set", "addrtype", "iprange", "pkttype", "icmp", "icmp6",
                              "icmpv6", "ipv6icmp", "mark", "connmark"})
_CORE_OPTIONS = frozenset({"-s", "--source", "-d", "--destination", "-p", "--protocol",
                           "-i", "--in-interface", "-o", "--out-interface",
                           "-f", "--fragment"})
_PROTO_NUMBERS = {"6": "tcp", "17": "udp", "1": "icmp", "58": "ipv6-icmp"}


def _ports(text: str) -> list[tuple[int, int]]:
    """
    Converte ``22``, ``1000:2000`` ou ``22,80,1000:2000`` em intervalos.

    :param text: str
    :return: list[tuple[int, int]]
    """
    ranges: list[tuple[int, int]] = []
    for item in text.split(","):
        start, _, end = item.partition(":")
        if not start.isdigit():
            continue
        ranges.append((int(start), int(end) if end.isdigit() else
                       (65535 if end == "" and ":" in item else int(start))))
    return ranges


def parse_nat_destination(value: str) -> tuple[str | None, int | None]:
    """
    Interpreta ``--to-destination`` (``1.2.3.4:80``, ``[2001:db8::1]:80``,
    ``1.2.3.4``, ``:80``).

    :param value: str
    :return: tuple[str | None, int | None]
    """
    text = value.strip()
    address: str | None = text
    port: int | None = None
    if text.startswith("["):
        address, _, rest = text[1:].partition("]")
        if rest.startswith(":"):
            port_text = rest[1:].split("-", 1)[0]
            port = int(port_text) if port_text.isdigit() else None
    elif text.count(":") == 1:
        address, _, port_text = text.partition(":")
        port_text = port_text.split("-", 1)[0]
        port = int(port_text) if port_text.isdigit() else None
    if address:
        address = address.split("-", 1)[0]
    return address or None, port


def _take_values(tokens: list[str], index: int) -> tuple[list[str], int]:
    """
    Consome os argumentos de uma opcao ate a proxima opcao.

    :param tokens: list[str]
    :param index: int
    :return: tuple[list[str], int]
    """
    values: list[str] = []
    while index < len(tokens) and not (tokens[index].startswith("-") or tokens[index] == "!"):
        values.append(tokens[index])
        index += 1
    return values, index


def _apply_addrtype(rule: Rule, option: str, value: str, negated: bool) -> None:
    """
    Interpreta ``-m addrtype`` para um pacote unicast destinado ao host
    vindo de origem externa.

    :param rule: Rule
    :param option: str
    :param value: str
    :param negated: bool
    :return: None
    """
    types = {item.upper() for item in value.split(",")}
    if option == "--dst-type":
        matches = bool(types & {"LOCAL", "UNICAST"})
    else:
        matches = "UNICAST" in types
    if matches == negated:
        rule.never_matches = f"addrtype {option} {'! ' if negated else ''}{value}"


def _apply_option(rule: Rule, module: str | None, option: str, values: list[str],
                  negated: bool) -> None:
    """
    Aplica uma opcao de match iptables ao modelo da regra.

    :param rule: Rule
    :param module: str | None
    :param option: str
    :param values: list[str]
    :param negated: bool
    :return: None
    """
    value = values[0] if values else ""
    if option in ("-s", "--source", "-d", "--destination"):
        match = AddressMatch(networks=value.split(","), negated=negated)
        if option in ("-s", "--source"):
            rule.src = match
        else:
            rule.dst = match
    elif option in ("-p", "--protocol"):
        proto = _PROTO_NUMBERS.get(value.lower(), value.lower())
        rule.protocols = None if proto == "all" else [proto]
        rule.proto_negated = negated
    elif option in ("-i", "--in-interface"):
        rule.in_iface = IfaceMatch([value], negated)
    elif option in ("-o", "--out-interface"):
        rule.out_iface = IfaceMatch([value], negated)
    elif option in ("--dport", "--destination-port", "--dports", "--destination-ports"):
        rule.dports = _ports(value)
        rule.dport_negated = negated
    elif option == "--ports":
        rule.dports = _ports(value)
        rule.dport_negated = negated
        rule.partial.append(f"multiport --ports {value} (origem ou destino)")
    elif option in ("--sport", "--source-port", "--sports", "--source-ports"):
        rule.partial.append(f"porta de origem {'! ' if negated else ''}{value}")
    elif option in ("--ctstate", "--state"):
        rule.ct_states = [item.lower() for item in value.split(",")]
        rule.ct_negated = negated
    elif option == "--ctstatus":
        rule.ct_status_dnat = ("DNAT" in value.upper().split(",")) != negated
    elif option == "--match-set" and len(values) >= 2:
        match = AddressMatch(set_name=values[0], negated=negated)
        if values[1].split(",")[0] == "src":
            rule.src = match
        else:
            rule.dst = match
    elif option in ("--src-range", "--dst-range"):
        start, _, end = value.partition("-")
        match = AddressMatch(networks=range_to_networks(start, end) or [value], negated=negated)
        if option == "--src-range":
            rule.src = match
        else:
            rule.dst = match
    elif option in ("--dst-type", "--src-type"):
        _apply_addrtype(rule, option, value, negated)
    elif option == "--limit-iface-in" or option == "--limit-iface-out":
        return
    elif option == "--pkt-type":
        if (value.lower() == "unicast") == negated:
            rule.never_matches = f"pkttype {value}"
    elif option == "--syn":
        if negated:
            rule.never_matches = "! --syn"
    elif option == "--tcp-flags":
        if len(values) >= 2 and values[1].upper() == "SYN" and "SYN" in values[0].upper():
            if negated:
                rule.never_matches = "! --tcp-flags ... SYN"
        else:
            rule.unknown.append(f"--tcp-flags {' '.join(values)}")
    elif option in ("-f", "--fragment"):
        if not negated:
            rule.never_matches = "fragmento"
    elif option in ("--comment", "--icmp-type", "--icmpv6-type", "--mark"):
        return
    elif option in ("--ctorigdstport", "--ctorigdst", "--ctdir", "--ctproto"):
        rule.partial.append(f"conntrack {option} {value}")
    elif module in _RATE_MODULES:
        rule.rate_limited = True
    else:
        rule.unknown.append(f"{module or '?'} {'! ' if negated else ''}{option} {' '.join(values)}".strip())


def _apply_target(rule: Rule, target: str, values: dict[str, str], goto: bool) -> None:
    """
    Define o verdict da regra a partir do alvo ``-j``/``-g``.

    :param rule: Rule
    :param target: str
    :param values: dict[str, str]
    :param goto: bool
    :return: None
    """
    if goto:
        rule.verdict, rule.target = GOTO, target
    elif target in (ACCEPT, DROP, REJECT, RETURN):
        rule.verdict = target
    elif target == "DNAT":
        rule.verdict = DNAT
        rule.nat_to_address, rule.nat_to_port = parse_nat_destination(
            values.get("--to-destination", ""))
    elif target == "REDIRECT":
        rule.verdict = REDIRECT
        port = values.get("--to-ports", "").split("-", 1)[0]
        rule.nat_to_port = int(port) if port.isdigit() else None
    elif target in _NON_TERMINAL_TARGETS:
        rule.verdict = CONTINUE
    else:
        # Pode ser chain de usuario; resolvido apos ler toda a tabela.
        rule.verdict, rule.target = JUMP, target


def parse_rule(chain: str, index: int, line: str) -> Rule:
    """
    Converte uma linha ``-A CHAIN ...`` em Rule.

    :param chain: str
    :param index: int
    :param line: str
    :return: Rule
    """
    rule = Rule(chain=chain, index=index, text=line)
    try:
        tokens = shlex.split(line)
    except ValueError:
        rule.unknown.append("linha nao interpretavel")
        return rule
    position = 2
    module: str | None = None
    negated = False
    while position < len(tokens):
        token = tokens[position]
        if token == "!":
            negated = True
            position += 1
            continue
        if token in ("-m", "--match"):
            module = tokens[position + 1] if position + 1 < len(tokens) else None
            if module and module not in _IGNORED_MODULES and module not in _RATE_MODULES:
                rule.unknown.append(f"modulo {module}")
            if module in _RATE_MODULES:
                rule.rate_limited = True
            position += 2
            negated = False
            continue
        if token in ("-j", "--jump", "-g", "--goto"):
            target = tokens[position + 1] if position + 1 < len(tokens) else ""
            position += 2
            target_values: dict[str, str] = {}
            while position < len(tokens):
                values, nxt = _take_values(tokens, position + 1)
                target_values[tokens[position]] = values[0] if values else ""
                position = max(nxt, position + 1)
            _apply_target(rule, target, target_values, token in ("-g", "--goto"))
            break
        values, position = _take_values(tokens, position + 1)
        if (token not in _CORE_OPTIONS and module is not None
                and module not in _IGNORED_MODULES and module not in _RATE_MODULES):
            # Opcoes de modulo desconhecido ja registradas pelo nome do modulo.
            negated = False
            continue
        _apply_option(rule, module, token, values, negated)
        negated = False
    return rule


def parse_iptables_save(output: str, family: str, origin: str = "iptables") -> list[Table]:
    """
    Interpreta a saida de ``iptables-save`` (``family='ip'``) ou
    ``ip6tables-save`` (``family='ip6'``).

    :param output: str
    :param family: str
    :param origin: str
    :return: list[Table]
    """
    tables: list[Table] = []
    current: Table | None = None
    counters: dict[str, int] = {}
    for raw in output.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            current = Table(origin=origin, family=family, name=line[1:])
            tables.append(current)
            counters = {}
            continue
        if current is None or line == "COMMIT":
            continue
        if line.startswith(":"):
            name, _, rest = line[1:].partition(" ")
            policy = rest.split()[0] if rest else "-"
            hook = _BUILTIN_HOOKS.get(current.name, {}).get(name)
            current.chains[name] = Chain(
                name=name,
                hook=hook[0] if hook else None,
                priority=hook[1] if hook else 0,
                policy=policy if policy != "-" else None,
                chain_type=current.name if current.name != "filter" else "filter",
            )
            continue
        if line.startswith("-A "):
            chain_name = line.split()[1]
            chain = current.chains.setdefault(chain_name, Chain(name=chain_name))
            counters[chain_name] = counters.get(chain_name, 0) + 1
            chain.rules.append(parse_rule(chain_name, counters[chain_name], line))
    for table in tables:
        for chain in table.chains.values():
            for rule in chain.rules:
                if rule.verdict in (JUMP, GOTO) and rule.target not in table.chains:
                    rule.unknown.append(f"alvo desconhecido {rule.target}")
                    rule.verdict = UNKNOWN
    return tables


def has_rules(output: str | None) -> bool:
    """
    Indica se a saida de ``*-save`` contem regras (linhas ``-A``) ou
    policies diferentes de ACCEPT.

    :param output: str | None
    :return: bool
    """
    if not output:
        return False
    for line in output.splitlines():
        if line.startswith("-A "):
            return True
        if line.startswith(":") and len(line.split()) > 1 and line.split()[1] in (DROP, REJECT):
            return True
    return False


def parse_ipset_save(output: str) -> dict[str, list[str]]:
    """
    Interpreta ``ipset save`` retornando o conteudo de cada conjunto.

    :param output: str
    :return: dict[str, list[str]]
    """
    sets: dict[str, list[str]] = {}
    for line in output.splitlines():
        tokens = line.split()
        if len(tokens) >= 2 and tokens[0] == "create":
            sets.setdefault(tokens[1], [])
        elif len(tokens) >= 3 and tokens[0] == "add":
            element = tokens[2].split(",", 1)[0]
            if "-" in element and "/" not in element:
                start, _, end = element.partition("-")
                sets.setdefault(tokens[1], []).extend(range_to_networks(start, end))
            else:
                sets.setdefault(tokens[1], []).append(element)
    return sets
