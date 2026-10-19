# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : nftables.py
# Descricao   : Parser de ``nft -j list ruleset`` (JSON) para o modelo
#               comum de firewall, incluindo sets e verdict maps.
# Author      : Jose Edson Moreno Jr.
# Email       : edson.moreno@gmail.com
# Versao      : 0.2
# Data        : 2026-10-19
# copyright   : (c) 2026 by Edson Moreno
# Parametros  :
# Opcoes      :
#
# Retorno     :
#
# CHANGELOG   : 2026-10-19: aceita expressao xt nula (extensao iptables-nft
#               que o nft nao traduz para JSON).
#
############################################################################

"""
Parser nftables.

Decisao: usa a saida JSON (``nft -j``) porque ela e estruturada e estavel;
a saida textual e coletada apenas como evidencia legivel. Expressoes nao
reconhecidas (incluindo ``xt`` de regras iptables-nft com extensoes
legadas) sao registradas em ``Rule.unknown``.
"""

import json
import socket
from typing import Any

from exposure_audit.collector.firewall.model import (
    ACCEPT, DNAT, DROP, GOTO, JUMP, REDIRECT, REJECT, RETURN, UNKNOWN, VMAP,
    AddressMatch, Chain, IfaceMatch, Rule, Table, VmapEntry)
from exposure_audit.netutils import range_to_networks

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.2"

_IP_FAMILIES = frozenset({"ip", "ip6", "inet"})
_NEVER_PROTOCOLS = frozenset({"icmp", "icmpv6", "igmp", "arp", "vlan", "ether", "esp",
                              "ah", "comp", "sctp", "dccp", "gre"})
_IGNORED_STATEMENTS = frozenset({"counter", "log", "set", "mangle", "notrack", "ct helper",
                                 "ct timeout", "ct expectation", "masquerade", "snat",
                                 "meta", "tproxy", "dup", "fwd", "flow", "secmark"})
_PROTO_NUMBERS = {6: "tcp", 17: "udp", 1: "icmp", 58: "ipv6-icmp"}
_VERDICT_NAMES = {"accept": ACCEPT, "drop": DROP, "reject": REJECT, "return": RETURN,
                  "jump": JUMP, "goto": GOTO}


def _flatten(value: Any) -> list[Any]:
    """
    Normaliza o lado direito de um match em lista de elementos.

    :param value: Any
    :return: list[Any]
    """
    if isinstance(value, dict) and "set" in value:
        return _flatten(value["set"])
    if isinstance(value, list):
        items: list[Any] = []
        for item in value:
            items.extend(_flatten(item))
        return items
    if isinstance(value, dict) and "elem" in value:
        return _flatten(value["elem"].get("val"))
    return [value]


def element_to_networks(element: Any) -> list[str]:
    """
    Converte elemento de set/match em lista de enderecos/CIDRs.

    :param element: Any
    :return: list[str]
    """
    if isinstance(element, dict) and "prefix" in element:
        return [f"{element['prefix']['addr']}/{element['prefix']['len']}"]
    if isinstance(element, dict) and "range" in element:
        start, end = element["range"]
        return range_to_networks(str(start), str(end))
    if isinstance(element, (str, int)):
        return [str(element)]
    return []


def element_to_ports(element: Any) -> list[tuple[int, int]]:
    """
    Converte elemento em intervalo de portas.

    :param element: Any
    :return: list[tuple[int, int]]
    """
    if isinstance(element, dict) and "range" in element:
        start, end = element["range"]
        return [(int(start), int(end))]
    if isinstance(element, int):
        return [(element, element)]
    if isinstance(element, str):
        if element.isdigit():
            return [(int(element), int(element))]
        try:
            port = socket.getservbyname(element)
        except OSError:
            return []
        return [(port, port)]
    return []


def _left_kind(left: Any) -> tuple[str, str | None]:
    """
    Identifica o tipo do lado esquerdo de um match.

    :param left: Any
    :return: tuple[str, str | None]
    """
    if not isinstance(left, dict):
        return "unknown", None
    if "payload" in left:
        proto = left["payload"].get("protocol")
        field_name = left["payload"].get("field")
        if field_name == "dport":
            return "dport", proto
        if field_name == "sport":
            return "sport", proto
        if proto in ("ip", "ip6") and field_name in ("saddr", "daddr"):
            return field_name, proto
        if (proto, field_name) in (("ip", "protocol"), ("ip6", "nexthdr")):
            return "l4proto", proto
        if proto in _NEVER_PROTOCOLS:
            return "never_proto", proto
        return "unknown", f"payload {proto} {field_name}"
    if "meta" in left:
        key = left["meta"].get("key")
        mapping = {"l4proto": "l4proto", "nfproto": "nfproto", "protocol": "meta_protocol",
                   "iifname": "iif", "iif": "iif", "oifname": "oif", "oif": "oif",
                   "pkttype": "pkttype"}
        return mapping.get(key, "unknown"), f"meta {key}"
    if "ct" in left:
        key = left["ct"].get("key")
        if key in ("state", "status"):
            return f"ct_{key}", None
        return "unknown", f"ct {key}"
    if "fib" in left:
        flags = left["fib"].get("flags", [])
        if left["fib"].get("result") == "type" and "daddr" in flags:
            return "fib_daddr_type", None
        return "unknown", "fib"
    return "unknown", next(iter(left), None)


def _render(expr: Any) -> str:
    """
    Gera representacao textual curta de uma expressao (para evidencias).

    :param expr: Any
    :return: str
    """
    if isinstance(expr, dict):
        if "payload" in expr:
            return f"{expr['payload'].get('protocol')} {expr['payload'].get('field')}"
        if "meta" in expr:
            return f"meta {expr['meta'].get('key')}"
        if "ct" in expr:
            return f"ct {expr['ct'].get('key')}"
        if "prefix" in expr:
            return f"{expr['prefix']['addr']}/{expr['prefix']['len']}"
        if "range" in expr:
            return f"{expr['range'][0]}-{expr['range'][1]}"
        if "set" in expr:
            return "{ " + ", ".join(_render(item) for item in _flatten(expr["set"])) + " }"
    if isinstance(expr, list):
        return "{ " + ", ".join(_render(item) for item in expr) + " }"
    return str(expr)


def _render_rule(exprs: list[dict[str, Any]]) -> str:
    """
    Gera texto aproximado da regra nftables.

    :param exprs: list[dict[str, Any]]
    :return: str
    """
    parts: list[str] = []
    for expr in exprs:
        if "match" in expr:
            match = expr["match"]
            operator = "" if match.get("op") in ("==", "in") else f"{match.get('op')} "
            parts.append(f"{_render(match.get('left'))} {operator}{_render(match.get('right'))}")
        elif "jump" in expr or "goto" in expr:
            name = "jump" if "jump" in expr else "goto"
            parts.append(f"{name} {expr[name].get('target')}")
        elif "dnat" in expr:
            parts.append(f"dnat to {expr['dnat'].get('addr')}:{expr['dnat'].get('port', '')}")
        elif "vmap" in expr:
            parts.append(f"{_render(expr['vmap'].get('key'))} vmap ...")
        else:
            parts.extend(key for key in expr if key != "counter")
    return " ".join(parts)


def _vmap_entries(data: Any, maps: dict[str, list[VmapEntry]]) -> list[VmapEntry] | None:
    """
    Converte dados de verdict map (anonimo ou ``@nome``) em entradas.

    :param data: Any
    :param maps: dict[str, list[VmapEntry]]
    :return: list[VmapEntry] | None
    """
    if isinstance(data, str) and data.startswith("@"):
        return maps.get(data[1:])
    entries: list[VmapEntry] = []
    pairs = data.get("set", []) if isinstance(data, dict) else data
    for pair in pairs or []:
        if not isinstance(pair, list) or len(pair) != 2:
            return None
        key, verdict = pair
        name = next(iter(verdict), "") if isinstance(verdict, dict) else ""
        target = verdict[name].get("target") if isinstance(verdict.get(name), dict) else None
        values = [str(item) for item in _flatten(key)]
        entries.append(VmapEntry(values=values, verdict=_VERDICT_NAMES.get(name, UNKNOWN),
                                 target=target))
    return entries


def _apply_match(rule: Rule, match: dict[str, Any]) -> None:
    """
    Aplica um match nftables ao modelo da regra.

    :param rule: Rule
    :param match: dict[str, Any]
    :return: None
    """
    kind, extra = _left_kind(match.get("left"))
    operator = match.get("op", "==")
    if operator not in ("==", "!=", "in"):
        rule.unknown.append(f"operador {operator} em {_render(match.get('left'))}")
        return
    negated = operator == "!="
    right = match.get("right")
    set_ref = right[1:] if isinstance(right, str) and right.startswith("@") else None
    values = [] if set_ref else _flatten(right)
    strings = [str(item).lower() for item in values]

    if kind == "dport":
        if extra in ("tcp", "udp"):
            rule.protocols = [extra]
        if set_ref:
            rule.dport_set = set_ref
        else:
            rule.dports = [rng for item in values for rng in element_to_ports(item)]
        rule.dport_negated = negated
    elif kind == "sport":
        if extra in ("tcp", "udp"):
            rule.protocols = [extra]
        rule.partial.append(f"{extra} sport {'!= ' if negated else ''}{_render(right)}")
    elif kind in ("saddr", "daddr"):
        rule.families = ["ipv4" if extra == "ip" else "ipv6"]
        address = AddressMatch(set_name=set_ref, negated=negated,
                               networks=[] if set_ref else
                               [net for item in values for net in element_to_networks(item)])
        if kind == "saddr":
            rule.src = address
        else:
            rule.dst = address
    elif kind == "l4proto":
        rule.protocols = [_PROTO_NUMBERS.get(item, str(item)) if isinstance(item, int)
                          else str(item) for item in values]
        rule.proto_negated = negated
    elif kind in ("nfproto", "meta_protocol"):
        mapped = {"ipv4": "ipv4", "ip": "ipv4", "ipv6": "ipv6", "ip6": "ipv6"}
        families = [mapped[item] for item in strings if item in mapped]
        if negated:
            families = [fam for fam in ("ipv4", "ipv6") if fam not in families]
        rule.families = families
    elif kind in ("iif", "oif"):
        iface = IfaceMatch([str(item) for item in values], negated)
        if set_ref:
            rule.unknown.append(f"interface via set @{set_ref}")
        elif kind == "iif":
            rule.in_iface = iface
        else:
            rule.out_iface = iface
    elif kind == "pkttype":
        if ("host" in strings) == negated:
            rule.never_matches = f"pkttype {_render(right)}"
    elif kind == "ct_state":
        rule.ct_states = strings
        rule.ct_negated = negated
    elif kind == "ct_status":
        rule.ct_status_dnat = ("dnat" in strings) != negated
    elif kind == "fib_daddr_type":
        if bool({"local", "unicast"} & set(strings)) == negated:
            rule.never_matches = f"fib daddr type {_render(right)}"
    elif kind == "never_proto":
        if not negated:
            rule.never_matches = f"protocolo {extra}"
    else:
        rule.unknown.append(f"match {extra or _render(match.get('left'))}")


def _apply_statement(rule: Rule, expr: dict[str, Any], maps: dict[str, list[VmapEntry]]) -> None:
    """
    Aplica um statement nftables (verdict, nat, limit...) a regra.

    :param rule: Rule
    :param expr: dict[str, Any]
    :param maps: dict[str, list[VmapEntry]]
    :return: None
    """
    name = next(iter(expr))
    body = expr[name]
    if name in ("accept", "drop", "reject", "return"):
        rule.verdict = _VERDICT_NAMES[name]
    elif name in ("jump", "goto"):
        rule.verdict = _VERDICT_NAMES[name]
        rule.target = body.get("target")
    elif name == "dnat":
        rule.verdict = DNAT
        addr = body.get("addr")
        rule.nat_to_address = addr if isinstance(addr, str) else None
        port = body.get("port")
        rule.nat_to_port = port if isinstance(port, int) else None
        if addr is not None and not isinstance(addr, str):
            rule.unknown.append("dnat com mapa de enderecos")
    elif name == "redirect":
        rule.verdict = REDIRECT
        port = (body or {}).get("port")
        rule.nat_to_port = port if isinstance(port, int) else None
    elif name == "limit":
        rule.rate_limited = True
    elif name == "vmap":
        kind, _ = _left_kind(body.get("key"))
        entries = _vmap_entries(body.get("data"), maps)
        if entries is None or kind not in ("ct_state", "l4proto", "dport", "iif"):
            rule.verdict = UNKNOWN
            rule.unknown.append(f"vmap sobre {_render(body.get('key'))}")
        else:
            rule.verdict = VMAP
            rule.vmap_key = kind
            rule.vmap = entries
    elif name in ("queue", "synproxy"):
        rule.verdict = UNKNOWN
        rule.unknown.append(f"statement {name}")
    elif name in _IGNORED_STATEMENTS or name == "quota":
        if name == "quota":
            rule.rate_limited = True
    else:
        rule.unknown.append(f"statement {name}")


def _parse_rule(data: dict[str, Any], index: int, maps: dict[str, list[VmapEntry]]) -> Rule:
    """
    Converte um objeto ``rule`` do JSON em Rule.

    :param data: dict[str, Any]
    :param index: int
    :param maps: dict[str, list[VmapEntry]]
    :return: Rule
    """
    exprs = data.get("expr", [])
    rule = Rule(chain=data.get("chain", ""), index=index,
                text=f"[handle {data.get('handle')}] {_render_rule(exprs)}")
    for expr in exprs:
        if not isinstance(expr, dict) or not expr:
            continue
        if "match" in expr:
            _apply_match(rule, expr["match"])
        elif "xt" in expr:
            # Algumas versoes do nft emitem "xt": null para extensoes
            # iptables-nft sem traducao JSON: condicao nao interpretada.
            xt = expr["xt"] if isinstance(expr["xt"], dict) else {}
            rule.unknown.append(f"extensao xt {xt.get('name', '')}".strip())
        else:
            _apply_statement(rule, expr, maps)
    return rule


def parse_nft_json(output: str, origin: str = "nftables") -> list[Table]:
    """
    Interpreta ``nft -j list ruleset``. Somente familias ``ip``, ``ip6`` e
    ``inet`` sao consideradas.

    :param output: str
    :param origin: str
    :return: list[Table]
    """
    data = json.loads(output)
    items = data.get("nftables", []) if isinstance(data, dict) else []
    tables: dict[tuple[str, str], Table] = {}
    maps: dict[tuple[str, str], dict[str, list[VmapEntry]]] = {}
    counters: dict[tuple[str, str, str], int] = {}

    def table_for(obj: dict[str, Any]) -> Table | None:
        """
        Obtem (ou cria) a tabela de um objeto.

        :param obj: dict[str, Any]
        :return: Table | None
        """
        family = obj.get("family")
        if family not in _IP_FAMILIES:
            return None
        key = (family, obj.get("table") or obj.get("name"))
        if key not in tables:
            tables[key] = Table(origin=origin, family=family, name=key[1])
        return tables[key]

    # Duas passagens: sets, maps e chains antes das regras que os referenciam.
    ordered = [item for item in items if "rule" not in item]
    ordered += [item for item in items if "rule" in item]
    for item in ordered:
        if "table" in item:
            table_for(item["table"])
        elif "set" in item:
            obj = item["set"]
            table = table_for(obj)
            if table is not None:
                table.sets[obj["name"]] = _set_elements(obj.get("elem", []))
        elif "map" in item:
            obj = item["map"]
            table = table_for(obj)
            if table is not None and obj.get("map") == "verdict":
                entries = _vmap_entries(obj.get("elem", []), {})
                maps.setdefault((table.family, table.name), {})[obj["name"]] = entries or []
        elif "chain" in item:
            obj = item["chain"]
            table = table_for(obj)
            if table is not None:
                policy = obj.get("policy")
                if obj.get("hook") and policy is None:
                    policy = "accept"
                prio = obj.get("prio", 0)
                table.chains[obj["name"]] = Chain(
                    name=obj["name"], hook=obj.get("hook"),
                    policy=policy.upper() if policy else None,
                    priority=prio if isinstance(prio, int) else 0,
                    chain_type=obj.get("type", "filter"),
                )
        elif "rule" in item:
            obj = item["rule"]
            table = table_for(obj)
            if table is None:
                continue
            chain = table.chains.setdefault(obj["chain"], Chain(name=obj["chain"]))
            key = (table.family, table.name, chain.name)
            counters[key] = counters.get(key, 0) + 1
            chain.rules.append(_parse_rule(obj, counters[key],
                                           maps.get((table.family, table.name), {})))

    for table in tables.values():
        for chain in table.chains.values():
            for rule in chain.rules:
                if rule.verdict in (JUMP, GOTO) and rule.target not in table.chains:
                    rule.unknown.append(f"alvo desconhecido {rule.target}")
                    rule.verdict = UNKNOWN
    return list(tables.values())


def _set_elements(elements: Any) -> list[str]:
    """
    Converte elementos de set nomeado em lista textual (CIDRs, portas ou
    intervalos ``a-b``).

    :param elements: Any
    :return: list[str]
    """
    result: list[str] = []
    for element in _flatten(elements):
        if isinstance(element, dict) and "range" in element:
            start, end = element["range"]
            if isinstance(start, int):
                result.append(f"{start}-{end}")
            else:
                result.extend(range_to_networks(str(start), str(end)))
        else:
            result.extend(element_to_networks(element))
    return result


def is_iptables_managed(table: Table) -> bool:
    """
    Indica se a tabela nftables foi criada por iptables-nft (mesmas
    tabelas/chains exibidas por ``iptables-save``).

    :param table: Table
    :return: bool
    """
    builtin = {"INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING"}
    return (table.family in ("ip", "ip6")
            and table.name in ("filter", "nat", "mangle", "raw", "security")
            and bool(builtin & set(table.chains)))

