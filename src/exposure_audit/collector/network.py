# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : network.py
# Descricao   : Parsers de enderecos (ip -o addr), rotas, regras de
#               policy routing e politicas XFRM.
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
Parsers de contexto de rede do host.
"""

from exposure_audit.models import AddressScope, Family, InterfaceAddress
from exposure_audit.netutils import address_scope

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"

_ADDR_FLAGS = ("temporary", "deprecated", "tentative", "dadfailed", "secondary",
               "dynamic", "noprefixroute", "mngtmpaddr")
_DEFAULT_RULE_PRIORITIES = {"0", "32766", "32767"}

#: Prefixos de interfaces virtuais que nao recebem trafego externo direto.
VIRTUAL_IFACE_PREFIXES: tuple[str, ...] = ("lo", "docker", "br-", "veth", "virbr",
                                          "cni", "flannel", "kube", "podman")


def parse_ip_addr(output: str) -> list[InterfaceAddress]:
    """
    Interpreta a saida de ``ip -o -4 addr show`` / ``ip -o -6 addr show``.

    Exemplo de linha::

        2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0

    :param output: str
    :return: list[InterfaceAddress]
    """
    addresses: list[InterfaceAddress] = []
    for line in output.splitlines():
        tokens = line.replace("\\", " ").split()
        if len(tokens) < 4 or tokens[2] not in ("inet", "inet6"):
            continue
        iface = tokens[1].split("@", 1)[0]
        address, _, prefix = tokens[3].partition("/")
        scope = address_scope(address)
        if scope is None:
            continue
        family = Family.IPV4 if tokens[2] == "inet" else Family.IPV6
        flags = [token for token in tokens[4:] if token in _ADDR_FLAGS]
        addresses.append(InterfaceAddress(
            interface=iface, family=family, address=address,
            prefixlen=int(prefix) if prefix.isdigit() else (32 if family == Family.IPV4 else 128),
            scope=scope, flags=flags,
        ))
    return addresses


def parse_route_get(output: str) -> dict[str, str]:
    """
    Interpreta ``ip route get <destino>`` (gateway, interface, IP de origem,
    tabela).

    :param output: str
    :return: dict[str, str]
    """
    result: dict[str, str] = {}
    tokens = output.split()
    keys = {"via": "gateway", "dev": "interface", "src": "source", "table": "table"}
    for index, token in enumerate(tokens[:-1]):
        if token in keys:
            result[keys[token]] = tokens[index + 1]
    if tokens:
        result["destination"] = tokens[0]
    return result


def parse_default_routes(output: str) -> list[dict[str, str]]:
    """
    Extrai rotas default de ``ip route`` / ``ip -6 route``.

    :param output: str
    :return: list[dict[str, str]]
    """
    routes: list[dict[str, str]] = []
    for line in output.splitlines():
        if line.startswith("default"):
            route = parse_route_get(line)
            route.pop("destination", None)
            routes.append(route)
    return routes


def parse_ip_rules(output: str) -> list[str]:
    """
    Retorna as regras de policy routing que nao sao as padrao do kernel.

    :param output: str
    :return: list[str]
    """
    rules: list[str] = []
    for line in output.splitlines():
        priority = line.split(":", 1)[0].strip()
        if line.strip() and priority not in _DEFAULT_RULE_PRIORITIES:
            rules.append(line.strip())
    return rules


def parse_routing_tables(output: str) -> list[str]:
    """
    Lista tabelas de roteamento nao padrao presentes em
    ``ip route show table all``.

    :param output: str
    :return: list[str]
    """
    tables: set[str] = set()
    for line in output.splitlines():
        tokens = line.split()
        if "table" in tokens:
            name = tokens[tokens.index("table") + 1] if tokens.index("table") + 1 < len(tokens) else ""
            if name and name not in ("local", "main", "default"):
                tables.add(name)
    return sorted(tables)


def has_xfrm_policies(output: str | None) -> bool:
    """
    Indica a presenca de politicas XFRM (IPsec) que nao sejam de socket.

    :param output: str | None
    :return: bool
    """
    if not output:
        return False
    blocks: list[list[str]] = []
    for line in output.splitlines():
        if line.startswith("src "):
            blocks.append([line])
        elif blocks:
            blocks[-1].append(line)
    return any(not any("socket" in line for line in block) for block in blocks)


def ingress_interfaces(addresses: list[InterfaceAddress]) -> list[str]:
    """
    Interfaces capazes de receber trafego externo (exclui loopback,
    bridges Docker, veth e similares).

    :param addresses: list[InterfaceAddress]
    :return: list[str]
    """
    names = {addr.interface for addr in addresses
             if addr.scope not in (AddressScope.LOOPBACK, AddressScope.LINK_LOCAL)}
    return sorted(name for name in names if not name.startswith(VIRTUAL_IFACE_PREFIXES))
