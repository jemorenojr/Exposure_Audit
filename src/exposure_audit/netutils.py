# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : netutils.py
# Descricao   : Classificacao de enderecos IP, binds e utilitarios de rede.
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
Utilitarios de rede usados por collector, firewall e correlator.

Decisao: faixas de documentacao (RFC 5737 e RFC 3849) sao tratadas como
publicas. Elas nunca aparecem em producao e sao usadas nas fixtures
anonimizadas para representar enderecos publicos reais.
"""

import fnmatch
import ipaddress

from exposure_audit.models import AddressScope, BindClass, Family

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_DOCUMENTATION_NETS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)

_UNSPECIFIED = {"0.0.0.0", "::", "*"}


def parse_ip(value: str) -> IPAddress | None:
    """
    Converte texto em endereco IP, removendo colchetes e zona (``%eth0``).
    Enderecos IPv4 mapeados em IPv6 sao convertidos para IPv4.

    :param value: str
    :return: IPAddress | None
    """
    text = value.strip().strip("[]").split("%", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def parse_network(value: str) -> IPNetwork | None:
    """
    Converte texto (endereco ou CIDR) em rede IP, sem exigir host bits zero.

    :param value: str
    :return: IPNetwork | None
    """
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def family_of(value: str) -> Family | None:
    """
    Retorna a familia IP de um endereco ou rede textual.

    :param value: str
    :return: Family | None
    """
    network = parse_network(value.strip("[]").split("%", 1)[0])
    if network is None:
        return None
    return Family.IPV4 if network.version == 4 else Family.IPV6


def _is_documentation(address: IPAddress) -> bool:
    """
    Indica se o endereco pertence a uma faixa de documentacao.

    :param address: IPAddress
    :return: bool
    """
    return any(address in net for net in _DOCUMENTATION_NETS
               if net.version == address.version)


def address_scope(value: str) -> AddressScope | None:
    """
    Classifica um endereco como loopback, private, public, link-local ou
    ipv6-global.

    :param value: str
    :return: AddressScope | None
    """
    address = parse_ip(value)
    if address is None:
        return None
    if address.is_loopback:
        return AddressScope.LOOPBACK
    if address.is_link_local:
        return AddressScope.LINK_LOCAL
    if address.is_global or _is_documentation(address):
        if address.version == 6:
            return AddressScope.IPV6_GLOBAL
        return AddressScope.PUBLIC
    return AddressScope.PRIVATE


def network_scope(network: IPNetwork) -> AddressScope:
    """
    Classifica uma rede inteira. Redes que contem enderecos publicos sao
    consideradas publicas (ex.: ``0.0.0.0/0``).

    :param network: IPNetwork
    :return: AddressScope
    """
    if network.prefixlen == 0:
        return AddressScope.PUBLIC if network.version == 4 else AddressScope.IPV6_GLOBAL
    first = address_scope(str(network.network_address))
    last = address_scope(str(network.broadcast_address))
    scopes = {first, last}
    public = {AddressScope.PUBLIC, AddressScope.IPV6_GLOBAL}
    if scopes & public:
        return AddressScope.PUBLIC if network.version == 4 else AddressScope.IPV6_GLOBAL
    if scopes == {AddressScope.LOOPBACK}:
        return AddressScope.LOOPBACK
    if scopes == {AddressScope.LINK_LOCAL}:
        return AddressScope.LINK_LOCAL
    return AddressScope.PRIVATE


def is_public_scope(scope: AddressScope | None) -> bool:
    """
    Indica se o escopo e roteavel na Internet.

    :param scope: AddressScope | None
    :return: bool
    """
    return scope in (AddressScope.PUBLIC, AddressScope.IPV6_GLOBAL)


def classify_bind(address: str, family: Family) -> BindClass:
    """
    Classifica o endereco de bind de um socket (secao 8 da diretriz).

    :param address: str
    :param family: Family
    :return: BindClass
    """
    text = address.strip().strip("[]").split("%", 1)[0]
    if text in _UNSPECIFIED:
        return BindClass.ALL_IPV4 if family == Family.IPV4 else BindClass.ALL_IPV6
    scope = address_scope(text)
    if scope == AddressScope.LOOPBACK:
        return BindClass.LOCAL_ONLY
    if is_public_scope(scope):
        return BindClass.PUBLIC_BIND
    return BindClass.PRIVATE_BIND


def is_wildcard_bind(bind_class: BindClass | None) -> bool:
    """
    Indica bind em todos os enderecos (0.0.0.0 ou ::).

    :param bind_class: BindClass | None
    :return: bool
    """
    return bind_class in (BindClass.ALL_IPV4, BindClass.ALL_IPV6)


def iface_matches(pattern: str, name: str) -> bool:
    """
    Compara nome de interface com padrao iptables (``eth+``) ou nftables
    (``eth*``).

    :param pattern: str
    :param name: str
    :return: bool
    """
    if pattern.endswith("+"):
        return name.startswith(pattern[:-1])
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatchcase(name, pattern)
    return name == pattern


def range_to_networks(start: str, end: str) -> list[str]:
    """
    Converte um intervalo de IPs em lista de CIDRs.

    :param start: str
    :param end: str
    :return: list[str]
    """
    first = parse_ip(start)
    last = parse_ip(end)
    if first is None or last is None or first.version != last.version:
        return []
    return [str(net) for net in ipaddress.summarize_address_range(first, last)]
