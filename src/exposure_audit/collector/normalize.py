# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : normalize.py
# Descricao   : Transforma a coleta bruta em modelo interno consistente
#               (HostState): identificacao, enderecos, rotas, listeners,
#               firewall, NAT e Docker.
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
Normalizacao (fase 2 da diretriz).

Recebe somente o dicionario bruto produzido por ``collector.host`` e, por
isso, pode ser reexecutada a partir do JSON bruto preservado.
"""

from dataclasses import dataclass, field

from exposure_audit.collector.docker import parse_docker_inspect
from exposure_audit.collector.firewall.loader import build_ruleset, extract_nat
from exposure_audit.collector.firewall.model import Ruleset
from exposure_audit.collector.host import command, command_output
from exposure_audit.collector.network import (has_xfrm_policies, ingress_interfaces,
                                              parse_default_routes, parse_ip_addr,
                                              parse_ip_rules, parse_route_get,
                                              parse_routing_tables)
from exposure_audit.collector.sockets import dedupe_listeners, parse_ss
from exposure_audit.models import (AddressScope, CommandStatus, DockerPublication,
                                   InterfaceAddress, Listener, NatMapping)

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"


@dataclass
class HostState:
    """Estado interno normalizado de um host."""

    hostname: str
    fqdn: str | None
    os_name: str | None
    addresses: list[InterfaceAddress]
    routing: dict[str, object]
    listeners: list[Listener]
    ruleset: Ruleset
    nat: list[NatMapping]
    docker: list[DockerPublication]
    ingress_ifaces: list[str]
    issues: list[dict[str, str]] = field(default_factory=list)

    def addresses_by_scope(self, *scopes: AddressScope) -> list[str]:
        """
        Lista enderecos do host nos escopos informados.

        :param scopes: AddressScope
        :return: list[str]
        """
        return [addr.address for addr in self.addresses if addr.scope in scopes]

    @property
    def primary_ip(self) -> str | None:
        """
        IP de origem da rota default (ou primeiro endereco nao loopback).

        :return: str | None
        """
        source = self.routing.get("route_get", {})
        if isinstance(source, dict) and source.get("source"):
            return str(source["source"])
        for addr in self.addresses:
            if addr.scope not in (AddressScope.LOOPBACK, AddressScope.LINK_LOCAL):
                return addr.address
        return None


def _os_name(os_release: str | None) -> str | None:
    """
    Extrai PRETTY_NAME de /etc/os-release.

    :param os_release: str | None
    :return: str | None
    """
    for line in (os_release or "").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return None


def _issues(raw: dict[str, object]) -> list[dict[str, str]]:
    """
    Lista comandos que falharam (exceto ausencia de ferramenta opcional).

    :param raw: dict[str, object]
    :return: list[dict[str, str]]
    """
    issues: list[dict[str, str]] = []
    commands = raw.get("commands", {})
    optional_missing = {"iptables_legacy_save", "ip6tables_legacy_save", "ipset_save",
                        "docker_ps", "nft_json", "nft_text"}
    for key in commands if isinstance(commands, dict) else []:
        result = command(raw, key)
        if result is None or result.ok:
            continue
        if result.status == CommandStatus.COMMAND_NOT_FOUND and key in optional_missing:
            continue
        issues.append({"source": key, "status": result.status.value,
                       "detail": (result.stderr or "").strip()[:300]})
    return issues


def _listeners(raw: dict[str, object]) -> list[Listener]:
    """
    Combina ``ss -lntup`` e ``ss -lnup``.

    :param raw: dict[str, object]
    :return: list[Listener]
    """
    listeners: list[Listener] = []
    for key in ("ss_listen", "ss_udp"):
        output = command_output(raw, key)
        if output:
            listeners.extend(parse_ss(output))
    return dedupe_listeners(listeners)


def normalize(raw: dict[str, object], fallback_name: str) -> HostState:
    """
    Normaliza a coleta bruta de um host.

    :param raw: dict[str, object]
    :param fallback_name: str
    :return: HostState
    """
    addresses = parse_ip_addr(command_output(raw, "ip4_addr") or "")
    addresses += parse_ip_addr(command_output(raw, "ip6_addr") or "")
    routing: dict[str, object] = {
        "default_v4": parse_default_routes(command_output(raw, "ip_route") or ""),
        "default_v6": parse_default_routes(command_output(raw, "ip6_route") or ""),
        "route_get": parse_route_get(command_output(raw, "ip_route_get") or ""),
        "policy_rules": parse_ip_rules(command_output(raw, "ip_rule") or ""),
        "extra_tables": parse_routing_tables(command_output(raw, "ip_route_all") or ""),
        "xfrm_policies": has_xfrm_policies(command_output(raw, "xfrm_policy")),
    }
    ruleset = build_ruleset(raw)
    docker_output = command_output(raw, "docker_inspect")
    hostname = (command_output(raw, "hostname") or "").strip() or fallback_name
    return HostState(
        hostname=hostname,
        fqdn=(command_output(raw, "hostname_fqdn") or "").strip() or None,
        os_name=_os_name(command_output(raw, "os_release")),
        addresses=addresses,
        routing=routing,
        listeners=_listeners(raw),
        ruleset=ruleset,
        nat=extract_nat(ruleset),
        docker=parse_docker_inspect(docker_output) if docker_output else [],
        ingress_ifaces=ingress_interfaces(addresses),
        issues=_issues(raw),
    )
