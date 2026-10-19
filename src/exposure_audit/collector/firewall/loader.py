# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : loader.py
# Descricao   : Monta o Ruleset a partir da coleta bruta, detectando
#               nftables, iptables, iptables-nft, iptables-legacy e ipset,
#               e extrai mapeamentos DNAT/REDIRECT.
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
# CHANGELOG   : 2026-10-19: AttributeError na leitura do nft -j tambem
#               degrada para firewall desconhecido.
#
############################################################################

"""
Carregamento do firewall.

Mecanismos mistos:

* ``iptables -V`` informa o backend (``nf_tables`` ou ``legacy``);
* com backend ``nf_tables``, as tabelas ``ip/ip6 filter|nat|...`` vistas
  pelo ``nft`` sao as mesmas do ``iptables-save``; elas sao lidas pelo
  parser iptables (mais fiel as extensoes xt) e ignoradas no nft, para
  nao duplicar regras;
* regras em ``iptables-legacy`` coexistindo com nf_tables sao avaliadas
  tambem (o pacote precisa passar pelos dois).
"""

import json
import logging

from exposure_audit.collector.firewall.iptables import (has_rules, parse_iptables_save,
                                                       parse_ipset_save)
from exposure_audit.collector.firewall.model import DNAT, REDIRECT, Ruleset, Table
from exposure_audit.collector.firewall.nftables import is_iptables_managed, parse_nft_json
from exposure_audit.collector.host import command
from exposure_audit.models import CommandStatus, Family, NatMapping
from exposure_audit.netutils import family_of

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.2"

LOG = logging.getLogger(__name__)


def _backend(raw: dict[str, object]) -> str | None:
    """
    Identifica o backend do iptables (``nf_tables`` ou ``legacy``).

    :param raw: dict[str, object]
    :return: str | None
    """
    result = command(raw, "iptables_version")
    if result is None or not result.ok:
        return None
    if "nf_tables" in result.stdout:
        return "nf_tables"
    if "legacy" in result.stdout:
        return "legacy"
    return "legacy"


def _family_status(statuses: list[CommandStatus | None]) -> str:
    """
    Consolida o status de coleta de uma familia a partir das fontes.

    OK somente se ao menos uma fonte foi lida e nenhuma falhou por motivo
    diferente de ausencia do comando.

    :param statuses: list[CommandStatus | None]
    :return: str
    """
    present = [status for status in statuses if status is not None]
    failures = [status for status in present
                if status not in (CommandStatus.OK, CommandStatus.COMMAND_NOT_FOUND)]
    if failures:
        return failures[0].value
    if CommandStatus.OK in present:
        return "OK"
    return CommandStatus.COMMAND_NOT_FOUND.value


def build_ruleset(raw: dict[str, object]) -> Ruleset:
    """
    Constroi o Ruleset normalizado a partir da coleta bruta.

    :param raw: dict[str, object]
    :return: Ruleset
    """
    ruleset = Ruleset()
    backend = _backend(raw)
    ipt = {"ip": command(raw, "iptables_save"), "ip6": command(raw, "ip6tables_save")}
    legacy = {"ip": command(raw, "iptables_legacy_save"),
              "ip6": command(raw, "ip6tables_legacy_save")}
    nft = command(raw, "nft_json")
    nft_text = command(raw, "nft_text")
    nft_status = nft.status if nft is not None else None

    origin = "iptables-nft" if backend == "nf_tables" else "iptables"
    for family, result in ipt.items():
        if result is not None and result.ok:
            ruleset.tables.extend(parse_iptables_save(result.stdout, family, origin))

    if backend == "nf_tables":
        for family, result in legacy.items():
            if result is not None and result.ok and has_rules(result.stdout):
                ruleset.tables.extend(parse_iptables_save(result.stdout, family,
                                                          "iptables-legacy"))
                ruleset.notes.append(f"regras iptables-legacy ({family}) coexistem com "
                                     "nf_tables; ambas avaliadas")

    if nft is not None and nft.ok:
        try:
            nft_tables = parse_nft_json(nft.stdout)
        except (json.JSONDecodeError, AttributeError, KeyError, TypeError, ValueError) as exc:
            # Formato inesperado: a evidencia nft vira FAILED (firewall
            # desconhecido), nunca uma conclusao favoravel nem perda do host.
            LOG.warning("falha ao interpretar nft -j: %s", exc)
            ruleset.notes.append(f"saida nft -j nao interpretada: {exc}")
            nft_status = CommandStatus.FAILED
            nft_tables = []
        skip_managed = backend != "legacy" and any(r is not None and r.ok for r in ipt.values())
        for table in nft_tables:
            if skip_managed and is_iptables_managed(table):
                continue
            ruleset.tables.append(table)
    elif (nft is not None and nft.status == CommandStatus.FAILED and nft_text is not None
          and nft_text.ok and not nft_text.stdout.strip()):
        # nft sem suporte a JSON, mas ruleset nftables vazio.
        nft_status = CommandStatus.OK

    ipset = command(raw, "ipset_save")
    if ipset is not None and ipset.ok:
        ruleset.ipsets = parse_ipset_save(ipset.stdout)

    ruleset.family_status = {
        Family.IPV4.value: _family_status([ipt["ip"].status if ipt["ip"] else None, nft_status]),
        Family.IPV6.value: _family_status([ipt["ip6"].status if ipt["ip6"] else None, nft_status]),
    }
    if backend:
        ruleset.notes.append(f"backend iptables: {backend}")
    return ruleset


def _mapping_family(table: Table, to_address: str | None, families: list[str] | None) -> Family:
    """
    Determina a familia de um mapeamento NAT.

    :param table: Table
    :param to_address: str | None
    :param families: list[str] | None
    :return: Family
    """
    if table.family == "ip":
        return Family.IPV4
    if table.family == "ip6":
        return Family.IPV6
    if to_address:
        detected = family_of(to_address)
        if detected:
            return detected
    if families == ["ipv6"]:
        return Family.IPV6
    return Family.IPV4


def extract_nat(ruleset: Ruleset) -> list[NatMapping]:
    """
    Extrai regras DNAT/REDIRECT de todas as tabelas.

    :param ruleset: Ruleset
    :return: list[NatMapping]
    """
    mappings: list[NatMapping] = []
    for table in ruleset.tables:
        for chain in table.chains.values():
            for rule in chain.rules:
                if rule.verdict not in (DNAT, REDIRECT):
                    continue
                conditions: list[str] = []
                if rule.in_iface:
                    conditions.append(f"{'!' if rule.in_iface.negated else ''}iif "
                                      f"{','.join(rule.in_iface.names)}")
                if rule.dst:
                    conditions.append(f"{'!' if rule.dst.negated else ''}dst "
                                      f"{','.join(rule.dst.networks) or rule.dst.set_name}")
                if rule.unknown:
                    conditions.extend(rule.unknown)
                source = "any"
                if rule.src:
                    source = (f"{'!' if rule.src.negated else ''}"
                              f"{rule.src.set_name or ','.join(rule.src.networks)}")
                dest_networks = (rule.dst.networks if rule.dst and not rule.dst.negated else [])
                ranges = rule.dports or [None]
                protocols = rule.protocols or [None]
                for proto in protocols:
                    for port_range in ranges:
                        mappings.append(NatMapping(
                            protocol=proto,
                            family=_mapping_family(table, rule.nat_to_address, rule.families),
                            external_ports=port_range,
                            to_address=rule.nat_to_address if rule.verdict == DNAT else None,
                            to_port=rule.nat_to_port,
                            source=source,
                            origin=f"{table.label()} {chain.name}",
                            rule=rule.text,
                            conditions=conditions,
                            dest_networks=list(dest_networks),
                        ))
    return mappings
