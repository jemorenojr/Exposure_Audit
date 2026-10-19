# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : nmap_parser.py
# Descricao   : Parser da saida XML do nmap (-oX -).
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
Parser XML do nmap.

Estados nmap -> estados normalizados (secao 15 da diretriz):

* ``open``                 -> OPEN
* ``closed``               -> CLOSED
* ``filtered``             -> FILTERED
* ``open|filtered`` e
  ``closed|filtered`` e
  ``unfiltered``           -> UNKNOWN (ambiguo; tipico de UDP)
* host ``down``            -> UNREACHABLE

Portas solicitadas que o nmap agrupa em ``<extraports>`` recebem o
estado do grupo quando ha um unico grupo.
"""

import xml.etree.ElementTree as ET

from exposure_audit.models import ExternalState, Family, PortObservation
from exposure_audit.netutils import family_of

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"

STATE_MAP: dict[str, ExternalState] = {
    "open": ExternalState.OPEN,
    "closed": ExternalState.CLOSED,
    "filtered": ExternalState.FILTERED,
}


def normalize_state(raw_state: str) -> ExternalState:
    """
    Converte estado nmap em ExternalState.

    :param raw_state: str
    :return: ExternalState
    """
    return STATE_MAP.get(raw_state, ExternalState.UNKNOWN)


def parse_nmap_xml(output: str, target: str,
                   requested: dict[str, list[int]] | None = None
                   ) -> tuple[list[PortObservation], bool | None]:
    """
    Interpreta XML do nmap e retorna (observacoes, host_up).

    :param output: str
    :param target: str
    :param requested: dict[str, list[int]] | None
    :return: tuple[list[PortObservation], bool | None]
    """
    root = ET.fromstring(output)
    family = family_of(target) or Family.IPV4
    observations: list[PortObservation] = []
    host = root.find("host")
    if host is None:
        return observations, None
    status = host.find("status")
    host_up = None if status is None else status.get("state") == "up"
    if host_up is False:
        for proto, ports in (requested or {}).items():
            for port in ports:
                observations.append(PortObservation(
                    target=target, family=family, protocol=proto, port=port,
                    state=ExternalState.UNREACHABLE, raw_state="host-down"))
        return observations, host_up

    seen: set[tuple[str, int]] = set()
    ports_el = host.find("ports")
    extra_states: list[str] = []
    if ports_el is not None:
        for extra in ports_el.findall("extraports"):
            extra_states.append(extra.get("state", ""))
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            raw_state = state_el.get("state", "") if state_el is not None else ""
            service = port_el.find("service")
            proto = port_el.get("protocol", "tcp")
            number = int(port_el.get("portid", "0"))
            seen.add((proto, number))
            observations.append(PortObservation(
                target=target, family=family, protocol=proto, port=number,
                state=normalize_state(raw_state), raw_state=raw_state,
                reason=state_el.get("reason", "") if state_el is not None else "",
                service_name=service.get("name") if service is not None else None,
                product=service.get("product") if service is not None else None,
                version=service.get("version") if service is not None else None,
            ))
    fallback = extra_states[0] if len(extra_states) == 1 else ""
    for proto, ports in (requested or {}).items():
        for port in ports:
            if (proto, port) not in seen:
                observations.append(PortObservation(
                    target=target, family=family, protocol=proto, port=port,
                    state=normalize_state(fallback) if fallback else ExternalState.UNKNOWN,
                    raw_state=fallback or "nao-reportado", reason="extraports"))
    return observations, host_up
