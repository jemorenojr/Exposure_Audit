# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : sockets.py
# Descricao   : Parser da saida de ``ss -lntup`` / ``ss -lnup``.
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
Descoberta de sockets em escuta.

Formatos tratados no endereco local:

* ``0.0.0.0:22``, ``10.0.0.5:5432``         -- IPv4;
* ``[::]:22``, ``[2001:db8::1]:443``        -- IPv6;
* ``*:80``                                  -- socket dual-stack (IPv4+IPv6);
* ``127.0.0.53%lo:53``                      -- bind associado a interface;
* ``[::ffff:127.0.0.1]:8080``               -- IPv4 mapeado em IPv6.
"""

import re

from exposure_audit.models import Family, Listener
from exposure_audit.netutils import classify_bind, parse_ip

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"

_PROCESS = re.compile(r'\("([^"]+)",pid=(\d+)')
_LISTEN_STATES = {"LISTEN", "UNCONN"}


def _split_local(local: str) -> tuple[str, str, str | None] | None:
    """
    Separa endereco, porta e interface de ``endereco[%iface]:porta``.

    :param local: str
    :return: tuple[str, str, str | None] | None
    """
    address, sep, port = local.rpartition(":")
    if not sep or not port.isdigit():
        return None
    address = address.strip("[]")
    iface: str | None = None
    if "%" in address:
        address, iface = address.split("%", 1)
        address = address.strip("[]")
    return address, port, iface


def _listener(protocol: str, family: Family, address: str, port: int,
              iface: str | None, process: str | None, pid: int | None,
              dual: bool) -> Listener:
    """
    Cria um Listener normalizado.

    :param protocol: str
    :param family: Family
    :param address: str
    :param port: int
    :param iface: str | None
    :param process: str | None
    :param pid: int | None
    :param dual: bool
    :return: Listener
    """
    return Listener(protocol=protocol, family=family, address=address, port=port,
                    bind_class=classify_bind(address, family), process=process,
                    pid=pid, bound_interface=iface, dual_stack=dual)


def parse_ss(output: str) -> list[Listener]:
    """
    Interpreta ``ss -lntup`` e retorna listeners TCP/UDP. Linhas
    desconhecidas sao ignoradas.

    :param output: str
    :return: list[Listener]
    """
    listeners: list[Listener] = []
    for line in output.splitlines():
        tokens = line.split()
        if len(tokens) < 5 or tokens[0] not in ("tcp", "udp") or tokens[1] not in _LISTEN_STATES:
            continue
        protocol = tokens[0]
        parts = _split_local(tokens[4])
        if parts is None:
            continue
        address, port_text, iface = parts
        match = _PROCESS.search(line)
        process = match.group(1) if match else None
        pid = int(match.group(2)) if match else None
        port = int(port_text)
        if address == "*":
            listeners.append(_listener(protocol, Family.IPV4, "0.0.0.0", port, iface,
                                       process, pid, True))
            listeners.append(_listener(protocol, Family.IPV6, "::", port, iface,
                                       process, pid, True))
            continue
        ip = parse_ip(address)
        if ip is None:
            continue
        family = Family.IPV4 if ip.version == 4 else Family.IPV6
        listeners.append(_listener(protocol, family, str(ip), port, iface, process, pid, False))
    return dedupe_listeners(listeners)


def dedupe_listeners(listeners: list[Listener]) -> list[Listener]:
    """
    Remove listeners repetidos (ex.: SO_REUSEPORT com varios workers).

    :param listeners: list[Listener]
    :return: list[Listener]
    """
    seen: dict[tuple[str, str, str, int, str | None], Listener] = {}
    for item in listeners:
        key = (item.protocol, item.family.value, item.address, item.port, item.bound_interface)
        seen.setdefault(key, item)
    return list(seen.values())
