# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : validation.py
# Descricao   : Validacao de hostname, IP, porta, protocolo e argumentos
#               recebidos pela CLI ou inventario.
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
Validacoes de entrada.

Todo valor que chega a um comando externo (ssh, nmap) passa por aqui
antes. Valores invalidos geram ``ValueError`` com mensagem explicativa.
"""

import ipaddress
import re

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"

_HOST_LABEL = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")
_SSH_USER = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}\$?$", re.IGNORECASE)
_CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")

PROTOCOLS: frozenset[str] = frozenset({"tcp", "udp"})


def is_ip(value: str) -> bool:
    """
    Indica se o valor e um endereco IPv4 ou IPv6 valido.

    :param value: str
    :return: bool
    """
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def validate_hostname(value: str) -> str:
    """
    Valida um hostname (RFC 1123) ou endereco IP.

    Rejeita valores iniciados por ``-`` para impedir injecao de opcoes
    em ``ssh`` e ``nmap``.

    :param value: str
    :return: str
    """
    candidate = value.strip()
    if not candidate or candidate.startswith("-"):
        raise ValueError(f"host invalido: {value!r}")
    if is_ip(candidate):
        return candidate
    if len(candidate) > 253:
        raise ValueError(f"hostname muito longo: {value!r}")
    labels = candidate.rstrip(".").split(".")
    if not all(_HOST_LABEL.match(label) for label in labels):
        raise ValueError(f"hostname invalido: {value!r}")
    return candidate


def validate_ip(value: str) -> str:
    """
    Valida e normaliza um endereco IP.

    :param value: str
    :return: str
    """
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"endereco IP invalido: {value!r}") from exc


def validate_port(value: int | str) -> int:
    """
    Valida uma porta TCP/UDP (1-65535).

    :param value: int | str
    :return: int
    """
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"porta invalida: {value!r}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"porta fora do intervalo: {value!r}")
    return port


def validate_protocol(value: str) -> str:
    """
    Valida o protocolo de transporte (tcp/udp).

    :param value: str
    :return: str
    """
    proto = value.strip().lower()
    if proto not in PROTOCOLS:
        raise ValueError(f"protocolo nao suportado: {value!r}")
    return proto


def validate_ssh_user(value: str) -> str:
    """
    Valida um nome de usuario SSH.

    :param value: str
    :return: str
    """
    if not _SSH_USER.match(value):
        raise ValueError(f"usuario SSH invalido: {value!r}")
    return value


def validate_container_id(value: str) -> str:
    """
    Valida um ID de container Docker (hexadecimal).

    :param value: str
    :return: str
    """
    if not _CONTAINER_ID.match(value):
        raise ValueError(f"ID de container invalido: {value!r}")
    return value


def validate_positive_int(value: int | str, name: str, maximum: int) -> int:
    """
    Valida um inteiro positivo limitado (workers, timeout, taxa).

    :param value: int | str
    :param name: str
    :param maximum: int
    :return: int
    """
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} invalido: {value!r}") from exc
    if not 1 <= number <= maximum:
        raise ValueError(f"{name} deve estar entre 1 e {maximum}: {value!r}")
    return number
