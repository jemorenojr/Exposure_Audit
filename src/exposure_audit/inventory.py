# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : inventory.py
# Descricao   : Leitura do inventario de hosts (arquivo texto, CSV ou CLI).
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
Inventario de hosts.

Formatos aceitos:

* texto: um host por linha, opcionalmente seguido do(s) IP(s) publico(s)
  separados por espaco; ``#`` inicia comentario;
* CSV com cabecalho: ``host`` (obrigatorio), ``public_ip`` (opcional,
  varios separados por ``;``), ``ssh_user``, ``ssh_port``, ``name``;
* argumentos CLI: ``--host`` repetivel.
"""

import csv
from dataclasses import dataclass, field
from pathlib import Path

from exposure_audit.validation import (validate_hostname, validate_ip,
                                       validate_port, validate_ssh_user)

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"


@dataclass
class HostEntry:
    """Entrada validada do inventario."""

    host: str
    name: str
    public_ips: list[str] = field(default_factory=list)
    ssh_user: str | None = None
    ssh_port: int | None = None


def _split_ips(value: str) -> list[str]:
    """
    Separa e valida uma lista de IPs publicos.

    :param value: str
    :return: list[str]
    """
    items = [item for item in value.replace(",", ";").split(";") if item.strip()]
    return [validate_ip(item) for item in items]


def make_entry(host: str, public_ips: list[str] | None = None, name: str | None = None,
               ssh_user: str | None = None, ssh_port: str | int | None = None) -> HostEntry:
    """
    Cria uma entrada de inventario validando todos os campos.

    :param host: str
    :param public_ips: list[str] | None
    :param name: str | None
    :param ssh_user: str | None
    :param ssh_port: str | int | None
    :return: HostEntry
    """
    target = validate_hostname(host)
    label = validate_hostname(name) if name else target
    return HostEntry(
        host=target,
        name=label,
        public_ips=[validate_ip(ip) for ip in (public_ips or [])],
        ssh_user=validate_ssh_user(ssh_user) if ssh_user else None,
        ssh_port=validate_port(ssh_port) if ssh_port else None,
    )


def parse_text(content: str) -> list[HostEntry]:
    """
    Le inventario em texto simples.

    :param content: str
    :return: list[HostEntry]
    """
    entries: list[HostEntry] = []
    for number, raw in enumerate(content.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        try:
            entries.append(make_entry(parts[0], public_ips=parts[1:]))
        except ValueError as exc:
            raise ValueError(f"linha {number}: {exc}") from exc
    return entries


def parse_csv(content: str) -> list[HostEntry]:
    """
    Le inventario em CSV com cabecalho.

    :param content: str
    :return: list[HostEntry]
    """
    reader = csv.DictReader(line for line in content.splitlines()
                            if line.strip() and not line.lstrip().startswith("#"))
    if not reader.fieldnames or "host" not in reader.fieldnames:
        raise ValueError("CSV de inventario precisa da coluna 'host'")
    entries: list[HostEntry] = []
    for number, row in enumerate(reader, start=2):
        try:
            entries.append(make_entry(
                row["host"],
                public_ips=_split_ips(row.get("public_ip") or ""),
                name=(row.get("name") or "").strip() or None,
                ssh_user=(row.get("ssh_user") or "").strip() or None,
                ssh_port=(row.get("ssh_port") or "").strip() or None,
            ))
        except ValueError as exc:
            raise ValueError(f"linha {number}: {exc}") from exc
    return entries


def load_inventory(path: Path | None, cli_hosts: list[str]) -> list[HostEntry]:
    """
    Carrega o inventario do arquivo (texto/CSV) e dos argumentos CLI,
    removendo duplicados pelo nome.

    :param path: Path | None
    :param cli_hosts: list[str]
    :return: list[HostEntry]
    """
    entries: list[HostEntry] = []
    if path is not None:
        content = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".csv":
            entries.extend(parse_csv(content))
        else:
            entries.extend(parse_text(content))
    entries.extend(make_entry(host) for host in cli_hosts)
    unique: dict[str, HostEntry] = {}
    for entry in entries:
        unique.setdefault(entry.name, entry)
    return list(unique.values())
