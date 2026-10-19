# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : models.py
# Descricao   : Modelos normalizados compartilhados entre collector,
#               scanner, correlator e relatorios.
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
Modelos de dados normalizados.

Estes tipos sao o contrato entre os componentes. O correlator depende
somente deles, nunca do formato bruto produzido por ``ss``, ``iptables``,
``nft`` ou ``nmap``. Assim, coletores e scanners podem ser substituidos
sem reescrever a logica de classificacao.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"


class StrEnum(str, Enum):
    """
    Enum cujo valor e uma string (serializa direto em JSON/CSV).
    """

    def __str__(self) -> str:
        """
        Retorna o valor textual do membro.

        :return: str
        """
        return str(self.value)


class Family(StrEnum):
    """Familia de protocolo IP."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"


class AddressScope(StrEnum):
    """Classificacao de um endereco IP (secao 7.2 da diretriz)."""

    LOOPBACK = "loopback"
    PRIVATE = "private"
    PUBLIC = "public"
    LINK_LOCAL = "link-local"
    IPV6_GLOBAL = "ipv6-global"


class BindClass(StrEnum):
    """Classificacao do endereco de bind de um socket (secao 8)."""

    LOCAL_ONLY = "LOCAL_ONLY"
    PRIVATE_BIND = "PRIVATE_BIND"
    PUBLIC_BIND = "PUBLIC_BIND"
    ALL_IPV4 = "ALL_IPV4"
    ALL_IPV6 = "ALL_IPV6"


class FirewallAccess(StrEnum):
    """Restricao de origem normalizada (secao 10)."""

    ANY = "ANY"
    RESTRICTED_SOURCE = "RESTRICTED_SOURCE"
    PRIVATE_ONLY = "PRIVATE_ONLY"
    LOCAL_ONLY = "LOCAL_ONLY"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


class ExternalState(StrEnum):
    """Estado externo normalizado de uma porta (secao 15)."""

    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"
    UNREACHABLE = "UNREACHABLE"
    UNKNOWN = "UNKNOWN"


class Classification(StrEnum):
    """Classificacao final de exposicao (secao 6)."""

    PROTEGIDO = "PROTEGIDO"
    PARCIAL = "PARCIAL"
    EXPOSTO = "EXPOSTO"
    INDETERMINADO = "INDETERMINADO"


class CommandStatus(StrEnum):
    """Resultado operacional de um comando executado."""

    OK = "OK"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    COMMAND_NOT_FOUND = "COMMAND_NOT_FOUND"
    PRIVILEGE_INSUFFICIENT = "PRIVILEGE_INSUFFICIENT"
    SSH_FAILED = "SSH_FAILED"
    SKIPPED = "SKIPPED"


#: Gravidade usada para agregar classificacoes de varias familias IP.
#: INDETERMINADO fica acima de PARCIAL: falta de informacao nunca vira
#: conclusao favoravel.
CLASSIFICATION_SEVERITY: dict[Classification, int] = {
    Classification.PROTEGIDO: 0,
    Classification.PARCIAL: 1,
    Classification.INDETERMINADO: 2,
    Classification.EXPOSTO: 3,
}


@dataclass
class InterfaceAddress:
    """Endereco configurado em uma interface do host."""

    interface: str
    family: Family
    address: str
    prefixlen: int
    scope: AddressScope
    flags: list[str] = field(default_factory=list)


@dataclass
class Listener:
    """Socket em escuta descoberto via ``ss``."""

    protocol: str
    family: Family
    address: str
    port: int
    bind_class: BindClass
    process: str | None = None
    pid: int | None = None
    bound_interface: str | None = None
    dual_stack: bool = False


@dataclass
class NatMapping:
    """Traducao de destino (DNAT/REDIRECT) identificada no host."""

    protocol: str | None
    family: Family
    external_ports: tuple[int, int] | None
    to_address: str | None
    to_port: int | None
    source: str
    origin: str
    rule: str
    conditions: list[str] = field(default_factory=list)
    dest_networks: list[str] = field(default_factory=list)


@dataclass
class DockerPublication:
    """Porta publicada por um container Docker."""

    container: str
    container_id: str
    protocol: str
    host_ip: str
    host_port: int
    container_port: int
    container_ips: list[str] = field(default_factory=list)


@dataclass
class FirewallVerdict:
    """
    Resultado normalizado da analise do ruleset para um servico e familia.

    ``sources`` lista as origens efetivamente autorizadas quando a
    restricao e parcial; ``evidence`` lista as regras que determinaram o
    resultado, em ordem de avaliacao.
    """

    access: FirewallAccess
    sources: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    path: str = "input"


@dataclass
class PortObservation:
    """Observacao externa de uma porta em um alvo."""

    target: str
    family: Family
    protocol: str
    port: int
    state: ExternalState
    raw_state: str = ""
    reason: str = ""
    service_name: str | None = None
    product: str | None = None
    version: str | None = None


@dataclass
class ExternalEvidence:
    """Evidencia externa consolidada de um servico em uma familia."""

    state: ExternalState
    scanned: bool
    observations: list[PortObservation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class NetworkContext:
    """Contexto de rede do host necessario ao correlator."""

    hostname: str
    has_ipv6_global: bool
    external_scan_available: bool
    scan_targets: dict[str, list[str]] = field(default_factory=dict)
    xfrm_policies_present: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class ServiceView:
    """
    Visao de um servico (protocolo + porta) agregando seus listeners.

    ``forwarded`` indica servico alcancado por DNAT (Docker ou
    encaminhamento), cujo caminho de firewall e FORWARD, nao INPUT.
    """

    protocol: str
    port: int
    listeners: list[Listener] = field(default_factory=list)
    process: str | None = None
    service_name: str | None = None
    nat_mappings: list[NatMapping] = field(default_factory=list)
    forwarded: bool = False
    forward_target: str | None = None

    @property
    def families(self) -> list[Family]:
        """
        Familias IP em que o servico possui listener (ou NAT).

        :return: list[Family]
        """
        found = {listener.family for listener in self.listeners}
        found.update(mapping.family for mapping in self.nat_mappings)
        return sorted(found, key=lambda item: item.value)

    @property
    def local_active(self) -> bool:
        """
        Indica se ha socket local em escuta.

        :return: bool
        """
        return bool(self.listeners)


@dataclass
class FamilyAssessment:
    """Classificacao de um servico em uma familia IP."""

    family: Family
    bind_class: BindClass | None
    bind_addresses: list[str]
    firewall: FirewallVerdict
    external: ExternalEvidence
    classification: Classification
    reason: str
    rule_id: str
    followup: bool


@dataclass
class ServiceAssessment:
    """Resultado final do correlator para um servico."""

    protocol: str
    port: int
    service: str
    process: str | None
    local_active: bool
    families: list[FamilyAssessment]
    classification: Classification
    reason: str
    followup: bool
    evidence: list[str] = field(default_factory=list)
    external_ports: list[int] = field(default_factory=list)
    kind: str = "local"


def to_dict(obj: Any) -> Any:
    """
    Converte dataclasses/enums em estruturas serializaveis em JSON.

    :param obj: Any
    :return: Any
    """
    if hasattr(obj, "__dataclass_fields__"):
        return to_dict(asdict(obj))
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {str(to_dict(key)): to_dict(value) for key, value in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_dict(item) for item in obj]
    return obj
