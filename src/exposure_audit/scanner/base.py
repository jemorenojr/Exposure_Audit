# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : base.py
# Descricao   : Interface abstrata do scanner externo.
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
Contrato do scanner externo (secao 33 da diretriz).

Implementacoes nao devem depender de provedor especifico. Toda falha
deve ser devolvida como ``ScanResult`` com ``error`` preenchido, nunca
como excecao que interrompa o lote.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from exposure_audit.models import PortObservation

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"


@dataclass
class ScanResult:
    """Resultado de uma execucao do scanner contra um alvo."""

    target: str
    kind: str
    observations: list[PortObservation] = field(default_factory=list)
    error: str | None = None
    host_up: bool | None = None
    raw: dict[str, object] = field(default_factory=dict)


class ExternalScanner(ABC):
    """Interface do scanner externo."""

    #: Descricao do ponto de origem do scan (para o relatorio).
    origin: str = "desconhecido"

    @abstractmethod
    def scan_ports(self, target: str, tcp_ports: list[int],
                   udp_ports: list[int]) -> ScanResult:
        """
        Testa as portas encontradas internamente (scan direcionado).

        :param target: str
        :param tcp_ports: list[int]
        :param udp_ports: list[int]
        :return: ScanResult
        """

    @abstractmethod
    def discover_ports(self, target: str) -> ScanResult:
        """
        Varre todas as portas TCP do alvo (scan independente), para
        detectar portas externas sem correspondencia interna (ex.: DNAT).

        :param target: str
        :return: ScanResult
        """

    @abstractmethod
    def identify_services(self, target: str, tcp_ports: list[int]) -> ScanResult:
        """
        Identificacao leve de servico (sem NSE invasivo).

        :param target: str
        :param tcp_ports: list[int]
        :return: ScanResult
        """

    @abstractmethod
    def path_evidence(self, target: str) -> dict[str, object]:
        """
        Coleta evidencias do caminho entre scanner e alvo (rota, XFRM),
        para detectar validacao comprometida por VPN/IPsec.

        :param target: str
        :return: dict[str, object]
        """

    def close(self) -> None:
        """
        Libera recursos.

        :return: None
        """
