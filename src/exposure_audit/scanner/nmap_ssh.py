# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : nmap_ssh.py
# Descricao   : Scanner externo baseado em nmap, executado em host remoto
#               via SSH (preferencial) ou na estacao local.
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
Implementacao ``SSH + nmap`` do scanner externo.

Somente varreduras de descoberta/estado (``-sS``/``-sT``/``-sU``) e
identificacao leve (``-sV --version-light``). Nenhum script NSE, nenhuma
exploracao, nenhuma tentativa de autenticacao.
"""

import logging
import xml.etree.ElementTree as ET

from exposure_audit.collector.network import has_xfrm_policies, parse_route_get
from exposure_audit.models import CommandStatus, Family
from exposure_audit.netutils import family_of
from exposure_audit.scanner.base import ExternalScanner, ScanResult
from exposure_audit.scanner.nmap_parser import parse_nmap_xml
from exposure_audit.ssh_client import CommandResult, CommandRunner
from exposure_audit.validation import validate_ip, validate_port

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"

LOG = logging.getLogger(__name__)


def port_spec(tcp_ports: list[int], udp_ports: list[int]) -> str:
    """
    Monta a especificacao ``-p T:...,U:...`` do nmap.

    :param tcp_ports: list[int]
    :param udp_ports: list[int]
    :return: str
    """
    parts: list[str] = []
    if tcp_ports:
        parts.append("T:" + ",".join(str(validate_port(p)) for p in sorted(set(tcp_ports))))
    if udp_ports:
        parts.append("U:" + ",".join(str(validate_port(p)) for p in sorted(set(udp_ports))))
    return ",".join(parts)


class NmapScanner(ExternalScanner):
    """Scanner nmap sobre um CommandRunner (SSH ou local)."""

    def __init__(self, runner: CommandRunner, scan_type: str = "syn", max_rate: int = 300,
                 timeout: int = 900, scan_udp: bool = True) -> None:
        """
        Inicializa o scanner.

        :param runner: CommandRunner
        :param scan_type: str
        :param max_rate: int
        :param timeout: int
        :param scan_udp: bool
        :return: None
        """
        self.runner = runner
        self.scan_type = scan_type
        self.max_rate = max_rate
        self.timeout = timeout
        self.scan_udp = scan_udp
        self.origin = runner.name
        self.privileged = self._detect_privilege()
        self.notes: list[str] = []
        if scan_type == "syn" and not self.privileged:
            self.notes.append("sem root/sudo no scanner: usando TCP connect (-sT) e sem UDP")
        LOG.info("scanner %s pronto (privilegiado=%s)", self.origin, self.privileged)

    def _detect_privilege(self) -> bool:
        """
        Verifica root ou ``sudo -n`` no scanner.

        :return: bool
        """
        uid = self.runner.run(["id", "-u"])
        if uid.ok and uid.stdout.strip() == "0":
            return True
        if self.runner.run(["sudo", "-n", "true"]).ok:
            self.runner.use_sudo = True
            return True
        return False

    def available(self) -> CommandResult:
        """
        Verifica se o nmap esta disponivel no scanner.

        :return: CommandResult
        """
        return self.runner.run(["nmap", "--version"])

    def _base(self, target: str) -> list[str]:
        """
        Argumentos comuns do nmap.

        :param target: str
        :return: list[str]
        """
        argv = ["nmap", "-n", "-Pn", "-oX", "-", "--max-retries", "2",
                "--max-rate", str(self.max_rate)]
        if family_of(target) == Family.IPV6:
            argv.append("-6")
        return argv

    def _run(self, argv: list[str], target: str, kind: str,
             requested: dict[str, list[int]] | None) -> ScanResult:
        """
        Executa o nmap e interpreta o XML.

        :param argv: list[str]
        :param target: str
        :param kind: str
        :param requested: dict[str, list[int]] | None
        :return: ScanResult
        """
        result = self.runner.run(argv, privileged=self.privileged, timeout=self.timeout)
        scan = ScanResult(target=target, kind=kind, raw={"argv": argv, **result.to_dict()})
        if result.status != CommandStatus.OK:
            scan.error = f"{result.status.value}: {result.stderr.strip()[:300]}"
            LOG.warning("scan %s de %s falhou: %s", kind, target, scan.error)
            return scan
        try:
            scan.observations, scan.host_up = parse_nmap_xml(result.stdout, target, requested)
        except ET.ParseError as exc:
            scan.error = f"XML do nmap invalido: {exc}"
            LOG.warning("scan %s de %s: %s", kind, target, scan.error)
        return scan

    def scan_ports(self, target: str, tcp_ports: list[int],
                   udp_ports: list[int]) -> ScanResult:
        """
        Scan direcionado das portas encontradas internamente.

        :param target: str
        :param tcp_ports: list[int]
        :param udp_ports: list[int]
        :return: ScanResult
        """
        target = validate_ip(target)
        udp = udp_ports if (self.scan_udp and self.privileged) else []
        if not tcp_ports and not udp:
            return ScanResult(target=target, kind="targeted", error="nenhuma porta a testar")
        argv = self._base(target)
        if tcp_ports:
            argv.append("-sS" if self.scan_type == "syn" and self.privileged else "-sT")
        if udp:
            argv.append("-sU")
        argv += ["-p", port_spec(tcp_ports, udp), target]
        requested = {"tcp": sorted(set(tcp_ports)), "udp": sorted(set(udp))}
        return self._run(argv, target, "targeted", requested)

    def discover_ports(self, target: str) -> ScanResult:
        """
        Scan independente de todas as portas TCP.

        :param target: str
        :return: ScanResult
        """
        target = validate_ip(target)
        argv = self._base(target)
        argv += ["-sS" if self.scan_type == "syn" and self.privileged else "-sT",
                 "-p-", "--open", target]
        return self._run(argv, target, "discovery", None)

    def identify_services(self, target: str, tcp_ports: list[int]) -> ScanResult:
        """
        Identificacao leve de servicos (``-sV --version-light``), sem NSE.

        :param target: str
        :param tcp_ports: list[int]
        :return: ScanResult
        """
        target = validate_ip(target)
        if not tcp_ports:
            return ScanResult(target=target, kind="identify", error="nenhuma porta aberta")
        argv = self._base(target)
        argv += ["-sS" if self.scan_type == "syn" and self.privileged else "-sT",
                 "-sV", "--version-light", "-p", port_spec(tcp_ports, []), target]
        return self._run(argv, target, "identify", {"tcp": sorted(set(tcp_ports))})

    def path_evidence(self, target: str) -> dict[str, object]:
        """
        Rota e politicas XFRM do scanner ate o alvo. Uma rota /32 nao
        garante desvio do IPsec quando existem politicas XFRM.

        :param target: str
        :return: dict[str, object]
        """
        target = validate_ip(target)
        route = self.runner.run(["ip", "route", "get", target])
        xfrm = self.runner.run(["ip", "xfrm", "policy"], privileged=True)
        evidence: dict[str, object] = {
            "route_get": parse_route_get(route.stdout) if route.ok else {},
            "route_status": route.status.value,
            "xfrm_status": xfrm.status.value,
            "xfrm_policies": has_xfrm_policies(xfrm.stdout) if xfrm.ok else None,
        }
        warnings: list[str] = []
        route_info = evidence["route_get"]
        if isinstance(route_info, dict) and route_info.get("interface") == "lo":
            warnings.append("alvo e endereco local do proprio scanner (rota via lo): o "
                            "resultado nao representa a visao externa")
        if evidence["xfrm_policies"]:
            warnings.append("scanner possui politicas XFRM (IPsec): o teste pode nao "
                            "representar a visao da Internet")
        elif not xfrm.ok:
            warnings.append("politicas XFRM do scanner nao verificadas "
                            f"({xfrm.status.value})")
        evidence["warnings"] = warnings
        return evidence

    def close(self) -> None:
        """
        Encerra o executor.

        :return: None
        """
        self.runner.close()
