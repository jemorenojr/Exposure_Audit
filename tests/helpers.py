# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : helpers.py
# Descricao   : Utilitarios de teste: leitura de fixtures, coleta bruta
#               sintetica e scanner falso.
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
Apoio aos testes unitarios.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from exposure_audit.models import CommandStatus  # noqa: E402
from exposure_audit.scanner.base import ExternalScanner, ScanResult  # noqa: E402
from exposure_audit.scanner.nmap_parser import parse_nmap_xml  # noqa: E402
from exposure_audit.ssh_client import CommandResult  # noqa: E402

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"

FIXTURES = ROOT / "tests" / "fixtures"


def fixture(name: str) -> str:
    """
    Le o conteudo de uma fixture.

    :param name: str
    :return: str
    """
    return (FIXTURES / name).read_text(encoding="utf-8")


def result(stdout: str = "", status: CommandStatus = CommandStatus.OK,
           stderr: str = "") -> dict[str, object]:
    """
    Cria um CommandResult serializado.

    :param stdout: str
    :param status: CommandStatus
    :param stderr: str
    :return: dict[str, object]
    """
    return CommandResult(argv=["fake"], status=status, returncode=0 if status ==
                         CommandStatus.OK else 1, stdout=stdout, stderr=stderr,
                         duration=0.0).to_dict()


def web_raw(**overrides: dict[str, object]) -> dict[str, object]:
    """
    Coleta bruta sintetica do host de referencia ``srv-web-01``.

    :param overrides: dict[str, object]
    :return: dict[str, object]
    """
    missing = result(status=CommandStatus.COMMAND_NOT_FOUND)
    commands: dict[str, object] = {
        "hostname": result("srv-web-01\n"),
        "hostname_fqdn": result("srv-web-01.example.net\n"),
        "os_release": result('PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'),
        "uname": result("Linux srv-web-01 6.1.0 x86_64 GNU/Linux\n"),
        "ip4_addr": result(fixture("ip4_addr.txt")),
        "ip6_addr": result(fixture("ip6_addr.txt")),
        "ip_route": result("default via 203.0.113.1 dev eth0\n10.0.0.0/24 dev eth1\n"),
        "ip6_route": result("default via fe80::ff dev eth0 metric 1024\n"),
        "ip_route_get": result("1.1.1.1 via 203.0.113.1 dev eth0 src 203.0.113.5 uid 0\n"),
        "ip_rule": result("0:\tfrom all lookup local\n32766:\tfrom all lookup main\n"
                          "32767:\tfrom all lookup default\n"),
        "ip_route_all": result(""),
        "xfrm_policy": result(""),
        "ss_listen": result(fixture("ss_lntup.txt")),
        "iptables_version": result("iptables v1.8.9 (nf_tables)\n"),
        "nft_json": result('{"nftables": [{"metainfo": {"json_schema_version": 1}}]}'),
        "iptables_save": result(fixture("iptables_save_v4.txt")),
        "ip6tables_save": result(fixture("ip6tables_save.txt")),
        "iptables_legacy_save": missing,
        "ip6tables_legacy_save": missing,
        "ipset_save": result(fixture("ipset_save.txt")),
        "docker_ps": result("4f1c2a9b8e7d\n9a8b7c6d5e4f\n"),
        "docker_inspect": result(fixture("docker_inspect.json")),
    }
    commands.update(overrides)
    return {"status": "OK", "commands": commands}


class FakeScanner(ExternalScanner):
    """Scanner falso baseado em fixtures XML do nmap."""

    origin = "fake"

    def __init__(self, targeted: dict[str, str], discovery: dict[str, str]) -> None:
        """
        Inicializa com XML por alvo.

        :param targeted: dict[str, str]
        :param discovery: dict[str, str]
        :return: None
        """
        self.targeted = targeted
        self.discovery = discovery
        self.calls: list[tuple[str, str]] = []

    def scan_ports(self, target: str, tcp_ports: list[int], udp_ports: list[int]) -> ScanResult:
        """
        Scan direcionado simulado.

        :param target: str
        :param tcp_ports: list[int]
        :param udp_ports: list[int]
        :return: ScanResult
        """
        self.calls.append(("targeted", target))
        if target not in self.targeted:
            return ScanResult(target=target, kind="targeted", error="sem fixture")
        observations, up = parse_nmap_xml(fixture(self.targeted[target]), target,
                                          {"tcp": tcp_ports, "udp": udp_ports})
        return ScanResult(target=target, kind="targeted", observations=observations, host_up=up)

    def discover_ports(self, target: str) -> ScanResult:
        """
        Scan independente simulado.

        :param target: str
        :return: ScanResult
        """
        self.calls.append(("discovery", target))
        if target not in self.discovery:
            return ScanResult(target=target, kind="discovery", error="sem fixture")
        observations, up = parse_nmap_xml(fixture(self.discovery[target]), target, None)
        return ScanResult(target=target, kind="discovery", observations=observations, host_up=up)

    def identify_services(self, target: str, tcp_ports: list[int]) -> ScanResult:
        """
        Identificacao simulada (nao utilizada).

        :param target: str
        :param tcp_ports: list[int]
        :return: ScanResult
        """
        return ScanResult(target=target, kind="identify", error="nao suportado")

    def path_evidence(self, target: str) -> dict[str, object]:
        """
        Evidencia de caminho simulada.

        :param target: str
        :return: dict[str, object]
        """
        return {"route_get": {}, "warnings": []}
