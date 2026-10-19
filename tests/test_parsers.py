# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : test_parsers.py
# Descricao   : Testes dos parsers de ss, ip addr, rotas, docker e nmap.
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
Testes de parsers do collector e do scanner.
"""

import unittest

from helpers import fixture

from exposure_audit.collector.docker import parse_docker_inspect
from exposure_audit.collector.host import sanitize_xfrm
from exposure_audit.collector.network import (has_xfrm_policies, ingress_interfaces,
                                              parse_ip_addr, parse_ip_rules, parse_route_get)
from exposure_audit.collector.sockets import parse_ss
from exposure_audit.models import AddressScope, BindClass, ExternalState, Family
from exposure_audit.scanner.nmap_parser import parse_nmap_xml

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"


class SocketParserTest(unittest.TestCase):
    """Parser de ``ss -lntup``."""

    def setUp(self) -> None:
        """
        Carrega a fixture.

        :return: None
        """
        self.listeners = parse_ss(fixture("ss_lntup.txt"))

    def find(self, port: int, family: Family) -> list:
        """
        Filtra listeners por porta e familia.

        :param port: int
        :param family: Family
        :return: list
        """
        return [item for item in self.listeners if item.port == port and item.family == family]

    def test_bind_classes(self) -> None:
        """
        Classificacao de bind conforme secao 8.

        :return: None
        """
        self.assertEqual(self.find(22, Family.IPV4)[0].bind_class, BindClass.ALL_IPV4)
        self.assertEqual(self.find(22, Family.IPV6)[0].bind_class, BindClass.ALL_IPV6)
        self.assertEqual(self.find(5432, Family.IPV4)[0].bind_class, BindClass.PRIVATE_BIND)
        self.assertEqual(self.find(6379, Family.IPV4)[0].bind_class, BindClass.LOCAL_ONLY)

    def test_process_and_pid(self) -> None:
        """
        Processo e PID extraidos; listener sem processo aceito.

        :return: None
        """
        ssh = self.find(22, Family.IPV4)[0]
        self.assertEqual((ssh.process, ssh.pid), ("sshd", 900))
        self.assertIsNone(self.find(51820, Family.IPV4)[0].process)

    def test_dual_stack_star(self) -> None:
        """
        ``*:9100`` gera listener IPv4 e IPv6.

        :return: None
        """
        self.assertTrue(self.find(9100, Family.IPV4)[0].dual_stack)
        self.assertTrue(self.find(9100, Family.IPV6)[0].dual_stack)

    def test_interface_zone_and_mapped(self) -> None:
        """
        ``127.0.0.53%lo`` e ``[::ffff:127.0.0.1]`` sao loopback IPv4.

        :return: None
        """
        dns = self.find(53, Family.IPV4)[0]
        self.assertEqual(dns.bound_interface, "lo")
        self.assertEqual(dns.bind_class, BindClass.LOCAL_ONLY)
        mapped = self.find(8081, Family.IPV4)[0]
        self.assertEqual(mapped.address, "127.0.0.1")
        self.assertEqual(mapped.bind_class, BindClass.LOCAL_ONLY)

    def test_dedupe_reuseport(self) -> None:
        """
        Sockets repetidos (SO_REUSEPORT) sao agrupados.

        :return: None
        """
        self.assertEqual(len(self.find(443, Family.IPV4)), 1)


class NetworkParserTest(unittest.TestCase):
    """Parsers de endereco e roteamento."""

    def test_address_scopes(self) -> None:
        """
        Classificacao loopback/private/public/link-local/ipv6-global.

        :return: None
        """
        addrs = parse_ip_addr(fixture("ip4_addr.txt")) + parse_ip_addr(fixture("ip6_addr.txt"))
        scopes = {addr.address: addr.scope for addr in addrs}
        self.assertEqual(scopes["127.0.0.1"], AddressScope.LOOPBACK)
        self.assertEqual(scopes["203.0.113.5"], AddressScope.PUBLIC)
        self.assertEqual(scopes["10.0.0.5"], AddressScope.PRIVATE)
        self.assertEqual(scopes["fe80::1"], AddressScope.LINK_LOCAL)
        self.assertEqual(scopes["2001:db8:10::5"], AddressScope.IPV6_GLOBAL)
        temporary = [a for a in addrs if a.address == "2001:db8:10::abcd"][0]
        self.assertIn("temporary", temporary.flags)
        self.assertEqual(ingress_interfaces(addrs), ["eth0", "eth1"])

    def test_route_get_and_rules(self) -> None:
        """
        ``ip route get`` e regras de policy routing nao padrao.

        :return: None
        """
        route = parse_route_get("1.1.1.1 via 203.0.113.1 dev eth0 src 203.0.113.5 uid 0")
        self.assertEqual(route["gateway"], "203.0.113.1")
        self.assertEqual(route["source"], "203.0.113.5")
        rules = parse_ip_rules("0:\tfrom all lookup local\n100:\tfrom all fwmark 0x1 lookup vpn\n"
                               "32766:\tfrom all lookup main\n")
        self.assertEqual(rules, ["100:\tfrom all fwmark 0x1 lookup vpn"])

    def test_xfrm(self) -> None:
        """
        Politicas XFRM e remocao de chaves.

        :return: None
        """
        policy = "src 10.1.0.0/16 dst 10.2.0.0/16\n\tdir out priority 375423\n"
        self.assertTrue(has_xfrm_policies(policy))
        self.assertFalse(has_xfrm_policies("src ::/0 dst ::/0\n\tsocket in priority 0\n"))
        state = "\tauth-trunc hmac(sha256) 0x0123456789abcdef0123456789abcdef 128\n"
        self.assertNotIn("0123456789abcdef", sanitize_xfrm(state))


class DockerParserTest(unittest.TestCase):
    """Parser de ``docker inspect``."""

    def test_publications(self) -> None:
        """
        Portas publicadas, HostIp e IP do container.

        :return: None
        """
        pubs = parse_docker_inspect(fixture("docker_inspect.json"))
        self.assertEqual(len(pubs), 2)
        web = [p for p in pubs if p.container == "webapp"][0]
        self.assertEqual((web.host_ip, web.host_port, web.container_port), ("0.0.0.0", 8080, 80))
        self.assertEqual(web.container_ips, ["172.17.0.2"])
        admin = [p for p in pubs if p.container == "admin-ui"][0]
        self.assertEqual(admin.host_ip, "127.0.0.1")


class NmapParserTest(unittest.TestCase):
    """Parser XML do nmap."""

    def test_targeted_with_extraports(self) -> None:
        """
        Estados normalizados e portas agrupadas em extraports.

        :return: None
        """
        obs, up = parse_nmap_xml(fixture("nmap_targeted_v4.xml"), "203.0.113.5",
                                 {"tcp": [22, 443, 5432, 9100], "udp": [51820]})
        states = {(o.protocol, o.port): o.state for o in obs}
        self.assertTrue(up)
        self.assertEqual(states[("tcp", 22)], ExternalState.OPEN)
        self.assertEqual(states[("tcp", 5432)], ExternalState.FILTERED)
        self.assertEqual(states[("tcp", 9100)], ExternalState.FILTERED)
        self.assertEqual(states[("udp", 51820)], ExternalState.UNKNOWN)

    def test_ipv6_target(self) -> None:
        """
        Alvo IPv6 recebe familia IPv6.

        :return: None
        """
        obs, _ = parse_nmap_xml(fixture("nmap_targeted_v6.xml"), "2001:db8:10::5", None)
        self.assertTrue(all(o.family == Family.IPV6 for o in obs))

    def test_host_down(self) -> None:
        """
        Host down vira UNREACHABLE.

        :return: None
        """
        obs, up = parse_nmap_xml(fixture("nmap_host_down.xml"), "192.0.2.99", {"tcp": [22]})
        self.assertFalse(up)
        self.assertEqual(obs[0].state, ExternalState.UNREACHABLE)


if __name__ == "__main__":
    unittest.main()
