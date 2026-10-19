# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : test_firewall.py
# Descricao   : Testes dos parsers iptables/nftables/ipset, do loader e
#               do avaliador de fluxo de regras.
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
# CHANGELOG   : 2026-10-19: teste de expressao xt nula no nft -j.
#
############################################################################

"""
Testes de analise de firewall.
"""

import json
import unittest

from helpers import fixture, result, web_raw

from exposure_audit.collector.firewall.evaluator import Probe, evaluate
from exposure_audit.collector.firewall.iptables import (parse_iptables_save, parse_ipset_save,
                                                       parse_rule)
from exposure_audit.collector.firewall.loader import build_ruleset, extract_nat
from exposure_audit.collector.firewall.model import DNAT, REDIRECT, Ruleset
from exposure_audit.collector.firewall.nftables import parse_nft_json
from exposure_audit.models import CommandStatus, Family, FirewallAccess

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.2"

V4_DEST = ["203.0.113.5", "10.0.0.5", "172.17.0.1"]
IFACES = ["eth0", "eth1"]


def probe(port: int, protocol: str = "tcp", family: Family = Family.IPV4,
          dest: list[str] | None = None, hook: str = "input", dnat: bool = False) -> Probe:
    """
    Cria uma sonda padrao.

    :param port: int
    :param protocol: str
    :param family: Family
    :param dest: list[str] | None
    :param hook: str
    :param dnat: bool
    :return: Probe
    """
    return Probe(family=family, protocol=protocol, port=port,
                 dest_addresses=dest if dest is not None else V4_DEST,
                 ingress_ifaces=IFACES, hook=hook, dnat=dnat)


def ruleset_from_save(v4: str, v6: str = "", ipsets: str = "") -> Ruleset:
    """
    Monta Ruleset a partir de saidas iptables-save.

    :param v4: str
    :param v6: str
    :param ipsets: str
    :return: Ruleset
    """
    rs = Ruleset(tables=parse_iptables_save(v4, "ip") + parse_iptables_save(v6, "ip6"),
                 ipsets=parse_ipset_save(ipsets) if ipsets else {})
    rs.family_status = {"ipv4": "OK", "ipv6": "OK"}
    return rs


class IptablesParserTest(unittest.TestCase):
    """Parser iptables-save."""

    def test_tables_and_policies(self) -> None:
        """
        Tabelas, policies e chains de usuario.

        :return: None
        """
        tables = {t.name: t for t in parse_iptables_save(fixture("iptables_save_v4.txt"), "ip")}
        self.assertEqual(set(tables), {"nat", "filter"})
        flt = tables["filter"]
        self.assertEqual(flt.chains["INPUT"].policy, "DROP")
        self.assertEqual(flt.chains["INPUT"].hook, "input")
        self.assertIsNone(flt.chains["f2b-sshd"].hook)

    def test_rule_fields(self) -> None:
        """
        Negacao, multiport, set e alvo DNAT.

        :return: None
        """
        rule = parse_rule("DOCKER", 1, "-A DOCKER ! -i docker0 -p tcp -m tcp --dport 8080 "
                                       "-j DNAT --to-destination 172.17.0.2:80")
        self.assertTrue(rule.in_iface.negated)
        self.assertEqual(rule.dports, [(8080, 8080)])
        self.assertEqual((rule.verdict, rule.nat_to_address, rule.nat_to_port),
                         (DNAT, "172.17.0.2", 80))
        rule = parse_rule("INPUT", 1, "-A INPUT -p tcp -m multiport --dports 80,8000:8100 "
                                      "-m set --match-set admins src -j ACCEPT")
        self.assertEqual(rule.dports, [(80, 80), (8000, 8100)])
        self.assertEqual(rule.src.set_name, "admins")

    def test_unknown_module(self) -> None:
        """
        Modulo nao suportado vira condicao desconhecida.

        :return: None
        """
        rule = parse_rule("INPUT", 1, "-A INPUT -p tcp -m geoip --src-cc BR --dport 22 -j ACCEPT")
        self.assertTrue(rule.unknown)

    def test_ipset(self) -> None:
        """
        Conteudo de ipset.

        :return: None
        """
        sets = parse_ipset_save(fixture("ipset_save.txt"))
        self.assertEqual(sets["monitoring"], ["10.50.0.0/16", "203.0.113.50"])


class IptablesEvaluationTest(unittest.TestCase):
    """Avaliacao do fluxo efetivo (iptables)."""

    def setUp(self) -> None:
        """
        Ruleset de referencia.

        :return: None
        """
        self.rs = ruleset_from_save(fixture("iptables_save_v4.txt"),
                                    fixture("ip6tables_save.txt"), fixture("ipset_save.txt"))

    def test_ssh_restricted_with_fail2ban(self) -> None:
        """
        SSH restrito a dois IPs; bloqueio fail2ban registrado.

        :return: None
        """
        verdict = evaluate(self.rs, probe(22))
        self.assertEqual(verdict.access, FirewallAccess.RESTRICTED_SOURCE)
        self.assertEqual(verdict.sources, ["203.0.113.10/32", "198.51.100.20/32"])
        self.assertTrue(any("192.0.2.66" in note for note in verdict.notes))

    def test_any_private_blocked(self) -> None:
        """
        443 ANY; 5432 somente rede privada; 3306 bloqueado pela policy.

        :return: None
        """
        self.assertEqual(evaluate(self.rs, probe(443)).access, FirewallAccess.ANY)
        self.assertEqual(evaluate(self.rs, probe(5432)).access, FirewallAccess.PRIVATE_ONLY)
        blocked = evaluate(self.rs, probe(3306))
        self.assertEqual(blocked.access, FirewallAccess.BLOCKED)
        self.assertIn("policy DROP", blocked.evidence[-1])

    def test_ipset_source(self) -> None:
        """
        Origem via ipset com conteudo publico = RESTRICTED_SOURCE.

        :return: None
        """
        verdict = evaluate(self.rs, probe(9100))
        self.assertEqual(verdict.access, FirewallAccess.RESTRICTED_SOURCE)
        self.assertIn("monitoring", verdict.sources[0])
        self.assertIn("203.0.113.50", verdict.sources[0])

    def test_ipset_without_content(self) -> None:
        """
        ipset nao coletado continua sendo restricao, com nome registrado.

        :return: None
        """
        self.rs.ipsets = {}
        verdict = evaluate(self.rs, probe(9100))
        self.assertEqual(verdict.access, FirewallAccess.RESTRICTED_SOURCE)
        self.assertIn("conteudo nao coletado", verdict.sources[0])

    def test_ipv6_open(self) -> None:
        """
        ip6tables com policy ACCEPT = ANY.

        :return: None
        """
        verdict = evaluate(self.rs, probe(22, family=Family.IPV6, dest=["2001:db8:10::5"]))
        self.assertEqual(verdict.access, FirewallAccess.ANY)

    def test_docker_forward_path(self) -> None:
        """
        Porta publicada avaliada no hook FORWARD (DOCKER chain).

        :return: None
        """
        verdict = evaluate(self.rs, probe(80, dest=["172.17.0.2"], hook="forward", dnat=True))
        self.assertEqual(verdict.access, FirewallAccess.ANY)
        other = evaluate(self.rs, probe(5000, dest=["172.17.0.9"], hook="forward", dnat=True))
        self.assertEqual(other.access, FirewallAccess.BLOCKED)

    def test_docker_user_restriction(self) -> None:
        """
        Restricao em DOCKER-USER limita a origem do container publicado.

        :return: None
        """
        text = fixture("iptables_save_v4.txt").replace(
            "-A DOCKER-USER -j RETURN",
            "-A DOCKER-USER -s 203.0.113.10/32 -j RETURN\n-A DOCKER-USER -j DROP")
        rs = ruleset_from_save(text)
        verdict = evaluate(rs, probe(80, dest=["172.17.0.2"], hook="forward", dnat=True))
        self.assertEqual(verdict.access, FirewallAccess.RESTRICTED_SOURCE)

    def test_unknown_condition_is_unknown(self) -> None:
        """
        Regra nao interpretavel antes da decisao gera UNKNOWN.

        :return: None
        """
        text = fixture("iptables_save_v4.txt").replace(
            "-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT",
            "-A INPUT -p tcp -m tcp --dport 443 -m geoip --src-cc BR -j ACCEPT")
        verdict = evaluate(ruleset_from_save(text), probe(443))
        self.assertEqual(verdict.access, FirewallAccess.UNKNOWN)

    def test_rate_limit_does_not_block(self) -> None:
        """
        DROP com limite de taxa nao encerra a avaliacao.

        :return: None
        """
        text = ("*filter\n:INPUT DROP [0:0]\n"
                "-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set\n"
                "-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update "
                "--seconds 60 --hitcount 4 -j DROP\n"
                "-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n")
        verdict = evaluate(ruleset_from_save(text), probe(22))
        self.assertEqual(verdict.access, FirewallAccess.ANY)
        self.assertTrue(any("limitacao de taxa" in note for note in verdict.notes))

    def test_negated_private_drop(self) -> None:
        """
        ``! -s 10.0.0.0/8 -j DROP`` bloqueia toda origem da Internet.

        :return: None
        """
        text = ("*filter\n:INPUT ACCEPT [0:0]\n"
                "-A INPUT ! -s 10.0.0.0/8 -p tcp --dport 3306 -j DROP\nCOMMIT\n")
        self.assertEqual(evaluate(ruleset_from_save(text), probe(3306)).access,
                         FirewallAccess.BLOCKED)

    def test_interface_partial_accept(self) -> None:
        """
        ACCEPT limitado a uma interface externa nao restringe origem.

        :return: None
        """
        text = ("*filter\n:INPUT DROP [0:0]\n"
                "-A INPUT -i eth1 -p tcp --dport 2049 -j ACCEPT\nCOMMIT\n")
        verdict = evaluate(ruleset_from_save(text), probe(2049))
        self.assertEqual(verdict.access, FirewallAccess.ANY)
        loopback_only = ("*filter\n:INPUT DROP [0:0]\n"
                         "-A INPUT -i lo -p tcp --dport 2049 -j ACCEPT\nCOMMIT\n")
        self.assertEqual(evaluate(ruleset_from_save(loopback_only), probe(2049)).access,
                         FirewallAccess.BLOCKED)

    def test_not_collected_is_unknown(self) -> None:
        """
        Familia nao coletada resulta em UNKNOWN.

        :return: None
        """
        self.rs.family_status["ipv4"] = "PRIVILEGE_INSUFFICIENT"
        self.assertEqual(evaluate(self.rs, probe(443)).access, FirewallAccess.UNKNOWN)


class NatExtractionTest(unittest.TestCase):
    """Extracao de DNAT/REDIRECT."""

    def test_mappings(self) -> None:
        """
        DNAT Docker, DNAT restrito a 127.0.0.1 e REDIRECT 8443->443.

        :return: None
        """
        mappings = extract_nat(ruleset_from_save(fixture("iptables_save_v4.txt")))
        by_port = {m.external_ports[0]: m for m in mappings}
        self.assertEqual(by_port[8080].to_address, "172.17.0.2")
        self.assertEqual(by_port[8080].to_port, 80)
        self.assertEqual(by_port[9000].dest_networks, ["127.0.0.1/32"])
        self.assertIsNone(by_port[8443].to_address)
        self.assertEqual(by_port[8443].to_port, 443)
        self.assertIn(REDIRECT, [r.verdict for t in ruleset_from_save(
            fixture("iptables_save_v4.txt")).tables for c in t.chains.values() for r in c.rules])


class NftablesTest(unittest.TestCase):
    """Parser e avaliacao nftables (estilo firewalld)."""

    def test_xt_null(self) -> None:
        """
        ``"xt": null`` (extensao iptables-nft sem traducao JSON) vira
        condicao desconhecida, sem excecao: a regra nao pode ser tratada
        como liberacao certa.

        :return: None
        """
        dport22 = {"match": {"op": "==", "right": 22,
                             "left": {"payload": {"protocol": "tcp", "field": "dport"}}}}
        output = json.dumps({"nftables": [
            {"table": {"family": "ip", "name": "filter"}},
            {"chain": {"family": "ip", "table": "filter", "name": "INPUT", "type": "filter",
                       "hook": "input", "prio": 0, "policy": "drop"}},
            {"rule": {"family": "ip", "table": "filter", "chain": "INPUT", "handle": 4,
                      "expr": [{"xt": None}, dport22, {"accept": None}]}},
        ]})
        rs = Ruleset(tables=parse_nft_json(output))
        rs.family_status = {"ipv4": "OK", "ipv6": "OK"}
        self.assertIn("extensao xt", rs.tables[0].chains["INPUT"].rules[0].unknown)
        self.assertEqual(evaluate(rs, probe(22)).access, FirewallAccess.UNKNOWN)
        self.assertEqual(evaluate(rs, probe(80)).access, FirewallAccess.BLOCKED)

    def setUp(self) -> None:
        """
        Ruleset nftables puro.

        :return: None
        """
        self.rs = Ruleset(tables=parse_nft_json(fixture("nft_firewalld.json")))
        self.rs.family_status = {"ipv4": "OK", "ipv6": "OK"}

    def test_parse(self) -> None:
        """
        Tabelas, base chain e set.

        :return: None
        """
        tables = {t.label(): t for t in self.rs.tables}
        fw = tables["nftables:inet/firewalld"]
        self.assertEqual(fw.chains["filter_INPUT"].priority, 10)
        self.assertEqual(fw.sets["admins"], ["203.0.113.0/24", "198.51.100.7"])

    def test_evaluation(self) -> None:
        """
        vmap de ct state, goto, set e reject final.

        :return: None
        """
        # A tabela ip filter (iptables-nft) com xt tambem e avaliada aqui.
        self.rs.tables = [t for t in self.rs.tables if t.family == "inet"]
        self.assertEqual(evaluate(self.rs, probe(22)).access, FirewallAccess.ANY)
        self.assertEqual(evaluate(self.rs, probe(22, family=Family.IPV6,
                                                 dest=["2001:db8:10::5"])).access,
                         FirewallAccess.ANY)
        admins = evaluate(self.rs, probe(8443))
        self.assertEqual(admins.access, FirewallAccess.RESTRICTED_SOURCE)
        self.assertIn("admins", admins.sources[0])
        self.assertEqual(evaluate(self.rs, probe(80)).access, FirewallAccess.BLOCKED)
        self.assertEqual(evaluate(self.rs, probe(3389)).access, FirewallAccess.UNKNOWN)
        limited = evaluate(self.rs, probe(60500))
        self.assertEqual(limited.access, FirewallAccess.ANY)

    def test_multiple_base_chains_intersection(self) -> None:
        """
        Duas base chains no hook input: prevalece a mais restritiva.

        :return: None
        """
        self.rs.tables = [t for t in self.rs.tables if t.family == "inet"]
        extra = parse_iptables_save("*filter\n:INPUT ACCEPT [0:0]\n"
                                    "-A INPUT -p tcp --dport 22 -j DROP\nCOMMIT\n", "ip")
        self.rs.tables.extend(extra)
        self.assertEqual(evaluate(self.rs, probe(22)).access, FirewallAccess.BLOCKED)

    def test_loader_skips_iptables_nft_tables(self) -> None:
        """
        Com backend nf_tables, tabelas ip/filter do nft nao sao duplicadas.

        :return: None
        """
        raw = web_raw(nft_json=result(fixture("nft_firewalld.json")))
        rs = build_ruleset(raw)
        labels = [t.label() for t in rs.tables]
        self.assertIn("nftables:inet/firewalld", labels)
        self.assertNotIn("nftables:ip/filter", labels)
        self.assertIn("iptables-nft:ip/filter", labels)
        self.assertEqual(rs.family_status, {"ipv4": "OK", "ipv6": "OK"})

    def test_loader_privilege(self) -> None:
        """
        Falta de privilegio no iptables-save torna a familia nao avaliavel.

        :return: None
        """
        raw = web_raw(iptables_save=result(status=CommandStatus.PRIVILEGE_INSUFFICIENT))
        rs = build_ruleset(raw)
        self.assertEqual(rs.family_status["ipv4"], "PRIVILEGE_INSUFFICIENT")


if __name__ == "__main__":
    unittest.main()
