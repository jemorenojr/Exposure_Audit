# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : test_classifier.py
# Descricao   : Testes do correlator: casos minimos obrigatorios (secao 36
#               da diretriz) e regras adicionais.
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
Testes do classificador. Usam somente modelos normalizados, provando que
o correlator e independente de collector e scanner.
"""

import unittest

import helpers  # noqa: F401  (ajusta sys.path)

from exposure_audit.correlator.classifier import classify
from exposure_audit.models import (Classification, ExternalEvidence, ExternalState, Family,
                                   FirewallAccess, FirewallVerdict, Listener, NetworkContext,
                                   PortObservation, ServiceView)
from exposure_audit.netutils import classify_bind

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"

CONTEXT = NetworkContext(hostname="srv01", has_ipv6_global=True, external_scan_available=True)


def service(port: int, *binds: str) -> ServiceView:
    """
    Cria um servico TCP com os binds informados.

    :param port: int
    :param binds: str
    :return: ServiceView
    """
    listeners = []
    for bind in binds:
        family = Family.IPV6 if ":" in bind else Family.IPV4
        listeners.append(Listener("tcp", family, bind, port, classify_bind(bind, family)))
    return ServiceView(protocol="tcp", port=port, listeners=listeners, process="proc")


def fw(access: FirewallAccess, *sources: str) -> FirewallVerdict:
    """
    Cria um verdict de firewall.

    :param access: FirewallAccess
    :param sources: str
    :return: FirewallVerdict
    """
    return FirewallVerdict(access, sources=list(sources))


def ext(state: ExternalState, port: int = 0, scanned: bool = True) -> ExternalEvidence:
    """
    Cria evidencia externa.

    :param state: ExternalState
    :param port: int
    :param scanned: bool
    :return: ExternalEvidence
    """
    obs = [PortObservation("203.0.113.5", Family.IPV4, "tcp", port, state)] if scanned else []
    return ExternalEvidence(state, scanned=scanned, observations=obs)


NO_SCAN = ExternalEvidence(ExternalState.UNKNOWN, scanned=False)


class MandatoryCasesTest(unittest.TestCase):
    """Casos minimos obrigatorios da diretriz."""

    def test_case1_loopback(self) -> None:
        """
        127.0.0.1:5432 -> PROTEGIDO.

        :return: None
        """
        result = classify(service(5432, "127.0.0.1"),
                          {Family.IPV4: fw(FirewallAccess.UNKNOWN)},
                          {Family.IPV4: NO_SCAN}, CONTEXT)
        self.assertEqual(result.classification, Classification.PROTEGIDO)
        self.assertIn("loopback", result.reason)

    def test_case2_exposed(self) -> None:
        """
        0.0.0.0:443 + ANY + OPEN -> EXPOSTO.

        :return: None
        """
        result = classify(service(443, "0.0.0.0"), {Family.IPV4: fw(FirewallAccess.ANY)},
                          {Family.IPV4: ext(ExternalState.OPEN, 443)}, CONTEXT)
        self.assertEqual(result.classification, Classification.EXPOSTO)
        self.assertTrue(result.followup)

    def test_case3_partial(self) -> None:
        """
        0.0.0.0:22 + origem 203.0.113.10/32 + OPEN -> PARCIAL.

        :return: None
        """
        result = classify(service(22, "0.0.0.0"),
                          {Family.IPV4: fw(FirewallAccess.RESTRICTED_SOURCE, "203.0.113.10/32")},
                          {Family.IPV4: ext(ExternalState.OPEN, 22)}, CONTEXT)
        self.assertEqual(result.classification, Classification.PARCIAL)
        self.assertIn("203.0.113.10/32", result.reason)

    def test_case4_private_drop(self) -> None:
        """
        10.0.0.5:5432 + DROP + FILTERED -> PROTEGIDO.

        :return: None
        """
        result = classify(service(5432, "10.0.0.5"), {Family.IPV4: fw(FirewallAccess.BLOCKED)},
                          {Family.IPV4: ext(ExternalState.FILTERED, 5432)}, CONTEXT)
        self.assertEqual(result.classification, Classification.PROTEGIDO)

    def test_case5_ipv6_open(self) -> None:
        """
        IPv4 protegido e IPv6 aberto -> EXPOSTO.

        :return: None
        """
        result = classify(service(22, "0.0.0.0", "::"),
                          {Family.IPV4: fw(FirewallAccess.BLOCKED),
                           Family.IPV6: fw(FirewallAccess.ANY)},
                          {Family.IPV4: ext(ExternalState.FILTERED, 22),
                           Family.IPV6: ext(ExternalState.OPEN, 22)}, CONTEXT)
        self.assertEqual(result.classification, Classification.EXPOSTO)
        v4 = [f for f in result.families if f.family == Family.IPV4][0]
        self.assertEqual(v4.classification, Classification.PROTEGIDO)
        self.assertIn("ipv6", result.reason)

    def test_case7_firewall_unknown(self) -> None:
        """
        Firewall nao coletado e sem evidencia externa -> INDETERMINADO.

        :return: None
        """
        result = classify(service(8080, "0.0.0.0"), {Family.IPV4: fw(FirewallAccess.UNKNOWN)},
                          {Family.IPV4: NO_SCAN}, CONTEXT)
        self.assertEqual(result.classification, Classification.INDETERMINADO)
        filtered = classify(service(8080, "0.0.0.0"), {Family.IPV4: fw(FirewallAccess.UNKNOWN)},
                            {Family.IPV4: ext(ExternalState.FILTERED, 8080)}, CONTEXT)
        self.assertEqual(filtered.classification, Classification.INDETERMINADO)


class AdditionalRulesTest(unittest.TestCase):
    """Regras complementares."""

    def test_filtered_is_not_protected_without_evidence(self) -> None:
        """
        FILTERED com firewall local ANY -> INDETERMINADO (filtro upstream).

        :return: None
        """
        result = classify(service(3306, "0.0.0.0"), {Family.IPV4: fw(FirewallAccess.ANY)},
                          {Family.IPV4: ext(ExternalState.FILTERED, 3306)}, CONTEXT)
        self.assertEqual(result.classification, Classification.INDETERMINADO)
        self.assertIn("upstream", result.reason)

    def test_open_with_unknown_firewall(self) -> None:
        """
        OPEN e firewall indeterminado -> EXPOSTO.

        :return: None
        """
        result = classify(service(21, "0.0.0.0"), {Family.IPV4: fw(FirewallAccess.UNKNOWN)},
                          {Family.IPV4: ext(ExternalState.OPEN, 21)}, CONTEXT)
        self.assertEqual(result.classification, Classification.EXPOSTO)

    def test_inconsistency(self) -> None:
        """
        OPEN apesar de BLOCKED -> INDETERMINADO com inconsistencia.

        :return: None
        """
        result = classify(service(25, "0.0.0.0"), {Family.IPV4: fw(FirewallAccess.BLOCKED)},
                          {Family.IPV4: ext(ExternalState.OPEN, 25)}, CONTEXT)
        self.assertEqual(result.classification, Classification.INDETERMINADO)
        self.assertIn("inconsistencia", result.reason)

    def test_without_scan(self) -> None:
        """
        Sem scan: BLOCKED -> PROTEGIDO; ANY -> INDETERMINADO.

        :return: None
        """
        blocked = classify(service(25, "0.0.0.0"), {Family.IPV4: fw(FirewallAccess.BLOCKED)},
                           {Family.IPV4: NO_SCAN}, CONTEXT)
        self.assertEqual(blocked.classification, Classification.PROTEGIDO)
        anyone = classify(service(25, "0.0.0.0"), {Family.IPV4: fw(FirewallAccess.ANY)},
                          {Family.IPV4: NO_SCAN}, CONTEXT)
        self.assertEqual(anyone.classification, Classification.INDETERMINADO)

    def test_ipv6_without_global_address(self) -> None:
        """
        Socket IPv6 em host sem IPv6 global -> PROTEGIDO nessa familia.

        :return: None
        """
        context = NetworkContext(hostname="srv", has_ipv6_global=False,
                                 external_scan_available=True)
        result = classify(service(22, "::"), {Family.IPV6: fw(FirewallAccess.ANY)},
                          {Family.IPV6: NO_SCAN}, context)
        self.assertEqual(result.classification, Classification.PROTEGIDO)

    def test_missing_family_data_is_unknown(self) -> None:
        """
        Familia sem dados de firewall/externo nunca vira conclusao favoravel.

        :return: None
        """
        result = classify(service(22, "0.0.0.0"), {}, {}, CONTEXT)
        self.assertEqual(result.classification, Classification.INDETERMINADO)


if __name__ == "__main__":
    unittest.main()
