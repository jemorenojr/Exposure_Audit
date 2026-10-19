# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : rules.py
# Descricao   : Regras deterministicas e ordenadas de classificacao de
#               exposicao por familia IP.
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
Regras de classificacao.

Cada regra possui identificador estavel, condicao explicita e
justificativa. A primeira regra que casa decide. Nao ha pontuacao.
Toda alteracao deve ser refletida em ``docs/classification.md``.
"""

from collections.abc import Callable
from dataclasses import dataclass

from exposure_audit.models import (BindClass, Classification, ExternalEvidence,
                                   ExternalState, Family, FirewallAccess, FirewallVerdict)

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"

NOT_OPEN = (ExternalState.FILTERED, ExternalState.CLOSED)
NO_RESULT = (ExternalState.UNKNOWN, ExternalState.UNREACHABLE)


@dataclass
class FamilyFacts:
    """Evidencias normalizadas de um servico em uma familia IP."""

    family: Family
    bind_class: BindClass | None
    bind_addresses: list[str]
    firewall: FirewallVerdict
    external: ExternalEvidence
    has_ipv6_global: bool = True
    forwarded: bool = False

    @property
    def access(self) -> FirewallAccess:
        """
        Atalho para a restricao de origem.

        :return: FirewallAccess
        """
        return self.firewall.access

    @property
    def state(self) -> ExternalState:
        """
        Atalho para o estado externo.

        :return: ExternalState
        """
        return self.external.state


@dataclass(frozen=True)
class ClassificationRule:
    """Regra deterministica de classificacao."""

    rule_id: str
    description: str
    condition: Callable[[FamilyFacts], bool]
    result: Classification
    reason: Callable[[FamilyFacts], str]
    followup: bool


def _sources(facts: FamilyFacts) -> str:
    """
    Texto das origens autorizadas.

    :param facts: FamilyFacts
    :return: str
    """
    return "; ".join(facts.firewall.sources) or "origens especificas"


def _binds(facts: FamilyFacts) -> str:
    """
    Texto dos enderecos de bind.

    :param facts: FamilyFacts
    :return: str
    """
    return ", ".join(facts.bind_addresses) or "N/A"


def _ext(facts: FamilyFacts) -> str:
    """
    Texto do estado externo.

    :param facts: FamilyFacts
    :return: str
    """
    if not facts.external.scanned:
        return "sem validacao externa"
    return f"teste externo {facts.state.value}"


RULES: tuple[ClassificationRule, ...] = (
    ClassificationRule(
        "R01", "bind somente em loopback",
        lambda f: f.bind_class == BindClass.LOCAL_ONLY and f.state != ExternalState.OPEN,
        Classification.PROTEGIDO,
        lambda f: f"escuta somente em loopback ({_binds(f)})",
        False),
    ClassificationRule(
        "R02", "firewall aceita somente loopback",
        lambda f: f.access == FirewallAccess.LOCAL_ONLY and f.state != ExternalState.OPEN,
        Classification.PROTEGIDO,
        lambda f: f"firewall aceita somente origem local ({_sources(f)})",
        False),
    ClassificationRule(
        "R03", "IPv6 sem endereco global no host",
        lambda f: (f.family == Family.IPV6 and not f.has_ipv6_global and not f.forwarded
                   and f.state != ExternalState.OPEN),
        Classification.PROTEGIDO,
        lambda f: "host sem endereco IPv6 global; socket IPv6 nao roteavel pela Internet",
        False),
    ClassificationRule(
        "R04", "aberto externamente e firewall sem restricao",
        lambda f: f.state == ExternalState.OPEN and f.access == FirewallAccess.ANY,
        Classification.EXPOSTO,
        lambda f: "acesso permitido a qualquer origem e confirmado externamente (OPEN)",
        True),
    ClassificationRule(
        "R05", "aberto externamente com restricao de origem",
        lambda f: f.state == ExternalState.OPEN and f.access == FirewallAccess.RESTRICTED_SOURCE,
        Classification.PARCIAL,
        lambda f: (f"permitido somente para {_sources(f)}; teste externo OPEN "
                   "(scanner autorizado ou caminho nao modelado)"),
        True),
    ClassificationRule(
        "R06", "aberto externamente e firewall indeterminado",
        lambda f: f.state == ExternalState.OPEN and f.access == FirewallAccess.UNKNOWN,
        Classification.EXPOSTO,
        lambda f: ("alcancavel externamente (OPEN) e nenhuma restricao local pode ser "
                   "confirmada"),
        True),
    ClassificationRule(
        "R07", "aberto externamente apesar de firewall restritivo",
        lambda f: f.state == ExternalState.OPEN and f.access in (
            FirewallAccess.BLOCKED, FirewallAccess.PRIVATE_ONLY, FirewallAccess.LOCAL_ONLY),
        Classification.INDETERMINADO,
        lambda f: (f"inconsistencia: teste externo OPEN, mas firewall local indica "
                   f"{f.access.value}; verificar NAT, caminho do scanner ou outro host "
                   "respondendo"),
        True),
    ClassificationRule(
        "R08", "firewall bloqueia e nao ha abertura externa",
        lambda f: f.access == FirewallAccess.BLOCKED,
        Classification.PROTEGIDO,
        lambda f: f"firewall bloqueia origens externas; {_ext(f)}",
        False),
    ClassificationRule(
        "R09", "firewall limita a redes privadas",
        lambda f: f.access == FirewallAccess.PRIVATE_ONLY,
        Classification.PROTEGIDO,
        lambda f: f"firewall permite somente redes privadas ({_sources(f)}); {_ext(f)}",
        False),
    ClassificationRule(
        "R10", "firewall restringe origem a enderecos publicos especificos",
        lambda f: f.access == FirewallAccess.RESTRICTED_SOURCE,
        Classification.PARCIAL,
        lambda f: f"permitido somente para {_sources(f)}; {_ext(f)}",
        True),
    ClassificationRule(
        "R11", "bind privado e teste externo negativo",
        lambda f: (f.bind_class == BindClass.PRIVATE_BIND and f.external.scanned
                   and f.state in NOT_OPEN),
        Classification.PROTEGIDO,
        lambda f: (f"bind privado ({_binds(f)}) e {_ext(f)}; firewall local "
                   f"{f.access.value}: acessivel a partir da rede interna"),
        True),
    ClassificationRule(
        "R12", "sem filtro local, mas bloqueado externamente",
        lambda f: f.access == FirewallAccess.ANY and f.external.scanned and f.state in NOT_OPEN,
        Classification.INDETERMINADO,
        lambda f: (f"firewall local permite qualquer origem, mas {_ext(f)}: filtragem por "
                   "mecanismo externo nao identificado (firewall upstream, security group, NAT)"),
        True),
    ClassificationRule(
        "R13", "sem filtro local e sem validacao externa",
        lambda f: f.access == FirewallAccess.ANY,
        Classification.INDETERMINADO,
        lambda f: ("firewall local permite qualquer origem e nao ha validacao externa "
                   "conclusiva; exposicao potencial"),
        True),
    ClassificationRule(
        "R14", "firewall nao determinado",
        lambda f: f.access == FirewallAccess.UNKNOWN,
        Classification.INDETERMINADO,
        lambda f: f"firewall nao pode ser determinado; {_ext(f)}",
        True),
)

DEFAULT_RULE = ClassificationRule(
    "R99", "evidencias insuficientes", lambda f: True, Classification.INDETERMINADO,
    lambda f: (f"evidencias insuficientes (firewall {f.access.value}, "
               f"externo {f.state.value})"),
    True)


def first_match(facts: FamilyFacts) -> ClassificationRule:
    """
    Retorna a primeira regra cuja condicao e satisfeita.

    :param facts: FamilyFacts
    :return: ClassificationRule
    """
    for rule in RULES:
        if rule.condition(facts):
            return rule
    return DEFAULT_RULE
