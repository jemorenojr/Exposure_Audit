# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : classifier.py
# Descricao   : Classificacao final de exposicao de um servico a partir
#               de evidencias normalizadas (bind, firewall, externo).
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
Classificador.

Interface conceitual da diretriz::

    classify(service, firewall, external_scan, network_context)

Cada familia IP (IPv4/IPv6) e classificada separadamente pelas regras de
``rules.py``; o resultado do servico e a familia mais grave
(EXPOSTO > INDETERMINADO > PARCIAL > PROTEGIDO). Assim, IPv4 protegido e
IPv6 aberto resulta em EXPOSTO.
"""

from exposure_audit.correlator.rules import FamilyFacts, first_match
from exposure_audit.models import (CLASSIFICATION_SEVERITY, BindClass, Classification,
                                   ExternalEvidence, ExternalState, Family,
                                   FamilyAssessment, FirewallAccess, FirewallVerdict,
                                   NetworkContext, ServiceAssessment, ServiceView)

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"

#: Prioridade de bind quando ha varios sockets na mesma familia: o mais
#: amplo representa a superficie potencial.
_BIND_BREADTH: dict[BindClass, int] = {
    BindClass.LOCAL_ONLY: 0,
    BindClass.PRIVATE_BIND: 1,
    BindClass.PUBLIC_BIND: 2,
    BindClass.ALL_IPV4: 3,
    BindClass.ALL_IPV6: 3,
}


def _family_bind(service: ServiceView, family: Family) -> tuple[BindClass | None, list[str]]:
    """
    Bind mais amplo e enderecos de bind do servico na familia.

    :param service: ServiceView
    :param family: Family
    :return: tuple[BindClass | None, list[str]]
    """
    listeners = [item for item in service.listeners if item.family == family]
    if not listeners:
        return None, []
    widest = max(listeners, key=lambda item: _BIND_BREADTH[item.bind_class])
    addresses = sorted({item.address for item in listeners})
    return widest.bind_class, addresses


def classify_family(service: ServiceView, family: Family, firewall: FirewallVerdict,
                    external: ExternalEvidence, context: NetworkContext) -> FamilyAssessment:
    """
    Classifica o servico em uma familia IP.

    :param service: ServiceView
    :param family: Family
    :param firewall: FirewallVerdict
    :param external: ExternalEvidence
    :param context: NetworkContext
    :return: FamilyAssessment
    """
    bind_class, addresses = _family_bind(service, family)
    facts = FamilyFacts(family=family, bind_class=bind_class, bind_addresses=addresses,
                        firewall=firewall, external=external,
                        has_ipv6_global=context.has_ipv6_global,
                        forwarded=service.forwarded)
    rule = first_match(facts)
    return FamilyAssessment(family=family, bind_class=bind_class, bind_addresses=addresses,
                            firewall=firewall, external=external,
                            classification=rule.result, reason=rule.reason(facts),
                            rule_id=rule.rule_id, followup=rule.followup)


def _evidence(assessments: list[FamilyAssessment], context: NetworkContext) -> list[str]:
    """
    Consolida evidencias citadas na justificativa.

    :param assessments: list[FamilyAssessment]
    :param context: NetworkContext
    :return: list[str]
    """
    evidence: list[str] = []
    for item in assessments:
        tag = item.family.value
        evidence.append(f"[{tag}] regra {item.rule_id}: bind={item.bind_class or 'N/A'} "
                        f"firewall={item.firewall.access.value} "
                        f"externo={item.external.state.value}")
        evidence.extend(f"[{tag}] firewall: {line}" for line in item.firewall.evidence)
        evidence.extend(f"[{tag}] nota: {line}" for line in item.firewall.notes)
        evidence.extend(f"[{tag}] externo: {obs.target}:{obs.port}/{obs.protocol} "
                        f"{obs.raw_state or obs.state.value}"
                        for obs in item.external.observations)
        evidence.extend(f"[{tag}] externo: {note}" for note in item.external.notes)
    if context.xfrm_policies_present:
        evidence.append("contexto: politicas XFRM presentes no host")
    return list(dict.fromkeys(evidence))


def classify(service: ServiceView, firewall: dict[Family, FirewallVerdict],
             external_scan: dict[Family, ExternalEvidence],
             network_context: NetworkContext) -> ServiceAssessment:
    """
    Classifica um servico combinando todas as familias IP.

    Familias sem verdict de firewall ou sem evidencia externa recebem
    UNKNOWN (nunca uma suposicao favoravel).

    :param service: ServiceView
    :param firewall: dict[Family, FirewallVerdict]
    :param external_scan: dict[Family, ExternalEvidence]
    :param network_context: NetworkContext
    :return: ServiceAssessment
    """
    assessments: list[FamilyAssessment] = []
    for family in service.families:
        verdict = firewall.get(family) or FirewallVerdict(
            FirewallAccess.UNKNOWN, notes=["firewall nao avaliado"])
        external = external_scan.get(family) or ExternalEvidence(
            ExternalState.UNKNOWN, scanned=False, notes=["sem scan externo"])
        assessments.append(classify_family(service, family, verdict, external,
                                           network_context))

    if not assessments:
        return ServiceAssessment(
            protocol=service.protocol, port=service.port,
            service=service.service_name or "?", process=service.process,
            local_active=service.local_active, families=[],
            classification=Classification.INDETERMINADO,
            reason="nenhuma familia IP avaliavel", followup=True, kind="local")

    ordered = sorted(assessments, key=lambda item: CLASSIFICATION_SEVERITY[item.classification],
                     reverse=True)
    worst = ordered[0]
    if len(ordered) == 1 or all(item.reason == worst.reason for item in ordered):
        reason = worst.reason
    else:
        reason = " | ".join(f"{item.family.value}: {item.classification.value} - {item.reason}"
                            for item in ordered)
    external_ports = sorted({obs.port for item in assessments
                             for obs in item.external.observations})
    return ServiceAssessment(
        protocol=service.protocol, port=service.port,
        service=service.service_name or service.process or "?",
        process=service.process, local_active=service.local_active,
        families=assessments, classification=worst.classification, reason=reason,
        followup=any(item.followup for item in assessments),
        evidence=_evidence(assessments, network_context),
        external_ports=external_ports,
        kind="forwarded" if service.forwarded else "local",
    )
