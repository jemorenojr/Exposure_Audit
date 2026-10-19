# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : text.py
# Descricao   : Relatorio textual por host e resumo executivo.
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
# CHANGELOG   : 2026-10-19: resumo agrupado por host e familia IP, com
#               classificacao e analise por familia.
#
############################################################################

"""
Relatorios textuais (secoes 5, 21 e 22 da diretriz).
"""

from exposure_audit.models import (Classification, ExternalState, Family, FirewallAccess,
                                   ServiceAssessment)
from exposure_audit.netutils import family_of
from exposure_audit.pipeline import HostReport

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.2"

_EXTERNAL_PREFIX = "externo: "

_FIREWALL_TEXT: dict[FirewallAccess, str] = {
    FirewallAccess.ANY: "ANY",
    FirewallAccess.RESTRICTED_SOURCE: "RESTRITO",
    FirewallAccess.PRIVATE_ONLY: "SOMENTE REDES PRIVADAS",
    FirewallAccess.LOCAL_ONLY: "SOMENTE LOCAL",
    FirewallAccess.BLOCKED: "BLOQUEADO PARA INTERNET",
    FirewallAccess.UNKNOWN: "INDETERMINADO",
}


def _join(values: list[str]) -> str:
    """
    Junta valores distintos preservando a ordem.

    :param values: list[str]
    :return: str
    """
    return " / ".join(dict.fromkeys(values)) or "-"


def external_status(service: ServiceAssessment) -> str:
    """
    Estado externo resumido do servico (por familia quando divergente).

    :param service: ServiceAssessment
    :return: str
    """
    if service.kind == "external-only":
        return ExternalState.OPEN.value
    states = [(fam.family.value, fam.external.state.value) for fam in service.families]
    if len({state for _, state in states}) <= 1:
        return states[0][1] if states else ExternalState.UNKNOWN.value
    return ";".join(f"{family}={state}" for family, state in states)


def bind_text(service: ServiceAssessment) -> str:
    """
    Enderecos de bind do servico.

    :param service: ServiceAssessment
    :return: str
    """
    binds = [addr for fam in service.families for addr in fam.bind_addresses]
    if not binds and service.kind == "forwarded":
        return "N/A (DNAT)"
    return _join(binds) if binds else "N/A"


def render_service(service: ServiceAssessment, verbose: bool = False) -> list[str]:
    """
    Bloco textual de um servico.

    :param service: ServiceAssessment
    :param verbose: bool
    :return: list[str]
    """
    show_process = service.process and service.process != service.service
    lines = [f"{service.port}/{service.protocol} {service.service}"
             + (f" ({service.process})" if show_process else "")]
    if service.kind == "external-only":
        lines.append("LOCAL:          SEM LISTENER LOCAL")
    else:
        lines.append(f"LOCAL:          {'ATIVO' if service.local_active else 'INATIVO (DNAT)'}")
    lines.append(f"BIND:           {bind_text(service)}")
    firewall = _join([_FIREWALL_TEXT[fam.firewall.access] for fam in service.families])
    lines.append(f"FIREWALL:       {firewall}")
    lines.append(f"EXTERNO:        {external_status(service)}")
    lines.append(f"CLASSIFICACAO:  {service.classification.value}")
    lines.append(f"MOTIVO:         {service.reason}")
    if service.followup:
        lines.append("ANALISE POSTERIOR: sim")
    if verbose:
        lines.extend(f"    - {item}" for item in service.evidence)
    return lines


def render_host(report: HostReport, verbose: bool = True) -> str:
    """
    Relatorio completo de um host.

    :param report: HostReport
    :param verbose: bool
    :return: str
    """
    lines = [f"HOST: {report.hostname or report.name}",
             f"ALVO SSH: {report.target}"]
    if report.error:
        lines += [f"STATUS: {report.status}", f"ERRO: {report.error}", ""]
        return "\n".join(lines)
    lines.append(f"SO: {report.os_name or '-'}")
    lines.append(f"IP INTERNO: {report.primary_ip or '-'}")
    lines.append(f"IP PUBLICO: {', '.join(report.public_ips) or '-'}")
    lines.append("")
    for service in report.services:
        lines.extend(render_service(service, verbose))
        lines.append("")
    if report.context and report.context.notes:
        lines.append("CONTEXTO:")
        lines.extend(f"  - {note}" for note in report.context.notes)
        lines.append("")
    if report.issues:
        lines.append("PROBLEMAS DE COLETA:")
        lines.extend(f"  - {item['source']}: {item['status']} {item['detail']}".rstrip()
                     for item in report.issues)
        lines.append("")
    return "\n".join(lines)


def summary_counts(reports: list[HostReport]) -> dict[str, int]:
    """
    Contadores do resumo executivo.

    :param reports: list[HostReport]
    :return: dict[str, int]
    """
    services = [svc for report in reports for svc in report.services]
    counts = {
        "hosts": len(reports),
        "hosts_com_falha": sum(1 for report in reports if report.error),
        "servicos_locais": sum(1 for svc in services if svc.local_active),
        "servicos_expostos_externamente": sum(
            1 for svc in services
            if svc.kind == "external-only"
            or any(fam.external.state == ExternalState.OPEN for fam in svc.families)),
    }
    for item in Classification:
        counts[item.value] = sum(1 for svc in services if svc.classification == item)
    return counts


def _external_only_families(service: ServiceAssessment) -> list[str]:
    """
    Familias de um servico ``external-only`` (sem FamilyAssessment),
    deduzidas dos alvos registrados na evidencia externa.

    :param service: ServiceAssessment
    :return: list[str]
    """
    families: list[str] = []
    for item in service.evidence:
        if not item.startswith(_EXTERNAL_PREFIX):
            continue
        target = item[len(_EXTERNAL_PREFIX):].split(" ", 1)[0].rsplit(":", 1)[0]
        family = family_of(target)
        families.append(family.value if family else "?")
    return list(dict.fromkeys(families)) or ["?"]


def summary_rows(report: HostReport) -> dict[str, list[tuple[str, str, str, str]]]:
    """
    Linhas do resumo de um host agrupadas por familia IP: (servico,
    porta/protocolo, classificacao da familia, analise da familia).

    :param report: HostReport
    :return: dict[str, list[tuple[str, str, str, str]]]
    """
    rows: dict[str, list[tuple[str, str, str, str]]] = {}
    for svc in report.services:
        port = f"{svc.port}/{svc.protocol}"
        if svc.kind == "external-only":
            for family in _external_only_families(svc):
                rows.setdefault(family, []).append(
                    (svc.service, port, svc.classification.value, svc.reason))
            continue
        for fam in svc.families:
            rows.setdefault(fam.family.value, []).append(
                (svc.service, port, fam.classification.value, fam.reason))
    order = {family.value: index for index, family in enumerate(Family)}
    return dict(sorted(rows.items(), key=lambda item: order.get(item[0], len(order))))


def render_summary(reports: list[HostReport]) -> str:
    """
    Resumo executivo: contadores e, por host e familia IP, cada servico
    com porta, classificacao e analise, em colunas alinhadas::

        <host> - ipv4:  <servico>  <porta>  <classificacao> - <analise>
                        <servico>  <porta>  <classificacao> - <analise>
                 ipv6:  <servico>  <porta>  <classificacao> - <analise>

    :param reports: list[HostReport]
    :return: str
    """
    counts = summary_counts(reports)
    lines = [
        f"HOSTS AUDITADOS:                {counts['hosts']}",
        f"HOSTS COM FALHA:                {counts['hosts_com_falha']}",
        f"SERVICOS LOCAIS:                {counts['servicos_locais']}",
        f"SERVICOS EXPOSTOS EXTERNAMENTE: {counts['servicos_expostos_externamente']}",
        f"PROTEGIDOS:                     {counts['PROTEGIDO']}",
        f"PARCIAIS:                       {counts['PARCIAL']}",
        f"EXPOSTOS:                       {counts['EXPOSTO']}",
        f"INDETERMINADOS:                 {counts['INDETERMINADO']}",
        "",
        "SERVICOS POR HOST:",
        "",
    ]
    per_host = [(report.hostname or report.name, report, summary_rows(report))
                for report in reports]
    if not per_host:
        lines.append("nenhum host")
        return "\n".join(lines) + "\n"
    all_rows = [row for _, _, rows in per_host for fam in rows.values() for row in fam]
    host_w = max(len(name) for name, _, _ in per_host)
    svc_w = max((len(row[0]) for row in all_rows), default=0)
    port_w = max((len(row[1]) for row in all_rows), default=0)
    cls_w = max(len(item.value) for item in Classification)
    fam_w = max((len(fam) for _, _, rows in per_host for fam in rows), default=4) + 1
    for name, report, rows in per_host:
        prefix = f"{name:<{host_w}} - "
        blank = " " * len(prefix)
        if report.error:
            lines.append(f"{prefix}ERRO: {report.error}")
        elif not rows:
            lines.append(f"{prefix}nenhum servico identificado")
        for family, items in rows.items():
            label = f"{family + ':':<{fam_w}}"
            for index, (svc, port, cls, reason) in enumerate(items):
                head = label if index == 0 else " " * fam_w
                lines.append(f"{prefix}{head}  {svc:<{svc_w}}  {port:<{port_w}}  "
                             f"{cls:<{cls_w}} - {reason}")
                prefix = blank
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"
