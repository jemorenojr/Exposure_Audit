# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : pipeline.py
# Descricao   : Orquestracao por host: coleta -> normalizacao -> scan
#               externo -> correlacao. Mantem os componentes desacoplados.
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
Pipeline de auditoria de um host.

E o unico ponto que conhece collector, scanner e correlator ao mesmo
tempo. Ele monta os dados normalizados e entrega ao correlator, que nao
executa coleta.
"""

import logging
import socket
from dataclasses import dataclass, field

from exposure_audit.collector.firewall.evaluator import Probe, evaluate, intersect
from exposure_audit.collector.normalize import HostState, normalize
from exposure_audit.correlator.classifier import classify
from exposure_audit.inventory import HostEntry
from exposure_audit.models import (AddressScope, BindClass, Classification, ExternalEvidence,
                                   ExternalState, Family, FirewallVerdict, NatMapping,
                                   NetworkContext, PortObservation, ServiceAssessment,
                                   ServiceView, to_dict)
from exposure_audit.netutils import family_of, is_wildcard_bind, parse_ip, parse_network
from exposure_audit.scanner.base import ExternalScanner, ScanResult

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"

LOG = logging.getLogger(__name__)

MAX_NAT_RANGE = 32


@dataclass
class AuditOptions:
    """Opcoes de execucao relevantes para o pipeline."""

    ipv6: bool = True
    fullscan: bool = True
    identify: bool = False


@dataclass
class ExternalData:
    """Resultados externos de um host."""

    available: bool
    targets: dict[str, list[str]] = field(default_factory=dict)
    scans: list[ScanResult] = field(default_factory=list)
    path: dict[str, dict[str, object]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def observations(self) -> list[PortObservation]:
        """
        Todas as observacoes de todos os scans bem sucedidos.

        :return: list[PortObservation]
        """
        return [obs for scan in self.scans if scan.error is None for obs in scan.observations]


@dataclass
class HostReport:
    """Resultado completo da auditoria de um host."""

    name: str
    target: str
    status: str
    hostname: str | None = None
    os_name: str | None = None
    primary_ip: str | None = None
    public_ips: list[str] = field(default_factory=list)
    services: list[ServiceAssessment] = field(default_factory=list)
    issues: list[dict[str, str]] = field(default_factory=list)
    context: NetworkContext | None = None
    raw: dict[str, object] = field(default_factory=dict)
    normalized: dict[str, object] = field(default_factory=dict)
    external: dict[str, object] = field(default_factory=dict)
    error: str | None = None


# ----------------------------------------------------------------------
# Servicos
# ----------------------------------------------------------------------
def service_label(port: int, protocol: str) -> str | None:
    """
    Nome conhecido do servico pela porta (base local de servicos).

    :param port: int
    :param protocol: str
    :return: str | None
    """
    try:
        return socket.getservbyport(port, protocol).upper()
    except (OSError, OverflowError):
        return None


def _host_addresses(state: HostState) -> set[str]:
    """
    Enderecos configurados no host (incluindo loopback).

    :param state: HostState
    :return: set[str]
    """
    return {addr.address for addr in state.addresses} | {"127.0.0.1", "::1"}


def _nat_reachable(mapping: NatMapping, state: HostState) -> bool:
    """
    Indica se o DNAT pode ser acionado por trafego externo (ex.: Docker
    publicado em 127.0.0.1 nao e).

    :param mapping: NatMapping
    :param state: HostState
    :return: bool
    """
    if not mapping.dest_networks:
        return True
    nets = [parse_network(net) for net in mapping.dest_networks]
    candidates = [parse_ip(addr.address) for addr in state.addresses
                  if addr.scope not in (AddressScope.LOOPBACK, AddressScope.LINK_LOCAL)]
    for ip in candidates:
        if ip is not None and any(net is not None and net.version == ip.version and ip in net
                                  for net in nets):
            return True
    return not candidates


def _docker_label(state: HostState, protocol: str, port: int) -> str | None:
    """
    Nome do container que publica a porta, se houver.

    :param state: HostState
    :param protocol: str
    :param port: int
    :return: str | None
    """
    for pub in state.docker:
        if pub.protocol == protocol and pub.host_port == port:
            return f"docker:{pub.container}"
    return None


def build_services(state: HostState, notes: list[str]) -> list[ServiceView]:
    """
    Agrupa listeners por protocolo/porta e incorpora mapeamentos NAT.

    :param state: HostState
    :param notes: list[str]
    :return: list[ServiceView]
    """
    services: dict[tuple[str, int], ServiceView] = {}
    for listener in state.listeners:
        key = (listener.protocol, listener.port)
        view = services.setdefault(key, ServiceView(
            protocol=listener.protocol, port=listener.port,
            service_name=service_label(listener.port, listener.protocol)))
        view.listeners.append(listener)
        if view.process is None and listener.process:
            view.process = listener.process

    local = _host_addresses(state)
    for mapping in state.nat:
        if not _nat_reachable(mapping, state):
            continue
        if mapping.external_ports is None:
            notes.append(f"DNAT sem porta especifica ({mapping.origin}): {mapping.rule}")
            continue
        low, high = mapping.external_ports
        if high - low >= MAX_NAT_RANGE:
            notes.append(f"DNAT de faixa {low}-{high} nao detalhado: {mapping.rule}")
            continue
        protocol = mapping.protocol if mapping.protocol in ("tcp", "udp") else "tcp"
        for ext_port in range(low, high + 1):
            to_port = mapping.to_port or ext_port
            if mapping.to_address is None or mapping.to_address in local:
                view = services.get((protocol, to_port))
                if view is None:
                    notes.append(f"NAT {ext_port}/{protocol} -> porta local {to_port} sem "
                                 f"listener: {mapping.rule}")
                    continue
                view.nat_mappings.append(mapping)
                continue
            view = services.setdefault((protocol, ext_port), ServiceView(
                protocol=protocol, port=ext_port,
                service_name=service_label(to_port, protocol)))
            view.forwarded = True
            view.forward_target = f"{mapping.to_address}:{to_port}"
            view.nat_mappings.append(mapping)
            if view.process is None or view.process == "docker-proxy":
                view.process = (_docker_label(state, protocol, ext_port)
                                or f"DNAT->{mapping.to_address}:{to_port}")
    return sorted(services.values(), key=lambda item: (item.protocol, item.port))


# ----------------------------------------------------------------------
# Firewall
# ----------------------------------------------------------------------
def _dest_addresses(state: HostState, service: ServiceView, family: Family) -> list[str]:
    """
    Enderecos de destino possiveis para o servico na familia.

    :param state: HostState
    :param service: ServiceView
    :param family: Family
    :return: list[str]
    """
    listeners = [item for item in service.listeners if item.family == family]
    if any(is_wildcard_bind(item.bind_class) for item in listeners) or not listeners:
        return [addr.address for addr in state.addresses if addr.family == family
                and addr.scope not in (AddressScope.LOOPBACK, AddressScope.LINK_LOCAL)]
    return [item.address for item in listeners]


def evaluate_firewall(state: HostState, service: ServiceView) -> dict[Family, FirewallVerdict]:
    """
    Avalia o firewall do servico em cada familia (INPUT ou FORWARD).

    :param state: HostState
    :param service: ServiceView
    :return: dict[Family, FirewallVerdict]
    """
    result: dict[Family, FirewallVerdict] = {}
    for family in service.families:
        forwards = [m for m in service.nat_mappings
                    if m.family == family and service.forwarded and m.to_address]
        if forwards:
            verdicts = []
            for mapping in forwards:
                probe = Probe(family=family, protocol=service.protocol,
                              port=mapping.to_port or service.port,
                              dest_addresses=[mapping.to_address or ""],
                              ingress_ifaces=state.ingress_ifaces, hook="forward", dnat=True)
                verdict = evaluate(state.ruleset, probe)
                verdict.notes.append(f"DNAT {service.port}/{service.protocol} -> "
                                     f"{mapping.to_address}:{mapping.to_port or service.port} "
                                     f"({mapping.origin}); avaliado hook FORWARD")
                if mapping.source != "any":
                    verdict.notes.append(f"DNAT condicionado a origem {mapping.source}")
                verdicts.append(verdict)
            result[family] = intersect(verdicts) if len(verdicts) > 1 else verdicts[0]
            continue
        probe = Probe(family=family, protocol=service.protocol, port=service.port,
                      dest_addresses=_dest_addresses(state, service, family),
                      ingress_ifaces=state.ingress_ifaces, hook="input")
        result[family] = evaluate(state.ruleset, probe)
    return result


# ----------------------------------------------------------------------
# Scanner externo
# ----------------------------------------------------------------------
def scan_targets(state: HostState, entry: HostEntry, options: AuditOptions) -> dict[str, list[str]]:
    """
    Define os IPs publicos a testar por familia.

    :param state: HostState
    :param entry: HostEntry
    :param options: AuditOptions
    :return: dict[str, list[str]]
    """
    targets: dict[str, list[str]] = {Family.IPV4.value: [], Family.IPV6.value: []}
    for ip in entry.public_ips:
        fam = family_of(ip)
        if fam is not None:
            targets[fam.value].append(ip)
    if not targets[Family.IPV4.value]:
        targets[Family.IPV4.value] = state.addresses_by_scope(AddressScope.PUBLIC)
        if not targets[Family.IPV4.value] and family_of(entry.host) == Family.IPV4:
            ip = parse_ip(entry.host)
            if ip is not None and ip.is_global:
                targets[Family.IPV4.value] = [entry.host]
    if options.ipv6:
        targets[Family.IPV6.value] += [addr.address for addr in state.addresses
                                       if addr.scope == AddressScope.IPV6_GLOBAL
                                       and not {"temporary", "deprecated"} & set(addr.flags)]
    else:
        targets[Family.IPV6.value] = []
    return {fam: list(dict.fromkeys(ips)) for fam, ips in targets.items()}


def _ports_to_scan(services: list[ServiceView], protocol: str) -> list[int]:
    """
    Portas a testar no scan direcionado (exclui servicos so em loopback).

    :param services: list[ServiceView]
    :param protocol: str
    :return: list[int]
    """
    ports: set[int] = set()
    for service in services:
        if service.protocol != protocol:
            continue
        only_loopback = service.listeners and all(
            item.bind_class == BindClass.LOCAL_ONLY for item in service.listeners)
        if not only_loopback or service.nat_mappings:
            ports.add(service.port)
        for mapping in service.nat_mappings:
            if mapping.external_ports:
                low, high = mapping.external_ports
                ports.update(range(low, high + 1))
    return sorted(ports)


def run_external(scanner: ExternalScanner | None, services: list[ServiceView],
                 targets: dict[str, list[str]], options: AuditOptions) -> ExternalData:
    """
    Executa scans direcionado, independente e (opcional) identificacao.

    :param scanner: ExternalScanner | None
    :param services: list[ServiceView]
    :param targets: dict[str, list[str]]
    :param options: AuditOptions
    :return: ExternalData
    """
    data = ExternalData(available=scanner is not None, targets=targets)
    if scanner is None:
        data.notes.append("scanner externo nao configurado")
        return data
    tcp = _ports_to_scan(services, "tcp")
    udp = _ports_to_scan(services, "udp")
    for family, ips in targets.items():
        for ip in ips:
            data.path[ip] = scanner.path_evidence(ip)
            data.scans.append(scanner.scan_ports(ip, tcp, udp))
            if options.fullscan:
                data.scans.append(scanner.discover_ports(ip))
            if options.identify:
                open_tcp = sorted({obs.port for scan in data.scans if scan.target == ip
                                   for obs in scan.observations
                                   if obs.protocol == "tcp" and obs.state == ExternalState.OPEN})
                if open_tcp:
                    data.scans.append(scanner.identify_services(ip, open_tcp))
        LOG.debug("scan externo %s concluido: %s", family, ips)
    return data


def _service_ports(service: ServiceView, family: Family) -> set[int]:
    """
    Portas externas associadas ao servico na familia (porta propria +
    portas externas de NAT).

    :param service: ServiceView
    :param family: Family
    :return: set[int]
    """
    ports = {service.port}
    for mapping in service.nat_mappings:
        if mapping.family == family and mapping.external_ports:
            low, high = mapping.external_ports
            ports.update(range(low, high + 1))
    return ports


def external_evidence(service: ServiceView, family: Family,
                      data: ExternalData) -> ExternalEvidence:
    """
    Consolida a evidencia externa do servico em uma familia.

    Considera todos os IPs publicos testados da familia: o resultado
    descreve a porta vista da Internet, independentemente do endereco
    especifico de bind.

    :param service: ServiceView
    :param family: Family
    :param data: ExternalData
    :return: ExternalEvidence
    """
    targets = data.targets.get(family.value, [])
    if not data.available:
        return ExternalEvidence(ExternalState.UNKNOWN, scanned=False, notes=list(data.notes))
    if not targets:
        return ExternalEvidence(ExternalState.UNKNOWN, scanned=False,
                                notes=[f"nenhum IP publico {family.value} conhecido para teste"])
    notes: list[str] = []
    for ip in targets:
        notes.extend(str(item) for item in data.path.get(ip, {}).get("warnings", []))  # type: ignore[union-attr]
    errors = [f"{scan.kind} {scan.target}: {scan.error}" for scan in data.scans
              if scan.error and scan.target in targets and scan.kind == "targeted"]
    ports = _service_ports(service, family)
    relevant = [obs for obs in data.observations()
                if obs.target in targets and obs.protocol == service.protocol
                and obs.port in ports]
    if not relevant:
        state = ExternalState.UNKNOWN
        notes.extend(errors or ["porta nao testada externamente"])
        return ExternalEvidence(state, scanned=False, notes=notes)
    states = {obs.state for obs in relevant}
    for candidate in (ExternalState.OPEN, ExternalState.FILTERED, ExternalState.CLOSED):
        if candidate in states:
            state = candidate
            break
    else:
        state = (ExternalState.UNREACHABLE if states == {ExternalState.UNREACHABLE}
                 else ExternalState.UNKNOWN)
    notes.extend(errors)
    return ExternalEvidence(state, scanned=True, observations=relevant, notes=notes)


def external_only(services: list[ServiceView], assessments: list[ServiceAssessment],
                  data: ExternalData) -> list[ServiceAssessment]:
    """
    Portas abertas externamente sem servico local correspondente
    (possivel DNAT upstream). Nao assume porta externa == porta interna.

    :param services: list[ServiceView]
    :param assessments: list[ServiceAssessment]
    :param data: ExternalData
    :return: list[ServiceAssessment]
    """
    known: set[tuple[str, int]] = set()
    for service in services:
        for family in (Family.IPV4, Family.IPV6):
            known.update((service.protocol, port) for port in _service_ports(service, family))
    candidates = [item for item in assessments
                  if item.local_active and any(fam.bind_class not in (None, BindClass.LOCAL_ONLY)
                                               for fam in item.families)
                  and not any(fam.external.state == ExternalState.OPEN for fam in item.families)]
    found: dict[tuple[str, int], list[PortObservation]] = {}
    for obs in data.observations():
        if obs.state == ExternalState.OPEN and (obs.protocol, obs.port) not in known:
            found.setdefault((obs.protocol, obs.port), []).append(obs)
    results: list[ServiceAssessment] = []
    for (protocol, port), observations in sorted(found.items()):
        local = [f"{item.port}/{item.protocol} ({item.process or item.service})"
                 for item in candidates if item.protocol == protocol]
        hint = f"; possiveis destinos locais: {', '.join(local)}" if local else ""
        names = {obs.service_name for obs in observations
                 if obs.service_name and obs.service_name != "unknown"}
        results.append(ServiceAssessment(
            protocol=protocol, port=port,
            service=(sorted(names)[0].upper() if names else service_label(port, protocol) or "?"),
            process=None, local_active=False, families=[],
            classification=Classification.INDETERMINADO,
            reason=("porta aberta externamente sem listener ou NAT local correspondente: "
                    "possivel DNAT/encaminhamento upstream ou outro equipamento respondendo "
                    f"pelo IP{hint}"),
            followup=True,
            evidence=[f"externo: {obs.target}:{obs.port}/{obs.protocol} {obs.raw_state}"
                      for obs in observations],
            external_ports=[port], kind="external-only"))
    return results


# ----------------------------------------------------------------------
# Host
# ----------------------------------------------------------------------
def build_context(state: HostState, data: ExternalData, notes: list[str]) -> NetworkContext:
    """
    Monta o contexto de rede para o correlator.

    :param state: HostState
    :param data: ExternalData
    :param notes: list[str]
    :return: NetworkContext
    """
    context_notes = list(notes)
    rules = state.routing.get("policy_rules") or []
    if rules:
        context_notes.append(f"policy routing presente: {'; '.join(rules)}")  # type: ignore[arg-type]
    if state.routing.get("xfrm_policies"):
        context_notes.append("politicas XFRM (IPsec) presentes no host")
    for ip, path in data.path.items():
        for warning in path.get("warnings", []):  # type: ignore[union-attr]
            context_notes.append(f"scanner -> {ip}: {warning}")
    return NetworkContext(
        hostname=state.hostname,
        has_ipv6_global=bool(state.addresses_by_scope(AddressScope.IPV6_GLOBAL)),
        external_scan_available=data.available,
        scan_targets=data.targets,
        xfrm_policies_present=bool(state.routing.get("xfrm_policies")),
        notes=list(dict.fromkeys(context_notes)),
    )


def _log_findings(host: str, assessment: ServiceAssessment) -> None:
    """
    Registra no log operacional inconsistencias e regras de firewall nao
    interpretadas (o resultado em si fica nos relatorios).

    :param host: str
    :param assessment: ServiceAssessment
    :return: None
    """
    label = f"{host} {assessment.port}/{assessment.protocol}"
    for family in assessment.families:
        if family.rule_id == "R07":
            LOG.warning("%s [%s]: inconsistencia entre firewall local e teste externo",
                        label, family.family.value)
        unknown = [note for note in family.firewall.notes if "nao interpretada" in note]
        if unknown:
            LOG.info("%s [%s]: regra de firewall nao interpretada: %s", label,
                     family.family.value, unknown[0])


def analyze(entry: HostEntry, raw: dict[str, object], scanner: ExternalScanner | None,
            options: AuditOptions) -> HostReport:
    """
    Analisa um host a partir da coleta bruta (normaliza, testa
    externamente e classifica).

    :param entry: HostEntry
    :param raw: dict[str, object]
    :param scanner: ExternalScanner | None
    :param options: AuditOptions
    :return: HostReport
    """
    report = HostReport(name=entry.name, target=entry.host, status=str(raw.get("status")),
                        raw=raw)
    if raw.get("status") != "OK":
        report.error = "host inacessivel via SSH"
        return report
    state = normalize(raw, entry.name)
    notes: list[str] = []
    services = build_services(state, notes)
    targets = scan_targets(state, entry, options)
    data = run_external(scanner, services, targets, options)
    context = build_context(state, data, notes)

    assessments: list[ServiceAssessment] = []
    for service in services:
        firewall = evaluate_firewall(state, service)
        external = {family: external_evidence(service, family, data)
                    for family in service.families}
        assessment = classify(service, firewall, external, context)
        _log_findings(entry.name, assessment)
        assessments.append(assessment)
    assessments.extend(external_only(services, assessments, data))

    report.hostname = state.hostname
    report.os_name = state.os_name
    report.primary_ip = state.primary_ip
    report.public_ips = [ip for ips in targets.values() for ip in ips]
    report.services = assessments
    report.issues = state.issues
    report.context = context
    report.normalized = {
        "hostname": state.hostname,
        "fqdn": state.fqdn,
        "os": state.os_name,
        "addresses": to_dict(state.addresses),
        "routing": state.routing,
        "listeners": to_dict(state.listeners),
        "firewall": {"family_status": state.ruleset.family_status,
                     "tables": [table.label() for table in state.ruleset.tables],
                     "ipsets": state.ruleset.ipsets,
                     "notes": state.ruleset.notes},
        "nat": to_dict(state.nat),
        "docker": to_dict(state.docker),
        "ingress_interfaces": state.ingress_ifaces,
    }
    report.external = {
        "available": data.available,
        "targets": data.targets,
        "path": data.path,
        "notes": data.notes,
        "scans": [{"target": scan.target, "kind": scan.kind, "error": scan.error,
                   "host_up": scan.host_up, "observations": to_dict(scan.observations),
                   "argv": scan.raw.get("argv")} for scan in data.scans],
    }
    return report
