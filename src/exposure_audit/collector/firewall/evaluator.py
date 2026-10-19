# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : evaluator.py
# Descricao   : Avaliacao do fluxo efetivo das regras de firewall para um
#               pacote novo vindo da Internet, por servico e familia IP.
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
Avaliador de ruleset.

Modelo de sonda: um pacote NEW (inicio de conexao), unicast, de origem
externa arbitraria, destinado ao servico (protocolo, porta, enderecos) e
chegando por qualquer interface externa do host.

As chains sao percorridas na ordem real (policy, ordem das regras,
jump/goto/return). Condicoes de origem sao tratadas simbolicamente:

* origem qualquer          -> decisao para todo o universo restante;
* origem especifica/set    -> decisao apenas para aquelas origens;
* condicao nao interpretada -> incerteza (resultado UNKNOWN).

Varias base chains no mesmo hook (nftables com prioridades diferentes,
iptables-legacy + nftables) sao combinadas por intersecao: o pacote
precisa ser aceito por todas.

O resultado e normalizado em ``FirewallAccess`` (secao 10 da diretriz).
Esta e uma etapa de normalizacao; a classificacao final de exposicao e
feita pelo correlator.
"""

from dataclasses import dataclass, field

from exposure_audit.collector.firewall.model import (
    ACCEPT, CONTINUE, DROP, GOTO, JUMP, REJECT, RETURN, VMAP, AddressMatch, Chain,
    IfaceMatch, Rule, Ruleset, Table)
from exposure_audit.collector.firewall.nftables import element_to_ports
from exposure_audit.models import AddressScope, Family, FirewallAccess, FirewallVerdict
from exposure_audit.netutils import (iface_matches, is_public_scope, network_scope,
                                     parse_ip, parse_network)

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"

MAX_DEPTH = 32

#: Ordem de restritividade usada na intersecao de varias base chains.
RESTRICTIVENESS: dict[FirewallAccess, int] = {
    FirewallAccess.ANY: 0,
    FirewallAccess.UNKNOWN: 1,
    FirewallAccess.RESTRICTED_SOURCE: 2,
    FirewallAccess.PRIVATE_ONLY: 3,
    FirewallAccess.LOCAL_ONLY: 4,
    FirewallAccess.BLOCKED: 5,
}

# Resultados de casamento
_NO = "no"
_YES = "yes"
_COND = "conditional"
_UNCERTAIN = "uncertain"


@dataclass
class Probe:
    """Pacote hipotetico avaliado contra o ruleset."""

    family: Family
    protocol: str
    port: int
    dest_addresses: list[str]
    ingress_ifaces: list[str]
    hook: str = "input"
    dnat: bool = False


@dataclass
class SourceSpec:
    """Conjunto de origens afetado por uma decisao condicional."""

    description: str
    kind: str  # public | private | loopback | broad


@dataclass
class _Walk:
    """Estado acumulado durante a avaliacao de uma base chain."""

    accepted: list[SourceSpec] = field(default_factory=list)
    denied: list[SourceSpec] = field(default_factory=list)
    uncertain: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    terminal: str | None = None
    terminal_rule: str | None = None


def _family_tag(family: Family) -> str:
    """
    Converte Family no rotulo usado em ``Rule.families``.

    :param family: Family
    :return: str
    """
    return "ipv4" if family == Family.IPV4 else "ipv6"


def _table_applies(table: Table, family: Family) -> bool:
    """
    Indica se a tabela processa pacotes da familia.

    :param table: Table
    :param family: Family
    :return: bool
    """
    if table.family == "inet":
        return True
    return (table.family == "ip") == (family == Family.IPV4)


class Evaluator:
    """Avalia um ruleset para uma sonda."""

    def __init__(self, ruleset: Ruleset, probe: Probe) -> None:
        """
        Inicializa o avaliador.

        :param ruleset: Ruleset
        :param probe: Probe
        :return: None
        """
        self.ruleset = ruleset
        self.probe = probe
        self._policy: str = ACCEPT

    # ------------------------------------------------------------------
    # Resolucao de conjuntos
    # ------------------------------------------------------------------
    def _set_content(self, table: Table, name: str) -> list[str] | None:
        """
        Retorna o conteudo de um set nftables ou ipset.

        :param table: Table
        :param name: str
        :return: list[str] | None
        """
        if name in table.sets:
            return table.sets[name]
        return self.ruleset.ipsets.get(name)

    # ------------------------------------------------------------------
    # Casamento de condicoes
    # ------------------------------------------------------------------
    def _match_source(self, table: Table, match: AddressMatch) -> tuple[str, SourceSpec | None]:
        """
        Avalia a condicao de origem para uma origem externa arbitraria.

        :param table: Table
        :param match: AddressMatch
        :return: tuple[str, SourceSpec | None]
        """
        label = f"set {match.set_name}" if match.set_name else ",".join(match.networks)
        networks = match.networks
        if match.set_name:
            content = self._set_content(table, match.set_name)
            if content is None:
                kind = "broad" if match.negated else "public"
                return _COND, SourceSpec(f"{'!' if match.negated else ''}{label} "
                                         "(conteudo nao coletado)", kind)
            networks = content
            label = f"set {match.set_name} = {{{', '.join(content[:20])}" + \
                    ("..." if len(content) > 20 else "") + "}"
        parsed = [parse_network(net) for net in networks]
        nets = [net for net in parsed if net is not None
                and (net.version == 4) == (self.probe.family == Family.IPV4)]
        if any(net is None for net in parsed):
            return _UNCERTAIN, SourceSpec(f"origem nao interpretada {label}", "broad")
        if not nets:
            # Nenhuma rede da familia: a regra nunca casa (ou sempre, se negada).
            return (_YES, None) if match.negated else (_NO, None)
        if any(net.prefixlen == 0 for net in nets):
            return (_NO, None) if match.negated else (_YES, None)
        scopes = {network_scope(net) for net in nets}
        public = any(is_public_scope(scope) for scope in scopes)
        if match.negated:
            if not public:
                return _YES, None
            return _COND, SourceSpec(f"!{label}", "broad")
        if scopes == {AddressScope.LOOPBACK}:
            return _COND, SourceSpec(label, "loopback")
        return _COND, SourceSpec(label, "public" if public else "private")

    def _match_dest(self, table: Table, match: AddressMatch) -> tuple[str, str | None]:
        """
        Avalia a condicao de destino contra os enderecos do servico.

        :param table: Table
        :param match: AddressMatch
        :return: tuple[str, str | None]
        """
        networks = match.networks
        if match.set_name:
            content = self._set_content(table, match.set_name)
            if content is None:
                return _COND, f"destino via set {match.set_name} (conteudo nao coletado)"
            networks = content
        parsed = [parse_network(net) for net in networks]
        nets = [net for net in parsed if net is not None]
        candidates = [ip for ip in (parse_ip(addr) for addr in self.probe.dest_addresses) if ip]
        if not candidates:
            return _COND, "destino restrito; enderecos do servico desconhecidos"
        hits = [ip for ip in candidates if any(ip.version == net.version and ip in net
                                               for net in nets)]
        if match.negated:
            hits = [ip for ip in candidates if ip not in hits]
        if not hits:
            return _NO, None
        if len(hits) == len(candidates):
            return _YES, None
        return _COND, f"destino {'!' if match.negated else ''}{','.join(networks)}"

    def _match_iface(self, match: IfaceMatch) -> tuple[str, str | None]:
        """
        Avalia interface de entrada contra as interfaces externas.

        :param match: IfaceMatch
        :return: tuple[str, str | None]
        """
        candidates = self.probe.ingress_ifaces
        if not candidates:
            return _COND, f"interface {','.join(match.names)} (interfaces externas desconhecidas)"
        hits = [name for name in candidates
                if any(iface_matches(pattern, name) for pattern in match.names) != match.negated]
        if not hits:
            return _NO, None
        if len(hits) == len(candidates):
            return _YES, None
        return _COND, f"interface {'!' if match.negated else ''}{','.join(match.names)}"

    def _match_ports(self, table: Table, rule: Rule) -> bool | None:
        """
        Avalia porta de destino (lista ou set). None = indeterminado.

        :param table: Table
        :param rule: Rule
        :return: bool | None
        """
        ranges = rule.dports
        if rule.dport_set:
            content = self._set_content(table, rule.dport_set)
            if content is None:
                return None
            ranges = []
            for item in content:
                start, _, end = item.partition("-")
                if start.isdigit():
                    ranges.append((int(start), int(end) if end.isdigit() else int(start)))
                else:
                    ranges.extend(element_to_ports(item))
        if ranges is None:
            return True
        inside = any(low <= self.probe.port <= high for low, high in ranges)
        return inside != rule.dport_negated

    def match(self, table: Table, rule: Rule) -> tuple[str, SourceSpec | None, list[str]]:
        """
        Avalia se a regra casa com a sonda.

        Retorna (resultado, condicao_de_origem, observacoes).

        :param table: Table
        :param rule: Rule
        :return: tuple[str, SourceSpec | None, list[str]]
        """
        probe = self.probe
        notes: list[str] = []
        if rule.never_matches:
            return _NO, None, notes
        if rule.families and _family_tag(probe.family) not in rule.families:
            return _NO, None, notes
        if rule.protocols is not None:
            if (probe.protocol in rule.protocols) == rule.proto_negated:
                return _NO, None, notes
        ports = self._match_ports(table, rule)
        if ports is False:
            return _NO, None, notes
        if rule.ct_states is not None:
            if ("new" in rule.ct_states) == rule.ct_negated:
                return _NO, None, notes
        if rule.ct_status_dnat is not None and rule.ct_status_dnat != probe.dnat:
            return _NO, None, notes

        partial: list[str] = list(rule.partial)
        if rule.in_iface is not None:
            result, detail = self._match_iface(rule.in_iface)
            if result == _NO:
                return _NO, None, notes
            if result == _COND and detail:
                partial.append(detail)
        if rule.out_iface is not None:
            notes.append(f"interface de saida {','.join(rule.out_iface.names)} assumida")
        if rule.dst is not None:
            result, detail = self._match_dest(table, rule.dst)
            if result == _NO:
                return _NO, None, notes
            if result == _COND and detail:
                partial.append(detail)

        source: SourceSpec | None = None
        if rule.src is not None:
            result, source = self._match_source(table, rule.src)
            if result == _NO:
                return _NO, None, notes
            if result == _UNCERTAIN:
                return _UNCERTAIN, source, [source.description if source else "origem"]

        if ports is None:
            return _UNCERTAIN, None, [f"set de portas {rule.dport_set} nao coletado"]
        if rule.unknown:
            return _UNCERTAIN, None, list(rule.unknown)
        if partial:
            description = "; ".join(partial)
            kind = "broad"
            if source is not None:
                description = f"{source.description}; {description}"
                kind = source.kind
            return _COND, SourceSpec(description, kind), notes
        if source is not None:
            return _COND, source, notes
        return _YES, None, notes

    # ------------------------------------------------------------------
    # Percurso das chains
    # ------------------------------------------------------------------
    def _vmap_verdict(self, rule: Rule) -> tuple[str, str | None] | None:
        """
        Resolve um verdict map para a sonda. None = nenhuma entrada casa.

        :param rule: Rule
        :return: tuple[str, str | None] | None
        """
        probe = self.probe
        for entry in rule.vmap:
            values = [value.lower() for value in entry.values]
            if rule.vmap_key == "ct_state" and "new" in values:
                return entry.verdict, entry.target
            if rule.vmap_key == "l4proto" and probe.protocol in values:
                return entry.verdict, entry.target
            if rule.vmap_key == "dport":
                ranges = [rng for value in entry.values for rng in element_to_ports(value)]
                if any(low <= probe.port <= high for low, high in ranges):
                    return entry.verdict, entry.target
            if rule.vmap_key == "iif":
                matched = [name for name in probe.ingress_ifaces
                           if any(iface_matches(value, name) for value in entry.values)]
                if matched:
                    return entry.verdict, entry.target
        return None

    def _walk(self, table: Table, chain: Chain, cond: SourceSpec | None, state: _Walk,
              depth: int, stack: list[tuple[Chain, int]], start: int = 0) -> str:
        """
        Percorre uma chain a partir da regra ``start``.

        ``cond`` e a condicao de origem herdada (None = todo o universo
        restante); ``stack`` guarda os pontos de retorno nas chains
        chamadoras, usados quando parte das origens sai da chain (RETURN
        ou GOTO condicional). Retorna ``terminal`` (universo decidido),
        ``decided`` (condicao herdada decidida), ``return`` ou ``end``.

        :param table: Table
        :param chain: Chain
        :param cond: SourceSpec | None
        :param state: _Walk
        :param depth: int
        :param stack: list[tuple[Chain, int]]
        :param start: int
        :return: str
        """
        if depth > MAX_DEPTH:
            state.uncertain.append(f"profundidade maxima de chains excedida em {chain.name}")
            return "decided"
        for position in range(start, len(chain.rules)):
            rule = chain.rules[position]
            result, source, notes = self.match(table, rule)
            if result == _NO:
                continue
            verdict, target = rule.verdict, rule.target
            if verdict == VMAP:
                resolved = self._vmap_verdict(rule)
                if resolved is None:
                    continue
                verdict, target = resolved
            if verdict == CONTINUE:
                continue
            ref = f"{table.label()} {chain.name}#{rule.index}: {rule.text}"
            if result == _UNCERTAIN:
                state.uncertain.append(f"{ref} -> {', '.join(notes)}")
                continue
            state.notes.extend(notes)
            if rule.rate_limited and verdict in (DROP, REJECT, JUMP, GOTO):
                state.notes.append(f"limitacao de taxa: {ref}")
                state.evidence.append(ref)
                continue
            if rule.rate_limited and verdict == ACCEPT:
                state.notes.append(f"aceite com limitacao de taxa: {ref}")
            if verdict not in (ACCEPT, DROP, REJECT, RETURN, JUMP, GOTO):
                state.uncertain.append(f"{ref} -> verdict {verdict} nao modelado")
                continue
            here = stack + [(chain, position + 1)]
            if result == _YES:
                outcome = self._apply(table, verdict, target, cond, ref, state, depth,
                                      here, stack)
                if outcome is not None:
                    return outcome
                continue
            spec = _combine(cond, source)
            if spec is not None:
                self._branch(table, verdict, target, spec, ref, state, depth, here, stack)
        return "end"

    def _sub(self, table: Table, target: str | None, ref: str, state: _Walk) -> Chain | None:
        """
        Resolve a chain alvo de jump/goto.

        :param table: Table
        :param target: str | None
        :param ref: str
        :param state: _Walk
        :return: Chain | None
        """
        sub = table.chains.get(target or "")
        if sub is None:
            state.uncertain.append(f"{ref} -> chain {target} inexistente")
        return sub

    def _apply(self, table: Table, verdict: str, target: str | None, cond: SourceSpec | None,
               ref: str, state: _Walk, depth: int, here: list[tuple[Chain, int]],
               stack: list[tuple[Chain, int]]) -> str | None:
        """
        Aplica um verdict a toda a condicao corrente (``cond``; None =
        universo restante). Retorna o desfecho da chain ou None para
        continuar na proxima regra.

        :param table: Table
        :param verdict: str
        :param target: str | None
        :param cond: SourceSpec | None
        :param ref: str
        :param state: _Walk
        :param depth: int
        :param here: list[tuple[Chain, int]]
        :param stack: list[tuple[Chain, int]]
        :return: str | None
        """
        if verdict in (ACCEPT, DROP, REJECT):
            state.evidence.append(ref)
            if cond is None:
                state.terminal = verdict
                state.terminal_rule = ref
                return "terminal"
            (state.accepted if verdict == ACCEPT else state.denied).append(cond)
            return "decided"
        if verdict == RETURN:
            return "return"
        sub = self._sub(table, target, ref, state)
        if sub is None:
            return None
        outcome = self._walk(table, sub, cond, state, depth + 1,
                             here if verdict == JUMP else stack)
        if outcome in ("terminal", "decided"):
            return outcome
        return "return" if verdict == GOTO else None

    def _branch(self, table: Table, verdict: str, target: str | None, spec: SourceSpec,
                ref: str, state: _Walk, depth: int, here: list[tuple[Chain, int]],
                stack: list[tuple[Chain, int]]) -> None:
        """
        Aplica um verdict somente a parte das origens (``spec``). O restante
        continua na chain corrente.

        :param table: Table
        :param verdict: str
        :param target: str | None
        :param spec: SourceSpec
        :param ref: str
        :param state: _Walk
        :param depth: int
        :param here: list[tuple[Chain, int]]
        :param stack: list[tuple[Chain, int]]
        :return: None
        """
        if verdict == ACCEPT:
            state.accepted.append(spec)
            state.evidence.append(ref)
        elif verdict in (DROP, REJECT):
            state.denied.append(spec)
            state.evidence.append(ref)
        elif verdict == RETURN:
            state.evidence.append(ref)
            self._resume(table, spec, stack, state, depth + 1)
        elif verdict in (JUMP, GOTO):
            sub = self._sub(table, target, ref, state)
            if sub is None:
                return
            outcome = self._walk(table, sub, spec, state, depth + 1,
                                 here if verdict == JUMP else stack)
            # JUMP que retorna: ``spec`` segue na chain corrente, ja coberta
            # pelo percurso do universo restante. GOTO que retorna: ``spec``
            # volta para a chain chamadora.
            if verdict == GOTO and outcome in ("return", "end"):
                self._resume(table, spec, stack, state, depth + 1)

    def _resume(self, table: Table, spec: SourceSpec, stack: list[tuple[Chain, int]],
                state: _Walk, depth: int) -> None:
        """
        Continua a avaliacao de ``spec`` na chain chamadora; sem chamadora,
        aplica a policy da base chain.

        :param table: Table
        :param spec: SourceSpec
        :param stack: list[tuple[Chain, int]]
        :param state: _Walk
        :param depth: int
        :return: None
        """
        if depth > MAX_DEPTH:
            state.uncertain.append("profundidade maxima ao retornar de chain")
            return
        if not stack:
            policy = self._policy or ACCEPT
            (state.accepted if policy == ACCEPT else state.denied).append(spec)
            return
        chain, index = stack[-1]
        outcome = self._walk(table, chain, spec, state, depth + 1, stack[:-1], start=index)
        if outcome in ("return", "end"):
            self._resume(table, spec, stack[:-1], state, depth + 1)

    def evaluate_chain(self, table: Table, chain: Chain) -> _Walk:
        """
        Avalia uma base chain completa.

        :param table: Table
        :param chain: Chain
        :return: _Walk
        """
        state = _Walk()
        self._policy = chain.policy or ACCEPT
        outcome = self._walk(table, chain, None, state, 0, [])
        if outcome != "terminal":
            state.terminal = self._policy
            state.terminal_rule = f"{table.label()} {chain.name} policy {state.terminal}"
            state.evidence.append(state.terminal_rule)
        return state


def _combine(outer: SourceSpec | None, inner: SourceSpec | None) -> SourceSpec | None:
    """
    Combina a condicao herdada (jump condicional) com a condicao da regra.

    :param outer: SourceSpec | None
    :param inner: SourceSpec | None
    :return: SourceSpec | None
    """
    if outer is None:
        return inner
    if inner is None:
        return outer
    order = ["loopback", "private", "public", "broad"]
    kind = min(outer.kind, inner.kind, key=order.index)
    return SourceSpec(f"{outer.description} + {inner.description}", kind)


def summarize(state: _Walk, label: str) -> FirewallVerdict:
    """
    Normaliza o resultado de uma base chain em FirewallVerdict.

    :param state: _Walk
    :param label: str
    :return: FirewallVerdict
    """
    notes = list(dict.fromkeys(state.notes))
    if state.denied:
        notes.append("origens bloqueadas explicitamente: " +
                     "; ".join(spec.description for spec in state.denied[:10]))
    if state.uncertain:
        return FirewallVerdict(FirewallAccess.UNKNOWN, evidence=state.evidence,
                               notes=notes + [f"{label}: condicao nao interpretada: {item}"
                                              for item in state.uncertain])
    broad = [spec for spec in state.accepted if spec.kind == "broad"]
    if state.terminal == ACCEPT:
        return FirewallVerdict(FirewallAccess.ANY, sources=["any"], evidence=state.evidence,
                               notes=notes)
    if broad:
        return FirewallVerdict(FirewallAccess.ANY, sources=[spec.description for spec in broad],
                               evidence=state.evidence,
                               notes=notes + ["aceite com condicao ampla (nao restringe origem)"])
    public = [spec.description for spec in state.accepted if spec.kind == "public"]
    private = [spec.description for spec in state.accepted if spec.kind == "private"]
    loopback = [spec.description for spec in state.accepted if spec.kind == "loopback"]
    if public:
        return FirewallVerdict(FirewallAccess.RESTRICTED_SOURCE, sources=public + private,
                               evidence=state.evidence, notes=notes)
    if private:
        return FirewallVerdict(FirewallAccess.PRIVATE_ONLY, sources=private,
                               evidence=state.evidence, notes=notes)
    if loopback:
        return FirewallVerdict(FirewallAccess.LOCAL_ONLY, sources=loopback,
                               evidence=state.evidence, notes=notes)
    return FirewallVerdict(FirewallAccess.BLOCKED, evidence=state.evidence, notes=notes)


def intersect(verdicts: list[FirewallVerdict]) -> FirewallVerdict:
    """
    Combina verdicts de varias base chains do mesmo hook (o pacote precisa
    passar por todas). Prevalece o mais restritivo.

    :param verdicts: list[FirewallVerdict]
    :return: FirewallVerdict
    """
    chosen = max(verdicts, key=lambda item: RESTRICTIVENESS[item.access])
    evidence: list[str] = []
    notes: list[str] = []
    for item in verdicts:
        evidence.extend(item.evidence)
        notes.extend(item.notes)
    sources = chosen.sources
    if chosen.access == FirewallAccess.RESTRICTED_SOURCE:
        merged = [src for item in verdicts if item.access == FirewallAccess.RESTRICTED_SOURCE
                  for src in item.sources]
        sources = list(dict.fromkeys(merged))
    return FirewallVerdict(chosen.access, sources=sources,
                           evidence=list(dict.fromkeys(evidence)),
                           notes=list(dict.fromkeys(notes)), path=chosen.path)


def base_chains(ruleset: Ruleset, family: Family, hook: str) -> list[tuple[Table, Chain]]:
    """
    Lista as base chains de filtragem de um hook, em ordem de prioridade.

    :param ruleset: Ruleset
    :param family: Family
    :param hook: str
    :return: list[tuple[Table, Chain]]
    """
    found: list[tuple[Table, Chain]] = []
    for table in ruleset.tables:
        if not _table_applies(table, family):
            continue
        for chain in table.chains.values():
            if chain.hook == hook and chain.chain_type == "filter":
                found.append((table, chain))
    return sorted(found, key=lambda item: item[1].priority)


def evaluate(ruleset: Ruleset, probe: Probe) -> FirewallVerdict:
    """
    Avalia o acesso efetivo ao servico descrito pela sonda.

    Se a coleta do firewall para a familia nao foi completa, retorna
    UNKNOWN: falta de informacao nunca vira conclusao favoravel.

    :param ruleset: Ruleset
    :param probe: Probe
    :return: FirewallVerdict
    """
    status = ruleset.family_status.get(probe.family.value, "UNKNOWN")
    if status != "OK":
        return FirewallVerdict(FirewallAccess.UNKNOWN, path=probe.hook,
                               notes=[f"firewall {probe.family.value} nao coletado "
                                      f"integralmente ({status})"] + ruleset.notes)
    chains = base_chains(ruleset, probe.family, probe.hook)
    if not chains:
        return FirewallVerdict(FirewallAccess.ANY, sources=["any"], path=probe.hook,
                               evidence=[f"nenhuma chain de filtragem no hook {probe.hook} "
                                         f"({probe.family.value})"],
                               notes=list(ruleset.notes))
    evaluator = Evaluator(ruleset, probe)
    verdicts = []
    for table, chain in chains:
        state = evaluator.evaluate_chain(table, chain)
        verdict = summarize(state, f"{table.label()} {chain.name}")
        verdict.path = probe.hook
        verdicts.append(verdict)
    result = intersect(verdicts)
    result.notes.extend(note for note in ruleset.notes if note not in result.notes)
    return result
