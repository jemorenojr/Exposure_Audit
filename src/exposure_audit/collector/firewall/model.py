# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : model.py
# Descricao   : Modelo comum de ruleset (iptables e nftables) usado pelo
#               avaliador de fluxo de regras.
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
Modelo de firewall independente de backend.

Os parsers de ``iptables-save`` e ``nft -j list ruleset`` produzem este
modelo; o avaliador (``evaluator.py``) percorre as chains na ordem real
de processamento do kernel. Nada aqui depende de busca textual por porta.
"""

from dataclasses import dataclass, field

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.1"

# Verdicts normalizados
ACCEPT = "ACCEPT"
DROP = "DROP"
REJECT = "REJECT"
RETURN = "RETURN"
JUMP = "JUMP"
GOTO = "GOTO"
CONTINUE = "CONTINUE"
DNAT = "DNAT"
REDIRECT = "REDIRECT"
UNKNOWN = "UNKNOWN"
VMAP = "VMAP"

TERMINAL_VERDICTS = frozenset({ACCEPT, DROP, REJECT})


@dataclass
class AddressMatch:
    """Condicao sobre endereco de origem ou destino."""

    networks: list[str] = field(default_factory=list)
    set_name: str | None = None
    negated: bool = False


@dataclass
class IfaceMatch:
    """Condicao sobre interface de entrada/saida."""

    names: list[str]
    negated: bool = False


@dataclass
class VmapEntry:
    """Entrada de verdict map do nftables."""

    values: list[str]
    verdict: str
    target: str | None = None


@dataclass
class Rule:
    """
    Regra normalizada.

    ``unknown`` lista condicoes nao interpretadas; ``never_matches``
    indica condicao que nunca casa com um pacote unicast novo vindo da
    Internet (ex.: ``--dst-type BROADCAST``, ``ct status dnat`` fora do
    caminho DNAT). ``partial`` lista condicoes que podem ou nao casar,
    independentemente da origem (ex.: porta de origem, controlada pelo
    cliente): ACCEPT parcial e tratado como amplo; DROP parcial nao
    encerra a avaliacao.
    """

    chain: str
    index: int
    text: str
    verdict: str = CONTINUE
    target: str | None = None
    protocols: list[str] | None = None
    proto_negated: bool = False
    dports: list[tuple[int, int]] | None = None
    dport_set: str | None = None
    dport_negated: bool = False
    partial: list[str] = field(default_factory=list)
    src: AddressMatch | None = None
    dst: AddressMatch | None = None
    in_iface: IfaceMatch | None = None
    out_iface: IfaceMatch | None = None
    ct_states: list[str] | None = None
    ct_negated: bool = False
    ct_status_dnat: bool | None = None
    families: list[str] | None = None
    rate_limited: bool = False
    never_matches: str | None = None
    unknown: list[str] = field(default_factory=list)
    vmap_key: str | None = None
    vmap: list[VmapEntry] = field(default_factory=list)
    nat_to_address: str | None = None
    nat_to_port: int | None = None


@dataclass
class Chain:
    """Chain de um backend. Base chains possuem hook e policy."""

    name: str
    hook: str | None = None
    policy: str | None = None
    priority: int = 0
    chain_type: str = "filter"
    rules: list[Rule] = field(default_factory=list)


@dataclass
class Table:
    """
    Tabela de um backend.

    ``family`` segue o nftables: ``ip``, ``ip6``, ``inet``. Para iptables
    usa-se ``ip`` (iptables-save) ou ``ip6`` (ip6tables-save).
    """

    origin: str
    family: str
    name: str
    chains: dict[str, Chain] = field(default_factory=dict)
    sets: dict[str, list[str]] = field(default_factory=dict)

    def label(self) -> str:
        """
        Identificacao legivel da tabela para evidencias.

        :return: str
        """
        return f"{self.origin}:{self.family}/{self.name}"


@dataclass
class Ruleset:
    """Conjunto de tabelas coletadas de todos os backends."""

    tables: list[Table] = field(default_factory=list)
    ipsets: dict[str, list[str]] = field(default_factory=dict)
    family_status: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
