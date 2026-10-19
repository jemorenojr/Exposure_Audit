# Análise de firewall

Módulos: `src/exposure_audit/collector/firewall/`.

## Objetivo

Determinar, para cada serviço e família IP, **quais origens da Internet
conseguem iniciar uma conexão**, seguindo o fluxo efetivo das regras do kernel.
Busca textual por porta (`iptables -L | grep 443`) nunca é usada.

## Coleta

| Comando | Uso |
|---------|-----|
| `iptables -V` | backend: `nf_tables` ou `legacy` |
| `nft -j list ruleset` | fonte estruturada nftables |
| `nft list ruleset` | evidência legível (não interpretada) |
| `iptables-save`, `ip6tables-save` | fonte iptables IPv4/IPv6 |
| `iptables-legacy-save`, `ip6tables-legacy-save` | regras legacy coexistindo com nf_tables |
| `iptables -nvL --line-numbers`, `iptables -t nat -nvL --line-numbers` | evidência legível (contadores) |
| `ipset save` | conteúdo de conjuntos usados em `-m set` |

Comandos privilegiados usam sudo quando disponível (`sudo -n` ou senha via
`--ask-sudo-password`; ver [architecture.md](architecture.md#segurança-operacional)).

## Mecanismos mistos (`loader.py`)

- Backend `nf_tables`: as tabelas `ip`/`ip6` `filter|nat|mangle|raw|security`
  que contêm chains `INPUT`/`FORWARD`/... aparecem tanto no `iptables-save`
  quanto no `nft`. Elas são lidas pelo parser iptables e **ignoradas** no nft,
  para não duplicar regras. Demais tabelas nft (ex.: `inet firewalld`) são
  lidas pelo parser nft.
- Regras em `iptables-legacy-save` (com backend `nf_tables`) também são
  avaliadas e geram nota.
- Backend `legacy`: todas as tabelas nft e iptables são avaliadas.

### Status de coleta por família

A família é avaliável (`OK`) somente se ao menos uma fonte foi lida e nenhuma
fonte presente falhou (ausência de comando não é falha). Caso contrário, todo
serviço da família recebe `FirewallAccess.UNKNOWN` com o motivo (ex.:
`PRIVILEGE_INSUFFICIENT`). Se `nft -j` não for suportado mas `nft list ruleset`
retornar vazio, o nftables é considerado sem regras.

## Modelo comum (`model.py`)

`Ruleset` → `Table` (origem, família `ip`/`ip6`/`inet`, chains, sets) →
`Chain` (hook, policy, prioridade, tipo) → `Rule` (protocolos, portas de
destino, origem/destino, interfaces, `ct state`, `ct status`, famílias,
limitação de taxa, condições parciais, condições desconhecidas, verdict).

Interpretação de condições relevantes:

| Condição | Tratamento |
|----------|-----------|
| `-p`, `meta l4proto`, `tcp dport` | casamento exato com a sonda |
| `--dport`, `--dports`, `tcp dport {..}`, `@set` de portas | intervalos de portas |
| `--ctstate`/`ct state` | a sonda é `new`; `ESTABLISHED,RELATED` não casa |
| `ct status dnat`/`--ctstatus DNAT` | casa somente no caminho DNAT |
| `-m addrtype --dst-type LOCAL`, `fib daddr type local`, `pkttype host` | casam; `BROADCAST`/`MULTICAST` não |
| `-i`/`iifname` | comparado com as interfaces externas do host (exclui `lo`, `docker*`, `br-*`, `veth*`...) |
| `-o`/`oifname` | assumido como casado (nota) |
| `-s`/`ip saddr`, `-m set ... src`, `@set`, `-m iprange` | condição de origem (ver abaixo) |
| `-d`/`ip daddr` | comparado com os endereços de destino do serviço |
| porta de origem, `--ports`, `--ctorigdstport` | condição **parcial** |
| `limit`, `hashlimit`, `recent`, `connlimit`, `quota` | limitação de taxa |
| `-m geoip`, `-m string`, `xt` (iptables-nft), `vmap` sobre chave não suportada, etc. | **desconhecida** |

Algumas versões do `nft` emitem `"xt": null` no JSON para extensões
iptables-nft que não conseguem traduzir (o nome da extensão se perde). A
condição é tratada como **desconhecida**, como qualquer `xt`. Se a leitura do
`nft -j` falhar por formato inesperado, a evidência nft vira `FAILED` e o
firewall da família fica desconhecido; o host não é interrompido.

## Avaliação (`evaluator.py`)

### Sonda

Pacote `NEW`, unicast, de origem externa arbitrária, para o protocolo/porta do
serviço, destinado aos endereços do serviço (bind específico, ou todos os
endereços não-loopback quando o bind é `0.0.0.0`/`::`), entrando por qualquer
interface externa.

- Serviço local: hook `input`, porta do serviço.
- Serviço via DNAT (Docker ou encaminhamento): hook `forward`, porta e
  endereço **após** a tradução, `dnat=true`.

### Percurso

As chains são percorridas na ordem real: regras em sequência, `jump`
(retorna), `goto` (não retorna), `return`, policy da base chain ao final.
Condições de origem são tratadas simbolicamente:

- origem qualquer → o verdict vale para todo o universo restante (encerra);
- origem específica/set → o verdict vale só para aquelas origens; o restante
  segue;
- `RETURN`/`goto` condicionais retomam a avaliação na chain chamadora para as
  origens afetadas (ex.: `DOCKER-USER -s X -j RETURN` seguido de `-j DROP`);
- regra desconhecida que poderia casar → incerteza → resultado `UNKNOWN`;
- `DROP`/`REJECT` com limitação de taxa não encerram (nota "limitação de
  taxa"); `ACCEPT` com limitação aceita (nota);
- `ACCEPT` com condição parcial (interface, porta de origem) é tratado como
  amplo; `DROP` parcial não encerra a avaliação.

Profundidade máxima de chains: 32 (proteção contra laços).

### Normalização

| Situação ao final | `FirewallAccess` |
|-------------------|------------------|
| alguma incerteza | `UNKNOWN` |
| universo restante aceito, ou aceite amplo | `ANY` |
| aceites com origens que incluem endereços públicos | `RESTRICTED_SOURCE` |
| aceites somente para redes privadas | `PRIVATE_ONLY` |
| aceites somente para loopback | `LOCAL_ONLY` |
| nenhum aceite | `BLOCKED` |
| família avaliável sem nenhuma base chain no hook | `ANY` |

Origens via set: com conteúdo coletado, o conteúdo define o tipo (e é
registrado); sem conteúdo, o set é tratado como restrição pública e registrado
como `set NOME (conteudo nao coletado)`. Origens negadas (`! -s 10.0.0.0/8`)
que excluem somente redes privadas casam com toda a Internet.

### Várias base chains no mesmo hook

nftables com várias chains `hook input` (prioridades diferentes) ou iptables +
nftables: o pacote precisa ser aceito por todas. O resultado é a interseção,
aproximada pelo mais restritivo:

```text
BLOCKED > LOCAL_ONLY > PRIVATE_ONLY > RESTRICTED_SOURCE > UNKNOWN > ANY
```

## NAT e Docker

`extract_nat` lê todas as regras `DNAT`/`REDIRECT`, inclusive em chains de
usuário (`DOCKER`):

- `REDIRECT` ou DNAT para endereço local → associado ao serviço da porta de
  destino; a porta externa passa a ser testada e atribuída a esse serviço;
- DNAT para outro endereço → serviço `forwarded`, avaliado no hook `forward`
  (chains `DOCKER-USER`, `DOCKER`...), rotulado `docker:<container>` quando
  há publicação correspondente em `docker inspect`;
- DNAT com destino restrito a loopback (Docker publicado em `127.0.0.1`) →
  ignorado, por não ser acionável externamente;
- DNAT com faixa > 32 portas ou sem porta → apenas nota no contexto.

A chain `INPUT` não representa a exposição de portas publicadas pelo Docker.

## Limitações conhecidas

- Tabelas `raw`/`mangle`, hooks `prerouting` de filtragem e `netdev ingress`
  não são avaliados. Como só poderiam bloquear, a análise pode superestimar a
  exposição, nunca subestimar.
- Interseção de várias base chains é aproximada pelo resultado mais restritivo.
- Origens sobrepostas (ex.: bloqueio de um IP dentro de uma faixa aceita) são
  registradas em notas, sem aritmética de conjuntos.
- `MARK`/`CONNMARK` usados para policy routing não são correlacionados.
- `bindv6only` é coletado mas não usado: sockets `[::]` são tratados como
  somente IPv6 e `*` como dual-stack, conforme exibidos pelo `ss`.
- Tabelas `ip filter` criadas manualmente no nftables, com backend
  `nf_tables` e nomes de chain idênticos aos do iptables, são confundidas com
  tabelas do iptables-nft.
