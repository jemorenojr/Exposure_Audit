# Formato das saídas

Cada execução grava em `<output>/<yyyymmddHHMMSS>/`, onde `<output>` é o
diretório base definido por `--output` (padrão `output/`) e o nome do
subdiretório é o instante de início da execução, em hora local:

```text
output/
├── 20261019140509/
│   ├── raw/<host>.json
│   ├── reports/<host>.txt
│   ├── exposicao.csv
│   ├── resumo.txt
│   └── audit.log
└── 20261019153012/
    └── ...
```

- Execuções diferentes nunca compartilham diretório: se duas começarem no
  mesmo segundo, a segunda recebe sufixo (`20261019140509_2`).
- O caminho da execução é escrito no stderr ao iniciar
  (`Saida desta execucao: ...`) e registrado no fim do `audit.log`.
- Diretórios antigos não são removidos pela ferramenta.

`<host>` é o campo `name` do inventário (padrão: o próprio host SSH).

## `raw/<host>.json`

Permite auditar a decisão do correlator: contém a coleta bruta, os dados
normalizados e o resultado. `schema_version` = `"1"`.

| Campo | Conteúdo |
|-------|----------|
| `schema_version`, `tool_version`, `generated` | versão do formato, da ferramenta e data UTC |
| `name`, `target`, `status`, `error`, `hostname` | identificação; `status` = `OK`, `SSH_FAILED` ou `ERROR` |
| `addresses` | endereços com `interface`, `family`, `address`, `prefixlen`, `scope`, `flags` |
| `routing` | `default_v4`, `default_v6`, `route_get`, `policy_rules`, `extra_tables`, `xfrm_policies` |
| `listeners` | sockets: `protocol`, `family`, `address`, `port`, `bind_class`, `process`, `pid`, `bound_interface`, `dual_stack` |
| `firewall` | `family_status`, `tables` avaliadas, `ipsets`, `notes` |
| `nat` | mapeamentos DNAT/REDIRECT |
| `docker` | publicações de containers |
| `external_scan` | `available`, `targets`, `path` (evidência de rota do scanner), `notes`, `scans` (argv, erro, observações) |
| `context` | `NetworkContext` usado pelo correlator |
| `services` | resultado por serviço (abaixo) |
| `issues` | comandos que falharam (exceto ferramentas opcionais ausentes) |
| `raw` | coleta bruta: `privilege` (`mode`: `root`, `sudo`, `sudo_password`, `PRIVILEGE_INSUFFICIENT` ou `unreachable`; testes `uid_check`, `sudo_check`, `sudo_password_check`) e `commands.<chave>` com `argv`, `status`, `returncode`, `sudo`, `duration`, `stdout`, `stderr` |

Serviço (resumido):

```json
{
  "protocol": "tcp",
  "port": 443,
  "service": "HTTPS",
  "process": "nginx",
  "local_active": true,
  "kind": "local",
  "classification": "EXPOSTO",
  "reason": "acesso permitido a qualquer origem e confirmado externamente (OPEN)",
  "followup": true,
  "bind": ["0.0.0.0"],
  "firewall_access": {"ipv4": "ANY"},
  "external_state": {"ipv4": "OPEN"},
  "external_ports": [443, 8443],
  "evidence": ["[ipv4] regra R04: bind=ALL_IPV4 firewall=ANY externo=OPEN"],
  "families": [
    {
      "family": "ipv4",
      "bind_class": "ALL_IPV4",
      "bind_addresses": ["0.0.0.0"],
      "firewall": {"access": "ANY", "sources": ["any"], "evidence": [], "notes": [], "path": "input"},
      "external": {"state": "OPEN", "scanned": true, "observations": [], "notes": []},
      "classification": "EXPOSTO",
      "reason": "acesso permitido a qualquer origem e confirmado externamente (OPEN)",
      "rule_id": "R04",
      "followup": true
    }
  ]
}
```

`kind`: `local` (listener no host), `forwarded` (DNAT para container/outro
host) ou `external-only` (aberta externamente sem listener nem NAT local).

Saídas de `ip xfrm state` têm chaves substituídas por `<redacted>`.

## `reports/<host>.txt`

```text
HOST: srv-web-01
ALVO SSH: srv-web-01.example.net
SO: Debian GNU/Linux 12 (bookworm)
IP INTERNO: 203.0.113.5
IP PUBLICO: 203.0.113.5, 2001:db8:10::5

5432/tcp POSTGRESQL (postgres)
LOCAL:          ATIVO
BIND:           10.0.0.5
FIREWALL:       SOMENTE REDES PRIVADAS
EXTERNO:        FILTERED
CLASSIFICACAO:  PROTEGIDO
MOTIVO:         firewall permite somente redes privadas (10.0.0.0/8); teste externo FILTERED
    - [ipv4] regra R09: bind=PRIVATE_BIND firewall=PRIVATE_ONLY externo=FILTERED
    - [ipv4] firewall: iptables-nft:ip/filter INPUT#8: -A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 5432 -j ACCEPT
    - [ipv4] firewall: iptables-nft:ip/filter INPUT policy DROP
    - [ipv4] nota: backend iptables: nf_tables
    - [ipv4] externo: 203.0.113.5:5432/tcp filtered
```

(Trecho gerado a partir das fixtures de `tests/fixtures/`.)

Seguido das seções `CONTEXTO` (policy routing, XFRM, NAT não detalhado,
avisos do scanner) e `PROBLEMAS DE COLETA`. Quando há várias famílias com
estados diferentes, `EXTERNO` mostra `ipv4=...;ipv6=...`. `ANALISE POSTERIOR:
sim` indica necessidade de avaliar controles adicionais.

## `exposicao.csv`

Uma linha por serviço; hosts com falha geram uma linha com
`protection=INDETERMINADO`.

| Coluna | Conteúdo |
|--------|----------|
| `hostname` | hostname coletado (ou nome do inventário) |
| `ip` | IP de origem da rota default |
| `public_ip` | IPs testados externamente, separados por `;` |
| `port`, `protocol`, `service` | identificação do serviço |
| `local_status` | `ATIVO`, `DNAT` (sem listener, via NAT), `SEM_LISTENER` (external-only) ou status de falha do host |
| `bind_address` | binds separados por ` / `; `N/A (DNAT)` |
| `external_status` | estado externo; `ipv4=X;ipv6=Y` quando divergente |
| `protection` | `PROTEGIDO`, `PARCIAL`, `EXPOSTO`, `INDETERMINADO` |
| `reason` | justificativa |

## `resumo.txt`

Também é impresso no stdout. Duas partes:

1. contadores: hosts, falhas, serviços locais, serviços expostos externamente
   e total por classificação (contagem por serviço, classificação agregada);
2. `SERVICOS POR HOST`: para cada host, agrupado por família IP (`ipv4`,
   depois `ipv6`), **todos** os serviços com nome, porta/protocolo,
   classificação **daquela família** e a análise (motivo) correspondente, em
   colunas alinhadas.

```text
srv-web-01 - ipv4:  SSH            22/tcp     PARCIAL       - permitido somente para 203.0.113.10/32; ...
                    HTTPS          443/tcp    EXPOSTO       - acesso permitido a qualquer origem e confirmado externamente (OPEN)
                    REDIS          6379/tcp   PROTEGIDO     - escuta somente em loopback (127.0.0.1)
             ipv6:  SSH            22/tcp     EXPOSTO       - acesso permitido a qualquer origem e confirmado externamente (OPEN)

srv-db-02  - ERRO: erro inesperado: ...
```

- o nome do host é o `hostname` coletado (ou o `name` do inventário);
- a classificação é uma de `PROTEGIDO`, `PARCIAL`, `EXPOSTO` ou
  `INDETERMINADO`;
- um serviço aparece na família em que foi avaliado; serviços só IPv4 não
  aparecem em `ipv6`;
- serviços `external-only` (porta aberta externamente sem listener local)
  aparecem na família do IP em que foram observados, com classificação
  `INDETERMINADO`;
- host com falha mostra `ERRO: <motivo>`; host sem serviços mostra
  `nenhum servico identificado`.

"Serviços expostos externamente" conta serviços com algum estado externo
`OPEN` (inclui `external-only`).

## `audit.log`

Log operacional, separado do resultado: início/fim por host, falha SSH,
timeout, comando ausente, privilégio insuficiente, falhas do scanner e
exceções. Nível `INFO` (ou `DEBUG` com `--debug`).
