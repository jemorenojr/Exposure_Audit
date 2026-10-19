# Classificação

Fonte de verdade das regras: `src/exposure_audit/correlator/rules.py`. Toda
alteração de regra deve atualizar este documento no mesmo conjunto de mudanças.

## Entradas normalizadas

### Bind (`BindClass`)

| Valor | Quando |
|-------|--------|
| `LOCAL_ONLY` | loopback (`127.0.0.0/8`, `::1`, `::ffff:127.0.0.1`) |
| `PRIVATE_BIND` | RFC 1918, CGNAT `100.64.0.0/10`, ULA `fc00::/7`, link-local |
| `PUBLIC_BIND` | endereço público específico |
| `ALL_IPV4` | `0.0.0.0` |
| `ALL_IPV6` | `::` |

`*:porta` (socket dual-stack exibido pelo `ss`) gera um listener `ALL_IPV4` e
outro `ALL_IPV6`. Com vários sockets na mesma família, vale o bind mais amplo.

### Restrição de origem (`FirewallAccess`)

Resultado do avaliador de firewall (ver [firewall-analysis.md](firewall-analysis.md)):

| Valor | Significado |
|-------|-------------|
| `ANY` | qualquer origem da Internet é aceita (inclui ausência de regras) |
| `RESTRICTED_SOURCE` | aceito apenas para origens específicas que incluem endereços públicos |
| `PRIVATE_ONLY` | aceito apenas para redes privadas |
| `LOCAL_ONLY` | aceito apenas para loopback |
| `BLOCKED` | nenhuma origem externa aceita |
| `UNKNOWN` | firewall não coletado ou regra não interpretável no caminho |

### Estado externo (`ExternalState`)

| nmap | Normalizado |
|------|-------------|
| `open` | `OPEN` |
| `closed` | `CLOSED` |
| `filtered` | `FILTERED` |
| `open\|filtered`, `closed\|filtered`, `unfiltered` | `UNKNOWN` |
| host `down` | `UNREACHABLE` |

Por família, o estado do serviço é o mais aberto observado entre os IPs
públicos testados e as portas externas associadas (porta própria + portas de
NAT): `OPEN` > `FILTERED` > `CLOSED` > `UNREACHABLE`/`UNKNOWN`. Sem alvo ou sem
scan, a evidência é marcada como `scanned=false` e o estado é `UNKNOWN`.

## Regras (primeira que casa decide)

| ID | Condição | Resultado | Análise posterior |
|----|----------|-----------|-------------------|
| R01 | bind `LOCAL_ONLY` e externo ≠ `OPEN` | PROTEGIDO | não |
| R02 | firewall `LOCAL_ONLY` e externo ≠ `OPEN` | PROTEGIDO | não |
| R03 | família IPv6, host sem endereço IPv6 global, serviço não encaminhado, externo ≠ `OPEN` | PROTEGIDO | não |
| R04 | externo `OPEN` e firewall `ANY` | EXPOSTO | sim |
| R05 | externo `OPEN` e firewall `RESTRICTED_SOURCE` | PARCIAL | sim |
| R06 | externo `OPEN` e firewall `UNKNOWN` | EXPOSTO | sim |
| R07 | externo `OPEN` e firewall `BLOCKED`/`PRIVATE_ONLY`/`LOCAL_ONLY` | INDETERMINADO (inconsistência) | sim |
| R08 | firewall `BLOCKED` | PROTEGIDO | não |
| R09 | firewall `PRIVATE_ONLY` | PROTEGIDO | não |
| R10 | firewall `RESTRICTED_SOURCE` (externo ≠ `OPEN`) | PARCIAL | sim |
| R11 | bind `PRIVATE_BIND`, scan executado e externo `FILTERED`/`CLOSED` | PROTEGIDO | sim |
| R12 | firewall `ANY`, scan executado e externo `FILTERED`/`CLOSED` | INDETERMINADO (filtro upstream) | sim |
| R13 | firewall `ANY` (sem validação externa conclusiva) | INDETERMINADO | sim |
| R14 | firewall `UNKNOWN` (externo ≠ `OPEN`) | INDETERMINADO | sim |
| R99 | nenhuma anterior | INDETERMINADO | sim |

Observações:

- R06 classifica como EXPOSTO porque a exposição foi **observada**; a falta de
  dados sobre o firewall não pode reduzir uma evidência positiva de acesso.
- R07 sinaliza inconsistência (NAT não modelado, scanner dentro da rede
  autorizada, outro equipamento respondendo pelo IP).
- R08/R09 sem scan seguem a especificação (`external != OPEN AND firewall ==
  BLOCKED → PROTEGIDO`); a justificativa registra "sem validação externa".
- R11 considera o bind privado como proteção quando o teste externo foi
  negativo, mas marca análise posterior: o serviço continua acessível pela
  rede interna.
- R12 aplica a seção 15: `FILTERED` não significa `PROTEGIDO` sem evidência
  adicional no host.

## Agregação entre famílias

Cada família (IPv4/IPv6) do serviço é classificada separadamente. O serviço
recebe a classificação mais grave:

```text
EXPOSTO > INDETERMINADO > PARCIAL > PROTEGIDO
```

Exemplo (caso 5 da especificação): IPv4 `BLOCKED` + `FILTERED` → PROTEGIDO;
IPv6 `ANY` + `OPEN` → EXPOSTO; serviço → **EXPOSTO**. Quando as famílias têm
justificativas diferentes, o motivo lista ambas, começando pela mais grave.

Família sem verdict de firewall ou sem evidência externa recebe `UNKNOWN`
(nunca suposição favorável).

## Portas externas sem listener local

Portas `OPEN` no scan independente que não correspondem a nenhum serviço nem
a NAT local recebem `INDETERMINADO` com o motivo "possível DNAT/encaminhamento
upstream". A justificativa lista serviços locais com bind não-loopback que não
foram vistos abertos externamente, como candidatos a destino. A ferramenta não
assume porta externa = porta interna.

## Casos mínimos (seção 36) e testes

| Caso | Teste |
|------|-------|
| 1 `127.0.0.1:5432` → PROTEGIDO | `test_classifier.MandatoryCasesTest.test_case1_loopback` |
| 2 `0.0.0.0:443`, ANY, OPEN → EXPOSTO | `test_case2_exposed` |
| 3 `0.0.0.0:22`, origem /32, OPEN → PARCIAL | `test_case3_partial` |
| 4 `10.0.0.5:5432`, DROP, FILTERED → PROTEGIDO | `test_case4_private_drop` |
| 5 `[::]:22`, IPv4 protegido, IPv6 OPEN → EXPOSTO | `test_case5_ipv6_open` |
| 6 local 443, externo 8443 OPEN → possível DNAT | `test_pipeline.PipelineTest.test_redirect_mapped_to_service` (NAT local) e `test_external_only_port` (sem NAT local) |
| 7 firewall não coletado → INDETERMINADO | `test_case7_firewall_unknown` |
