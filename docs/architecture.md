# Arquitetura

## Objetivo

Transformar evidências dispersas (sockets, endereços, firewall, NAT, Docker,
scan externo) em uma classificação de exposição **explicável** por serviço.

## Componentes

```text
                 ┌──────────────────────────── pipeline.py ───────────────────────────┐
 inventário ──►  │  collector/host.py ──► collector/normalize.py ──► HostState         │
 (texto/CSV/CLI) │        (SSH, read-only)       (parsers + firewall/evaluator)        │
                 │                                                                     │
                 │  scanner/nmap_ssh.py (ExternalScanner) ──► PortObservation           │
                 │                                                                     │
                 │  ServiceView + FirewallVerdict + ExternalEvidence + NetworkContext  │
                 │                         │                                           │
                 │                         ▼                                           │
                 │              correlator/classifier.py + rules.py                    │
                 └─────────────────────────┬───────────────────────────────────────────┘
                                           ▼
                              report/ (TXT, JSON, CSV, resumo)
```

| Componente | Módulos | Responsabilidade | Não faz |
|------------|---------|------------------|---------|
| collector  | `collector/host.py`, `network.py`, `sockets.py`, `docker.py`, `normalize.py` | executa comandos somente leitura e normaliza a saída | não decide exposição |
| firewall   | `collector/firewall/` (`model`, `iptables`, `nftables`, `loader`, `evaluator`) | converte rulesets em modelo comum e avalia o fluxo efetivo por serviço → `FirewallAccess` | não classifica o serviço |
| scanner    | `scanner/base.py`, `nmap_parser.py`, `nmap_ssh.py` | valida a visão externa (portas, estado, rota do scanner) | não interpreta proteção |
| correlator | `correlator/rules.py`, `classifier.py` | combina evidências e classifica com justificativa | não executa coleta |
| report     | `report/text.py`, `json_report.py`, `csv_report.py` | apresenta o resultado | não reclassifica |
| pipeline   | `pipeline.py` | único ponto que conhece os três componentes; monta serviços, sondas de firewall e evidência externa | — |
| CLI        | `main.py`, `inventory.py`, `ssh_client.py`, `validation.py` | entrada, paralelismo, execução de comandos, gravação | — |

## Contrato entre componentes

O contrato é `src/exposure_audit/models.py`. O correlator recebe apenas:

- `ServiceView` — protocolo, porta, listeners (bind por família), mapeamentos NAT;
- `FirewallVerdict` por família — `FirewallAccess` + origens + evidências;
- `ExternalEvidence` por família — `ExternalState` + observações;
- `NetworkContext` — hostname, presença de IPv6 global, alvos testados, notas.

Interface conceitual da especificação, implementada em
`correlator/classifier.py`:

```python
classify(service, firewall, external_scan, network_context) -> ServiceAssessment
```

Os testes de `tests/test_classifier.py` exercitam o correlator sem nenhum
coletor ou scanner, comprovando a independência.

## Fluxo por host

1. `collect_host` detecta privilégio (`id -u`, `sudo -n true` e, com
   `--ask-sudo-password`, `sudo -k -S true`) e executa a lista
   fixa `COMMANDS` de `collector/host.py`; cada resultado (status, stdout,
   stderr, duração) é preservado. Falha SSH interrompe o host imediatamente.
2. `normalize` produz `HostState`: endereços classificados, rotas, policy
   routing, XFRM, listeners, `Ruleset`, NAT e publicações Docker.
3. `build_services` agrupa listeners por protocolo/porta e incorpora NAT:
   `REDIRECT`/DNAT local é associado ao serviço de destino; DNAT para outro
   endereço (Docker, encaminhamento) vira serviço `forwarded`.
4. `evaluate_firewall` cria uma sonda por família (hook `input`, ou `forward`
   para serviços via DNAT) e chama o avaliador de firewall.
5. `run_external` executa, por IP público: evidência de caminho, scan
   direcionado, scan independente (opcional) e identificação (opcional).
6. `classify` aplica as regras de `docs/classification.md` por família e
   agrega.
7. `external_only` lista portas abertas externamente sem listener nem NAT local.

## Paralelismo e isolamento

- `ThreadPoolExecutor` com `--workers` hosts simultâneos.
- Cada host roda em `audit_host`, que captura qualquer exceção: um host
  problemático gera relatório com erro (`status` `ERROR`, preservando em `raw`
  o que já tinha sido coletado) e não interrompe o lote.
- Todos os comandos têm timeout (`--timeout` na coleta, `--scan-timeout` no nmap).
- O scanner é compartilhado entre threads; a taxa agregada no scanner pode
  chegar a `workers × scan-max-rate` pacotes/s.

## Segurança operacional

- Nunca `shell=True`; comandos são listas fixas. No SSH, o comando remoto é
  montado com `shlex.join` e precedido de `env LC_ALL=C PATH=...`.
- SSH com `BatchMode=yes`, `ConnectTimeout`, `ControlMaster` em diretório
  temporário `0700` removido ao final; nenhuma senha/chave é gravada em disco.
- Sudo, em ordem de preferência por host:
  1. root: sem sudo;
  2. `sudo -n` funcional: usado sem senha; a senha, se informada, é
     descartada para esse host;
  3. `--ask-sudo-password`: `sudo -k -S -p ''`, com a senha enviada pela
     entrada padrão do processo (canal SSH cifrado). Ela nunca aparece em
     argv, variável de ambiente, log, JSON ou relatório. `-k` força o sudo a
     consumir a senha mesmo com credencial em cache, para que ela nunca sobre
     na entrada padrão do comando executado. A senha é testada uma única vez
     por host (`sudo -k -S true`); falha faz o host seguir sem privilégio,
     sem novas tentativas;
  4. sem sudo: comandos privilegiados rodam sem ele e falhas são registradas
     como `PRIVILEGE_INSUFFICIENT`.
- A senha do sudo fica apenas na memória do processo durante a execução
  (strings Python não podem ser apagadas com garantia) e é enviada a todos os
  hosts do inventário que não aceitam `sudo -n`: um host comprometido do
  inventário pode capturá-la.
- Hostnames, IPs, portas, usuários SSH e IDs de container são validados antes
  de chegar a qualquer comando (`validation.py`); valores iniciados por `-`
  são rejeitados.
- Chaves de `ip xfrm state` são removidas (`sanitize_xfrm`) antes de gravar.

## Decisões de projeto

| Decisão | Motivo |
|---------|--------|
| Pacote em `src/exposure_audit/` em vez de `src/` com módulos soltos (sugestão da seção 34) | instalação via `pip install -e .` e imports absolutos estáveis; a separação lógica collector/scanner/correlator foi mantida, como exige a especificação |
| Sudo com senha opcional (`--ask-sudo-password`) em vez de exigir `sudo -n` | o responsável não quer alterar o sudoers dos hosts auditados (regras de segurança pré-existentes); a senha é pedida uma vez e só usada onde `sudo -n` falha |
| Uma única tentativa de senha por host | senha errada repetida a cada comando geraria várias falhas de autenticação e poderia bloquear a conta (`pam_faillock`) |
| Avaliador de firewall dentro de `collector/firewall/` | produz uma normalização (`FirewallAccess`), não a classificação final; a decisão continua no correlator |
| `nft -j` (JSON) como fonte nftables | saída estruturada e estável; o texto (`nft list ruleset`) é guardado apenas como evidência |
| Somente biblioteca padrão | facilita execução em servidores de salto sem acesso a PyPI |
| Relatório `json_report.py` em vez de `json.py` | evita confusão com o módulo `json` da biblioteca padrão |
| Faixas de documentação tratadas como públicas | permitem fixtures anonimizadas realistas; nunca ocorrem em produção |
| Gravidade de agregação `EXPOSTO > INDETERMINADO > PARCIAL > PROTEGIDO` | uma família desconhecida não pode ser mascarada por outra parcialmente controlada |

> Motivo da escolha de `ThreadPoolExecutor` (e não processos): não documentado
> na especificação; adotado porque o trabalho é dominado por espera de I/O
> (SSH e nmap).
