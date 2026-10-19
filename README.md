# Exposure Audit

Auditoria técnica de **exposição de serviços** em servidores Linux. Para cada
serviço, a ferramenta correlaciona estado local do host, bind, firewall efetivo,
restrição de origem, NAT e validação externa real, e produz uma classificação
explicável: `PROTEGIDO`, `PARCIAL`, `EXPOSTO` ou `INDETERMINADO`.

Não é ferramenta de pentest, scanner de vulnerabilidades, SIEM ou EDR. Opera
em modo **somente leitura**: não altera firewall, rotas, serviços ou pacotes,
não executa exploits nem brute force.

Especificação de origem: `docs/Agents/EXPOSURE_AUDIT_AGENT.md`, mantida em
repositório privado separado e não incluída neste repositório. As referências
a "seções" da especificação nos documentos de `docs/` apontam para ela.

## Princípio central

```text
PORTA EM LISTEN   != PORTA EXPOSTA
PORTA FILTRADA    != SERVIÇO SEGURO
```

A classificação resulta da correlação entre múltiplas evidências. Falta de
informação nunca vira conclusão favorável.

## Requisitos

| Onde               | Requisito                                                                                   |
|--------------------|---------------------------------------------------------------------------------------------|
| Controlador        | Python >= 3.10 (somente biblioteca padrão), cliente OpenSSH                                 |
| Hosts auditados    | acesso SSH por chave, `sudo` (sem senha ou com `--ask-sudo-password`), `iproute2` (`ip`, `ss`); `iptables`/`nftables`/`ipset`/`docker` quando existirem |
| Scanner externo    | acesso SSH por chave, `nmap`; root ou `sudo -n` para `-sS`/`-sU`                            |

## Instalação

```bash
cd Exposure_Audit
. ./ambiente.sh          # cria/ativa o venv em .env/usr e instala requirements.txt
```

O `requirements.txt` instala o próprio pacote em modo editável (`-e .`), o que
disponibiliza o comando `exposure-audit`. Sem o `ambiente.sh`:

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -e .
```

## Uso

```bash
exposure-audit \
    --hosts hosts.txt \
    --external-scanner scanner.example.net \
    --output output/
```

Exemplos de inventário: [hosts.example.txt](hosts.example.txt) e
[hosts.example.csv](hosts.example.csv).

| Opção                  | Descrição                                                                 | Padrão   |
|------------------------|---------------------------------------------------------------------------|----------|
| `--hosts ARQ`          | inventário texto ou `.csv`                                                | -        |
| `--output DIR`         | diretório base; cada execução cria `DIR/<yyyymmddHHMMSS>/`                | `output/` |
| `--host H`             | host adicional (repetível); `local` audita a própria máquina sem SSH      | -        |
| `--ssh-user/--ssh-port`| usuário/porta SSH padrão dos hosts                                        | `~/.ssh/config` |
| `--external-scanner H` | host do scanner via SSH, ou `local` (não recomendado)                     | sem scan |
| `--scanner-user/--scanner-port` | usuário/porta SSH do scanner                                     | -        |
| `--scan-type`          | `syn` ou `connect` (sem root no scanner cai para `connect`)               | `syn`    |
| `--scan-max-rate N`    | pacotes/s por execução do nmap                                            | 300      |
| `--scan-timeout S`     | timeout de cada execução do nmap                                          | 1800     |
| `--workers N`          | hosts auditados em paralelo                                               | 5        |
| `--timeout S`          | timeout de cada comando de coleta                                         | 30       |
| `--no-ipv6`            | não testar IPv6 externamente (evidência local IPv6 continua avaliada)     | -        |
| `--no-fullscan`        | não executar o scan independente `-p-`                                    | -        |
| `--no-udp-scan`        | não testar portas UDP                                                     | -        |
| `--identify-services`  | identificação leve (`nmap -sV --version-light`), sem NSE                  | -        |
| `--ask-sudo-password`  | pede a senha do sudo dos hosts auditados (ver abaixo)                     | -        |
| `--verbose/--debug`    | nível do log operacional no terminal                                      | -        |

### Sudo com senha

Sem privilégio, `nft`, `iptables-save`, `ipset`, os processos do `ss` e o
Docker não são coletados; o firewall fica desconhecido e a maioria dos
serviços resulta `INDETERMINADO`. Se o sudo dos hosts exige senha:

```bash
exposure-audit --hosts hosts.txt --ask-sudo-password --output output/
```

- a senha é pedida uma vez, sem eco, e vale para **todos** os hosts do
  inventário; hosts com senha diferente ficam sem privilégio;
- hosts onde `sudo -n` já funciona não recebem a senha;
- a senha é testada uma única vez por host; se falhar, a coleta desse host
  segue sem privilégio (aviso no terminal e em `audit.log`);
- `Defaults requiretty` no sudoers impede o modo com senha;
- a senha não vale para o scanner externo, que continua usando somente
  `sudo -n`.

Detalhes de segurança: [docs/architecture.md](docs/architecture.md#segurança-operacional).

Sem `--external-scanner`, a classificação usa somente evidências locais
(fase 3 da especificação): serviços sem restrição local ficam `INDETERMINADO`.

Código de saída: `0` todos os hosts auditados; `1` algum host falhou; `2` erro
de uso.

## Saídas

Cada execução grava em um subdiretório próprio de `--output`, nomeado pelo
instante de início em hora local (`yyyymmddHHMMSS`). Execuções diferentes
nunca se misturam nem se sobrescrevem; o caminho é mostrado no início da
execução (`Saida desta execucao: ...`).

```text
output/
└── 20261019140509/
    ├── raw/<host>.json     # evidências brutas + dados normalizados + decisão
    ├── reports/<host>.txt  # relatório por host, com evidências por serviço
    ├── exposicao.csv       # consolidado, uma linha por serviço
    ├── resumo.txt          # contadores + serviços por host/família (classificação e análise)
    └── audit.log           # log operacional (separado do resultado)
```

Formato detalhado: [docs/output-format.md](docs/output-format.md).

## Arquitetura resumida

```text
collector/   visão interna do host (coleta + normalização + análise de firewall)
scanner/     visão externa real (interface ExternalScanner + nmap via SSH)
correlator/  classificação determinística e justificada (componente principal)
report/      TXT, JSON e CSV
pipeline.py  orquestra os três componentes por host
main.py      CLI, paralelismo, gravação das saídas
```

O correlator depende apenas dos modelos normalizados (`models.py`); coletores e
scanners podem ser substituídos sem alterar a lógica de classificação.

## Documentação

| Documento | Conteúdo |
|-----------|----------|
| [docs/architecture.md](docs/architecture.md) | componentes, fluxo, contratos, decisões de projeto |
| [docs/classification.md](docs/classification.md) | regras R01–R99, agregação IPv4/IPv6, normalizações |
| [docs/firewall-analysis.md](docs/firewall-analysis.md) | iptables, nftables, ipset, NAT, Docker, mecanismos mistos |
| [docs/external-scanner.md](docs/external-scanner.md) | scanner externo, etapas, VPN/IPsec, limites |
| [docs/output-format.md](docs/output-format.md) | JSON, TXT, CSV, resumo e log |

## Testes

```bash
python -m unittest discover -s tests -t tests
```

Os testes usam fixtures em `tests/fixtures/` com o formato real das ferramentas
(`ss`, `ip`, `iptables-save`, `nft -j`, `ipset`, `docker inspect`, nmap XML) e
endereços anonimizados nas faixas de documentação (RFC 5737/3849).

## Limitações conhecidas

Resumo; detalhes em cada documento de `docs/`.

- firewall upstream, security groups, balanceadores e proxies não são
  observáveis a partir do host; quando influenciam o resultado, o serviço fica
  `INDETERMINADO`;
- tabelas `raw`/`mangle` e hooks `prerouting`/`ingress` não são avaliados
  (ignorá-los só pode superestimar a exposição, nunca subestimá-la);
- policy routing e XFRM são registrados como contexto, não modelados;
- DNAT com faixa maior que 32 portas ou sem porta específica é apenas anotado;
- UDP costuma resultar em `open|filtered` (normalizado como `UNKNOWN`).
