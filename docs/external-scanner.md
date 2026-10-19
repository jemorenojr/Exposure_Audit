# Scanner externo

Módulos: `src/exposure_audit/scanner/`.

## Objetivo

Validar se as portas são alcançáveis a partir da Internet. O scanner **não**
decide se o serviço está protegido; ele fornece `ExternalEvidence` ao
correlator.

## Arquitetura recomendada

```text
Controlador ---SSH---> Host auditado
     |
     +---SSH---> Scanner externo ----Internet----> IP público do host
```

O scanner deve ficar fora da rede corporativa e fora de VPN/IPsec com o
ambiente auditado. `--external-scanner local` é aceito, mas gera aviso.

## Interface (`base.py`)

```python
class ExternalScanner:
    def scan_ports(target, tcp_ports, udp_ports) -> ScanResult
    def discover_ports(target) -> ScanResult
    def identify_services(target, tcp_ports) -> ScanResult
    def path_evidence(target) -> dict
```

Falhas são devolvidas em `ScanResult.error`, nunca como exceção que interrompa
o lote. Implementação atual: `NmapScanner` (`nmap_ssh.py`) sobre um
`CommandRunner` SSH ou local; não há acoplamento a provedor.

## Alvos

Por família, em ordem de preferência:

- IPv4: IPs públicos do inventário; senão endereços públicos do host; senão o
  próprio alvo SSH, se for IPv4 público;
- IPv6: IPv6 do inventário + endereços IPv6 globais do host, exceto
  `temporary`/`deprecated` (omitido com `--no-ipv6`).

Sem alvo na família, a evidência externa fica `scanned=false` com a nota
"nenhum IP publico ... conhecido para teste".

## Etapas

| Etapa | Comando nmap (base: `-n -Pn -oX - --max-retries 2 --max-rate N`, `-6` para IPv6) | Quando |
|-------|-----------------------------------------------------------|--------|
| Evidência de caminho | `ip route get <alvo>`, `ip xfrm policy` no scanner | sempre |
| Direcionado | `-sS` (ou `-sT`) + `-sU` `-p T:...,U:...` | sempre que há scanner |
| Independente | `-sS`/`-sT -p- --open` | exceto com `--no-fullscan` |
| Identificação | `-sS`/`-sT -sV --version-light -p <abertas>` | com `--identify-services` |

Portas do scan direcionado: portas de todos os serviços locais, exceto os que
escutam somente em loopback, mais as portas externas de NAT.

Sem root/`sudo -n` no scanner: TCP usa `-sT` e UDP não é testado (aviso no
log). Nenhum script NSE é executado; não há exploração nem autenticação.

## VPN/IPsec

`path_evidence` gera avisos, registrados no contexto do host e na evidência do
serviço, quando:

- a rota até o alvo sai por `lo` (o alvo é o próprio scanner);
- existem políticas XFRM no scanner (uma rota `/32` não garante desvio do
  IPsec);
- as políticas XFRM não puderam ser verificadas (sem privilégio).

## Estados

Ver a tabela em [classification.md](classification.md#estado-externo-externalstate).
Portas solicitadas que o nmap agrupa em `<extraports>` recebem o estado do
grupo quando existe um único grupo.

## Limitações conhecidas

- A taxa agregada no scanner pode chegar a `--workers × --scan-max-rate`.
- `-p-` em muitos hosts é demorado; ajuste `--scan-timeout` ou use
  `--no-fullscan`.
- UDP raramente produz resultado conclusivo (`open|filtered` → `UNKNOWN`).
- `UNREACHABLE` só ocorre se o nmap reportar host `down` (com `-Pn` isso é raro).
- O IP de origem do scanner não é comparado com as origens autorizadas do
  firewall; R05 registra a hipótese "scanner autorizado ou caminho não
  modelado".
