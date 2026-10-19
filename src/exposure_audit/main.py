# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : main.py
# Descricao   : Interface de linha de comando do Exposure Audit.
# Author      : Jose Edson Moreno Jr.
# Email       : edson.moreno@gmail.com
# Versao      : 0.3
# Data        : 2026-10-19
# copyright   : (c) 2026 by Edson Moreno
# Parametros  : --hosts, --host, --external-scanner, --output, --workers,
#               --timeout e demais opcoes (ver --help)
# Opcoes      : --no-ipv6, --no-fullscan, --no-udp-scan,
#               --identify-services, --ask-sudo-password, --verbose, --debug
#
# Retorno     : 0 = todos os hosts auditados; 1 = algum host falhou;
#               2 = erro de uso/configuracao
#
# CHANGELOG   : 2026-10-19: opcao --ask-sudo-password (senha do sudo
#               dos hosts auditados, solicitada uma vez no terminal).
#               2026-10-19: erro na analise preserva a coleta bruta.
#               2026-10-19: cada execucao grava em <output>/<yyyymmddHHMMSS>/.
#
############################################################################

"""
CLI do Exposure Audit.

Exemplo::

    exposure-audit --hosts hosts.txt \\
        --external-scanner scanner.example.net \\
        --output output/

Cada execucao grava em um subdiretorio proprio de ``--output``, nomeado
pelo instante de inicio (hora local, ``yyyymmddHHMMSS``), para que
execucoes diferentes nunca se misturem.

O log operacional (``audit.log``) fica separado do resultado da
auditoria (``raw/``, ``reports/``, ``exposicao.csv``, ``resumo.txt``).
"""

import argparse
import getpass
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from exposure_audit import __version__ as package_version
from exposure_audit.collector.host import collect_host
from exposure_audit.inventory import HostEntry, load_inventory
from exposure_audit.pipeline import AuditOptions, HostReport, analyze
from exposure_audit.report.csv_report import render_csv
from exposure_audit.report.json_report import render_json
from exposure_audit.report.text import render_host, render_summary
from exposure_audit.scanner.base import ExternalScanner
from exposure_audit.scanner.nmap_ssh import NmapScanner
from exposure_audit.ssh_client import CommandRunner, LocalRunner, SSHRunner, is_local_target
from exposure_audit.validation import validate_positive_int

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.3"

LOG = logging.getLogger("exposure_audit")


def build_parser() -> argparse.ArgumentParser:
    """
    Define os argumentos da CLI.

    :return: argparse.ArgumentParser
    """
    parser = argparse.ArgumentParser(
        prog="exposure-audit",
        description="Auditoria tecnica de exposicao de servicos em hosts Linux "
                    "(somente leitura).")
    parser.add_argument("--hosts", type=Path, help="inventario (texto ou .csv)")
    parser.add_argument("--host", action="append", default=[],
                        help="host adicional (repetivel); 'local' audita esta maquina")
    parser.add_argument("--ssh-user", help="usuario SSH padrao dos hosts")
    parser.add_argument("--ssh-port", type=int, help="porta SSH padrao dos hosts")
    parser.add_argument("--external-scanner",
                        help="host do scanner externo via SSH, ou 'local' (nao recomendado)")
    parser.add_argument("--scanner-user", help="usuario SSH do scanner")
    parser.add_argument("--scanner-port", type=int, help="porta SSH do scanner")
    parser.add_argument("--scan-type", choices=("syn", "connect"), default="syn",
                        help="tipo de scan TCP (padrao: syn; cai para connect sem root)")
    parser.add_argument("--scan-max-rate", type=int, default=300,
                        help="pacotes/s maximo por execucao do nmap (padrao: 300)")
    parser.add_argument("--scan-timeout", type=int, default=1800,
                        help="timeout de cada execucao do nmap em segundos (padrao: 1800)")
    parser.add_argument("--output", type=Path, default=Path("output"),
                        help="diretorio base de saida; cada execucao cria "
                             "<output>/<yyyymmddHHMMSS>/ (padrao: output/)")
    parser.add_argument("--workers", type=int, default=5, help="hosts em paralelo (padrao: 5)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="timeout por comando de coleta em segundos (padrao: 30)")
    parser.add_argument("--no-ipv6", action="store_true", help="nao testar IPv6 externamente")
    parser.add_argument("--no-fullscan", action="store_true",
                        help="nao executar scan independente de todas as portas TCP")
    parser.add_argument("--no-udp-scan", action="store_true", help="nao testar portas UDP")
    parser.add_argument("--identify-services", action="store_true",
                        help="identificacao leve de servicos (nmap -sV --version-light)")
    parser.add_argument("--ask-sudo-password", action="store_true",
                        help="solicita a senha do sudo dos hosts auditados (mesma senha "
                             "para todos); usada apenas onde 'sudo -n' nao funciona")
    parser.add_argument("--verbose", action="store_true", help="log informativo no terminal")
    parser.add_argument("--debug", action="store_true", help="log de depuracao")
    parser.add_argument("--version", action="version", version=f"%(prog)s {package_version}")
    return parser


def create_run_dir(base: Path, started: datetime) -> Path:
    """
    Cria o diretorio exclusivo da execucao, ``<base>/<yyyymmddHHMMSS>``,
    com ``raw/`` e ``reports/``. Se outra execucao ja usou o mesmo segundo,
    acrescenta ``_2``, ``_3``... em vez de misturar ou sobrescrever saidas.

    :param base: Path
    :param started: datetime
    :return: Path
    """
    base.mkdir(parents=True, exist_ok=True)
    stamp = started.strftime("%Y%m%d%H%M%S")
    candidate = base / stamp
    suffix = 1
    while True:
        try:
            candidate.mkdir()
            break
        except FileExistsError:
            suffix += 1
            candidate = base / f"{stamp}_{suffix}"
    for sub in ("raw", "reports"):
        (candidate / sub).mkdir()
    return candidate


def setup_logging(output: Path, verbose: bool, debug: bool) -> None:
    """
    Configura log operacional em arquivo e no terminal.

    :param output: Path
    :param verbose: bool
    :param debug: bool
    :return: None
    """
    LOG.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(threadName)s %(name)s: %(message)s")
    file_handler = logging.FileHandler(output / "audit.log", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    file_handler.setFormatter(fmt)
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if debug else logging.INFO if verbose else logging.WARNING)
    console.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    LOG.handlers = [file_handler, console]


def build_scanner(args: argparse.Namespace) -> ExternalScanner | None:
    """
    Cria o scanner externo configurado (ou None).

    :param args: argparse.Namespace
    :return: ExternalScanner | None
    """
    if not args.external_scanner:
        LOG.warning("sem --external-scanner: classificacao somente com evidencias locais")
        return None
    runner: CommandRunner
    if is_local_target(args.external_scanner):
        LOG.warning("scanner local: a estacao pode nao representar a visao da Internet "
                    "(VPN/IPsec); evidencias de rota serao registradas")
        runner = LocalRunner(args.scan_timeout)
    else:
        runner = SSHRunner(args.external_scanner, args.scan_timeout,
                           user=args.scanner_user, port=args.scanner_port)
    scanner = NmapScanner(runner, scan_type=args.scan_type, max_rate=args.scan_max_rate,
                          timeout=args.scan_timeout, scan_udp=not args.no_udp_scan)
    check = scanner.available()
    if not check.ok:
        LOG.error("nmap indisponivel no scanner %s (%s): %s", runner.name,
                  check.status.value, check.stderr.strip()[:200])
        scanner.close()
        return None
    for note in scanner.notes:
        LOG.warning("scanner: %s", note)
    return scanner


def host_runner(entry: HostEntry, args: argparse.Namespace,
                sudo_password: str | None = None) -> CommandRunner:
    """
    Cria o executor de comandos do host.

    :param entry: HostEntry
    :param args: argparse.Namespace
    :param sudo_password: str | None
    :return: CommandRunner
    """
    runner: CommandRunner
    if is_local_target(entry.host):
        runner = LocalRunner(args.timeout)
    else:
        runner = SSHRunner(entry.host, args.timeout, user=entry.ssh_user or args.ssh_user,
                           port=entry.ssh_port or args.ssh_port)
    runner.sudo_password = sudo_password
    return runner


def read_sudo_password() -> str | None:
    """
    Solicita a senha do sudo no terminal, sem eco. Senha vazia equivale a
    nao informar senha.

    :return: str | None
    """
    password = getpass.getpass("Senha do sudo (hosts auditados): ")
    if not password:
        LOG.warning("senha do sudo vazia: coleta usara apenas 'sudo -n'")
        return None
    if "\n" in password or "\r" in password:
        raise ValueError("senha do sudo nao pode conter quebra de linha")
    return password


def audit_host(entry: HostEntry, args: argparse.Namespace, scanner: ExternalScanner | None,
               options: AuditOptions, sudo_password: str | None = None) -> HostReport:
    """
    Audita um host isoladamente. Nenhuma excecao escapa: falhas viram
    HostReport com erro, para nao interromper o lote.

    :param entry: HostEntry
    :param args: argparse.Namespace
    :param scanner: ExternalScanner | None
    :param options: AuditOptions
    :param sudo_password: str | None
    :return: HostReport
    """
    LOG.info("%s: inicio", entry.name)
    runner: CommandRunner | None = None
    raw: dict[str, object] = {}
    try:
        runner = host_runner(entry, args, sudo_password)
        raw = collect_host(runner)
        runner.close()
        runner = None
        if raw.get("status") != "OK":
            LOG.error("%s: falha SSH", entry.name)
        report = analyze(entry, raw, scanner, options)
    except Exception as exc:  # noqa: BLE001 - isolamento por host
        LOG.exception("%s: erro inesperado", entry.name)
        # Preserva a coleta bruta para diagnostico (raw/<host>.json).
        report = HostReport(name=entry.name, target=entry.host, status="ERROR",
                            raw=raw, error=f"erro inesperado: {exc}")
    finally:
        if runner is not None:
            runner.close()
    LOG.info("%s: fim (%s)", entry.name, report.status)
    return report


def write_host(report: HostReport, output: Path) -> None:
    """
    Grava JSON bruto e relatorio texto do host.

    :param report: HostReport
    :param output: Path
    :return: None
    """
    (output / "raw" / f"{report.name}.json").write_text(render_json(report), encoding="utf-8")
    (output / "reports" / f"{report.name}.txt").write_text(render_host(report),
                                                            encoding="utf-8")


def validate_args(args: argparse.Namespace) -> None:
    """
    Valida limites numericos da CLI.

    :param args: argparse.Namespace
    :return: None
    """
    validate_positive_int(args.workers, "workers", 64)
    validate_positive_int(args.timeout, "timeout", 3600)
    validate_positive_int(args.scan_timeout, "scan-timeout", 86400)
    validate_positive_int(args.scan_max_rate, "scan-max-rate", 100000)


def main(argv: list[str] | None = None) -> int:
    """
    Ponto de entrada da CLI.

    :param argv: list[str] | None
    :return: int
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        validate_args(args)
        entries = load_inventory(args.hosts, args.host)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if not entries:
        parser.error("nenhum host informado (--hosts ou --host)")

    try:
        output = create_run_dir(args.output, datetime.now())
    except OSError as exc:
        parser.error(f"nao foi possivel criar o diretorio de saida: {exc}")
    sys.stderr.write(f"Saida desta execucao: {output}\n")
    setup_logging(output, args.verbose, args.debug)
    LOG.info("exposure-audit %s: %d host(s), %d worker(s)", package_version, len(entries),
             args.workers)

    sudo_password: str | None = None
    if args.ask_sudo_password:
        try:
            sudo_password = read_sudo_password()
        except ValueError as exc:
            parser.error(str(exc))
        except (EOFError, KeyboardInterrupt):
            parser.error("leitura da senha do sudo cancelada")

    try:
        scanner = build_scanner(args)
    except ValueError as exc:
        parser.error(str(exc))
    options = AuditOptions(ipv6=not args.no_ipv6, fullscan=not args.no_fullscan,
                           identify=args.identify_services)

    reports: list[HostReport] = []
    try:
        with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="host") as pool:
            futures = {pool.submit(audit_host, entry, args, scanner, options,
                                   sudo_password): entry
                       for entry in entries}
            for future in as_completed(futures):
                report = future.result()
                write_host(report, output)
                reports.append(report)
    finally:
        sudo_password = None
        if scanner is not None:
            scanner.close()

    order = {entry.name: index for index, entry in enumerate(entries)}
    reports.sort(key=lambda item: order.get(item.name, 0))
    (output / "exposicao.csv").write_text(render_csv(reports), encoding="utf-8")
    summary = render_summary(reports)
    (output / "resumo.txt").write_text(summary, encoding="utf-8")
    sys.stdout.write(summary)
    LOG.info("concluido: resultados em %s", output)
    return 1 if any(report.error for report in reports) else 0


if __name__ == "__main__":
    sys.exit(main())
