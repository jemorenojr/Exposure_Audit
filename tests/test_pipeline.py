# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : test_pipeline.py
# Descricao   : Teste ponta a ponta do pipeline (coleta bruta sintetica +
#               scanner falso), CSV, inventario e executor de comandos.
# Author      : Jose Edson Moreno Jr.
# Email       : edson.moreno@gmail.com
# Versao      : 0.3
# Data        : 2026-10-19
# copyright   : (c) 2026 by Edson Moreno
# Parametros  :
# Opcoes      :
#
# Retorno     :
#
# CHANGELOG   : 2026-10-19: testes do modo sudo com senha.
#               2026-10-19: teste do diretorio de saida por execucao.
#               2026-10-19: teste do layout do resumo por host/familia.
#
############################################################################

"""
Testes de integracao do pipeline e componentes de borda.
"""

import csv
import io
import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from helpers import FakeScanner, web_raw

from exposure_audit.collector.host import collect_host
from exposure_audit.inventory import make_entry, parse_csv, parse_text
from exposure_audit.main import create_run_dir
from exposure_audit.models import Classification, CommandStatus
from exposure_audit.pipeline import AuditOptions, analyze
from exposure_audit.report.csv_report import COLUMNS, render_csv
from exposure_audit.report.json_report import render_json
from exposure_audit.report.text import render_host, render_summary
from exposure_audit.ssh_client import CommandRunner, classify_failure

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.3"


def scanner() -> FakeScanner:
    """
    Scanner falso do host de referencia.

    :return: FakeScanner
    """
    return FakeScanner(
        targeted={"203.0.113.5": "nmap_targeted_v4.xml",
                  "2001:db8:10::5": "nmap_targeted_v6.xml"},
        discovery={"203.0.113.5": "nmap_discovery_v4.xml"})


class PipelineTest(unittest.TestCase):
    """Fluxo completo com dados sinteticos."""

    def setUp(self) -> None:
        """
        Executa a analise uma vez.

        :return: None
        """
        self.scanner = scanner()
        self.report = analyze(make_entry("srv-web-01"), web_raw(), self.scanner, AuditOptions())
        self.by_port = {(s.protocol, s.port): s for s in self.report.services}

    def cls(self, port: int, protocol: str = "tcp") -> Classification:
        """
        Classificacao de um servico.

        :param port: int
        :param protocol: str
        :return: Classification
        """
        return self.by_port[(protocol, port)].classification

    def test_targets(self) -> None:
        """
        Alvos: IPv4 publico e IPv6 global nao temporario.

        :return: None
        """
        self.assertEqual(self.report.public_ips, ["203.0.113.5", "2001:db8:10::5"])
        self.assertIn(("discovery", "203.0.113.5"), self.scanner.calls)

    def test_classifications(self) -> None:
        """
        Classificacao esperada por servico do host de referencia.

        :return: None
        """
        self.assertEqual(self.cls(22), Classification.EXPOSTO)          # IPv6 aberto
        self.assertEqual(self.cls(443), Classification.EXPOSTO)
        self.assertEqual(self.cls(5432), Classification.PROTEGIDO)
        self.assertEqual(self.cls(6379), Classification.PROTEGIDO)
        self.assertEqual(self.cls(8081), Classification.PROTEGIDO)
        self.assertEqual(self.cls(9100), Classification.INDETERMINADO)  # IPv6 filtrado upstream
        self.assertEqual(self.cls(8080), Classification.EXPOSTO)        # Docker via FORWARD
        self.assertEqual(self.cls(53, "udp"), Classification.PROTEGIDO)
        self.assertEqual(self.cls(51820, "udp"), Classification.INDETERMINADO)

    def test_ssh_ipv4_partial(self) -> None:
        """
        SSH IPv4 restrito a IPs administrativos -> PARCIAL nessa familia.

        :return: None
        """
        v4 = [f for f in self.by_port[("tcp", 22)].families if f.family.value == "ipv4"][0]
        self.assertEqual(v4.classification, Classification.PARCIAL)
        self.assertIn("203.0.113.10/32", v4.reason)

    def test_redirect_mapped_to_service(self) -> None:
        """
        REDIRECT 8443->443 associado ao servico 443 (nao vira porta orfa).

        :return: None
        """
        self.assertIn(8443, self.by_port[("tcp", 443)].external_ports)
        self.assertNotIn(("tcp", 8443), self.by_port)

    def test_docker(self) -> None:
        """
        Porta Docker rotulada; publicacao em 127.0.0.1 ignorada.

        :return: None
        """
        web = self.by_port[("tcp", 8080)]
        self.assertEqual(web.kind, "forwarded")
        self.assertEqual(web.process, "docker:webapp")
        self.assertNotIn(("tcp", 9000), self.by_port)

    def test_external_only_port(self) -> None:
        """
        Porta 10443 aberta sem listener: possivel DNAT upstream.

        :return: None
        """
        orphan = self.by_port[("tcp", 10443)]
        self.assertEqual(orphan.kind, "external-only")
        self.assertEqual(orphan.classification, Classification.INDETERMINADO)
        self.assertIn("DNAT", orphan.reason)
        self.assertIn("5432/tcp", orphan.reason)
        self.assertNotIn("51820/udp", orphan.reason)
        self.assertEqual(orphan.service, "?")

    def test_reports(self) -> None:
        """
        TXT, JSON, CSV e resumo gerados e coerentes.

        :return: None
        """
        text = render_host(self.report)
        self.assertIn("HOST: srv-web-01", text)
        self.assertIn("CLASSIFICACAO:  EXPOSTO", text)
        document = json.loads(render_json(self.report))
        self.assertEqual(document["hostname"], "srv-web-01")
        self.assertIn("raw", document)
        rows = list(csv.DictReader(io.StringIO(render_csv([self.report]))))
        self.assertEqual(tuple(rows[0].keys()), COLUMNS)
        row = [r for r in rows if r["port"] == "5432"][0]
        self.assertEqual((row["protection"], row["external_status"]), ("PROTEGIDO", "FILTERED"))
        summary = render_summary([self.report])
        self.assertIn("SERVICOS LOCAIS:", summary)
        self.assertIn("SERVICOS POR HOST", summary)
        lines = summary.splitlines()
        first = next(line for line in lines if line.startswith("srv-web-01 - "))
        self.assertRegex(first, r"^srv-web-01 - ipv4:  \S+ +\d+/(tcp|udp) +[A-Z]+ +- \S")
        self.assertTrue(any(line.startswith(" " * len("srv-web-01 - ")) and "ipv6:" in line
                            for line in lines) or "ipv6:" not in summary)
        for line in lines[lines.index("SERVICOS POR HOST:") + 1:]:
            if line:
                self.assertRegex(line, r" (PROTEGIDO|PARCIAL|EXPOSTO|INDETERMINADO) +- ")

    def test_without_scanner(self) -> None:
        """
        Sem scanner: classificacao local (fase 3).

        :return: None
        """
        report = analyze(make_entry("srv-web-01"), web_raw(), None, AuditOptions())
        by_port = {(s.protocol, s.port): s.classification for s in report.services}
        self.assertEqual(by_port[("tcp", 5432)], Classification.PROTEGIDO)
        self.assertEqual(by_port[("tcp", 22)], Classification.INDETERMINADO)

    def test_ssh_failure(self) -> None:
        """
        Host inacessivel gera relatorio com erro, sem excecao.

        :return: None
        """
        report = analyze(make_entry("srv-down"), {"status": "SSH_FAILED", "commands": {}},
                         None, AuditOptions())
        self.assertIsNotNone(report.error)
        self.assertIn("INDETERMINADO", render_csv([report]))


class FakeRunner(CommandRunner):
    """Executor falso com respostas fixas."""

    name = "fake"

    def __init__(self, responses: dict[str, tuple[int, str, str]]) -> None:
        """
        Inicializa com respostas por comando.

        :param responses: dict[str, tuple[int, str, str]]
        :return: None
        """
        super().__init__(5)
        self.responses = responses
        self.seen: list[list[str]] = []
        self.stdin_seen: list[str | None] = []

    def _execute(self, argv: list[str], timeout: int,
                 stdin_data: str | None = None) -> tuple[int | None, str, str, bool]:
        """
        Retorna a resposta configurada.

        :param argv: list[str]
        :param timeout: int
        :param stdin_data: str | None
        :return: tuple[int | None, str, str, bool]
        """
        self.seen.append(argv)
        self.stdin_seen.append(stdin_data)
        command = " ".join(argv[3:])
        for prefix in ("sudo -n ", "sudo -k -S -p  "):
            if command not in self.responses and command.startswith(prefix):
                command = command[len(prefix):]
        rc, out, err = self.responses.get(command, (127, "", "command not found"))
        return rc, out, err, False


class CollectorTest(unittest.TestCase):
    """Coleta bruta e executor."""

    def test_collect_with_sudo(self) -> None:
        """
        Comandos privilegiados recebem ``sudo -n``; falta de comando e
        registrada sem interromper.

        :return: None
        """
        runner = FakeRunner({"id -u": (0, "1000\n", ""), "sudo -n true": (0, "", ""),
                             "hostname": (0, "srv\n", ""),
                             "ip xfrm state": (0, "enc cbc(aes) 0xdeadbeefdeadbeef\n", "")})
        raw = collect_host(runner)
        self.assertEqual(raw["privilege"]["mode"], "sudo")
        self.assertTrue(any(argv[3:5] == ["sudo", "-n"] and "iptables-save" in argv
                            for argv in runner.seen))
        self.assertEqual(raw["commands"]["nft_json"]["status"], "COMMAND_NOT_FOUND")
        self.assertNotIn("deadbeef", raw["commands"]["xfrm_state"]["stdout"])

    def test_collect_with_sudo_password(self) -> None:
        """
        Sem ``sudo -n``, a senha informada e enviada somente pela entrada
        padrao de ``sudo -k -S``; nunca aparece em argv nem no JSON bruto.

        :return: None
        """
        secret = "s3nh@-de-teste"
        runner = FakeRunner({"id -u": (0, "1000\n", ""),
                             "sudo -n true": (1, "", "sudo: a password is required"),
                             "sudo -k -S -p  true": (0, "", ""),
                             "hostname": (0, "srv\n", "")})
        runner.sudo_password = secret
        raw = collect_host(runner)
        self.assertEqual(raw["privilege"]["mode"], "sudo_password")
        sudo_calls = [(argv, data) for argv, data in zip(runner.seen, runner.stdin_seen)
                      if "iptables-save" in argv]
        self.assertTrue(sudo_calls)
        for argv, data in sudo_calls:
            self.assertEqual(argv[3:8], ["sudo", "-k", "-S", "-p", ""])
            self.assertEqual(data, secret + "\n")
        for argv, data in zip(runner.seen, runner.stdin_seen):
            self.assertNotIn(secret, " ".join(argv))
            if "sudo" not in argv:
                self.assertIsNone(data)
        self.assertNotIn(secret, json.dumps(raw))

    def test_sudo_password_wrong_tried_once(self) -> None:
        """
        Senha incorreta: uma unica tentativa por host e coleta sem
        privilegio (sem sudo nos comandos seguintes).

        :return: None
        """
        runner = FakeRunner({"id -u": (0, "1000\n", ""),
                             "sudo -n true": (1, "", "sudo: a password is required"),
                             "sudo -k -S -p  true": (1, "", "Sorry, try again.\n"
                                                     "sudo: 1 incorrect password attempt")})
        runner.sudo_password = "errada"
        raw = collect_host(runner)
        self.assertEqual(raw["privilege"]["mode"], "PRIVILEGE_INSUFFICIENT")
        self.assertEqual(raw["privilege"]["sudo_password_check"]["status"],
                         "PRIVILEGE_INSUFFICIENT")
        attempts = [argv for argv in runner.seen if "-S" in argv]
        self.assertEqual(len(attempts), 1)

    def test_sudo_nopasswd_does_not_send_password(self) -> None:
        """
        Host com ``sudo -n`` funcional nao recebe a senha.

        :return: None
        """
        runner = FakeRunner({"id -u": (0, "1000\n", ""), "sudo -n true": (0, "", "")})
        runner.sudo_password = "nao-enviar"
        raw = collect_host(runner)
        self.assertEqual(raw["privilege"]["mode"], "sudo")
        self.assertTrue(all(data is None for data in runner.stdin_seen))

    def test_unreachable(self) -> None:
        """
        Falha SSH interrompe a coleta do host rapidamente.

        :return: None
        """
        class Down(FakeRunner):
            """Executor que simula falha SSH."""

            @property
            def is_ssh(self) -> bool:
                """
                Simula SSH.

                :return: bool
                """
                return True

        raw = collect_host(Down({"id -u": (255, "", "ssh: connect: timed out")}))
        self.assertEqual(raw["status"], "SSH_FAILED")

    def test_classify_failure(self) -> None:
        """
        Classificacao de falhas de comando.

        :return: None
        """
        self.assertEqual(classify_failure(1, "sudo: a password is required", True),
                         CommandStatus.PRIVILEGE_INSUFFICIENT)
        self.assertEqual(classify_failure(1, "sudo: 1 incorrect password attempt", True),
                         CommandStatus.PRIVILEGE_INSUFFICIENT)
        self.assertEqual(classify_failure(1, "sudo: sorry, you must have a tty to run sudo",
                                          True), CommandStatus.PRIVILEGE_INSUFFICIENT)
        self.assertEqual(classify_failure(127, "", True), CommandStatus.COMMAND_NOT_FOUND)
        self.assertEqual(classify_failure(255, "", True), CommandStatus.SSH_FAILED)
        self.assertEqual(classify_failure(4, "iptables-save v1.8: Permission denied (you must be "
                                             "root)", True), CommandStatus.PRIVILEGE_INSUFFICIENT)


class RunDirTest(unittest.TestCase):
    """Diretorio de saida exclusivo por execucao."""

    def test_run_dir(self) -> None:
        """
        Subdiretorio ``yyyymmddHHMMSS`` com raw/ e reports/; execucao no
        mesmo segundo recebe sufixo e nao reaproveita o anterior.

        :return: None
        """
        started = datetime(2026, 10, 19, 14, 5, 9)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "output"
            first = create_run_dir(base, started)
            second = create_run_dir(base, started)
            self.assertEqual(first, base / "20261019140509")
            self.assertEqual(second, base / "20261019140509_2")
            for run in (first, second):
                self.assertTrue((run / "raw").is_dir())
                self.assertTrue((run / "reports").is_dir())


class InventoryTest(unittest.TestCase):
    """Inventario e validacao."""

    def test_text_and_csv(self) -> None:
        """
        Formatos texto e CSV.

        :return: None
        """
        hosts = parse_text("# comentario\nsrv01 203.0.113.5\n10.0.0.7\n")
        self.assertEqual(hosts[0].public_ips, ["203.0.113.5"])
        self.assertEqual(hosts[1].host, "10.0.0.7")
        rows = parse_csv("host,public_ip,ssh_user,ssh_port,name\n"
                         "10.0.0.8,203.0.113.8;2001:db8::8,auditor,2222,srv02\n")
        self.assertEqual((rows[0].name, rows[0].ssh_port), ("srv02", 2222))
        self.assertEqual(rows[0].public_ips, ["203.0.113.8", "2001:db8::8"])

    def test_rejects_injection(self) -> None:
        """
        Valores que poderiam virar opcoes do ssh sao rejeitados.

        :return: None
        """
        with self.assertRaises(ValueError):
            parse_text("-oProxyCommand=evil\n")
        with self.assertRaises(ValueError):
            parse_text("srv01 not-an-ip\n")
        with self.assertRaises(ValueError):
            make_entry("srv01", ssh_user="root;id")


if __name__ == "__main__":
    unittest.main()
