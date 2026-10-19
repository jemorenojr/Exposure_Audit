# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : ssh_client.py
# Descricao   : Execucao de comandos somente leitura, local ou via SSH,
#               com timeout, sudo (sem senha ou com senha informada pelo
#               operador) e classificacao de falhas.
# Author      : Jose Edson Moreno Jr.
# Email       : edson.moreno@gmail.com
# Versao      : 0.2
# Data        : 2026-10-19
# copyright   : (c) 2026 by Edson Moreno
# Parametros  :
# Opcoes      :
#
# Retorno     :
#
# CHANGELOG   : 2026-10-19: sudo com senha via stdin (sudo -k -S),
#               usado quando o operador informa --ask-sudo-password.
#
############################################################################

"""
Executores de comando.

Regras de seguranca adotadas:

* nunca usa ``shell=True`` localmente;
* o comando remoto e montado com ``shlex.join`` a partir de argv fixo;
* SSH sempre com ``BatchMode=yes`` (nunca pede senha);
* sudo com ``-n`` (nunca bloqueia aguardando senha), exceto quando o
  operador informa a senha com ``--ask-sudo-password``: nesse caso usa
  ``sudo -k -S -p ''`` e entrega a senha pela entrada padrao do processo
  (nunca em argv, variavel de ambiente, log ou JSON). ``-k`` obriga o sudo
  a consumir a senha mesmo com credencial em cache, para que ela nunca
  sobre na entrada padrao do comando executado;
* todo comando possui timeout;
* nenhuma senha ou chave e gravada em disco: usa a infraestrutura SSH do
  usuario (``~/.ssh/config``, agente, chaves existentes); a senha do sudo,
  quando informada, existe somente na memoria do processo.
"""

import os
import re
import shlex
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from exposure_audit.models import CommandStatus
from exposure_audit.validation import validate_hostname, validate_port, validate_ssh_user

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.2"

SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MAX_OUTPUT = 8 * 1024 * 1024

_PRIVILEGE_PATTERNS = re.compile(
    r"a password is required|permission denied|operation not permitted|"
    r"you must be root|are you root|must be run as root|"
    r"not allowed to execute|is not in the sudoers|"
    r"got permission denied while trying to connect to the docker daemon|"
    r"incorrect password|no password was provided|sorry, try again|"
    r"must have a tty",
    re.IGNORECASE,
)
_NOT_FOUND_PATTERNS = re.compile(
    r"command not found|no such file or directory|not found$",
    re.IGNORECASE | re.MULTILINE,
)


@dataclass
class CommandResult:
    """Resultado de um comando, preservado como evidencia bruta."""

    argv: list[str]
    status: CommandStatus
    returncode: int | None
    stdout: str
    stderr: str
    duration: float
    sudo: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """
        Indica execucao bem sucedida.

        :return: bool
        """
        return self.status == CommandStatus.OK

    def to_dict(self) -> dict[str, object]:
        """
        Serializa o resultado para o JSON bruto.

        :return: dict[str, object]
        """
        return {
            "argv": self.argv,
            "status": self.status.value,
            "returncode": self.returncode,
            "sudo": self.sudo,
            "duration": round(self.duration, 3),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "CommandResult":
        """
        Reconstroi um resultado a partir do JSON bruto.

        :param data: dict[str, object]
        :return: CommandResult
        """
        return cls(
            argv=list(data.get("argv", [])),  # type: ignore[arg-type]
            status=CommandStatus(str(data.get("status", "FAILED"))),
            returncode=data.get("returncode"),  # type: ignore[arg-type]
            stdout=str(data.get("stdout", "")),
            stderr=str(data.get("stderr", "")),
            duration=float(data.get("duration", 0.0)),  # type: ignore[arg-type]
            sudo=bool(data.get("sudo", False)),
            notes=list(data.get("notes", [])),  # type: ignore[arg-type]
        )


def classify_failure(returncode: int | None, stderr: str, ssh: bool) -> CommandStatus:
    """
    Classifica a falha de um comando a partir do codigo de retorno e stderr.

    :param returncode: int | None
    :param stderr: str
    :param ssh: bool
    :return: CommandStatus
    """
    if returncode == 0:
        return CommandStatus.OK
    if ssh and returncode == 255:
        return CommandStatus.SSH_FAILED
    if returncode == 127 or _NOT_FOUND_PATTERNS.search(stderr.strip()):
        if "sudo:" in stderr and "password" in stderr:
            return CommandStatus.PRIVILEGE_INSUFFICIENT
        return CommandStatus.COMMAND_NOT_FOUND
    if _PRIVILEGE_PATTERNS.search(stderr):
        return CommandStatus.PRIVILEGE_INSUFFICIENT
    return CommandStatus.FAILED


def _truncate(text: str) -> str:
    """
    Limita o tamanho da saida armazenada.

    :param text: str
    :return: str
    """
    if len(text) <= MAX_OUTPUT:
        return text
    return text[:MAX_OUTPUT] + "\n[saida truncada pelo Exposure Audit]\n"


class CommandRunner(ABC):
    """Interface comum para execucao de comandos somente leitura."""

    name: str = "runner"

    def __init__(self, timeout: int) -> None:
        """
        Inicializa o executor.

        :param timeout: int
        :return: None
        """
        self.timeout = timeout
        self.use_sudo = False
        self.sudo_password: str | None = None

    @abstractmethod
    def _execute(self, argv: list[str], timeout: int,
                 stdin_data: str | None = None) -> tuple[int | None, str, str, bool]:
        """
        Executa argv e retorna (returncode, stdout, stderr, timed_out).

        :param argv: list[str]
        :param timeout: int
        :param stdin_data: str | None
        :return: tuple[int | None, str, str, bool]
        """

    @property
    def is_ssh(self) -> bool:
        """
        Indica se o executor usa SSH.

        :return: bool
        """
        return False

    def run(self, argv: list[str], privileged: bool = False,
            timeout: int | None = None) -> CommandResult:
        """
        Executa um comando, prefixando sudo quando privilegiado e sudo
        estiver disponivel: ``sudo -n`` sem senha, ou ``sudo -k -S -p ''``
        com a senha enviada pela entrada padrao.

        :param argv: list[str]
        :param privileged: bool
        :param timeout: int | None
        :return: CommandResult
        """
        full = ["env", "LC_ALL=C", f"PATH={SAFE_PATH}"]
        sudo = privileged and self.use_sudo
        stdin_data: str | None = None
        if sudo and self.sudo_password is not None:
            full += ["sudo", "-k", "-S", "-p", ""]
            stdin_data = self.sudo_password + "\n"
        elif sudo:
            full += ["sudo", "-n"]
        full += argv
        limit = timeout or self.timeout
        started = time.monotonic()
        returncode, stdout, stderr, timed_out = self._execute(full, limit, stdin_data)
        duration = time.monotonic() - started
        if timed_out:
            status = CommandStatus.TIMEOUT
        else:
            status = classify_failure(returncode, stderr, self.is_ssh)
        return CommandResult(argv=argv, status=status, returncode=returncode,
                             stdout=_truncate(stdout), stderr=_truncate(stderr),
                             duration=duration, sudo=sudo)

    def close(self) -> None:
        """
        Libera recursos (ex.: conexao SSH multiplexada).

        :return: None
        """


def _run_subprocess(argv: list[str], timeout: int,
                    stdin_data: str | None = None) -> tuple[int | None, str, str, bool]:
    """
    Executa um processo local sem shell, com timeout. Sem ``stdin_data``,
    a entrada padrao e ``/dev/null``.

    :param argv: list[str]
    :param timeout: int
    :param stdin_data: str | None
    :return: tuple[int | None, str, str, bool]
    """
    stdin_kwargs: dict[str, object] = (
        {"input": stdin_data.encode("utf-8")} if stdin_data is not None
        else {"stdin": subprocess.DEVNULL})
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout,
                              check=False, **stdin_kwargs)  # type: ignore[call-overload]
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"").decode("utf-8", "replace")
        err = (exc.stderr or b"").decode("utf-8", "replace")
        return None, out, err, True
    except FileNotFoundError as exc:
        return 127, "", f"{exc.filename}: command not found", False
    return (proc.returncode, proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"), False)


class LocalRunner(CommandRunner):
    """Executa comandos na maquina local (host ``local``/``localhost``)."""

    name = "local"

    def _execute(self, argv: list[str], timeout: int,
                 stdin_data: str | None = None) -> tuple[int | None, str, str, bool]:
        """
        Executa localmente.

        :param argv: list[str]
        :param timeout: int
        :param stdin_data: str | None
        :return: tuple[int | None, str, str, bool]
        """
        return _run_subprocess(argv, timeout, stdin_data)


class SSHRunner(CommandRunner):
    """
    Executa comandos remotamente via cliente OpenSSH do sistema.

    Usa ControlMaster em diretorio temporario privado para reaproveitar a
    conexao entre os comandos do mesmo host.
    """

    def __init__(self, host: str, timeout: int, user: str | None = None,
                 port: int | None = None, connect_timeout: int = 10) -> None:
        """
        Inicializa o executor SSH.

        :param host: str
        :param timeout: int
        :param user: str | None
        :param port: int | None
        :param connect_timeout: int
        :return: None
        """
        super().__init__(timeout)
        self.host = validate_hostname(host)
        self.user = validate_ssh_user(user) if user else None
        self.port = validate_port(port) if port else None
        self.connect_timeout = connect_timeout
        self.name = f"ssh:{self.host}"
        self._control_dir = tempfile.mkdtemp(prefix="exposure-audit-ssh-")
        os.chmod(self._control_dir, 0o700)

    @property
    def is_ssh(self) -> bool:
        """
        Indica uso de SSH.

        :return: bool
        """
        return True

    def _base_argv(self) -> list[str]:
        """
        Monta os argumentos fixos do cliente ssh.

        :return: list[str]
        """
        argv = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={self.connect_timeout}",
            "-o", "ControlMaster=auto",
            "-o", f"ControlPath={self._control_dir}/%C",
            "-o", "ControlPersist=60",
            "-o", "LogLevel=ERROR",
        ]
        if self.user:
            argv += ["-l", self.user]
        if self.port:
            argv += ["-p", str(self.port)]
        return argv

    def _execute(self, argv: list[str], timeout: int,
                 stdin_data: str | None = None) -> tuple[int | None, str, str, bool]:
        """
        Executa o comando no host remoto. ``stdin_data`` segue pelo canal
        SSH cifrado ate a entrada padrao do comando remoto.

        :param argv: list[str]
        :param timeout: int
        :param stdin_data: str | None
        :return: tuple[int | None, str, str, bool]
        """
        remote = shlex.join(argv)
        return _run_subprocess(self._base_argv() + ["--", self.host, remote], timeout,
                               stdin_data)

    def close(self) -> None:
        """
        Encerra a conexao mestre e remove o diretorio de controle.

        :return: None
        """
        _run_subprocess(self._base_argv() + ["-O", "exit", "--", self.host], 10)
        try:
            for entry in os.listdir(self._control_dir):
                os.unlink(os.path.join(self._control_dir, entry))
            os.rmdir(self._control_dir)
        except OSError:
            pass


def is_local_target(host: str) -> bool:
    """
    Indica se o alvo deve ser coletado localmente, sem SSH.

    :param host: str
    :return: bool
    """
    return host in ("local", "localhost")
