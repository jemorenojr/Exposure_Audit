# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : host.py
# Descricao   : Coleta bruta de evidencias internas do host (comandos
#               somente leitura), com sanitizacao de dados sensiveis.
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
# CHANGELOG   : 2026-10-19: deteccao de sudo com senha (modo
#               sudo_password), com uma unica tentativa por host.
#
############################################################################

"""
Coleta bruta.

Cada comando e executado isoladamente e seu resultado (status, stdout,
stderr) e preservado no JSON bruto, permitindo auditar posteriormente a
decisao do correlator. Nenhum comando altera o estado do host.
"""

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from exposure_audit.models import CommandStatus
from exposure_audit.ssh_client import CommandResult, CommandRunner
from exposure_audit.validation import validate_container_id

__author__ = "Jose Edson Moreno Jr."
__email__ = "edson.moreno@gmail.com"
__maintainer__ = "Jose Edson Moreno Jr."
__version__ = "0.2"

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class CommandSpec:
    """Comando de coleta: chave no JSON, argv e necessidade de privilegio."""

    key: str
    argv: tuple[str, ...]
    privileged: bool = False


#: Comandos de coleta (secoes 7 a 11 da diretriz). Todos somente leitura.
COMMANDS: tuple[CommandSpec, ...] = (
    CommandSpec("hostname", ("hostname",)),
    CommandSpec("hostname_fqdn", ("hostname", "-f")),
    CommandSpec("os_release", ("cat", "/etc/os-release")),
    CommandSpec("uname", ("uname", "-a")),
    CommandSpec("ip_br_addr", ("ip", "-br", "addr")),
    CommandSpec("ip4_addr", ("ip", "-o", "-4", "addr", "show")),
    CommandSpec("ip6_addr", ("ip", "-o", "-6", "addr", "show")),
    CommandSpec("ip_route", ("ip", "route")),
    CommandSpec("ip6_route", ("ip", "-6", "route")),
    CommandSpec("ip_route_get", ("ip", "route", "get", "1.1.1.1")),
    CommandSpec("ip_rule", ("ip", "rule")),
    CommandSpec("ip_route_all", ("ip", "route", "show", "table", "all")),
    CommandSpec("xfrm_policy", ("ip", "xfrm", "policy"), privileged=True),
    CommandSpec("xfrm_state", ("ip", "xfrm", "state"), privileged=True),
    CommandSpec("bindv6only", ("cat", "/proc/sys/net/ipv6/bindv6only")),
    CommandSpec("ss_listen", ("ss", "-lntup"), privileged=True),
    CommandSpec("ss_udp", ("ss", "-lnup"), privileged=True),
    CommandSpec("iptables_version", ("iptables", "-V")),
    CommandSpec("nft_json", ("nft", "-j", "list", "ruleset"), privileged=True),
    CommandSpec("nft_text", ("nft", "list", "ruleset"), privileged=True),
    CommandSpec("iptables_save", ("iptables-save",), privileged=True),
    CommandSpec("ip6tables_save", ("ip6tables-save",), privileged=True),
    CommandSpec("iptables_legacy_save", ("iptables-legacy-save",), privileged=True),
    CommandSpec("ip6tables_legacy_save", ("ip6tables-legacy-save",), privileged=True),
    CommandSpec("iptables_list", ("iptables", "-nvL", "--line-numbers"), privileged=True),
    CommandSpec("iptables_nat_list",
                ("iptables", "-t", "nat", "-nvL", "--line-numbers"), privileged=True),
    CommandSpec("ipset_save", ("ipset", "save"), privileged=True),
    CommandSpec("docker_ps", ("docker", "ps", "-q", "--no-trunc"), privileged=True),
)

_XFRM_SECRET = re.compile(r"\b0x[0-9a-fA-F]{8,}\b")


def sanitize_xfrm(text: str) -> str:
    """
    Remove chaves criptograficas da saida de ``ip xfrm state``.

    :param text: str
    :return: str
    """
    return _XFRM_SECRET.sub("<redacted>", text)


def detect_privilege(runner: CommandRunner) -> dict[str, object]:
    """
    Detecta se o usuario e root ou possui sudo funcional e ajusta o
    executor.

    Ordem: root; ``sudo -n`` (a senha nao e enviada a hosts que nao a
    exigem); sudo com a senha do executor, quando informada. A senha e
    testada uma unica vez por host: se falhar, a coleta segue sem
    privilegio, evitando repetir tentativas invalidas a cada comando
    (registro em log de autenticacao e possivel bloqueio por faillock).

    Modos resultantes: ``root``, ``sudo``, ``sudo_password``,
    ``PRIVILEGE_INSUFFICIENT`` ou ``unreachable``.

    :param runner: CommandRunner
    :return: dict[str, object]
    """
    uid = runner.run(["id", "-u"])
    info: dict[str, object] = {"uid_check": uid.to_dict(), "mode": "unprivileged"}
    if uid.status == CommandStatus.SSH_FAILED:
        info["mode"] = "unreachable"
        return info
    if uid.ok and uid.stdout.strip() == "0":
        info["mode"] = "root"
        return info
    sudo = runner.run(["sudo", "-n", "true"])
    info["sudo_check"] = sudo.to_dict()
    if sudo.ok:
        # sudo -n basta: descarta a senha para que este host nunca a receba
        runner.sudo_password = None
        runner.use_sudo = True
        info["mode"] = "sudo"
        return info
    if runner.sudo_password is not None:
        runner.use_sudo = True
        with_password = runner.run(["true"], privileged=True)
        info["sudo_password_check"] = with_password.to_dict()
        if with_password.ok:
            info["mode"] = "sudo_password"
            return info
        runner.use_sudo = False
        LOG.warning("%s: sudo com senha falhou (%s): %s; coleta sem privilegio",
                    runner.name, with_password.status.value,
                    with_password.stderr.strip()[:200])
    else:
        LOG.warning("%s: sudo -n indisponivel (%s); coleta sem privilegio "
                    "(use --ask-sudo-password se o sudo exigir senha)",
                    runner.name, sudo.status.value)
    info["mode"] = CommandStatus.PRIVILEGE_INSUFFICIENT.value
    return info


def _collect_docker_inspect(runner: CommandRunner, ps: CommandResult) -> CommandResult | None:
    """
    Executa ``docker inspect`` para os containers retornados por ``docker ps``.

    :param runner: CommandRunner
    :param ps: CommandResult
    :return: CommandResult | None
    """
    if not ps.ok:
        return None
    ids: list[str] = []
    for line in ps.stdout.split():
        try:
            ids.append(validate_container_id(line.strip()))
        except ValueError:
            LOG.warning("%s: ID de container ignorado: %r", runner.name, line)
    if not ids:
        return None
    return runner.run(["docker", "inspect", *ids], privileged=True)


def collect_host(runner: CommandRunner) -> dict[str, object]:
    """
    Executa toda a coleta interna de um host e retorna a evidencia bruta.

    Um host inacessivel retorna rapidamente com ``status=SSH_FAILED`` sem
    executar os demais comandos.

    :param runner: CommandRunner
    :return: dict[str, object]
    """
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    privilege = detect_privilege(runner)
    raw: dict[str, object] = {
        "collector_version": __version__,
        "runner": runner.name,
        "started": started,
        "privilege": privilege,
        "commands": {},
    }
    commands: dict[str, dict[str, object]] = {}
    raw["commands"] = commands
    if privilege["mode"] == "unreachable":
        raw["status"] = CommandStatus.SSH_FAILED.value
        raw["finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return raw

    for spec in COMMANDS:
        result = runner.run(list(spec.argv), privileged=spec.privileged)
        if spec.key == "xfrm_state":
            result.stdout = sanitize_xfrm(result.stdout)
        if not result.ok and result.status != CommandStatus.COMMAND_NOT_FOUND:
            LOG.info("%s: %s -> %s", runner.name, " ".join(spec.argv), result.status.value)
        commands[spec.key] = result.to_dict()
        if spec.key == "docker_ps":
            inspect = _collect_docker_inspect(runner, result)
            if inspect is not None:
                commands["docker_inspect"] = inspect.to_dict()

    raw["status"] = CommandStatus.OK.value
    raw["finished"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return raw


def command(raw: dict[str, object], key: str) -> CommandResult | None:
    """
    Recupera um resultado de comando da coleta bruta.

    :param raw: dict[str, object]
    :param key: str
    :return: CommandResult | None
    """
    commands = raw.get("commands", {})
    if not isinstance(commands, dict) or key not in commands:
        return None
    return CommandResult.from_dict(commands[key])


def command_output(raw: dict[str, object], key: str) -> str | None:
    """
    Retorna o stdout de um comando bem sucedido, ou None.

    :param raw: dict[str, object]
    :param key: str
    :return: str | None
    """
    result = command(raw, key)
    if result is None or not result.ok:
        return None
    return result.stdout
