#!/bin/sh
###########################################################################
#
# Nome       : ambiente.sh
# Descricao  : Configura o ambiente virtual Python local do Exposure Audit.
#              Compatível com bash, zsh, dash e outros shells POSIX.
#              Deve ser carregado (source) na raiz do projeto, que contém
#              o requirements.txt; o venv fica em .env/usr e os artefatos
#              de build/cache em build/:
#
#                      cd Exposure_Audit && . ./ambiente.sh
#
#              O requirements.txt instala o próprio pacote em modo
#              editável (-e .), disponibilizando o comando exposure-audit.
# Author     : Jose Edson Moreno Jr.
# Email      : edson.moreno@gmail.com
# Versao     : 0.6
# Data       : 2026-09-28
# copyright  : (c) 2026 by Edson Moreno
# Parametros : --make-vars  imprime as variáveis de diretório no formato
#                           do make e encerra, sem criar o venv
# Retorno    : 0 = ambiente ativado; 1 = falha (mensagem em stderr)
#
# CHANGELOG  : 0.2 - Corrige tratamento de erros, recuperação de venv incompleto
#              e remove dependência desnecessária de pip3 global.
#              0.3 - Garante psycopg[binary]>=3 em toda execução do ambiente.
#              0.4 - Instala dependências da interface web em toda execução.
#              0.5 - 2026-09-28: Separação syslog-digest/syslog-web. Instala
#              somente o requirements.txt do componente em toda execução e
#              grava o .gitignore na raiz do repositório.
#              (0.2 a 0.5: histórico do projeto de origem do script.)
#              0.6 - 2026-10-19: Adaptado ao Exposure Audit: cabeçalho,
#              comentários e mensagens; exige Python >= 3.10; avisa se
#              o cliente ssh não existir; .gitignore passa a proteger
#              output/, inventários reais e docs/Agents/.
############################################################################


###############################################################################
# Funções auxiliares
###############################################################################

mensagem_erro()
{
    printf '%s\n' "ERRO: $*" >&2
}

comando_existe()
{
    command -v "$1" >/dev/null 2>&1
}

###############################################################################
# Diretórios do projeto
###############################################################################

PROJECT_HOME=$(pwd)
PATH_ENV="${PROJECT_HOME}/.env"
VIRTUAL_ENV="${PATH_ENV}/usr"
REQUIREMENTS="${PROJECT_HOME}/requirements.txt"

BUILD_HOME="${PROJECT_HOME}/build"
BUILD_BIN="${BUILD_HOME}/bin"
BUILD_LIB="${BUILD_HOME}/lib"
BUILD_CONF="${BUILD_HOME}/confs"
BUILD_TMP="${BUILD_HOME}/tmp"
BUILD_CACHE="${BUILD_HOME}/cache"
BUILD_DIST="${BUILD_HOME}/dist"
BUILD_COVERAGE="${BUILD_HOME}/coverage"
PYTHONPYCACHEPREFIX="${BUILD_CACHE}/pycache"

export PROJECT_HOME
export PATH_ENV
export VIRTUAL_ENV
export BUILD_HOME
export BUILD_BIN
export BUILD_LIB
export BUILD_CONF
export BUILD_TMP
export BUILD_CACHE
export BUILD_DIST
export BUILD_COVERAGE
export PYTHONPYCACHEPREFIX

###############################################################################
# Diretórios de build
###############################################################################

for diretorio in \
    "$BUILD_HOME" \
    "$BUILD_BIN" \
    "$BUILD_LIB" \
    "$BUILD_CONF" \
    "$BUILD_TMP" \
    "$BUILD_CACHE" \
    "$BUILD_DIST" \
    "$BUILD_COVERAGE" \
    "$PYTHONPYCACHEPREFIX"
do
    [ -d "$diretorio" ] || mkdir -p "$diretorio" || {
        mensagem_erro "Falha ao criar diretório: ${diretorio}"
        return 1 2>/dev/null || exit 1
    }
done

if [ "${1:-}" = "--make-vars" ]; then
    printf '%s\n' \
        "PROJECT_HOME := ${PROJECT_HOME}" \
        "PATH_ENV := ${PATH_ENV}" \
        "VIRTUAL_ENV := ${VIRTUAL_ENV}" \
        "BUILD_HOME := ${BUILD_HOME}" \
        "BUILD_BIN := ${BUILD_BIN}" \
        "BUILD_LIB := ${BUILD_LIB}" \
        "BUILD_CONF := ${BUILD_CONF}" \
        "BUILD_TMP := ${BUILD_TMP}" \
        "BUILD_CACHE := ${BUILD_CACHE}" \
        "BUILD_DIST := ${BUILD_DIST}" \
        "BUILD_COVERAGE := ${BUILD_COVERAGE}" \
        "PYTHONPYCACHEPREFIX := ${PYTHONPYCACHEPREFIX}"
    return 0 2>/dev/null || exit 0
fi

###############################################################################
# Identificação do gerenciador de pacotes
###############################################################################

PKG_MANAGER=""

if comando_existe apt-get; then
    PKG_MANAGER="apt"
elif comando_existe dnf; then
    PKG_MANAGER="dnf"
elif comando_existe yum; then
    PKG_MANAGER="yum"
fi

###############################################################################
# Instalação/validação do Python
###############################################################################

if ! comando_existe python3; then
    printf '%s\n' "Python 3 não encontrado. Tentando instalar..."

    case "$PKG_MANAGER" in
        apt)
            sudo apt-get update || {
                mensagem_erro "Falha ao atualizar os repositórios."
                return 1 2>/dev/null || exit 1
            }
            sudo apt-get -y install python3 python3-venv || {
                mensagem_erro "Falha ao instalar Python pelo apt."
                return 1 2>/dev/null || exit 1
            }
            ;;
        dnf)
            sudo dnf -y install python3 || {
                mensagem_erro "Falha ao instalar Python pelo dnf."
                return 1 2>/dev/null || exit 1
            }
            ;;
        yum)
            sudo yum -y install python3 || {
                mensagem_erro "Falha ao instalar Python pelo yum."
                return 1 2>/dev/null || exit 1
            }
            ;;
        *)
            mensagem_erro "Python 3 não encontrado e nenhum gerenciador suportado está disponível."
            return 1 2>/dev/null || exit 1
            ;;
    esac
fi

###############################################################################
# Localização do Python
###############################################################################

PYTHON3=$(command -v python3) || {
    mensagem_erro "Não foi possível localizar o executável python3."
    return 1 2>/dev/null || exit 1
}

# pyproject.toml exige Python >= 3.10 (anotações "X | None" avaliadas em
# tempo de execução nas dataclasses).
"$PYTHON3" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || {
    mensagem_erro "Exposure Audit exige Python >= 3.10; encontrado: $("$PYTHON3" --version 2>&1)."
    return 1 2>/dev/null || exit 1
}

###############################################################################
# Ferramentas externas do controlador
###############################################################################

# O cliente OpenSSH só é necessário para hosts remotos e scanner via SSH;
# "--host local" funciona sem ele, por isso apenas avisa.
comando_existe ssh || printf '%s\n' \
    "AVISO: cliente ssh não encontrado; somente '--host local' funcionará."

###############################################################################
# Criação/validação do ambiente virtual
###############################################################################

ACTIVATE="${VIRTUAL_ENV}/bin/activate"
VENV_PYTHON="${VIRTUAL_ENV}/bin/python"

# Um venv válido precisa, no mínimo, de python, activate e pip funcional.
venv_valido=1

[ -x "$VENV_PYTHON" ] || venv_valido=0
[ -f "$ACTIVATE" ] || venv_valido=0

if [ "$venv_valido" -eq 1 ]; then
    "$VENV_PYTHON" -m pip --version >/dev/null 2>&1 || venv_valido=0
fi

# Recupera automaticamente restos de uma criação anterior interrompida.
if [ -e "$VIRTUAL_ENV" ] && [ "$venv_valido" -eq 0 ]; then
    printf '%s\n' \
        "Ambiente virtual incompleto detectado em ${VIRTUAL_ENV}." \
        "Removendo somente o venv incompleto para recriação..."

    rm -rf -- "$VIRTUAL_ENV" || {
        mensagem_erro "Falha ao remover ambiente virtual incompleto: ${VIRTUAL_ENV}"
        return 1 2>/dev/null || exit 1
    }
fi

if [ "$venv_valido" -eq 0 ]; then
    printf '%s\n' "Criando ambiente virtual em ${VIRTUAL_ENV}..."

    if ! "$PYTHON3" -m venv "$VIRTUAL_ENV"; then
        # Debian/Ubuntu separam os componentes necessários ao venv em pacote próprio.
        if [ "$PKG_MANAGER" = "apt" ]; then
            printf '%s\n' \
                "Falha ao criar o venv. Tentando instalar python3-venv e recriar..."

            rm -rf -- "$VIRTUAL_ENV"

            sudo apt-get update && sudo apt-get -y install python3-venv || {
                mensagem_erro "Falha ao instalar python3-venv."
                return 1 2>/dev/null || exit 1
            }

            "$PYTHON3" -m venv "$VIRTUAL_ENV" || {
                mensagem_erro "Falha ao criar o ambiente virtual após instalar python3-venv."
                return 1 2>/dev/null || exit 1
            }
        else
            mensagem_erro "Falha ao criar o ambiente virtual com ${PYTHON3} -m venv."
            return 1 2>/dev/null || exit 1
        fi
    fi

    [ -x "$VENV_PYTHON" ] && [ -f "$ACTIVATE" ] || {
        mensagem_erro "O ambiente virtual foi criado de forma incompleta."
        return 1 2>/dev/null || exit 1
    }

    "$VENV_PYTHON" -m pip install --upgrade pip setuptools wheel || {
        mensagem_erro "Falha ao atualizar pip, setuptools e wheel."
        return 1 2>/dev/null || exit 1
    }

    "$VENV_PYTHON" -m pip install ipython || {
        mensagem_erro "Falha ao instalar o IPython."
        return 1 2>/dev/null || exit 1
    }
fi

###############################################################################
# Dependências do projeto
#
# O requirements.txt do projeto instala o pacote exposure_audit em modo
# editável (-e .); o pacote usa somente a biblioteca padrão.
###############################################################################

[ -f "$REQUIREMENTS" ] || {
    mensagem_erro "requirements.txt não encontrado em ${PROJECT_HOME}. Carregue o ambiente.sh a partir da raiz do projeto Exposure_Audit."
    return 1 2>/dev/null || exit 1
}

printf '%s\n' "Instalando dependências de ${REQUIREMENTS}..."

"$VENV_PYTHON" -m pip install -r "$REQUIREMENTS" || {
    mensagem_erro "Falha ao instalar ${REQUIREMENTS}."
    return 1 2>/dev/null || exit 1
}

###############################################################################
# Ativação do ambiente
###############################################################################

[ -f "$ACTIVATE" ] || {
    mensagem_erro "Arquivo de ativação não encontrado: ${ACTIVATE}"
    return 1 2>/dev/null || exit 1
}

# shellcheck disable=SC1090
. "$ACTIVATE" || {
    mensagem_erro "Falha ao ativar o ambiente virtual: ${ACTIVATE}"
    return 1 2>/dev/null || exit 1
}

###############################################################################
# Cria/atualiza o .gitignore
###############################################################################

# O .gitignore fica na raiz do repositório git (a raiz do projeto).
# Entradas do projeto protegem dados reais de auditoria (output/,
# inventários) e o repositório privado docs/Agents/.
GIT_TOP=$(git -C "$PROJECT_HOME" rev-parse --show-toplevel 2>/dev/null) || GIT_TOP=""
GITIGNORE="${GIT_TOP:+${GIT_TOP}/.gitignore}"

# Acrescenta apenas as entradas inexistentes
[ -n "$GITIGNORE" ] && while IFS= read -r linha; do
    [ -z "$linha" ] && continue

    if ! grep -Fqx -- "$linha" "$GITIGNORE" 2>/dev/null; then
        printf '%s\n' "$linha" >> "$GITIGNORE"
    fi
done <<'EOF'
*.pyc
*.pyo
*.orig
*.bak
*.rej
*~
cur/
tmp/
.env/
.codex/
__pycache__/
*.DS_Store
*.project
*.dbeaver
*.pydevproject
*.settings
*.sqlite
*.sqlite-journal
**/src/logs
**/src/tmp
*.tar.bz2
build/
*.egg-info/
output/
hosts*.txt
hosts*.csv
!hosts.example.txt
!hosts.example.csv
docs/Agents/
EOF

###############################################################################
# Confirmação
###############################################################################

export PATH="${BUILD_BIN}:${VIRTUAL_ENV}/bin:${PATH}"

printf '%s\n' \
    "Ambiente Python ativado:" \
    "  Projeto: ${PROJECT_HOME}" \
    "  Virtualenv: ${VIRTUAL_ENV}" \
    "  Build: ${BUILD_HOME}" \
    "  Python: $(command -v python)" \
    "  Versão: $(python --version 2>&1)"
