# Exposure Audit — Instruções para agentes

Diretrizes específicas deste projeto para agentes de código (Claude Code,
Codex e equivalentes). Complementam as instruções do workspace e as regras
globais do responsável; em caso de conflito, prevalece este arquivo.

## Regras globais

As regras globais de documentação, Python, HTML, PHP, Flask e validação
continuam valendo integralmente neste projeto, inclusive a estrutura de
cabeçalho, docstrings, type hints, versionamento e resumo final de tarefa.

## Exceção: autoria nos cabeçalhos

Onde as regras globais definem e-mail e copyright, este projeto usa:

| Campo | Valor |
|-------|-------|
| Autor (`Author`, `__author__`, `__maintainer__`) | `Jose Edson Moreno Jr.` (inalterado) |
| E-mail (`Email`, `__email__`, `pyproject.toml`) | `edson.moreno@gmail.com` |
| Copyright | `(c) 2026 by Edson Moreno` |

Exemplo de cabeçalho Python:

```python
# -*- coding: utf8 -*-#
#
###########################################################################
#
# Nome        : <nome_arquivo>
# Descricao   : <descricao>
# Author      : Jose Edson Moreno Jr.
# Email       : edson.moreno@gmail.com
# Versao      : 0.1
# Data        : <data_atual>
# copyright   : (c) 2026 by Edson Moreno
# Parametros  :
# Opcoes      :
#
# Retorno     :
#
# CHANGELOG   :
#
############################################################################
```

O mesmo vale para shell, HTML, PHP e qualquer outro arquivo com cabeçalho.

## Repositório público

Este repositório é público. Portanto:

- não incluir referência a empresa empregadora, clientes ou domínios
  corporativos em código, comentários, documentação, exemplos ou fixtures;
- não versionar dados reais de auditoria: `output/`, inventários reais
  (`hosts*.txt`, `hosts*.csv`, exceto `hosts.example.*`) e coleta bruta já
  estão no `.gitignore`;
- fixtures de teste usam somente endereços de documentação
  (RFC 5737/3849) e saídas anonimizadas;
- antes de cada commit, conferir que nenhum dado real entrou nos arquivos
  rastreados.

## Documentos de agentes e handoffs

- `docs/Agents/` é um repositório git **privado e separado**, clonado
  dentro deste diretório e ignorado pelo `.gitignore` deste repositório.
  Contém a especificação do agente (`EXPOSURE_AUDIT_AGENT.md`) e os
  handoffs.
- Não criar links para `docs/Agents/` na documentação pública.
- O handoff cobre o **projeto inteiro** (código, documentação, execução,
  decisões e pendências), apesar de os repositórios serem separados.
  Gravar em `docs/Agents/HANDOFF-<yyyymmdd>-<HHMM>.md`.
- Commits são feitos separadamente em cada repositório: alterações de
  código/documentação pública neste repositório; especificação e handoffs
  no repositório de `docs/Agents/`.

## Validação

```bash
python -m unittest discover -s tests -t tests
sh -n ambiente.sh
```
