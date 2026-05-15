VENV ?= ../.venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
RUFF := $(VENV)/bin/ruff
MYPY := $(VENV)/bin/mypy
PYTEST := $(VENV)/bin/pytest
ALEMBIC := $(VENV)/bin/alembic

.PHONY: help install lint type test check fmt up down logs migrate eval smoke

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "\033[36m%-12s\033[0m %s\n",$$1,$$2}'

install: ## Create venv and install deps (dev)
	python3 -m venv $(VENV) && $(PIP) install -U pip && $(PIP) install -e ".[dev]"

fmt: ## Auto-format / fix
	$(RUFF) check --fix . && $(RUFF) format .

lint: ## Lint
	$(RUFF) check .

type: ## Type-check
	$(MYPY) aegis

test: ## Unit + integration tests
	$(PYTEST) -q

check: lint type test ## All gates (CI parity)

smoke: ## Import + syntax smoke (no deps required)
	python3 -m compileall -q aegis alembic && echo "compile OK"

up: ## Bring the stack up
	cd deploy && docker compose up -d --build

down: ## Tear the stack down
	cd deploy && docker compose down

logs: ## Tail service logs
	cd deploy && docker compose logs -f api worker

migrate: ## Apply DB migrations
	$(ALEMBIC) upgrade head

eval: ## Run the golden-set eval harness (Phase 10)
	$(PYTHON) -m eval.run
