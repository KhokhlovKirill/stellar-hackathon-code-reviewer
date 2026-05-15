.PHONY: help install lint type test check fmt up down logs migrate eval smoke

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "\033[36m%-12s\033[0m %s\n",$$1,$$2}'

install: ## Create venv and install deps (dev)
	python3 -m venv .venv && . .venv/bin/activate && pip install -U pip && pip install -e ".[dev]"

fmt: ## Auto-format / fix
	. .venv/bin/activate && ruff check --fix . && ruff format .

lint: ## Lint
	. .venv/bin/activate && ruff check .

type: ## Type-check
	. .venv/bin/activate && mypy aegis

test: ## Unit + integration tests
	. .venv/bin/activate && pytest -q

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
	. .venv/bin/activate && alembic upgrade head

eval: ## Run the golden-set eval harness (Phase 10)
	. .venv/bin/activate && python -m eval.run
