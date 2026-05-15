.PHONY: help backend-install backend-check backend-test backend-lint backend-type docker-build docker-up docker-down docker-logs frontend-install frontend-dev frontend-build

help:
	@printf "%s\n" "Quick start:  cp backend/.env.example .env  # fill AEGIS_VAULT_KEY"
	@printf "%s\n" "              make docker-up                 # UI http://localhost:8099"
	@printf "%s\n" ""
	@printf "%s\n" "Targets: backend-install backend-check backend-test backend-lint backend-type"
	@printf "%s\n" "         docker-build docker-up docker-down docker-logs"
	@printf "%s\n" "         frontend-install frontend-dev frontend-build"

backend-install:
	cd backend && $(MAKE) install

backend-check:
	cd backend && $(MAKE) check

backend-test:
	cd backend && $(MAKE) test

backend-lint:
	cd backend && $(MAKE) lint

backend-type:
	cd backend && $(MAKE) type

docker-build:
	docker compose -f backend/deploy/docker-compose.yml build

docker-up:
	docker compose -f backend/deploy/docker-compose.yml up -d

docker-down:
	docker compose -f backend/deploy/docker-compose.yml down

docker-logs:
	docker compose -f backend/deploy/docker-compose.yml logs -f api worker web

frontend-install:
	cd frontend && npm install

frontend-dev:
	cd frontend && npm run dev

frontend-build:
	cd frontend && npm run build
