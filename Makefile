.PHONY: help backend-install backend-check backend-test backend-lint backend-type docker-build docker-up docker-down docker-logs

help:
	@printf "%s\n" "Targets: backend-install backend-check backend-test backend-lint backend-type docker-build docker-up docker-down docker-logs"

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
	docker compose -f backend/deploy/docker-compose.yml logs -f api worker
