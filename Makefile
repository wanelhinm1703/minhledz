# AI-Pentest Copilot - Master Makefile
SHELL := /bin/bash
PYTHON ?= python

.PHONY: help setup dev scan test ingest ingest-update kb-stats clean docker-up docker-up-ollama docker-up-lab docker-up-full

help:
	@echo "AI-Pentest Copilot - Available commands:"
	@echo "  make setup                     Initialize directories & install dependencies"
	@echo "  make scan TARGET=<target>      Scan dynamic target (IP, URL, CIDR, domain, etc.)"
	@echo "  make test                      Run automated test suite"
	@echo "  make dev                       Run development server"
	@echo "  make ingest                    Ingest vulnerability knowledge base"
	@echo "  make kb-stats                  Display knowledge base statistics"

setup:
	@bash scripts/init.sh 2>/dev/null || $(PYTHON) toolkit/scripts/init_dirs.py
	@$(PYTHON) -m pip install -q -r backend/requirements.txt || true
	@echo "Setup completed successfully."

scan:
	@if [ -z "$(TARGET)" ]; then \
		echo "ERROR: TARGET variable is required. Example: make scan TARGET=192.168.56.101"; \
		exit 1; \
	fi
	@$(PYTHON) toolkit/scripts/targets.py scan --target "$(TARGET)"

test:
	@$(PYTHON) -m pytest backend/tests -v

dev:
	@uvicorn backend.app.main:app --reload --port 8000

ingest:
	@$(PYTHON) -m backend.app.ingest.run

ingest-update:
	@$(PYTHON) -m backend.app.ingest.run --update

kb-stats:
	@$(PYTHON) -m backend.app.storage.db --stats

clean:
	@rm -rf toolkit/tmp/*
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

docker-up:
	@docker compose up -d

docker-up-ollama:
	@docker compose --profile ollama up -d

docker-up-lab:
	@docker compose --profile lab up -d

docker-up-full:
	@docker compose --profile full up -d
