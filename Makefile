# Safekeys — common tasks.
#
# `make dev` starts the local stack; `make build` builds the Go binaries.

SHELL := /bin/bash
GO    ?= go
BIN   := bin

.PHONY: help build test test-all lint typecheck generate check dev dev-down clean demo mcp-smoke sdk-test

help:
	@echo "Safekeys targets:"
	@echo "  make build        Build the Go binaries (cli, control plane, sidecar)"
	@echo "  make test         Run the Go test suite"
	@echo "  make test-all     Run Go, MCP (TS) and Python suites"
	@echo "  make lint         go vet + gofmt check"
	@echo "  make generate     Regenerate USM docs and agent rules files"
	@echo "  make check        usm check (spec validity + drift)"
	@echo "  make dev          Start Postgres/OpenBao, control plane and sidecar"
	@echo "  make dev-down     Stop the local stack"
	@echo "  make demo         Run the end-to-end demo against the local stack"
	@echo "  make mcp-smoke    Drive the MCP server against the local stack"
	@echo "  make sdk-test     Run the Python SDK tests"
	@echo "  make clean        Remove build output"

build:
	mkdir -p $(BIN)
	$(GO) build -o $(BIN)/safekeys         ./apps/cli/cmd/safekeys
	$(GO) build -o $(BIN)/safekeys-cp      ./apps/control-plane/cmd/server
	$(GO) build -o $(BIN)/safekeys-sidecar ./apps/sidecar/cmd/sidecar
	@echo "built $(BIN)/safekeys{, -cp, -sidecar}"

test:
	$(GO) test ./...

test-all: test sdk-test
	cd packages/mcp-server && npm test

lint:
	$(GO) vet ./...
	@out=$$(gofmt -l ./apps ./pkg 2>/dev/null); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	@echo "gofmt clean"

sdk-test:
	cd packages/sdk-python && (test -d .venv || python3 -m venv .venv) \
	  && .venv/bin/pip install -q -e '.[dev]' \
	  && .venv/bin/ruff check safekeys tests \
	  && .venv/bin/python -m pytest -q

generate:
	usm generate
	usm generate --only agents-md >/dev/null 2>&1 || true

check:
	usm check
	usm validate .usm/system.usm

dev:
	docker compose up -d
	@until docker compose exec -T postgres pg_isready -U safekeys -d safekeys >/dev/null 2>&1; do sleep 0.3; done
	./scripts/dev-up.sh --daemon

dev-down:
	./scripts/dev-down.sh

demo:
	./scripts/demo.sh

mcp-smoke:
	cd packages/mcp-server && node scripts/mcp-smoke.mjs

clean:
	rm -rf $(BIN) packages/mcp-server/dist .usm-workspace
