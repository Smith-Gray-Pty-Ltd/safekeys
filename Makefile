# Safekeys — common tasks.
#
# `make dev` starts the local stack; `make build` builds the Go binaries.

SHELL := /bin/bash
GO    ?= go
BIN   := bin

.PHONY: help build test test-all lint typecheck generate check docs docs-help docs-build docs-preview dev dev-down clean demo mcp-smoke sdk-test images deploy-check verify-hardening

help:
	@echo "Safekeys targets:"
	@echo "  make build        Build the Go binaries (cli, control plane, sidecar)"
	@echo "  make test         Run the Go test suite"
	@echo "  make test-all     Run Go, MCP (TS) and Python suites"
	@echo "  make lint         go vet + gofmt check"
	@echo "  make generate     Regenerate USM docs and agent rules files"
	@echo "  make check        usm check (spec validity + drift)"
	@echo "  make docs         Serve the contributor spec docs with live reload"
	@echo "  make docs-help    Serve the help (public-facing) docs instead"
	@echo "  make docs-build   Build static spec docs HTML"
	@echo "  make docs-preview Serve the built static docs"
	@echo "  make dev          Start Postgres/OpenBao, control plane and sidecar"
	@echo "  make dev-down     Stop the local stack"
	@echo "  make demo         Run the end-to-end demo against the local stack"
	@echo "  make mcp-smoke    Drive the MCP server against the local stack"
	@echo "  make sdk-test     Run the Python SDK tests"
	@echo "  make images       Build the production container images"
	@echo "  make deploy-check Validate the production Compose file"
	@echo "  make clean        Remove build output"

build:
	mkdir -p $(BIN)
	$(GO) build -o $(BIN)/safekeys         ./apps/cli/cmd/safekeys
	$(GO) build -o $(BIN)/safekeys-cp      ./apps/control-plane/cmd/server
	$(GO) build -o $(BIN)/safekeys-sidecar ./apps/sidecar/cmd/sidecar
	@echo "built $(BIN)/safekeys{, -cp, -sidecar}"

test:
	$(GO) test ./...

sdk-build:
	cd packages/sdk-python && python3 -m build --outdir dist/

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
	usm generate --only help-docs >/dev/null 2>&1 || true
	usm generate --only agents-md >/dev/null 2>&1 || true

check:
	usm check
	usm validate .usm/system.usm

# ── Documentation ────────────────────────────────────────────────────────────
# USM produces two doc sets, both into gitignored .usm-workspace build output —
# there is no committed docs site:
#
#   .usm-workspace/docs/       contributor docs (architecture, specs, references)
#   .usm-workspace/help-docs/  help docs — a filtered public-facing subset
#
# `make generate` produces both. To read them:
#
#   make docs          live-reload dev server while editing .usm/ (recommended)
#   make docs-help     serve the help (public) audience instead
#   make docs-build    static HTML, then `make docs-preview` to serve it
#
# NOTE: the help docs are currently a *filtered subset* of the developer docs,
# not true user documentation. USM composes real user docs from personas and
# journeys, and system.usm declares none yet — so --only help-docs can only
# filter. Adding personas/journeys is what would make these user-facing.
#
# `usm docs serve` also writes .vitepress/config.mts on first run, which is what
# makes the pages render at all — serving the directory with bare `vitepress dev`
# produces an empty shell, because the config does not exist until then.
docs:
	usm docs serve --watch

docs-help:
	usm docs serve --watch --audience help

docs-build:
	usm docs build

docs-preview:
	@npx vitepress preview .usm-workspace/docs --port 5195

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

# ── Production deployment ────────────────────────────────────────────────────
# See deploy/README.md. These build and validate the hardened artefacts; they
# do not touch the development stack.

images:
	docker build -f Dockerfile.control-plane -t safekeys-control-plane:dev .
	docker build -f Dockerfile.sidecar       -t safekeys-sidecar:dev .
	@echo
	@echo "built safekeys-control-plane:dev and safekeys-sidecar:dev"
	@echo "pin digests for production with:"
	@echo "  docker inspect --format='{{index .RepoDigests 0}}' safekeys-control-plane:dev"

# Syntax-check the production Compose file and show the resolved config. The
# secrets are placeholders at this stage, so a missing file is expected; this
# proves the file parses and the image references resolve to digests.
deploy-check:
	docker compose -f deploy/compose.prod.yml config --quiet && echo "deploy/compose.prod.yml: valid"

# Prove the sidecar unit's systemd confinement still permits the operations the
# resolver performs (socket bind, fork/exec, file injection). Needs Docker and a
# Linux systemd image; see scripts/verify-hardening.sh.
verify-hardening:
	./scripts/verify-hardening.sh

clean:
	rm -rf $(BIN) packages/mcp-server/dist .usm-workspace
