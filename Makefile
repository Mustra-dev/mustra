# Everyday commands. `make` with no target lists them.
#
# Build identity comes from git so a locally built image or binary reports
# what it actually is on the About page rather than "dev".
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "")
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
# Only an explicit Make override should supersede Compose's .env pin.
IMAGE_AGENT_VERSION := $(if $(AGENT_VERSION),MUSTRA_AGENT_VERSION=$(AGENT_VERSION))
AGENT_VERSION ?= $(if $(MUSTRA_AGENT_VERSION),$(MUSTRA_AGENT_VERSION),$(VERSION))
IMAGE      ?= ghcr.io/mustra-dev/mustra
MODULE      = github.com/mustra-dev/mustra
IDENTITY_LDFLAGS = -X $(MODULE)/internal/version.AgentVersion=$(AGENT_VERSION) \
              -X $(MODULE)/internal/version.Version=$(VERSION) \
              -X $(MODULE)/internal/version.Commit=$(COMMIT)
LDFLAGS = $(IDENTITY_LDFLAGS) -X $(MODULE)/internal/version.BuildTime=$(BUILD_TIME)
SERVER_TARGETS = linux/amd64 linux/arm64
AGENT_TARGETS = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.DEFAULT_GOAL := help

.PHONY: help
help: ## List targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[1m%-14s\033[0m %s\n", $$1, $$2}'

# ---- build & check --------------------------------------------------------

.PHONY: build
build: ## Compile everything (no binaries written)
	go build ./...

.PHONY: server
server: ## Build bin/mustra-server for this machine
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/mustra-server ./cmd/server

# Agent payloads must stay identical across server-only commits/checkouts.
# The independent agent version supplies identity without server VCS metadata.
.PHONY: agents
# The Windows tray is built first: each Windows agent embeds the tray of its
# own build (internal/agent/trayembed), and the placeholders are emptied
# again afterwards so a build leaves the checkout clean.
agents: python-runtimes ## Cross-compile the agent for every platform into bin/agents/
	@set -e; for arch in amd64 arm64; do \
	  echo "  windows/$$arch tray"; \
	  CGO_ENABLED=0 GOOS=windows GOARCH=$$arch go build -trimpath -buildvcs=false \
	    -ldflags="-H windowsgui -X main.version=$(AGENT_VERSION)" \
	    -o bin/agents/mustra-tray-windows-$$arch.exe ./cmd/mustra-tray; \
	  cp bin/agents/mustra-tray-windows-$$arch.exe internal/agent/trayembed/mustra-tray-windows-$$arch.bin; \
	done
	@set -e; trap ': > internal/agent/trayembed/mustra-tray-windows-amd64.bin; : > internal/agent/trayembed/mustra-tray-windows-arm64.bin' EXIT; \
	for target in $(AGENT_TARGETS); do \
	  os=$${target%/*}; arch=$${target#*/}; ext=""; [ "$$os" = windows ] && ext=.exe; \
	  echo "  $$target"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -buildvcs=false -ldflags="-X main.version=$(AGENT_VERSION)" \
	    -o bin/agents/mustra-agent-$$os-$$arch$$ext ./cmd/agent; \
	done

# CI builds once on the host, then packages these outputs for each image arch.
# -trimpath, as in Dockerfile.server's server stage: without it the checkout
# directory is part of every package's cache key, so E2E's image build could
# not reuse the Go cache this build leaves (.github/workflows/e2e.yml).
.PHONY: servers
servers: ## Cross-compile Linux servers into bin/servers/<os>_<arch>/
	@set -e; for target in $(SERVER_TARGETS); do \
	  os=$${target%/*}; arch=$${target#*/}; \
	  echo "  server $$target"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags="$(LDFLAGS)" \
	    -o bin/servers/$${os}_$$arch/mustra-server ./cmd/server; \
	done

.PHONY: test
test: ## Run the unit tests
	go test ./...

.PHONY: lint
lint: ## gofmt and go vet, the checks CI enforces
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needs to run on:"; echo "$$out"; exit 1; fi
	go vet ./...

.PHONY: fmt
fmt: ## gofmt the tree
	gofmt -w .

.PHONY: check
check: lint build test ## Everything CI runs

# ---- production stack (deploy/) -------------------------------------------

.PHONY: quickstart
quickstart: ## From a fresh clone to a running console, in one command
	./deploy/init.sh --start

.PHONY: init
init: ## First-run bootstrap: .env with real secrets, NATS certs, LAN address
	./deploy/init.sh

# script-tools is built alongside the server, never pulled: `server` will not
# start without it (depends_on: service_healthy) and most installs have no
# published image for it, so building only `server` leaves the stack wedged
# on a pull that cannot succeed.
.PHONY: image
image: ## Build the control-plane and script-tools images with version stamping
	cd deploy && MUSTRA_VERSION=$(VERSION) $(IMAGE_AGENT_VERSION) MUSTRA_COMMIT=$(COMMIT) MUSTRA_BUILD_TIME=$(BUILD_TIME) \
	  docker compose build script-tools server

.PHONY: up
up: image ## Build and start the production stack, waiting for it to be healthy
	cd deploy && docker compose up -d --wait

.PHONY: down
down: ## Stop the production stack (volumes kept)
	cd deploy && docker compose down

.PHONY: logs
logs: ## Follow the server's logs
	cd deploy && docker compose logs -f server

# ---- local development ----------------------------------------------------
#
# NATS, Postgres, and script tools in containers, server and agent from source. See
# docs/DEVELOPMENT.md.

.PHONY: dev-up
dev-up: ## Start backing services and script tools for local development
	cd deploy && docker compose -f compose.dev.yml up -d --build --wait

.PHONY: dev-down
dev-down: ## Stop the development services (volumes kept)
	cd deploy && docker compose -f compose.dev.yml down

.PHONY: dev-reset
dev-reset: ## Stop the development services and wipe their data
	cd deploy && docker compose -f compose.dev.yml down -v

.PHONY: dev-server
# Loopback only, plain HTTP, and a fresh random break-glass password on every
# run (printed below): a console that runs commands on a fleet must not sit
# on the LAN with admin/admin. Override DEV_HTTP_ADDR to expose it on purpose.
DEV_HTTP_ADDR ?= 127.0.0.1:8080
dev-server: ## Run the server from source against the dev services (127.0.0.1, random password)
	@pw="$$(openssl rand -base64 18 2>/dev/null || head -c 18 /dev/urandom | base64)"; \
	echo "mustra dev server: http://$(DEV_HTTP_ADDR)  sign in as admin / $$pw"; \
	MUSTRA_HTTP_ADDR=$(DEV_HTTP_ADDR) \
	MUSTRA_COOKIE_SECURE=false \
	MUSTRA_BREAKGLASS_USERNAME=admin MUSTRA_BREAKGLASS_PASSWORD="$$pw" \
	MUSTRA_ALLOW_PLACEHOLDER_SECRETS=true \
	MUSTRA_AGENT_NATS_URL=nats://127.0.0.1:4222 \
	MUSTRA_PUBLIC_URL=http://127.0.0.1:8080 MUSTRA_ALLOW_INSECURE_PUBLIC_URL=true \
	MUSTRA_AGENT_BUILDS_DIR=$(CURDIR)/bin/agents \
	MUSTRA_LOG_LEVEL=debug \
	go run -ldflags="$(IDENTITY_LDFLAGS)" ./cmd/server

.PHONY: dev-agent
dev-agent: ## Run an agent from source against the dev services (needs sudo for most sensors)
	MUSTRA_DATA_DIR=$(CURDIR)/scratch/agent-data MUSTRA_SITE=dev \
	go run ./cmd/agent --nats-url nats://127.0.0.1:4222

.PHONY: python-runtimes
python-runtimes: ## Package pinned private Python runtimes alongside agent downloads
	python3 tools/python-runtime/package.py bin/agents
