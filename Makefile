# teardown: developer tasks. Needs GNU make and a Go toolchain (>= 1.24).
# On Windows run the same commands from PowerShell or use `make` from Git Bash.

BINARY   := teardown
PKG      := ./cmd/teardown
MODULE   := github.com/q6r/teardown
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w -X $(MODULE)/internal/version.version=$(VERSION) -X $(MODULE)/internal/version.commit=$(COMMIT) -X $(MODULE)/internal/version.date=$(DATE)
FUZZTIME ?= 20s

.DEFAULT_GOAL := help
.PHONY: help all build test race vet fmt fmt-check lint fuzz cover sample rules-doc web-check serve clean

help: ## List the available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

all: fmt-check vet test build ## Format check, vet, test and build

build: ## Build bin/teardown (static, stripped, version stamped)
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) $(PKG)

test: ## Run the unit tests
	go test -count=1 ./...

race: ## Run the unit tests with the race detector (needs cgo; one package at a time)
	go test -race -count=1 -p 1 ./...

vet: ## go vet
	go vet ./...

fmt: ## Format all Go files
	gofmt -w .

fmt-check: ## Fail when a file is not gofmt-clean
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "gofmt needed: run 'make fmt'"; exit 1; }

lint: ## golangci-lint (configured in .golangci.yml)
	golangci-lint run

fuzz: ## Run every fuzz target for FUZZTIME (default 20s) each
	@for dir in $$(grep -rl --include='*_test.go' 'func Fuzz' internal | xargs -n1 dirname | sort -u); do \
	  for target in $$(grep -ho 'func Fuzz[A-Za-z0-9_]*' $$dir/*_test.go | awk '{print $$2}'); do \
	    echo "== fuzz $$dir $$target"; \
	    go test -run '^$$' -fuzz "^$$target$$" -fuzztime $(FUZZTIME) ./$$dir || exit 1; \
	  done; \
	done

cover: ## Coverage report in coverage/index.html
	@mkdir -p coverage
	go test -count=1 -coverprofile=coverage/coverage.out ./...
	go tool cover -func=coverage/coverage.out | tail -n 1
	go tool cover -html=coverage/coverage.out -o coverage/index.html

sample: ## Regenerate testdata/sample-report.json from the fixture
	go test ./internal/analyze -run TestSampleReport -update

rules-doc: ## Regenerate docs/rules.md from the rule catalogue
	go test ./internal/rules -run TestCatalogDoc -update

web-check: ## Syntax-check the dashboard scripts (needs Node)
	@for f in web/app.js web/report-view.js web/report-boot.js; do node --check $$f || exit 1; done

serve: build ## Build and start the dashboard on 127.0.0.1:7777
	./bin/$(BINARY) serve

clean: ## Remove build output
	rm -rf bin dist coverage
