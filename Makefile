SHELL := bash
GO    := go
PKG   := ./...
BIN   := bin/sophosfw
LDFLAGS := -X main.version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: fmt vet lint test test-int build install completions skill-doctor clean

fmt:
	$(GO) fmt $(PKG)

vet:
	$(GO) vet $(PKG)

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed; skipping"; exit 0; }
	golangci-lint run

test:
	$(GO) test -race $(PKG)

test-int:
	SOPHOSFW_INTEGRATION=1 $(GO) test -tags integration $(PKG)

build:
	mkdir -p bin
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/sophosfw

install: build
	install $(BIN) $$GOBIN/sophosfw

skill-doctor: build
	$(BIN) skill doctor

completions: build
	mkdir -p completions
	$(BIN) completion bash > completions/sophosfw.bash
	$(BIN) completion zsh > completions/sophosfw.zsh
	$(BIN) completion fish > completions/sophosfw.fish

clean:
	rm -rf bin dist coverage.txt
