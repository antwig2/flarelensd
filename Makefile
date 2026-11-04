.PHONY: all build test cross-compile release-snapshot check clean

BINARY_NAME := flarelensd
BIN_DIR := bin
DIST_DIR := dist
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X main.Version=$(VERSION) \
	-X main.Commit=$(COMMIT) \
	-X main.Date=$(DATE) \
	-X main.BuiltBy=makefile

all: check test build

build:
	@mkdir -p $(BIN_DIR)
	go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/agent
	@echo "[+] Built $(BIN_DIR)/$(BINARY_NAME) (v$(VERSION))"

test:
	go test -v -race ./...

check:
	go vet ./...
	@if command -v goreleaser >/dev/null 2>&1; then \
		goreleaser check; \
	fi

cross-compile:
	@mkdir -p $(BIN_DIR)
	@echo "[*] Compiling cross-platform binaries into $(BIN_DIR)/..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/agent
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/agent
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/agent
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/agent
	@echo "[+] Completed multi-platform build:"
	@ls -lh $(BIN_DIR)/

release-snapshot:
	@if command -v goreleaser >/dev/null 2>&1; then \
		goreleaser release --snapshot --clean; \
	elif [ -f /tmp/goreleaser-bin/goreleaser ]; then \
		/tmp/goreleaser-bin/goreleaser release --snapshot --clean; \
	else \
		echo "[-] GoReleaser is not installed. Run: go install github.com/goreleaser/goreleaser/v2@latest"; \
		exit 1; \
	fi

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)
