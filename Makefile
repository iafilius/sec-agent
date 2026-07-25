VERSION := v1.9.3
BUILD_DATE := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildDate=$(BUILD_DATE)"

.PHONY: all build clean test codesign verify-sip sec-check sync package

all: build codesign

build:
	go build $(LDFLAGS) -o sec cmd/sec/main.go

codesign: build
	@echo "Signing binary with macOS Hardened Runtime..."
	codesign --force --options runtime --sign - sec

package:
	@echo "=== Building Release Binaries & Tarballs for $(VERSION) ==="
	rm -rf dist && mkdir -p dist
	go build $(LDFLAGS) -o dist/sec-agent cmd/sec/main.go
	codesign --force --options runtime --sign - dist/sec-agent
	cp README.md dist/README.md
	tar -czf dist/sec-agent_$(VERSION)_darwin_arm64.tar.gz -C dist sec-agent README.md
	rm -f dist/sec-agent dist/README.md
	cd dist && shasum -a 256 *.tar.gz > checksums.txt
	@echo "=== Release packages generated in dist/ ==="

clean:
	rm -f sec sec-agent
	rm -rf ~/.config/sec/sec.sock ~/.config/sec-agent/sec-agent.sock

test:
	go test -v ./...

verify-sip: build codesign
	@echo "Verifying codesign entitlements and flags..."
	codesign -d --verbose sec-agent
	@echo "Attempting to inspect with lldb (expected to fail if SIP is enabled and Hardened Runtime is active)..."
	@echo "Run: lldb -batch -o 'process launch' ./sec-agent"

sec-check:
	@echo "=== Running Go Vet ==="
	go vet ./...
	@echo "=== Running Go Vulncheck ==="
	@if [ -f $$HOME/go/bin/govulncheck ]; then $$HOME/go/bin/govulncheck ./...; else govulncheck ./...; fi
	@echo "=== Running Go AST Security Checker (gosec) ==="
	@if [ -f $$HOME/go/bin/gosec ]; then $$HOME/go/bin/gosec -exclude=G115 ./...; else gosec -exclude=G115 ./...; fi

sync:
	@echo "=== Cleaning old root packages in sec-agent/ ==="
	rm -rf sec-agent/backup sec-agent/biometrics sec-agent/config sec-agent/crypto sec-agent/daemon sec-agent/keychain sec-agent/store sec-agent/main.go sec-agent/main_test.go sec-agent/migration_test.go
	@echo "=== Syncing core codebase and packages to sec-agent/ ==="
	cp -r cmd docs internal sec-agent/
	rm -f sec-agent/docs/corporate_pitch_communications.md
	cp go.mod go.sum Makefile LICENSE README.md sec-agent/
	@echo "=== Running sanity build & tests inside sec-agent/ ==="
	cd sec-agent && make build codesign && make sec-check && go test -v ./...
