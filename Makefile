VERSION := v2.1.0
BUILD_DATE := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildDate=$(BUILD_DATE)"

.PHONY: all build clean test codesign verify-sip sec-check sync package gui-app app

all: build codesign app

build:
	go build $(LDFLAGS) -o sec-agent cmd/sec-agent/*.go
	ln -sf sec-agent sec

codesign: build
	@echo "Signing sec-agent binary with macOS Hardened Runtime..."
	codesign --force --options runtime --sign - sec-agent

app: gui-app

gui-app: build
	@echo "=== Packaging sec-agent.app macOS Application Bundle ==="
	rm -rf sec-agent.app
	mkdir -p sec-agent.app/Contents/MacOS
	mkdir -p sec-agent.app/Contents/Resources
	cp sec-agent sec-agent.app/Contents/MacOS/sec-agent
	printf '#!/bin/sh\nDIR="$$(cd "$$(dirname "$$0")" && pwd)"\nexec "$$DIR/sec-agent" gui\n' > sec-agent.app/Contents/MacOS/SecAgentLauncher
	chmod +x sec-agent.app/Contents/MacOS/SecAgentLauncher
	printf '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n    <key>CFBundleExecutable</key>\n    <string>SecAgentLauncher</string>\n    <key>CFBundleIdentifier</key>\n    <string>io.iafilius.sec-agent</string>\n    <key>CFBundleName</key>\n    <string>sec-agent</string>\n    <key>CFBundlePackageType</key>\n    <string>APPL</string>\n    <key>CFBundleShortVersionString</key>\n    <string>2.0.0</string>\n    <key>LSUIElement</key>\n    <true/>\n</dict>\n</plist>\n' > sec-agent.app/Contents/Info.plist
	codesign --force --deep --options runtime --sign - sec-agent.app
	@echo "=== sec-agent.app created! Double-click it in Finder or move to /Applications ==="

package:
	@echo "=== Building Release Binaries & Tarballs for $(VERSION) ==="
	rm -rf dist && mkdir -p dist
	go build $(LDFLAGS) -o dist/sec-agent cmd/sec-agent/*.go
	codesign --force --options runtime --sign - dist/sec-agent
	cp README.md dist/README.md
	tar -czf dist/sec-agent_$(VERSION)_darwin_arm64.tar.gz -C dist sec-agent README.md
	rm -f dist/sec-agent dist/README.md
	cd dist && shasum -a 256 *.tar.gz > checksums.txt
	@echo "=== Release packages generated in dist/ ==="

clean:
	rm -rf bin sec sec-agent sec-agent-gui
	rm -rf sec-agent.app sec-agent-gui.app
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
	@echo "=== Cleaning old packages in publish/ ==="
	rm -rf publish/cmd publish/docs publish/internal publish/backup publish/biometrics publish/config publish/crypto publish/daemon publish/keychain publish/store publish/main.go publish/main_test.go publish/migration_test.go publish/bin
	@echo "=== Syncing core codebase and packages to publish/ ==="
	cp -r cmd docs internal publish/
	rm -f publish/docs/corporate_pitch_communications.md
	cp go.mod go.sum Makefile LICENSE README.md publish/
	@echo "=== Running sanity build & tests inside publish/ ==="
	cd publish && make build codesign && make sec-check && go test -v ./...

release-brew: package
	@echo "=== Updating Homebrew Formula & Tap Repository ==="
	@SHA=$$(shasum -a 256 dist/sec-agent_$(VERSION)_darwin_arm64.tar.gz | awk '{print $$1}'); \
	sed -i '' "s|url \".*\"|url \"https://github.com/iafilius/sec-agent/releases/download/$(VERSION)/sec-agent_$(VERSION)_darwin_arm64.tar.gz\"|g" Formula/sec-agent.rb; \
	sed -i '' "s|sha256 \".*\"|sha256 \"$$SHA\"|g" Formula/sec-agent.rb; \
	sed -i '' "s|assert_match \".*\"|assert_match \"$(VERSION)\"|g" Formula/sec-agent.rb; \
	mkdir -p publish/Formula && cp Formula/sec-agent.rb publish/Formula/sec-agent.rb; \
	if [ -d "scratch/homebrew-tap" ]; then \
		cp Formula/sec-agent.rb scratch/homebrew-tap/Formula/sec-agent.rb; \
		git -C scratch/homebrew-tap pull --rebase origin main 2>/dev/null || true; \
		git -C scratch/homebrew-tap add Formula/sec-agent.rb; \
		git -C scratch/homebrew-tap commit -m "chore(brew): Update sec-agent formula to $(VERSION)" 2>/dev/null || true; \
		git -C scratch/homebrew-tap push origin main 2>/dev/null || true; \
	fi
