# TailConnect build. Everything is plain `go build`; this file adds version
# stamping, release tarballs and shortcuts. See docs/installation.md.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath
ARCHES  ?= amd64 arm64

.PHONY: build test e2e bench perf perf-budget cross dist dist-windows android android-install install-server install-client clean

build: ## bin/tc-control, bin/tcd, bin/tc, bin/tc-relay
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...

test:
	go vet ./...
	go test -race ./...

e2e: ## network-namespace tests (no root needed with unprivileged user namespaces)
	tests/e2e/lan.sh
	tests/e2e/nat.sh

bench: ## Go benchmarks: packet paths, control-plane scale, end-to-end tunnel
	go test -run '^$$' -bench . -benchmem ./...

perf: ## throughput and latency with real kernel TUN devices (network namespaces)
	tests/perf/throughput.sh

perf-budget: ## fail if key operations exceed their performance budgets
	TC_PERF_BUDGET=1 go test -count=1 -run PerfBudget ./...

cross: ## compile checks for the other target platforms
	CGO_ENABLED=0 GOOS=windows go build ./...
	CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build ./...

android: ## android/build/tailconnect.apk (needs a JDK and the Android SDK; see docs/android.md)
	VERSION=$(VERSION) android/build.sh

android-install: ## build the APK and install it on the device connected over USB (adb)
	VERSION=$(VERSION) android/build.sh install

dist: ## dist/tailconnect-VERSION-linux-ARCH.tar.gz for each of ARCHES
	@mkdir -p dist
	@for arch in $(ARCHES); do \
		name=tailconnect-$(VERSION)-linux-$$arch; \
		d=dist/$$name; \
		mkdir -p $$d/bin $$d/packaging; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $$d/bin/ ./cmd/... || exit 1; \
		cp -r packaging/linux $$d/packaging/; \
		cp -r README.md docs $$d/; \
		tar -C dist -czf dist/$$name.tar.gz $$name; \
		rm -r dist/$$name; \
		echo "dist/$$name.tar.gz"; \
	done

# Wintun (the Windows TUN driver, from wintun.net) ships next to tcd.exe. Its
# license allows that; the zip is downloaded once and checked against this hash.
WINTUN_VERSION := 0.14.1
WINTUN_SHA256  := 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
WINTUN_ZIP     := dist/.cache/wintun-$(WINTUN_VERSION).zip

$(WINTUN_ZIP):
	@mkdir -p $(dir $@)
	curl -fsSL -o $@.tmp https://www.wintun.net/builds/wintun-$(WINTUN_VERSION).zip
	echo "$(WINTUN_SHA256)  $@.tmp" | sha256sum -c --quiet
	mv $@.tmp $@

dist-windows: $(WINTUN_ZIP) ## dist/tailconnect-VERSION-windows-ARCH.zip and -setup.exe (one-click installer) for each of ARCHES
	@for arch in $(ARCHES); do \
		name=tailconnect-$(VERSION)-windows-$$arch; \
		d=dist/$$name; \
		rm -rf $$d; mkdir -p $$d; \
		for c in tcd tc; do \
			CGO_ENABLED=0 GOOS=windows GOARCH=$$arch go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $$d/$$c.exe ./cmd/$$c || exit 1; \
		done; \
		CGO_ENABLED=0 GOOS=windows GOARCH=$$arch go build $(GOFLAGS) -ldflags "$(LDFLAGS) -H windowsgui" -o $$d/TailConnect.exe ./cmd/tc-gui || exit 1; \
		unzip -p $(WINTUN_ZIP) wintun/bin/$$arch/wintun.dll > $$d/wintun.dll || exit 1; \
		unzip -p $(WINTUN_ZIP) wintun/LICENSE.txt > $$d/LICENSE-wintun.txt; \
		sed 's/$$/\r/' packaging/windows/README.txt > $$d/README.txt; \
		cp -r docs $$d/; \
		rm -f dist/$$name.zip; (cd dist && zip -qr $$name.zip $$name) || exit 1; \
		rm -r $$d; \
		echo "dist/$$name.zip"; \
		cp dist/$$name.zip cmd/tc-gui/setup-payload.zip; \
		CGO_ENABLED=0 GOOS=windows GOARCH=$$arch go build -tags setup $(GOFLAGS) -ldflags "$(LDFLAGS) -H windowsgui" \
			-o dist/$$name-setup.exe ./cmd/tc-gui; rc=$$?; rm -f cmd/tc-gui/setup-payload.zip; [ $$rc = 0 ] || exit 1; \
		echo "dist/$$name-setup.exe"; \
	done

install-server: build
	sudo packaging/linux/install.sh server

install-client: build
	sudo packaging/linux/install.sh client

clean:
	rm -r -f bin dist
