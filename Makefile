# TailConnect build. Everything is plain `go build`; this file adds version
# stamping, release tarballs and shortcuts. See docs/installation.md.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath
ARCHES  ?= amd64 arm64

.PHONY: build test e2e bench perf perf-budget cross dist android android-install install-server install-client clean

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

install-server: build
	sudo packaging/linux/install.sh server

install-client: build
	sudo packaging/linux/install.sh client

clean:
	rm -r -f bin dist
