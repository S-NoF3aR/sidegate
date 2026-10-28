VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# Where this version's source is published (linked in the UI, AGPL §13).
SOURCE_URL ?= https://github.com/s-nof3ar/sidegate
LDFLAGS := -s -w -X main.version=$(VERSION) -X sidegate/internal/config.DefaultSourceURL=$(SOURCE_URL)
GUAC_LICENSE := internal/server/web/static/vendor/guacamole-common-LICENSE.txt
DIST ?= dist
# The sidegate CLI is built for these; the server for linux/amd64 and linux/arm64.
CLI_PLATFORMS ?= windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
PROXY_PLATFORMS ?= linux/amd64 linux/arm64
IMAGE ?= sidegate

.PHONY: build test release cli proxy image notices clean

# Local binaries for this machine.
build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/sidegate-server ./cmd/sidegate-server
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/sidegate ./cmd/sidegate

test:
	go test -race ./...
	cd terraform-provider-sidegate && go test ./...

# Everything to publish: dist/cli/ (what the proxy serves on /cli) and
# dist/sidegate-server-<os>-<arch>.
release: clean cli proxy notices
	@cp LICENSE NOTICE $(DIST)/
	@cp LICENSE $(DIST)/cli/
	@cp $(DIST)/THIRD_PARTY_NOTICES $(DIST)/cli/
	@echo "Release $(VERSION) in $(DIST)/"

# License texts of all third-party components in the binaries.
notices:
	@mkdir -p $(DIST)
	go run ./tools/notices -extra "guacamole-common-js 1.5.0=$(GUAC_LICENSE)" ./cmd/... > $(DIST)/THIRD_PARTY_NOTICES
	go run ./tools/notices -C terraform-provider-sidegate ./... > $(DIST)/THIRD_PARTY_NOTICES.terraform-provider

cli:
	@mkdir -p $(DIST)/cli
	@set -e; for p in $(CLI_PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; \
		if [ "$$os" = windows ]; then ext=.exe; fi; \
		echo "  sidegate $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o $(DIST)/cli/sidegate-$$os-$$arch$$ext ./cmd/sidegate; \
	done
	@echo $(VERSION) > $(DIST)/cli/VERSION
	@cd $(DIST)/cli && sha256sum sidegate-* > SHA256SUMS

proxy:
	@mkdir -p $(DIST)
	@set -e; for p in $(PROXY_PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		echo "  sidegate-server $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o $(DIST)/sidegate-server-$$os-$$arch ./cmd/sidegate-server; \
	done
	@cd $(DIST) && sha256sum sidegate-server-linux-* > SHA256SUMS

image:
	docker build --build-arg VERSION=$(VERSION) \
		--build-arg SOURCE_URL=$(SOURCE_URL) -t $(IMAGE):$(VERSION) .

clean:
	rm -rf $(DIST) bin
