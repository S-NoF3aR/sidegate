VERSION ?= 0.1.0
OS_ARCH := $(shell go env GOOS)_$(shell go env GOARCH)
PLUGIN_ROOT ?= $(HOME)/.terraform.d/plugins
PLUGIN_DIR := $(PLUGIN_ROOT)/registry.terraform.io/s-nof3ar/sidegate/$(VERSION)/$(OS_ARCH)

.PHONY: build install test

build:
	CGO_ENABLED=0 go build -ldflags "-X main.version=$(VERSION)" -o terraform-provider-sidegate .

# Installs into Terraform's implied local mirror, so `terraform init` finds
# source = "s-nof3ar/sidegate", version = "$(VERSION)" without a registry.
install:
	mkdir -p $(PLUGIN_DIR)
	CGO_ENABLED=0 go build -ldflags "-X main.version=$(VERSION)" -o $(PLUGIN_DIR)/terraform-provider-sidegate_v$(VERSION) .

test:
	go test ./...
