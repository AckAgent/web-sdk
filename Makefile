.PHONY: build test coverage pnpm-install clean lint format set-version download-bbs-wasm download-test-vectors release

# BBS+ WASM artifact — checked in for npm consumers (runtime dependency).
# Use `make download-bbs-wasm` to fetch from the ackagent/bbs-ffi GitHub Release.
BBS_WASM := src/generated/bbs_ffi_wasm/bbs_ffi_bg.wasm

BBS_FFI_VERSION ?= latest

# ── VERSION resolution ─────────────────────────────────────
# Supports: make release VERSION=1.2.3 | VERSION=patch | VERSION=minor | VERSION=major
ifdef VERSION
  ifneq ($(filter v%,$(VERSION)),)
    $(error VERSION must not start with 'v' — the prefix is added automatically. Usage: make release VERSION=1.2.3)
  endif
  ifneq ($(filter patch minor major,$(VERSION)),)
    _LATEST_TAG := $(shell git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo v0.0.0)
    _LATEST_VER := $(patsubst v%,%,$(_LATEST_TAG))
    _VER_PARTS  := $(subst ., ,$(_LATEST_VER))
    _CUR_MAJOR  := $(or $(word 1,$(_VER_PARTS)),0)
    _CUR_MINOR  := $(or $(word 2,$(_VER_PARTS)),0)
    _CUR_PATCH  := $(or $(word 3,$(_VER_PARTS)),0)
    ifeq ($(VERSION),patch)
      override VERSION := $(_CUR_MAJOR).$(_CUR_MINOR).$(shell echo $$(($(_CUR_PATCH) + 1)))
    else ifeq ($(VERSION),minor)
      override VERSION := $(_CUR_MAJOR).$(shell echo $$(($(_CUR_MINOR) + 1))).0
    else ifeq ($(VERSION),major)
      override VERSION := $(shell echo $$(($(_CUR_MAJOR) + 1))).0.0
    endif
  endif
  ifeq ($(shell echo '$(VERSION)' | grep -cE '^[0-9]+\.[0-9]+\.[0-9]+$$'),0)
    $(error Invalid VERSION '$(VERSION)'. Must be semver X.Y.Z (e.g. 1.2.3) or bump keyword (patch|minor|major))
  endif
endif
# ────────────────────────────────────────────────────────────

# Download BBS WASM from ackagent/bbs-ffi GitHub Release
download-bbs-wasm:
	@mkdir -p src/generated/bbs_ffi_wasm
	@echo "Downloading BBS WASM from ackagent/bbs-ffi release ($(BBS_FFI_VERSION))..."
	gh release download $(BBS_FFI_VERSION) \
		--repo ackagent/bbs-ffi \
		--pattern "bbs_ffi_wasm.*" \
		--dir src/generated/bbs_ffi_wasm \
		--clobber
	@echo "BBS WASM downloaded to src/generated/bbs_ffi_wasm/"

# Cross-platform test vectors — downloaded from ackagent/api (single source of truth)
TEST_VECTORS_VERSION ?= v0.1.12
TEST_VECTORS_BASE = https://raw.githubusercontent.com/AckAgent/api/$(TEST_VECTORS_VERSION)

download-test-vectors:
	@if [ ! -f test-fixtures/crypto_test_vectors.json ]; then \
		echo "==> Downloading test vectors $(TEST_VECTORS_VERSION)..."; \
		mkdir -p test-fixtures; \
		curl -sfL $(TEST_VECTORS_BASE)/data/crypto_test_vectors.json -o test-fixtures/crypto_test_vectors.json; \
		curl -sfL $(TEST_VECTORS_BASE)/data/protocol_test_vectors.json -o test-fixtures/protocol_test_vectors.json; \
		echo "==> Test vectors downloaded to test-fixtures/"; \
	else \
		echo "==> Test vectors already present"; \
	fi

# Set version in package.json (called by make release)
set-version:
ifndef VERSION
	$(error VERSION is required)
endif
	@node -e "const pkg=require('./package.json'); pkg.version='$(VERSION)'; require('fs').writeFileSync('package.json', JSON.stringify(pkg,null,2)+'\n')"
	@echo "Updated package.json to version $(VERSION)"

build: pnpm-install
	pnpm build

test: pnpm-install download-test-vectors
	pnpm test

coverage: pnpm-install download-test-vectors
	pnpm test:coverage

pnpm-install:
	pnpm install

lint: pnpm-install
	pnpm lint

format: pnpm-install
	pnpm format

# Release: bump version, commit, tag, push
# Usage: make release VERSION=0.2.0
release:
ifndef VERSION
	$(error VERSION is required. Usage: make release VERSION=1.2.3 (or patch|minor|major))
endif
	@echo "Releasing v$(VERSION)$(if $(_LATEST_VER), (was v$(_LATEST_VER)),)"
	$(MAKE) set-version VERSION=$(VERSION)
	git add package.json
	git commit -m "chore: release v$(VERSION)"
	git tag v$(VERSION)
	git push origin main v$(VERSION)

clean:
	rm -rf dist coverage
