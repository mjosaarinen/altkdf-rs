# Makefile — TLS 1.3 deck key schedule prototype
#
# Thin wrapper over cargo for the workspace, plus housekeeping.
# `make` or `make help` lists the targets.

CARGO        ?= cargo
CARGO_FLAGS  ?=
CLIPPY_ARGS  := --all-targets --all-features -- -D warnings
# Bare-metal target with no std, to prove `deck-schedule` is genuinely no_std.
NOSTD_TARGET ?= thumbv7em-none-eabi

.DEFAULT_GOAL := help
.PHONY: all build release test fmt fmt-check lint check ci doc doc-check vectors reproduce bench no-std clean distclean help

all: build ## Build the workspace (debug)

build: ## cargo build (debug)
	$(CARGO) build $(CARGO_FLAGS)

release: ## cargo build --release
	$(CARGO) build --release $(CARGO_FLAGS)

test: ## cargo test (all crates)
	$(CARGO) test $(CARGO_FLAGS)

fmt: ## Format the tree in place
	$(CARGO) fmt

fmt-check: ## Check formatting (no writes)
	$(CARGO) fmt --check

lint: ## clippy with warnings-as-errors
	$(CARGO) clippy $(CLIPPY_ARGS)

check: ## Fast type-check
	$(CARGO) check --all-targets --all-features

doc: ## Build API docs (this workspace only)
	$(CARGO) doc --no-deps

doc-check: ## Strict rustdoc (warnings-as-errors), incl. deck-schedule --all-features
	RUSTDOCFLAGS='-D warnings' $(CARGO) doc --no-deps
	RUSTDOCFLAGS='-D warnings' $(CARGO) doc -p deck-schedule --no-deps --all-features

vectors: ## Emit independent Rust appendix values as name/hex pairs
	$(CARGO) run $(CARGO_FLAGS) -p deck-schedule --example gen_vectors

reproduce: ## Compare all 162 independent Rust values against the combined draft
	$(CARGO) test -p deck-schedule --test vectors

bench: ## Schedule-only count: 15/23 vs HKDF-SHA3-256 30/120
	$(CARGO) run $(CARGO_FLAGS) -p deck-schedule --example invocations --features bench

no-std: ## Build deck-schedule as no_std for a bare-metal target (regression guard)
	@rustup target add $(NOSTD_TARGET) >/dev/null 2>&1 || true
	$(CARGO) build -p deck-schedule --lib --target $(NOSTD_TARGET)

ci: fmt-check lint test reproduce bench no-std doc-check ## Full local gate: fmt-check + lint + test + reproduction + benchmark + no_std + strict docs

clean: ## cargo clean + remove demo capture artifacts
	$(CARGO) clean
	@find . -type f \( -name '*.keylog' -o -name '*.pcap' -o -name '*.pcapng' \) \
		-not -path './.git/*' -delete
	@echo "cleaned: target/ and capture artifacts"

distclean: clean ## clean + drop Cargo.lock (back to pristine sources)
	@rm -f Cargo.lock
	@echo "removed Cargo.lock"

help: ## Show this help
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / \
		{printf "  \033[36m%-11s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
