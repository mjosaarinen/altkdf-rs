# Makefile — TLS 1.3 deck key schedule prototype
#
# Thin wrapper over cargo for the workspace, plus housekeeping.
# `make` or `make help` lists the targets.

CARGO        ?= cargo
CARGO_FLAGS  ?=
PYTHON       ?= python3
CLIPPY_ARGS  := --all-targets --all-features -- -D warnings
# Bare-metal target with no std, to prove `deck-schedule` is genuinely no_std.
NOSTD_TARGET ?= thumbv7em-none-eabi

.DEFAULT_GOAL := help
.PHONY: all build release test fmt fmt-check lint check ci doc vectors reproduce bench no-std clean distclean help

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

vectors: ## Regenerate deck-schedule/vectors/*.json (Appendix C deck + Appendix D FIPS)
	$(CARGO) run $(CARGO_FLAGS) -p deck-schedule --example gen_vectors

reproduce: ## Independently reproduce the vectors (draft App. C + App. D gate)
	$(PYTHON) deck-schedule/vectors/reproduce.py

bench: ## Appendix A.1 permutation-count benchmark (deck vs HKDF-SHA3-256)
	$(CARGO) run $(CARGO_FLAGS) -p deck-schedule --example invocations --features bench

no-std: ## Build deck-schedule as no_std for a bare-metal target (regression guard)
	@rustup target add $(NOSTD_TARGET) >/dev/null 2>&1 || true
	$(CARGO) build -p deck-schedule --lib --target $(NOSTD_TARGET)

ci: fmt-check lint test reproduce bench no-std ## Full local gate: fmt-check + lint + test + reproduction + benchmark + no_std

clean: ## cargo clean + remove demo capture artifacts
	$(CARGO) clean
	@find . -type f \( -name '*.keylog' -o -name '*.pcap' -o -name '*.pcapng' \) \
		-not -path './.git/*' -delete
	@echo "cleaned: target/ and capture artifacts (doc/ references untouched)"

distclean: clean ## clean + drop Cargo.lock (back to pristine sources)
	@rm -f Cargo.lock
	@echo "removed Cargo.lock"

help: ## Show this help
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_-]+:.*?## / \
		{printf "  \033[36m%-11s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
