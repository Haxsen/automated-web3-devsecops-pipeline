# Run the same security gates as CI, locally, with only Docker installed.
# Images and versions match .github/workflows/security-pipeline.yml.

SHELL := bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

PWD_ABS        := $(shell pwd)
SOLC_VERSION   := 0.8.28
FOUNDRY_IMAGE  := ghcr.io/foundry-rs/foundry:v1.9.0
TERRAFORM_IMAGE:= hashicorp/terraform:1.17.2
TFLINT_IMAGE   := ghcr.io/terraform-linters/tflint:v0.66.0
TRUFFLEHOG_IMAGE := trufflesecurity/trufflehog:3.99.9@sha256:2ec535840f860aa27f11fee20222fb790326ecd66325c96bd49d02ec6af46eca
GITLEAKS_IMAGE := zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
MYTHRIL_IMAGE  := mythril/myth:0.24.8@sha256:49e11758e359d0b410f648df5bbcba28a52e091a78e4772b5c02b9043666b4ff
CHECKOV_IMAGE  := bridgecrew/checkov:3.4.5@sha256:122602cf32cc72286155d39f1f234b7b594818f7b8d7fdf490701620e521368b
CONFTEST_IMAGE := openpolicyagent/conftest:v0.71.1@sha256:0e77cdf7c1fcde035f3c579e4aaa6664ee2a8be5777eaa9af9f520cdd02280c0
ACTIONLINT_IMAGE := rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
ZIZMOR_IMAGE   := ghcr.io/zizmorcore/zizmor:1.32.0@sha256:3014cc8f68f663935f69b3c3e0e41f5ce102b268d97db13db0f62208747f860d

DOCKER_RUN := docker run --rm -v "$(PWD_ABS):/repo" -w /repo
FORGE      := $(DOCKER_RUN) -w /repo/contracts $(FOUNDRY_IMAGE)
# Containers run as a different uid than the checkout owner; let git read the repo anyway.
GIT_SAFE   := -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=*

.PHONY: help all test coverage slither mythril secrets iac policy workflows lock clean

help: ## Show targets
	@grep -E '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

all: workflows secrets test slither iac policy mythril ## Run every gate (Mythril last, it is slow)

test: ## forge fmt + build + 10k-run fuzz + invariants
	$(FORGE) "forge fmt --check && forge build --sizes && FOUNDRY_PROFILE=ci forge test"

coverage: ## Coverage report + gate
	$(FORGE) "forge coverage --no-match-coverage '(test|script|canary)' --report summary --report lcov"
	python3 scripts/coverage_gate.py contracts/lcov.info --min-lines 100 --min-branches 95

slither: ## Slither gate + canary (builds a throwaway image from the hash-locked requirements)
	docker build -q -t local/slither -f - requirements <<< $$'FROM python:3.12-slim\nCOPY --from=$(FOUNDRY_IMAGE) /usr/local/bin/forge /usr/local/bin/forge\nRUN apt-get update -qq && apt-get install -y -qq git >/dev/null\nCOPY slither.txt /tmp/\nRUN pip install -q --require-hashes --no-deps -r /tmp/slither.txt && solc-select install $(SOLC_VERSION) >/dev/null'
	$(DOCKER_RUN) local/slither sh -c "git config --global --add safe.directory '*' && \
	  slither contracts/canary/VulnerableVault.sol --compile-force-framework solc --solc-solcs-select $(SOLC_VERSION) --fail-none --json /tmp/canary.json >/dev/null 2>&1; \
	  python scripts/slither_canary.py /tmp/canary.json --expect reentrancy-eth --expect tx-origin --expect arbitrary-send-eth && \
	  slither contracts --config-file contracts/slither.config.json"

mythril: ## Mythril gate on SecureVault (~10 min)
	$(FORGE) "mkdir -p build && forge flatten src/SecureVault.sol --output build/SecureVault.flat.sol"
	$(DOCKER_RUN) -e SOLC=$(SOLC_VERSION) -w /repo/contracts $(MYTHRIL_IMAGE) analyze build/SecureVault.flat.sol:SecureVault \
	  --solv $(SOLC_VERSION) --execution-timeout 600 --max-depth 128 -t 2 -o json > mythril.json || true
	python3 scripts/mythril_gate.py mythril.json --fail-on medium

secrets: ## Secret canary + TruffleHog + Gitleaks over git history
	bash scripts/secret_canary.sh "$(GITLEAKS_IMAGE)"
	$(DOCKER_RUN) $(GIT_SAFE) $(TRUFFLEHOG_IMAGE) git file:///repo --results=verified,unknown --fail --no-update
	$(DOCKER_RUN) $(GIT_SAFE) $(GITLEAKS_IMAGE) git /repo --config /repo/.gitleaks.toml --redact --no-banner

iac: ## terraform fmt/validate + TFLint + Checkov
	$(DOCKER_RUN) -w /repo/infra/terraform $(TERRAFORM_IMAGE) fmt -check -recursive -diff
	$(DOCKER_RUN) -w /repo/infra/terraform $(TERRAFORM_IMAGE) init -backend=false -input=false -lockfile=readonly >/dev/null
	$(DOCKER_RUN) -w /repo/infra/terraform $(TERRAFORM_IMAGE) validate
	$(DOCKER_RUN) -w /repo/infra/terraform --entrypoint sh $(TFLINT_IMAGE) -c "tflint --init >/dev/null && tflint --format compact"
	$(DOCKER_RUN) $(CHECKOV_IMAGE) --config-file .checkov.yaml

policy: ## OPA policy unit tests + enforce on Terraform
	$(DOCKER_RUN) $(CONFTEST_IMAGE) verify --policy policies/terraform
	$(DOCKER_RUN) --entrypoint sh $(CONFTEST_IMAGE) -c 'conftest test --parser hcl2 --combine --all-namespaces --policy policies/terraform infra/terraform/*.tf'

workflows: ## actionlint + zizmor on the CI workflows
	$(DOCKER_RUN) $(ACTIONLINT_IMAGE)
	$(DOCKER_RUN) $(ZIZMOR_IMAGE) --persona regular .github/workflows

lock: ## Regenerate the hash-locked Slither requirements
	$(DOCKER_RUN) python:3.12-slim sh -c "pip install -q uv && uv pip compile requirements/slither.in --generate-hashes \
	  --python-version 3.12 --python-platform x86_64-unknown-linux-gnu -o requirements/slither.txt"

clean: ## Remove build and scanner output
	rm -rf contracts/out contracts/cache contracts/build contracts/lcov.info *.sarif mythril.json
