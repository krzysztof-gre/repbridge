.PHONY: lint fuzz security catalog-check setup test vet fmt fmt-check build ci docker-build vault-key-init mcp-key-init release-package release-check
COMPOSE ?= docker compose
DEV = $(COMPOSE) -f compose.dev.yaml run --build --rm dev
QUICK = $(COMPOSE) -f compose.quickstart.yaml
setup:
	$(QUICK) run --build --rm --service-ports setup
test:
	$(COMPOSE) -f compose.dev.yaml run --build --rm test
vet:
	$(DEV) go vet ./...
fmt:
	$(DEV) gofmt -w cmd internal scripts
fmt-check:
	$(DEV) sh -ec 'files=$$(gofmt -l cmd internal scripts); test -z "$$files" || { printf "%s\n" "$$files"; exit 1; }'
build:
	$(QUICK) build repbridge
catalog-check:
	$(DEV) sh -ec 'go run ./cmd/upstream-audit; go run ./cmd/repbridge catalog check'

ci: fmt-check catalog-check test vet lint release-check build
docker-build: build
vault-key-init:
	$(QUICK) run --build --rm setup init
mcp-key-init:
	$(QUICK) run --build --rm init-access
release-package:
	$(COMPOSE) -f compose.release.yaml run --build --rm snapshot release --snapshot --clean --skip=publish

# actionlint 1.7.12 predates GitHub's concurrency.queue field (May 2026).
# Suppress only that obsolete parser diagnostic; GitHub validates queue: max.
lint:
	$(DEV) sh -ec 'shellcheck scripts/*.sh; go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 -ignore "^unexpected key .queue. for .concurrency. section[.]" -color'
fuzz:
	$(COMPOSE) -f compose.dev.yaml run --build --rm test sh -ec 'go test ./internal/jsondoc -run=^$$ -fuzz=FuzzDecode -fuzztime=10s; go test ./internal/policy -run=^$$ -fuzz=FuzzPolicyParse -fuzztime=10s; go test ./internal/policy -run=^$$ -fuzz=FuzzProjectionDoesNotDiscloseSiblings -fuzztime=10s; go test ./internal/policy -run=^$$ -fuzz=FuzzGlobMatchesReference -fuzztime=10s'
security:
	$(DEV) go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

release-check:
	$(COMPOSE) -f compose.release.yaml run --build --rm release check
