LOCAL_BIN:=$(CURDIR)/bin
MINIMOCK_BIN:=$(LOCAL_BIN)/minimock
MINIMOCK_TAG:=v3.3.6
GOLANGCI_BIN:=$(LOCAL_BIN)/golangci-lint
GOLANGCI_TAG:=v1.64.8

export CGO_ENABLED=0
export GOSUMDB=sum.golang.org
export GONOPROXY=
export GONOSUMDB=
export GOPRIVATE=
export GOPROXY=

.PHONY: publish
publish:
	$(info Building and publishing image...)
	./scripts/docker-publish.sh

.PHONY: bin-deps
bin-deps:
ifeq (,$(wildcard $(MINIMOCK_BIN)))
	$(info Installing minimock dependency...)
	tmp=$$(mktemp -d) && cd $$tmp && pwd && go mod init temp && \
	GOBIN=$(LOCAL_BIN) go install github.com/gojuno/minimock/v3/cmd/minimock@$(MINIMOCK_TAG)
endif

ifeq (,$(wildcard $(GOLANGCI_BIN)))
	$(info Installing golangci-lint dependency...)
	tmp=$$(mktemp -d) && cd $$tmp && pwd && go mod init temp && \
	GOBIN=$(LOCAL_BIN) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_TAG)
endif

.PHONY: lint
lint: bin-deps
	$(info Running lint...)
	$(GOLANGCI_BIN) run --new-from-rev=origin/master --config=.golangci.yml ./...

.PHONY: lint-full
lint-full: bin-deps
	$(info Running lint-full...)
	$(GOLANGCI_BIN) run --config=.golangci.yml ./...

clean:
	@rm -rf ./bin
	@go clean

.PHONY: build
build: clean
	@go build -o ./bin/mikrotik-exporter ./main.go
	@chmod +x ./bin/*

.PHONY: mocks
mocks: bin-deps
	$(info Generating mocks...)
	$(MINIMOCK_BIN) -g -i github.com/ogi4i/mikrotik-exporter/collector.* -o ./collector/mocks -s _mock.go
	$(MINIMOCK_BIN) -g -i github.com/ogi4i/mikrotik-exporter/routeros.* -o ./routeros/mocks -s _mock.go

.PHONY: test
test:
	$(info Running tests...)
	@go test -v -coverprofile=cover.out ./...

.PHONY: cover
cover: test
	$(info Generating coverage...)
	@go tool cover -html=cover.out -o=cover.html
