#!/usr/bin/make -f

PROJECT=checknscweb
MAKE:=make
SHELL:=bash
GOVERSION:=$(shell \
    go version | \
    awk -F'go| ' '{ split($$5, a, /\./); printf ("%04d%04d", a[1], a[2]); exit; }' \
)
# also update .github/workflows/citest.yml when changing minumum version
# find . -name go.mod
MINGOVERSION:=00010023
MINGOVERSIONSTR:=1.23
BUILD:=$(shell git rev-parse --short HEAD)
REVISION:=$(shell printf "%04d" $$( git rev-list --all --count))
# see https://github.com/go-modules-by-example/index/blob/master/010_tools/README.md
# and https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module
TOOLSFOLDER=$(shell pwd)/tools
export GOBIN := $(TOOLSFOLDER)
export PATH := $(GOBIN):$(PATH)

BUILD_FLAGS=-ldflags "-s -w -X main.Build=$(BUILD) -X main.Revision=$(REVISION)"
TEST_FLAGS=-timeout=5m $(BUILD_FLAGS)
GO=go

all: build

CMDS = $(shell cd ./cmd && ls -1)

tools: | versioncheck
	set -e; for DEP in $(shell grep "_ " buildtools/tools.go | awk '{ print $$2 }' | grep -v go-spew); do \
		( cd buildtools && $(GO) install $$DEP@latest ) ; \
	done
	set -e; for DEP in $(shell grep "_ " buildtools/tools.go | awk '{ print $$2 }' | grep go-spew); do \
		( cd buildtools && $(GO) install $$DEP ) ; \
	done
	( cd buildtools && $(GO) mod tidy )

updatedeps: versioncheck
	$(MAKE) clean
	$(MAKE) tools
	$(GO) mod download
	set -e; for dir in $(shell ls -d1 pkg/*); do \
		( cd ./$$dir && $(GO) mod download ); \
		( cd ./$$dir && GOPROXY=direct $(GO) get -u ); \
		( cd ./$$dir && GOPROXY=direct $(GO) get -t -u ); \
	done
	$(GO) mod download
	$(MAKE) cleandeps

cleandeps:
	set -e; for dir in $(shell ls -d1 pkg/* cmd/*); do \
		( cd ./$$dir && $(GO) mod tidy ); \
	done
	$(GO) mod tidy
	( cd buildtools && $(GO) mod tidy )

vendor: go.work
	$(GO) mod download
	$(GO) mod tidy
	GOWORK=off $(GO) mod vendor

go.work: pkg/*
	echo "go $(MINGOVERSIONSTR)" > go.work
	$(GO) work use . pkg/* cmd/* buildtools/.

build: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && $(GO) build $(BUILD_FLAGS) -o ../../$$CMD ) ; \
	done

# run build watch, ex. with tracing: make build-watch -- -vv
build-watch: vendor tools
	set -x ; ls pkg/*/*.go cmd/*/*.go | entr -sr "$(MAKE) build && ./check_nsc_web $(filter-out $@,$(MAKECMDGOALS)) $(shell echo $(filter-out --,$(MAKEFLAGS)) | tac -s " ")"

build-linux-amd64: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o ../../$$CMD.linux.amd64 ) ; \
	done

build-windows-i386: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=windows GOARCH=386 CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o ../../$$CMD.windows.i386.exe ) ; \
	done

build-windows-amd64: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o ../../$$CMD.windows.amd64.exe ) ; \
	done

build-freebsd-i386: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=freebsd GOARCH=386 CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o ../../$$CMD.freebsd.i386 ) ; \
	done

build-darwin-aarch64: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -o ../../$$CMD.darwin.aarch64 ) ; \
	done

test: vendor
	$(GO) test -short -v $(TEST_FLAGS) ./pkg/* ./cmd/*
	if grep -Irn TODO: ./cmd/ ./pkg/;  then exit 1; fi

# test with filter
testf: vendor
	$(GO) test -short -v $(TEST_FLAGS) ./pkg/* ./cmd/* -run "$(filter-out $@,$(MAKECMDGOALS))" 2>&1 | grep -v "no test files" | grep -v "no tests to run" | grep -v "^PASS"

longtest: vendor
	$(GO) test -v $(TEST_FLAGS) ./pkg/* ./cmd/*

citest: tools vendor
	#
	# Checking gofmt errors
	#
	if [ $$(gofmt -s -l ./cmd/ ./pkg/ | wc -l) -gt 0 ]; then \
		echo "found format errors in these files:"; \
		gofmt -s -l ./cmd/ ./pkg/ ; \
		exit 1; \
	fi
	#
	# Checking TODO items
	#
	if grep -Irn TODO: ./cmd/ ./pkg/ ; then exit 1; fi
	#
	# Run other subtests
	#
	$(MAKE) golangci
	-$(MAKE) govulncheck
	$(MAKE) fmt
	#
	# Normal test cases
	#
	$(MAKE) test
	#
	# Benchmark tests
	#
	$(MAKE) benchmark
	#
	# Race rondition tests
	#
	$(MAKE) racetest
	#
	# Test cross compilation
	#
	$(MAKE) build-linux-amd64
	$(MAKE) build-windows-amd64
	$(MAKE) build-windows-i386
	$(MAKE) build-freebsd-i386
	$(MAKE) build-darwin-aarch64
	#
	# All CI tests successful
	#

benchmark:
	$(GO) test $(TEST_FLAGS) -v -bench=B\* -run=^$$ -benchmem ./pkg/*

racetest:
	$(GO) test -race -short $(TEST_FLAGS) -coverprofile=coverage.txt -covermode=atomic -gcflags "-d=checkptr=0" ./pkg/*

covertest:
	$(GO) test -v $(TEST_FLAGS) -coverprofile=cover.out ./pkg/*
	$(GO) tool cover -func=cover.out
	$(GO) tool cover -html=cover.out -o coverage.html

coverweb:
	$(GO) test -v $(TEST_FLAGS) -coverprofile=cover.out ./pkg/*
	$(GO) tool cover -html=cover.out

clean:
	set -e; for CMD in $(CMDS); do \
		rm -f ./cmd/$$CMD/$$CMD; \
	done
	rm -f $(CMDS)
	rm -f *.windows.*.exe
	rm -f *.linux.*
	rm -f *.darwin.*
	rm -f *.freebsd.*
	rm -f go.work
	rm -f go.work.sum
	rm -f cover.out
	rm -f coverage.html
	rm -f coverage.txt
	rm -rf vendor/
	rm -rf $(TOOLSFOLDER)

GOVET=$(GO) vet -all
SRCFOLDER=./cmd/. ./pkg/. ./buildtools/.
fmt: tools
	set -e; for CMD in $(CMDS); do \
		$(GOVET) ./cmd/$$CMD; \
	done
	set -e; for dir in $(shell ls -d1 pkg/*); do \
		$(GOVET) ./$$dir; \
	done
	gofmt -w -s $(SRCFOLDER)
	./tools/gofumpt -w $(SRCFOLDER)
	./tools/gci write --skip-generated $(SRCFOLDER)
	./tools/goimports -w $(SRCFOLDER)

versioncheck:
	@[ $$( printf '%s\n' $(GOVERSION) $(MINGOVERSION) | sort | head -n 1 ) = $(MINGOVERSION) ] || { \
		echo "**** ERROR:"; \
		echo "**** $(PROJECT) requires at least golang version $(MINGOVERSIONSTR) or higher"; \
		echo "**** this is: $$(go version)"; \
		exit 1; \
	}

golangci: tools
	#
	# golangci combines a few static code analyzer
	# See https://github.com/golangci/golangci-lint
	#
	@set -e; for dir in $$(ls -1d pkg/* cmd); do \
		echo $$dir; \
		echo "  - GOOS=linux"; \
		( cd $$dir && GOOS=linux golangci-lint run --timeout=5m ./... ); \
	done

govulncheck: tools
	govulncheck ./...

version:
	OLDVERSION="$(shell grep "VERSION =" ./pkg/$(PROJECT)/check.go | awk '{print $$4}' | tr -d '"')"; \
	NEWVERSION=$$(dialog --stdout --inputbox "New Version:" 0 0 "v$$OLDVERSION") && \
		NEWVERSION=$$(echo $$NEWVERSION | sed "s/^v//g"); \
		if [ "v$$OLDVERSION" = "v$$NEWVERSION" -o "x$$NEWVERSION" = "x" ]; then echo "no changes"; exit 1; fi; \
		sed -i -e 's/VERSION =.*/VERSION = "'$$NEWVERSION'"/g' pkg/$(PROJECT)/check.go

check_nsc_web: build

# just skip unknown make targets
.DEFAULT:
	@if [[ "$(MAKECMDGOALS)" =~ ^testf ]]; then \
		: ; \
	else \
		echo "unknown make target(s): $(MAKECMDGOALS)"; \
		exit 1; \
	fi
