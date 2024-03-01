#!/usr/bin/make -f

MAKE:=make
SHELL:=bash
GOVERSION:=$(shell \
    go version | \
    awk -F'go| ' '{ split($$5, a, /\./); printf ("%04d%04d", a[1], a[2]); exit; }' \
)
MINGOVERSION:=00010021
MINGOVERSIONSTR:=1.21
BUILD:=$(shell git rev-parse --short HEAD)
REVISION:=$(shell printf "%04d" $$( git rev-list --all --count))
# see https://github.com/go-modules-by-example/index/blob/master/010_tools/README.md
# and https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module
TOOLSFOLDER=$(shell pwd)/tools
export GOBIN := $(TOOLSFOLDER)
export PATH := $(GOBIN):$(PATH)
GO=go

VERSION ?= $(shell ./buildtools/get_version)

all: build

CMDS = $(shell cd ./cmd && ls -1)

tools: | versioncheck vendor go.work
	$(GO) mod download
	$(GO) mod tidy
	$(GO) mod vendor
	set -e; for DEP in $(shell grep "_ " buildtools/tools.go | awk '{ print $$2 }'); do \
		( cd buildtools && $(GO) install $$DEP@latest ) ; \
	done
	( cd buildtools && $(GO) mod tidy )

updatedeps: versioncheck
	$(MAKE) clean
	$(MAKE) tools
	$(GO) mod download
	set -e; for dir in $(shell ls -d1 pkg/* cmd/*); do \
		( cd ./$$dir && $(GO) mod download ); \
		( cd ./$$dir && $(GO) get -u ); \
		( cd ./$$dir && $(GO) get -t -u ); \
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
	$(GO) mod vendor

go.work: pkg/*
	echo "go $(MINGOVERSIONSTR)" > go.work
	$(GO) work use . pkg/* cmd/* buildtools/.

build: vendor go.work
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && CGO_ENABLED=0 go build -ldflags "-s -w -X main.Build=$(BUILD) -X main.Revision=$(REVISION)" -o ../../$$CMD ) ; \
	done

# run build watch, ex. with tracing: make build-watch -- -vv
build-watch: vendor
	ls cmd/*/*.go pkg/*/*.go | entr -sr "$(MAKE) && ./check_nsc_web $(filter-out $@,$(MAKECMDGOALS)) $(shell echo $(filter-out --,$(MAKEFLAGS)) | tac -s " ")"

build-linux-amd64: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w -X main.Build=$(BUILD) -X main.Revision=$(REVISION)" -o ../../$$CMD.linux.amd64 ) ; \
	done

build-windows-i386: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=windows GOARCH=386 CGO_ENABLED=0 go build -ldflags "-s -w -X main.Build=$(BUILD) -X main.Revision=$(REVISION)" -o ../../$$CMD.windows.i386.exe ) ; \
	done

build-windows-amd64: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w -X main.Build=$(BUILD) -X main.Revision=$(REVISION)" -o ../../$$CMD.windows.amd64.exe ) ; \
	done

build-freebsd-i386: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=freebsd GOARCH=386 CGO_ENABLED=0 go build -ldflags "-s -w -X main.Build=$(BUILD) -X main.Revision=$(REVISION)" -o ../../$$CMD.freebsd.i386 ) ; \
	done

build-darwin-aarch64: vendor
	set -e; for CMD in $(CMDS); do \
		( cd ./cmd/$$CMD && GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w -X main.Build=$(BUILD) -X main.Revision=$(REVISION)" -o ../../$$CMD.darwin.aarch64 ) ; \
	done

test: vendor
	go test -short -v -timeout=1m pkg/*
	if grep -rn TODO: ./cmd/ ./pkg/ ; then exit 1; fi

longtest: vendor
	go test -v -timeout=1m pkg/*

citest: vendor
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
	if grep -rn TODO: ./cmd/ ./pkg/ ; then exit 1; fi
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
	go test -timeout=1m -ldflags "-s -w -X main.Build=$(BUILD)" -v -bench=B\* -run=^$$ -benchmem ./pkg/*

racetest:
	go test -race -timeout=3m -coverprofile=coverage.txt -covermode=atomic ./pkg/*

covertest:
	go test -v -coverprofile=cover.out -timeout=1m ./pkg/*
	go tool cover -func=cover.out
	go tool cover -html=cover.out -o coverage.html

coverweb:
	go test -v -coverprofile=cover.out -timeout=1m ./pkg/*
	go tool cover -html=cover.out

clean:
	set -e; for CMD in $(CMDS); do \
		rm -f ./cmd/$$CMD/$$CMD; \
	done
	rm -f $(CMDS)
	rm -f *.windows.*.exe
	rm -f *.linux.*
	rm -f *.darwin.*
	rm -f *.freebsd.*
	rm -f cover.out
	rm -f coverage.html
	rm -f coverage.txt
	rm -rf vendor/
	rm -rf $(TOOLSFOLDER)

GOVET=$(GO) vet -all
fmt: tools
	set -e; for CMD in $(CMDS); do \
		$(GOVET) ./cmd/$$CMD; \
	done
	set -e; for dir in $(shell ls -d1 pkg/*); do \
		$(GOVET) ./$$dir; \
	done
	gofmt -w -s ./cmd/ ./pkg/ ./buildtools/
	./tools/gofumpt -w ./cmd/ ./pkg/ ./buildtools/.
	./tools/gci write ./cmd/. ./pkg/. ./buildtools/. --skip-generated
	goimports -w ./cmd/ ./pkg/ ./buildtools/.

versioncheck:
	@[ $$( printf '%s\n' $(GOVERSION) $(MINGOVERSION) | sort | head -n 1 ) = $(MINGOVERSION) ] || { \
		echo "**** ERROR:"; \
		echo "**** check_nsc_web requires at least golang version $(MINGOVERSIONSTR) or higher"; \
		echo "**** this is: $$(go version)"; \
		exit 1; \
	}

golangci: tools
	#
	# golangci combines a few static code analyzer
	# See https://github.com/golangci/golangci-lint
	#
	set -e; for dir in $$(ls -1d pkg/* cmd/*); do \
		echo $$dir; \
		( cd $$dir && golangci-lint run ./... ); \
	done

govulncheck: tools
	govulncheck ./...

version:
	OLDVERSION="$(shell grep "VERSION =" ./pkg/checknscweb/check.go | awk '{print $$4}' | tr -d '"')"; \
	NEWVERSION=$$(dialog --stdout --inputbox "New Version:" 0 0 "v$$OLDVERSION") && \
		NEWVERSION=$$(echo $$NEWVERSION | sed "s/^v//g"); \
		if [ "v$$OLDVERSION" = "v$$NEWVERSION" -o "x$$NEWVERSION" = "x" ]; then echo "no changes"; exit 1; fi; \
		sed -i -e 's/VERSION =.*/VERSION = "'$$NEWVERSION'"/g' cmd/*/*.go pkg/checknscweb/*.go

check_nsc_web: build

docker:
	docker build -t dockerbuilder .
	docker run -it --rm -e CGO_ENABLED=1 -v $(shell pwd):/go/src/app dockerbuilder make $(target)
