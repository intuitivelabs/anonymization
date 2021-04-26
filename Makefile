debug ?= off
tests ?=

LDFLAGS=
RUNFLAGS=

GO_SRC := $(wildcard *.go)

ifeq ($(debug),on)
	LDFLAGS := -ldflags="-X github.com/intuitivelabs/anonymization.Debug=on"
endif

ifdef tests
	RUNFLAGS := -run "$(tests)"
endif

all: build

test: $(GO_SRC)
	go test $(LDFLAGS) $(RUNFLAGS)

build: $(GO_SRC)
	@go build $(LDFLAGS) ./...

install: $(GO_SRC)
	@go install

clean:
	@go clean -i -cache
	@go clean -testcache
