debug ?= off
tests ?=

LDFLAGS=
RUNFLAGS=

GO_SRC := $(wildcard *.go)

ifeq ($(debug),on)
	LDFLAGS := -ldflags="-X github.com/intuitivelabs/anonymization.Debug=on"
	TAGS := -tags debug
endif

ifdef tests
	RUNFLAGS := -run "$(tests)"
endif

all: build

test: $(GO_SRC)
	go test $(TAGS) $(LDFLAGS) $(RUNFLAGS)

build: $(GO_SRC)
	@go build $(TAGS) $(LDFLAGS) ./...

install: $(GO_SRC)
	@go install

clean:
	@go clean -i -cache
	@go clean -testcache
