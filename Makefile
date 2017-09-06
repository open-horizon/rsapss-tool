SHELL := /bin/bash
EXECUTABLE = $(shell basename $$PWD)
PKGS=$(shell go list ./...)

COMPILE_ARGS := CGO_ENABLED=0
ifeq ($(shell uname -m),armv7l)
	COMPILE_ARGS +=  GOARCH=arm GOARM=7
endif

all: $(EXECUTABLE)

$(EXECUTABLE): $(shell find . -name '*.go')
	$(COMPILE_ARGS) go build -o $(EXECUTABLE)

clean:
	rm -f $(EXECUTABLE)

lint:
	-golint ./... | grep -v "vendor/"
	-go vet ./... 2>&1 | grep -vP "exit\ status|vendor/"

# only unit tests
test: all
	go test -v -cover $(PKGS)

test-integration: all
	go test -v -cover -tags=integration $(PKGS)

.PHONY: clean lint test test-integration
