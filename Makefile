ifeq ($(TMPDIR),)
  TMPDIR := /tmp/
endif

ifneq ("$(wildcard ./rules.env)","")
  include rules.env
  export $(shell sed 's/=.*//' rules.env)
endif

EXECUTABLE = $(shell basename $$PWD)

export TMPGOPATH := $(TMPDIR)$(EXECUTABLE)
export PKGPATH := $(TMPGOPATH)/src/github.com/open-horizon/$(EXECUTABLE)
export PATH := $(TMPGOPATH)/bin:$(PATH)

SHELL := /bin/bash
PKGS=$(shell cd $(PKGPATH); GOPATH=$(TMPGOPATH) go list ./... | gawk '$$1 !~ /vendor\// {print $$1}')


COMPILE_ARGS := CGO_ENABLED=0
ifeq ($(shell uname -m),armv7l)
	COMPILE_ARGS +=  GOARCH=arm GOARM=7
endif

all: $(EXECUTABLE)

ifndef verbose
.SILENT:
endif

$(EXECUTABLE): $(shell find . -name '*.go' -not -path './vendor/*') deps
	cd $(PKGPATH) && \
    export GOPATH=$(TMPGOPATH); \
			$(COMPILE_ARGS) go build -o $(EXECUTABLE)

# let this run on every build to ensure newest deps are pulled
deps: $(TMPGOPATH)/bin/govendor
ifneq ($(GOPATH_CACHE),)
  if [ ! -d $(TMPGOPATH)/.cache ] && [ -e $(GOPATH_CACHE) ]; then \
		ln -s $(GOPATH_CACHE) $(TMPGOPATH)/.cache; \
	fi
endif
	cd $(PKGPATH) && \
		export GOPATH=$(TMPGOPATH); \
      govendor sync

$(TMPGOPATH)/bin/govendor: gopathlinks
	mkdir -p $(TMPGOPATH)/bin
		-export GOPATH=$(TMPGOPATH); \
			go get -u github.com/kardianos/govendor

# this is a symlink to facilitate building outside of user's GOPATH
gopathlinks:
ifneq ($(GOPATH),$(TMPGOPATH))
	if [ ! -h $(PKGPATH) ]; then \
		mkdir -p $(shell dirname $(PKGPATH)); \
		ln -s $(CURDIR) $(PKGPATH); \
	fi
endif

clean:
	rm -f $(EXECUTABLE)
	find ./vendor -maxdepth 1 -not -path ./vendor -and -not -iname "vendor.json" -print0 | xargs -0 rm -Rf
ifneq ($(TMPGOPATH),$(GOPATH))
	rm -rf $(TMPGOPATH)
endif

lint:
	-golint ./... | grep -v "vendor/"
	-go vet ./... 2>&1 | grep -vP "exit\ status|vendor/"

# only unit tests
test: deps
	cd $(PKGPATH) && \
    GOPATH=$(TMPGOPATH) go test -v -cover $(PKGS)

test-integration: deps
	cd $(PKGPATH) && \
    GOPATH=$(TMPGOPATH) go test -v -cover -tags=integration $(PKGS)

check: test test-integration

.PHONY: check clean deps gopathlinks lint test test-integration
