SHELL:=/bin/bash -euo pipefail
ROOT_DIR = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
DEBS = $(patsubst $(ROOT_DIR)%/, %, $(filter %/, $(wildcard $(ROOT_DIR)*/)))

ARCH ?= i386

ifeq ($(ARCH), i386)
IMAGE = i386/ubuntu:trusty
endif
ifeq ($(ARCH), amd64)
IMAGE = ubuntu:trusty
endif

.PHONY: all $(DEBS)

$(DEBS):
	cd $@; \
		sed 's|#IMAGE#|$(IMAGE)|g' Dockerfile > Dockerfile.tmp \
		&& docker build . -f Dockerfile.tmp -t trusty/$@:$(ARCH) \
		&& docker run --rm -v "$(ROOT_DIR)../out:/out" trusty/$@:$(ARCH)

all: $(DEBS)
