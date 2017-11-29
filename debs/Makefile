SHELL:=/bin/bash -euo pipefail
ROOT_DIR = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
DEBS = $(patsubst $(ROOT_DIR)%/, %, $(filter %/, $(wildcard $(ROOT_DIR)*/)))

.PHONY: all $(DEBS)

$(DEBS):
	cd $@; \
		docker build . -f Dockerfile -t xenial/$@:amd64 \
		&& docker run --rm -v "$(ROOT_DIR)../out:/out" xenial/$@:amd64

all: $(DEBS)
