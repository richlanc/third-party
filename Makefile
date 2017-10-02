SHELL:=/bin/bash -euo pipefail
ROOT_DIR = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
DEBS = $(patsubst $(ROOT_DIR)%/, %, $(filter %/, $(wildcard $(ROOT_DIR)debs/*/)))

.PHONY: pull debs-32 32 debs-64 64 index $(DEBS)

test:
	@echo $(DEBS)

debs-32:
	$(MAKE) -C debs all ARCH=i386

debs-64:
	$(MAKE) -C debs all ARCH=amd64

$(DEBS):
	$(MAKE) -C debs $(patsubst debs/%, %, $@) ARCH=i386
	$(MAKE) -C debs $(patsubst debs/%, %, $@) ARCH=amd64

64: | debs-64 index
32: | debs-32 index
all: pull debs-32 debs-64 index

index:
	docker build ./index -t xenial/index
	docker run --rm -v "$(CURDIR)/out:/packages" xenial/index

#  --delete
sync:
	aws s3 sync --storage-class REDUCED_REDUNDANCY out/ s3://osirium-trusty/$(shell git rev-list --count HEAD)-$(shell git rev-parse --short head)/
