SHELL:=/bin/bash -euo pipefail
ROOT_DIR = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
DEBS = $(patsubst $(ROOT_DIR)%/, %, $(filter %/, $(wildcard $(ROOT_DIR)debs/*/)))

.PHONY: debs packages index $(DEBS)

test:
	@echo $(DEBS)

debs:
	$(MAKE) -C debs all

packages: debs index

index:
	docker build ./index -t xenial/index
	docker run --rm -v "$(CURDIR)/out:/packages" xenial/index

$(DEBS):
	$(MAKE) -C debs $(patsubst debs/%, %, $@)

#  --delete
sync:
	aws s3 sync --storage-class REDUCED_REDUNDANCY out/ s3://osirium-trusty/$(shell git rev-list --count HEAD)-$(shell git rev-parse --short head)/
