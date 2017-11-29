SHELL:=/bin/bash -euo pipefail
ROOT_DIR = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
DEBS = $(patsubst $(ROOT_DIR)%/, %, $(filter %/, $(wildcard $(ROOT_DIR)debs/*/)))
OUTPUT = $(wildcard $(ROOT_DIR)out/dists/xenial/main/binary-amd64/*.deb)

.PHONY: debs $(DEBS)

test:
	@echo $(DEBS)

debs:
	$(MAKE) -C debs all

$(DEBS):
	$(MAKE) -C debs $(patsubst debs/%, %, $@)

upload: $(OUTPUT)
	$(foreach package, $(OUTPUT), curl -u $(ARTIFACTORY_USR):$(ARTIFACTORY_PSW) -XPUT "http://artifactory.osirium.net/debian-local/pool/$(notdir $(package));deb.distribution=xenial;deb.component=main;deb.architecture=amd64" -T $(package))
