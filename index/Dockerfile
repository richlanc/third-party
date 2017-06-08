FROM ubuntu:trusty

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get --quiet --yes --no-install-recommends install \
      curl \
      dpkg-dev \
      python3-apt \
      python3-software-properties \
      software-properties-common \
      ;

VOLUME /packages
WORKDIR /packages

CMD dpkg-scanpackages -m dists/trusty/main/binary-i386 /dev/null | gzip -9c > dists/trusty/main/binary-i386/Packages.gz \
    && dpkg-scanpackages -m dists/trusty/main/binary-amd64 /dev/null | gzip -9c > dists/trusty/main/binary-amd64/Packages.gz
