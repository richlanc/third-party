FROM ubuntu:xenial

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

CMD dpkg-scanpackages -m dists/$( lsb_release -c -s )/main/binary-i386 /dev/null | gzip -9c > dists/$( lsb_release -c -s )/main/binary-i386/Packages.gz \
    && dpkg-scanpackages -m dists/$( lsb_release -c -s )/main/binary-amd64 /dev/null | gzip -9c > dists/$( lsb_release -c -s )/main/binary-amd64/Packages.gz
