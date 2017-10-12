FROM #IMAGE#

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get --quiet --yes --no-install-recommends install \
      build-essential \
      ca-certificates \
      curl \
      debhelper \
      lsb-release \
      python-sphinx \
      python-mock \
      python-setuptools \
      ;

WORKDIR /build

ADD https://github.com/spotify/dh-virtualenv/archive/1.0.tar.gz /build/dh-virtualenv_1.0.orig.tar.gz

RUN tar xvpzf dh-virtualenv_1.0.orig.tar.gz

WORKDIR /build/dh-virtualenv-1.0

VOLUME /out

RUN dpkg-buildflags && DEB_BUILD_OPTIONS="parallel=$(nproc) nocheck" dpkg-buildpackage -us -uc

CMD mkdir -p /out/dists/$( lsb_release -c -s )/main/binary-$( dpkg --print-architecture )/ \
    && dpkg -c /build/*.deb \
    && cp /build/*.deb /out/dists/$( lsb_release -c -s )/main/binary-$( dpkg --print-architecture )/
