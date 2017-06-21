FROM #IMAGE#

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get --quiet --yes --no-install-recommends install \
      build-essential \
      ca-certificates \
      curl \
      debhelper \
      devscripts \
      equivs \
      ;

WORKDIR /build/source

COPY debian/changelog debian/changelog

ARG commit=3e16bc87075c33d241d1ef22d0885c69153676c4

RUN curl -L https://github.com/FreeTDS/freetds/archive/${commit}.tar.gz \
    | tar -x -z -v -p --strip-components=1

RUN ln -sn /bin/true /bin/git

COPY debian/control debian/control

RUN apt-get update && mk-build-deps --install --tool 'apt-get --no-install-recommends -y'

COPY . ./

RUN dpkg-buildflags && DEB_BUILD_OPTIONS="parallel=$(nproc) nocheck" dpkg-buildpackage -B

CMD mkdir -p /out/dists/trusty/main/binary-$( dpkg --print-architecture )/ \
    && dpkg -c /build/*.deb \
    && cp /build/*.deb /out/dists/trusty/main/binary-$( dpkg --print-architecture )/
