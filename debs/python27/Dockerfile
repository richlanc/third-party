FROM #IMAGE#

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get --quiet --yes --no-install-recommends install \
      build-essential \
      ca-certificates \
      curl \
      debhelper \
      devscripts \
      dh-exec \
      equivs \
      ;

VOLUME /out
WORKDIR /build/source

COPY debian/control debian/control
RUN apt-get update && mk-build-deps --install --tool 'apt-get --no-install-recommends -y'

COPY debian/changelog debian/changelog
RUN export VERSION="$( /usr/bin/dpkg-parsechangelog --show-field Version | cut -d'-' -f1 )" \
    && curl -L "https://www.python.org/ftp/python/${VERSION}/Python-${VERSION}.tgz" \
    | tar -x -z -v -p --strip-components=1

COPY . .

# CFLAGS appear to be added by dpkg-buildpackage
RUN patch -p0 <debian/patches/lto-link-flags.diff \
    && export DEB_CFLAGS_STRIP='-O2' DEB_CXXFLAGS_STRIP='-O2' \
    && dpkg-buildflags \
    && DEB_BUILD_OPTIONS="parallel=$(nproc) nocheck" dpkg-buildpackage -B

CMD mkdir -p /out/dists/trusty/main/binary-$( dpkg --print-architecture )/ \
    && find /build -name '*.deb' -exec dpkg -c {} \; \
    && cp /build/*.deb /out/dists/trusty/main/binary-$( dpkg --print-architecture )/
