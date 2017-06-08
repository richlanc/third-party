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

RUN export VERSION="$( /usr/bin/dpkg-parsechangelog --show-field Version | cut -d'-' -f1 )" \
    && curl -L https://github.com/Osirium/winexe/archive/${VERSION}.tar.gz \
    | tar -x -v -p -z --strip-components=2 winexe-${VERSION}/source

COPY waf.pm /tmp/waf.pm

RUN mkdir -p /usr/share/perl5/Debian/Debhelper/Buildsystem && ln -sn /tmp/waf.pm /usr/share/perl5/Debian/Debhelper/Buildsystem/waf.pm

COPY debian/control debian/control

RUN apt-get update && mk-build-deps --install --tool 'apt-get --no-install-recommends -y'

COPY debian ./debian

RUN dpkg-buildflags && DEB_BUILD_OPTIONS="parallel=$(nproc) nocheck" dpkg-buildpackage -B

CMD mkdir -p /out/dists/trusty/main/binary-$( dpkg --print-architecture )/ \
    && dpkg -c /build/*.deb \
    && cp /build/*.deb /out/dists/trusty/main/binary-$( dpkg --print-architecture )/
