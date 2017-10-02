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
      lsb-release \
      ;

RUN apt-get update \
    && apt-get --quiet --yes --no-install-recommends install \
      clang-4.0 \
      llvm-4.0 \
      llvm-4.0-dev \
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

RUN export PATH="/usr/lib/llvm-4.0/bin:$PATH" \
        DEB_CFLAGS_STRIP='-O2' \
        DEB_CXXFLAGS_STRIP='-O2' \
        CC="/usr/bin/clang-4.0" \
        CXX="/usr/bin/clang++-4.0++" \
        AR=llvm-ar \
        NM=llvm-nm \
        RANLIB=llvm-ranlib \
        DEB_LDFLAGS_APPEND='-use-gold-plugin -fuse-ld=gold' \
    && dpkg-buildflags \
    && DEB_BUILD_OPTIONS="parallel=$(nproc) nocheck" dpkg-buildpackage -B

CMD mkdir -p /out/dists/$( lsb_release -c -s )/main/binary-$( dpkg --print-architecture )/ \
    && find /build -name '*.deb' -exec dpkg -c {} \; \
    && cp /build/*.deb /out/dists/$( lsb_release -c -s )/main/binary-$( dpkg --print-architecture )/
