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

VOLUME /out
WORKDIR /build/source

COPY xrdp/debian/control xrdp/debian/control
COPY neutrinordp/debian/control neutrinordp/debian/control

RUN cd /build/source/neutrinordp && \
	apt-get update && \
	mk-build-deps --install --tool 'apt-get --no-install-recommends -y'

RUN cd /build/source/xrdp && \
	apt-get update && \
	mk-build-deps --install --tool 'apt-get --no-install-recommends -y'

ARG neutrinordpcommit=d014578
RUN cd /build/source/neutrinordp && \
	curl -L https://github.com/Osirium/NeutrinoRDP/archive/${neutrinordpcommit}.tar.gz \
	| tar -x -z -v -p --strip-components=1

ARG xrdpcommit=b8077f835249e7eb0c5d75050dfb7b2c2442314e
RUN cd /build/source/xrdp && curl -L https://github.com/Osirium/xrdp/archive/${xrdpcommit}.tar.gz \
    | tar -x -z -v -p --strip-components=1

COPY neutrinordp neutrinordp
COPY xrdp xrdp

ARG ENVIRONMENT=""
ENV ENVIRONMENT=$ENVIRONMENT

RUN ln -sn /bin/true /usr/bin/git

RUN export DEB_BUILD_OPTIONS="$( [ "${ENVIRONMENT}" = "debug" ] && echo nostrip )" \
	&& cd /build/source/neutrinordp \
	&& dpkg-buildflags \
	&& dpkg-buildpackage -B

RUN dpkg -i /build/source/osirium-neutrinordp_*_$( dpkg --print-architecture ).deb

RUN export DEB_BUILD_OPTIONS="$( [ "${ENVIRONMENT}" = "debug" ] && echo nostrip )" \
	&& cd /build/source/xrdp \
	&& dpkg-buildflags \
	&& dpkg-buildpackage -B

CMD mkdir -p /out/dists/$( lsb_release -c -s )/main/binary-$( dpkg --print-architecture )/ \
    && cp /build/source/*.deb /out/dists/$( lsb_release -c -s )/main/binary-$( dpkg --print-architecture )/
