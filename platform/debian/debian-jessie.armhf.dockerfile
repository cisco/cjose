FROM armv7/armhf-debian:jessie
MAINTAINER Matthew A. Miller <linuxwolf@outer-planes.net>

# Add static emulation
ADD ./qemu-arm-static /usr/bin/qemu-arm-static

# Add and run preparation script
ADD ./prepare.sh /opt/bin/prepare.sh
RUN /opt/bin/prepare.sh
VOLUME /opt/dist
VOLUME /opt/src

# Assume 'platform/debian' is mounted as '/opt/src'
CMD ["/opt/src/build.sh"]
