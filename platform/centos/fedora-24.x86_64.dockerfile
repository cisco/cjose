FROM fedora:24
MAINTAINER Matthew A. Miller <linuxwolf@outer-planes.net>

# Setup extra repositories
RUN yum update -y

# Include and run preparation script
ADD ./prepare.sh /opt/bin/prepare.sh
RUN /opt/bin/prepare.sh
VOLUME /opt/dist
VOLUME /opt/src

# Assume 'platform/centos' is mounted as '/opt/src'
CMD ["/opt/src/build.sh"]
