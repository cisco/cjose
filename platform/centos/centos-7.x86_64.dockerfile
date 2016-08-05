FROM centos:7
MAINTAINER Matthew A. Miller <linuxwolf@outer-planes.net>

# Setup extra repositories
RUN rpm --import https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-7 && \
    rpm -ihv https://dl.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-8.noarch.rpm && \
    yum update -y

# Include and run preparation script
ADD ./prepare.sh /opt/bin/prepare.sh
RUN /opt/bin/prepare.sh
VOLUME /opt/dist
VOLUME /opt/src

# Assume 'platform/centos' is mounted as '/opt/src'
CMD ["/opt/src/build.sh"]
