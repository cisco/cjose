#!/usr/bin/env bash

# Setup dev environment
mkdir -p /opt/rpmbuild/{BUILD,SRPMS,SPECS,SOURCES,RPMS}
mkdir -p /opt/{build,dist,src}

# Install dev tools
yum install -y \
    cmake make gcc doxygen \
    rpm-build tar \
    check-devel openssl-devel jansson-devel
