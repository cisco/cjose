#!/usr/bin/env bash

# Setup dev environment
mkdir -p /opt/{build,dist,src}

# Install dev tools 
apt-get update && apt-get upgrade -y --force-yes
apt-get install -y --fix-missing \
        build-essential devscripts dh-make autoconf automake pkg-config \
        libssl-dev libjansson-dev check 
