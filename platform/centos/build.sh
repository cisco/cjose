#! /usr/bin/env bash

DST_DIR=/opt/dist
SRC_DIR=/opt/src
RPM_DIR=/opt/rpmbuild

function check_result() {
    if [ $1 != 0 ]; then
        exit $1
    fi
}

echo "Clear previous builds"
rm -rf ${RPM_DIR}/BUILD/*

echo "Build RPMs"
cp ${DST_DIR}/cjose-${PACKAGE_VERSION}.tar.gz ${RPM_DIR}/SOURCES
rpmbuild --define "release ${PACKAGE_VERSION}" -bb ${SRC_DIR}/cjose.spec
check_result $?

OUTPUT_RPMS=$( ls -1 ${RPM_DIR}/RPMS/*/*.rpm | grep cjose)
for src in ${OUTPUT_RPMS}; do
    dst=/opt/dist/$(basename $src)
    echo "copy $src to $dst"
    yes | cp $src $dst
done
