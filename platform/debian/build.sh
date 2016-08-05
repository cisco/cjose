#! /usr/bin/env /bin/bash

BUILD_DIR=/opt/build
DST_DIR=/opt/dist
SRC_DIR=/opt/src

PACKAGE_OS="$(lsb_release -is | awk '{print tolower($0)}')"
PACKAGE_PLATFORM="$(lsb_release -cs | awk '{print tolower($0)}')"

function check_result() {
    if [ $1 != 0 ]; then
        exit $1
    fi
}

function fixup_changelog() {
    cat ./debian/changelog.in | \
        sed -e "s/@PACKAGE_VERSION@/${PACKAGE_VERSION}/g" | \
        sed -e "s/@PACKAGE_PLATFORM@/${PACKAGE_PLATFORM}/g" \
        > ./debian/changelog && \
        rm -rf ./debian/changelog.in
    return $?
}

echo "Clear previous builds"
rm -rf ${BUILD_DIR}/*

echo "Build DEBs"
cp  ${DST_DIR}/cjose-${PACKAGE_VERSION}.tar.gz \
    ${BUILD_DIR}/cjose_${PACKAGE_VERSION}.orig.tar.gz
tar xz -C ${BUILD_DIR} -f ${BUILD_DIR}/cjose_${PACKAGE_VERSION}.orig.tar.gz
check_result $?

cd ${BUILD_DIR}/cjose-${PACKAGE_VERSION}
cp -r ${SRC_DIR}/debian ./debian
fixup_changelog
check_result $?

dpkg-buildpackage -us -uc
check_result $?

OUTPUT_DEBS=$( ls -1 ${BUILD_DIR}/*.deb | grep libcjose)
for src in ${OUTPUT_DEBS} ; do
    dst=/opt/dist/$(basename $src .deb | sed -e "s/${PACKAGE_PLATFORM}/${PACKAGE_OS}-${PACKAGE_PLATFORM}/").deb
    echo "copy $src to $dst"
    yes | cp $src $dst
done
