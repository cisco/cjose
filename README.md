[![Build](https://github.com/cisco/cjose/actions/workflows/build.yml/badge.svg)](https://github.com/cisco/cjose/actions/workflows/build.yml)
[![Archs](https://github.com/cisco/cjose/actions/workflows/archs.yml/badge.svg)](https://github.com/cisco/cjose/actions/workflows/archs.yml)
[![CodeQL](https://github.com/cisco/cjose/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/cisco/cjose/actions/workflows/codeql-analysis.yml)

# cjose #

Implementation of JOSE for C/C++

## Supported Algorithms ##

JWS signing algorithms (`alg`):

| Identifier | Algorithm | Requires |
|------------|-----------|----------|
| `HS256`, `HS384`, `HS512` | HMAC with SHA-2 | |
| `RS256`, `RS384`, `RS512` | RSASSA-PKCS1-v1_5 with SHA-2 | |
| `PS256`, `PS384`, `PS512` | RSASSA-PSS with SHA-2 | |
| `ES256`, `ES384`, `ES512` | ECDSA with P-256, P-384 and P-521 | |
| `ES256K` | ECDSA with secp256k1 | OpenSSL built with `secp256k1` |
| `Ed25519`, `Ed448` | EdDSA (RFC 9864) | |

The polymorphic `EdDSA` identifier of RFC 8037, deprecated by RFC 9864, and
`none` are not accepted.

JWE key management algorithms (`alg`):

| Identifier | Algorithm | Requires |
|------------|-----------|----------|
| `RSA-OAEP` | RSAES OAEP with SHA-1 and MGF1 with SHA-1 | |
| `RSA-OAEP-256` | RSAES OAEP with SHA-256 and MGF1 with SHA-256 | |
| `RSA1_5` | RSAES-PKCS1-v1_5 | build option `CJOSE_ENABLE_RSA1_5` |
| `A128KW`, `A192KW`, `A256KW` | AES Key Wrap | |
| `dir` | direct use of a shared symmetric key | |
| `ECDH-ES` | ECDH-ES direct key agreement | |
| `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW` | ECDH-ES with AES Key Wrap | |

JWE content encryption algorithms (`enc`):

| Identifier | Algorithm |
|------------|-----------|
| `A128GCM`, `A192GCM`, `A256GCM` | AES GCM |
| `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512` | AES CBC with HMAC SHA-2 |

JWK key types (`kty`):

| Identifier | Keys | Requires |
|------------|------|----------|
| `RSA` | RSA | |
| `EC` | `P-256`, `P-384`, `P-521`, `secp256k1` | `secp256k1`: OpenSSL built with it |
| `oct` | symmetric | |
| `OKP` | `Ed25519`, `Ed448`, `X25519`, `X448` | |

JWEs can be produced and consumed in both the compact and the JSON
serialization, with one or more recipients.

## Prerequisites ##

*MAC OS X* All of the prerequisites can be installed via [brew](http://brew.sh/).

### Build Tools ###

* CMake (>= 3.22)
* A C99 compiler (LLVM/Clang >= 5.1, GCC >= 4.5 or MSVC >= 14)
* Check (>= 0.12.0) - unit testing (e.g. check-devel)
* Doxygen (>= 1.8) - API documentation (optional)
* clang-format - source formatting (optional)

The autotools toolchain (pkg-config, GNU Make, Autoconf, Automake, libtool) is
only required for the deprecated build described at the end of this document.

### Libraries ###

* OpenSSL >= 3.0.0
* Jansson >= 2.3

## Getting Started ##

cjose builds with [CMake](https://cmake.org/) (>= 3.22):

    git clone https://github.com/cisco/cjose.git
    cd cjose
    cmake -S . -B build
    cmake --build build

By default both the shared and static libraries are built (and, when cjose is
the top-level project, the unit tests).

### Build Options ###

Pass options with `-D<OPTION>=<VALUE>` at configure time:

| Option | Default | Description |
| --- | --- | --- |
| `CJOSE_BUILD_SHARED` | `ON` | Build the shared/dynamic library |
| `CJOSE_BUILD_STATIC` | `ON` | Build the static library |
| `CJOSE_BUILD_TESTS` | `ON` when top-level | Build the unit tests (requires Check) |
| `CJOSE_ENABLE_RSA1_5` | `OFF` | Enable the RSA1_5 (RSAES-PKCS1-v1_5) key encryption algorithm |
| `CJOSE_MSVC_STATIC_RUNTIME` | `OFF` | (MSVC) Link against the static C runtime (`/MT`) |
| `CJOSE_MACOS_DYLIB` | `OFF` | (macOS) Build a plain `.dylib` instead of a framework |

For example, to build only the static library in debug mode:

    cmake -S . -B build -DCJOSE_BUILD_SHARED=OFF -DCMAKE_BUILD_TYPE=Debug
    cmake --build build

### Dependencies in Non-Standard Locations ###

OpenSSL and Jansson are located automatically. If they live in a custom prefix,
point CMake at it:

    cmake -S . -B build -DCMAKE_PREFIX_PATH="/usr/local/opt/openssl;/usr/local/opt/jansson"

## Tests ##

To run the unit tests:

    ctest --test-dir build --output-on-failure -V

## API Docs ##

To generate the Doxygen API documentation (requires Doxygen):

    cmake --build build --target doxygen

The generated HTML is placed in `build/doc/html`.

## Installing ##

    cmake --install build --prefix /your/install/prefix

This installs the libraries, the public headers, a `cjose.pc` pkg-config file
and a CMake package config.

## Using cjose From Another Project ##

After installing, consume cjose from a CMake project via `find_package`:

    find_package(cjose REQUIRED)
    target_link_libraries(myapp PRIVATE cjose::cjose)

The `cjose::cjose` target aliases the shared/dynamic library when it is built,
or the static library when `CJOSE_BUILD_SHARED=OFF`. The explicit
`cjose::cjose_shared` target is also available when that library type is built.
Using the shared library does not require the OpenSSL or Jansson development
packages on the consuming system.

Static consumers need cjose's private dependencies and can request them and the
explicit static target with:

    find_package(cjose REQUIRED COMPONENTS static)
    target_link_libraries(myapp PRIVATE cjose::cjose_static)

Alternatively, embed the sources directly with `add_subdirectory()` or
`FetchContent`; the same CMake targets are provided.

## Contributing ##

### Before Submitting PR ###

* Run `cmake --build build --target clang-format`
* Run `ctest --test-dir build --output-on-failure -V`

## Deprecated: Autotools Build ##

> **Deprecated.** The autotools (autoconf/automake/libtool) build below is kept
> for reference only and will be **removed soon**. Please use the CMake build
> described above.

As with most autoconf/automake projects:

    git clone https://github.com/cisco/cjose.git
    cd cjose
    ./configure && make

### Common Options ###

    --with-openssl: Specify the location where OpenSSL/CiscoSSL is installed
    --with-jansson: Specify the location where Jansson is installed
    --disable-shared: Only build static library

### Debug Mode ###

To compile in debug mode (minimal optimization, active asserts, etc), specify the appropriate CFLAGS as a command-line argument when executing configure:

    ./configure CFLAGS="-g -O0 -DDEBUG"

### Tests ###

To execute the unit tests:

    make test

If successful, the list of checks will be displayed on the console.  Otherwise, the file "test/test-suite.log" will list the specific test(s) that failed.

### API Docs ###

To generate Doxygen API documentation:

    make doxygen

Which will place the generated documentation in "doc/html".

### From Scratch ###

To rebuild all of the project -- including those files generated by autoconf and automake:

    autoreconf --force --install

### Troubleshooting ###

#### Configure can't find check.h header file.

This has been seen on Mac OSX 10.8 and 10.9 when check has been installed
via brew.  A solution is to explicitly include the /usr/local/include directory
in the cflags:

    ./configure CFLAGS="-I/usr/local/include"

#### Make fails due to many OpenSSL functions being "deprecated" or missing.

This can happen when the compiler selects an unsupported OpenSSL installation. A solution is to explicitly include an OpenSSL 3.0.0-or-newer directory in the configure command:

    ./configure --with-openssl=/usr/local/opt/openssl

#### Make fails due to json_* functions missing.

This has been seen on Mac OSX 10.9 when Jansson has been installed via brew.  A solution is to explicitly include the jansson directory in the configure command:

    ./configure --with-jansson=/usr/local/opt/jansson

### Before Submitting PR (Autotools) ###

* Run `make clang-format`
* Run `make test`
