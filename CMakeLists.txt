cmake_minimum_required(VERSION 3.22)

project(cjose
    VERSION 0.6.1
    DESCRIPTION "JOSE implementation for C"
    HOMEPAGE_URL "https://github.com/cisco/cjose"
    LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)
include(CMakeDependentOption)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(CJOSE_BUILD_SHARED "Build the cjose shared/dynamic library" ON)
option(CJOSE_BUILD_STATIC "Build the cjose static library" ON)
# Off by default when embedded (add_subdirectory/FetchContent), on when top-level.
option(CJOSE_BUILD_TESTS  "Build the cjose unit tests (requires Check)" ${PROJECT_IS_TOP_LEVEL})

# Only meaningful with MSVC; lets the library link against the static CRT (/MT).
cmake_dependent_option(CJOSE_MSVC_STATIC_RUNTIME
    "Use the static C runtime (/MT) with MSVC" OFF
    MSVC OFF)

cmake_dependent_option(CJOSE_MACOS_DYLIB
    "Build the macOS dynamic library as a plain .dylib instead of a framework" OFF
    "CMAKE_SYSTEM_NAME STREQUAL \"Darwin\"" OFF)

if(NOT CJOSE_BUILD_SHARED AND NOT CJOSE_BUILD_STATIC)
    message(FATAL_ERROR "At least one of CJOSE_BUILD_SHARED or CJOSE_BUILD_STATIC must be ON")
endif()

if(PROJECT_IS_TOP_LEVEL AND NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type" FORCE)
endif()

if(MSVC AND CJOSE_MSVC_STATIC_RUNTIME)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
find_package(OpenSSL 1.0.1 REQUIRED)
find_package(Jansson 2.3 REQUIRED)

# Optional Cisco "Fundamental EC" OpenSSL extension (openssl/fec.h).
include(CheckIncludeFile)
include(CMakePushCheckState)
cmake_push_check_state(RESET)
set(CMAKE_REQUIRED_LIBRARIES OpenSSL::Crypto)
check_include_file("openssl/fec.h" CJOSE_HAVE_OPENSSL_FEC_H)
cmake_pop_check_state()

# ---------------------------------------------------------------------------
# Generated public header (version.h)
# ---------------------------------------------------------------------------
set(PACKAGE_VERSION "${PROJECT_VERSION}")
set(CJOSE_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated-include")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/cjose/version.h.in"
    "${CJOSE_GENERATED_INCLUDE_DIR}/cjose/version.h"
    @ONLY)

# ---------------------------------------------------------------------------
# Library sources
# ---------------------------------------------------------------------------
set(CJOSE_SOURCES
    src/version.c
    src/util.c
    src/base64.c
    src/concatkdf.c
    src/jwk.c
    src/jwe.c
    src/jws.c
    src/header.c
    src/error.c)

set(CJOSE_INTERNAL_HEADERS
    src/include/concatkdf_int.h
    src/include/header_int.h
    src/include/jwk_int.h
    src/include/jwe_int.h
    src/include/jws_int.h
    src/include/util_int.h)

# Public API headers
set(CJOSE_PUBLIC_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/cjose/cjose.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/cjose/base64.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/cjose/jwk.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/cjose/jwe.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/cjose/jws.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/cjose/header.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/cjose/error.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/cjose/util.h"
    "${CJOSE_GENERATED_INCLUDE_DIR}/cjose/version.h")

set(CJOSE_EXPORTS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmake/exports")

# Compile once; both the static and shared libraries reuse these objects (PIC).
add_library(cjose_objects OBJECT ${CJOSE_SOURCES} ${CJOSE_INTERNAL_HEADERS})
set_target_properties(cjose_objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS ON)

target_compile_definitions(cjose_objects PRIVATE OPENSSL_API_COMPAT=0x10100000L)
if(CJOSE_HAVE_OPENSSL_FEC_H)
    target_compile_definitions(cjose_objects PRIVATE HAVE_OPENSSL_FEC_H=1)
endif()
if(MSVC)
    target_compile_options(cjose_objects PRIVATE /W3 /WX)
    # Silence MSVC's noise about "insecure" CRT functions used by portable C.
    target_compile_definitions(cjose_objects PRIVATE
        _CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_WARNINGS)
else()
    target_compile_options(cjose_objects PRIVATE -pedantic -Wall -Werror)
endif()

target_include_directories(cjose_objects PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CJOSE_GENERATED_INCLUDE_DIR}"
    "${CJOSE_GENERATED_INCLUDE_DIR}/cjose"
    "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_link_libraries(cjose_objects PRIVATE
    OpenSSL::Crypto
    Jansson::Jansson)

# Public include usage requirements. The generated .../cjose dir is exposed in
# the build tree only so the umbrella header's quoted `#include "version.h"`
# resolves; once installed all headers sit together under include/cjose.
set(CJOSE_PUBLIC_INCLUDES
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<BUILD_INTERFACE:${CJOSE_GENERATED_INCLUDE_DIR}>"
    "$<BUILD_INTERFACE:${CJOSE_GENERATED_INCLUDE_DIR}/cjose>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

set(CJOSE_INSTALL_TARGETS "")

# ---------------------------------------------------------------------------
# Static library
# ---------------------------------------------------------------------------
if(CJOSE_BUILD_STATIC)
    add_library(cjose_static STATIC $<TARGET_OBJECTS:cjose_objects>)
    add_library(cjose::cjose_static ALIAS cjose_static)

    target_include_directories(cjose_static PUBLIC ${CJOSE_PUBLIC_INCLUDES})
    target_link_libraries(cjose_static PUBLIC OpenSSL::Crypto Jansson::Jansson)

    # Ship the archive as libcjose.a; on Windows keep the target's default name
    # (cjose_static) so it doesn't clash with the DLL's "cjose.lib" import lib.
    if(NOT WIN32)
        set_target_properties(cjose_static PROPERTIES OUTPUT_NAME cjose)
    endif()

    list(APPEND CJOSE_INSTALL_TARGETS cjose_static)
endif()

# ---------------------------------------------------------------------------
# Shared / dynamic library
# ---------------------------------------------------------------------------
if(CJOSE_BUILD_SHARED)
    add_library(cjose_shared SHARED $<TARGET_OBJECTS:cjose_objects>)
    add_library(cjose::cjose_shared ALIAS cjose_shared)

    target_include_directories(cjose_shared PUBLIC ${CJOSE_PUBLIC_INCLUDES})
    target_link_libraries(cjose_shared PUBLIC OpenSSL::Crypto Jansson::Jansson)

    set_target_properties(cjose_shared PROPERTIES
        OUTPUT_NAME cjose
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        # Link with the final RPATH up front: no install-time relink (keeps
        # code signatures valid / reproducible).
        BUILD_WITH_INSTALL_RPATH ON)

    # Relocatable RPATH (no absolute build paths leak). Apple uses the app-bundle
    # Frameworks convention; macOS is versioned (../Frameworks) vs. flat iOS.
    if(APPLE)
        if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
            set_target_properties(cjose_shared PROPERTIES INSTALL_RPATH
                "@executable_path/../Frameworks;@loader_path/../Frameworks")
        else()
            set_target_properties(cjose_shared PROPERTIES INSTALL_RPATH
                "@executable_path/Frameworks;@loader_path/Frameworks")
        endif()
    elseif(NOT WIN32)
        set_target_properties(cjose_shared PROPERTIES INSTALL_RPATH "$ORIGIN")
    endif()

    # --- Control the exported symbol set: only the public API is visible. ---
    if(WIN32)
        # Windows: export exactly the functions listed in the .def file.
        target_sources(cjose_shared PRIVATE "${CJOSE_EXPORTS_DIR}/cjose.def")
        if(MINGW)
            target_link_options(cjose_shared PRIVATE
                "LINKER:${CJOSE_EXPORTS_DIR}/cjose.def")
        endif()
    elseif(APPLE)
        # Apple: restrict exports via an exported-symbols list.
        target_link_options(cjose_shared PRIVATE
            "LINKER:-exported_symbols_list,${CJOSE_EXPORTS_DIR}/libcjose.symbols")
        set_target_properties(cjose_shared PROPERTIES
            LINK_DEPENDS "${CJOSE_EXPORTS_DIR}/libcjose.symbols")
    else()
        # ELF: version script exports the public API and
        # marks every other symbol local (hidden).
        target_link_options(cjose_shared PRIVATE
            "LINKER:--version-script,${CJOSE_EXPORTS_DIR}/libcjose.version")
        set_target_properties(cjose_shared PROPERTIES
            LINK_DEPENDS "${CJOSE_EXPORTS_DIR}/libcjose.version")
    endif()

    # --- Apple: ship the dynamic library as a framework. ---
    if(APPLE AND NOT CJOSE_MACOS_DYLIB)
        target_sources(cjose_shared PRIVATE ${CJOSE_PUBLIC_HEADERS})
        set_source_files_properties(${CJOSE_PUBLIC_HEADERS} PROPERTIES
            MACOSX_PACKAGE_LOCATION Headers/cjose)
        set_target_properties(cjose_shared PROPERTIES
            FRAMEWORK TRUE
            FRAMEWORK_VERSION A
            MACOSX_FRAMEWORK_IDENTIFIER com.cisco.cjose
            MACOSX_FRAMEWORK_BUNDLE_VERSION ${PROJECT_VERSION}
            MACOSX_FRAMEWORK_SHORT_VERSION_STRING ${PROJECT_VERSION})
    endif()

    list(APPEND CJOSE_INSTALL_TARGETS cjose_shared)
endif()

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------
install(TARGETS ${CJOSE_INSTALL_TARGETS}
    EXPORT cjoseTargets
    RUNTIME   DESTINATION "${CMAKE_INSTALL_BINDIR}"
    LIBRARY   DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE   DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    FRAMEWORK DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    INCLUDES  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

# Install the public headers (a framework also bundles its own copy).
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/cjose"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    FILES_MATCHING PATTERN "*.h")
install(FILES "${CJOSE_GENERATED_INCLUDE_DIR}/cjose/version.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/cjose")

# ---------------------------------------------------------------------------
# pkg-config
# ---------------------------------------------------------------------------
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cjose.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cjose.pc"
    @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/cjose.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

# ---------------------------------------------------------------------------
# CMake package config (find_package(cjose))
# ---------------------------------------------------------------------------
include(CMakePackageConfigHelpers)
set(CJOSE_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/cjose")

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cjoseConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cjoseConfig.cmake"
    INSTALL_DESTINATION "${CJOSE_INSTALL_CMAKEDIR}")

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/cjoseConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/cjoseConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/cjoseConfigVersion.cmake"
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindJansson.cmake"
    DESTINATION "${CJOSE_INSTALL_CMAKEDIR}")

install(EXPORT cjoseTargets
    NAMESPACE cjose::
    DESTINATION "${CJOSE_INSTALL_CMAKEDIR}")

# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------
if(CJOSE_BUILD_TESTS)
    include(CTest)

    # Locate the Check unit-testing framework: prefer its CMake config, then
    # fall back to pkg-config.
    set(_cjose_check_target "")

    find_package(Check CONFIG QUIET)
    if(TARGET Check::check)
        set(_cjose_check_target Check::check)
    elseif(TARGET Check::checkShared)
        set(_cjose_check_target Check::checkShared)
    endif()

    if(NOT _cjose_check_target)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(CHECK QUIET check>=0.9.4 IMPORTED_TARGET)
            if(TARGET PkgConfig::CHECK)
                set(_cjose_check_target PkgConfig::CHECK)
            endif()
        endif()
    endif()

    if(NOT _cjose_check_target)
        message(WARNING "Check (>= 0.9.4) not found; skipping cjose unit tests.")
    else()
        set(CJOSE_TEST_SOURCES
            test/check_cjose.c
            test/check_version.c
            test/check_util.c
            test/check_base64.c
            test/check_concatkdf.c
            test/check_jwk.c
            test/check_jwe.c
            test/check_jws.c
            test/check_header.c
            test/check_cjose.h)

        add_executable(check_cjose ${CJOSE_TEST_SOURCES} $<TARGET_OBJECTS:cjose_objects>)

        target_include_directories(check_cjose PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/include"
            "${CJOSE_GENERATED_INCLUDE_DIR}"
            "${CJOSE_GENERATED_INCLUDE_DIR}/cjose"
            "${CMAKE_CURRENT_SOURCE_DIR}/src")

        target_link_libraries(check_cjose PRIVATE
            ${_cjose_check_target}
            OpenSSL::Crypto
            Jansson::Jansson)

        set_target_properties(check_cjose PROPERTIES
            C_STANDARD 99
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS ON)
        target_compile_definitions(check_cjose PRIVATE OPENSSL_API_COMPAT=0x10100000L)
        if(MSVC)
            target_compile_options(check_cjose PRIVATE /W3)
            target_compile_definitions(check_cjose PRIVATE
                _CRT_SECURE_NO_WARNINGS _CRT_NONSTDC_NO_WARNINGS)
        else()
            target_compile_options(check_cjose PRIVATE -pedantic -Wall)
        endif()

        target_compile_definitions(check_cjose PRIVATE VERSION="${PROJECT_VERSION}")

        # Some platforms need the math and pthread libs Check depends on.
        find_library(CJOSE_M_LIB m)
        if(CJOSE_M_LIB)
            target_link_libraries(check_cjose PRIVATE ${CJOSE_M_LIB})
        endif()
        set(THREADS_PREFER_PTHREAD_FLAG ON)
        find_package(Threads QUIET)
        if(TARGET Threads::Threads)
            target_link_libraries(check_cjose PRIVATE Threads::Threads)
        endif()

        add_test(NAME check_cjose
            COMMAND check_cjose
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/test")
    endif()
endif()

# ---------------------------------------------------------------------------
# Developer convenience targets (only when cjose is the top-level project).
# ---------------------------------------------------------------------------
if(PROJECT_IS_TOP_LEVEL)
    # --- Doxygen documentation ('doxygen' target). ---
    find_package(Doxygen)
    if(DOXYGEN_FOUND)
        set(DOXYGEN_PROJECT_NAME "CJOSE")
        set(DOXYGEN_PROJECT_NUMBER "${PROJECT_VERSION}")
        set(DOXYGEN_FILE_PATTERNS "*.h")

        doxygen_add_docs(doxygen
            "${CMAKE_CURRENT_SOURCE_DIR}/include/cjose"
            COMMENT "Generating API documentation with Doxygen")
    else()
        message(STATUS "Doxygen not found; the 'doxygen' documentation target will be unavailable.")
    endif()

    # --- clang-format target. ---
    find_program(CLANG_FORMAT_EXECUTABLE NAMES clang-format)
    if(CLANG_FORMAT_EXECUTABLE)
        file(GLOB_RECURSE CJOSE_FORMAT_FILES
            "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h"
            "${CMAKE_CURRENT_SOURCE_DIR}/test/*.c"
            "${CMAKE_CURRENT_SOURCE_DIR}/test/*.h")

        add_custom_target(clang-format
            COMMAND ${CLANG_FORMAT_EXECUTABLE} -i ${CJOSE_FORMAT_FILES}
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            COMMENT "Formatting sources with clang-format"
            VERBATIM)
    else()
        message(STATUS "clang-format not found; the 'clang-format' target will be unavailable.")
    endif()
endif()
