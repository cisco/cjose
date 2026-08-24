cmake_minimum_required(VERSION 3.22)

cmake_policy(SET CMP0091 NEW)

project(cjose
    VERSION 0.6.1
    DESCRIPTION "JOSE implementation for C"
    LANGUAGES C)

include(CheckIncludeFile)
include(CMakePackageConfigHelpers)
include(CMakePushCheckState)
include(GNUInstallDirs)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(CJOSE_BUILD_TESTS "Build cjose unit tests when Check is available" ON)
option(CJOSE_BUILD_DOCS "Add cjose Doxygen documentation target when Doxygen is available" ON)
option(CJOSE_INSTALL "Install cjose targets and package metadata" ON)

if(MSVC)
    option(CJOSE_STATIC_MSVC_STATIC_RUNTIME "Use static CRT (/MT) for cjose_static" OFF)
endif()

set(CJOSE_SHARED_OPENSSL_CRYPTO_LIBRARY "" CACHE FILEPATH "OpenSSL Crypto library for cjose")
set(CJOSE_STATIC_OPENSSL_CRYPTO_LIBRARY "" CACHE FILEPATH "OpenSSL Crypto library for cjose_static")
set(CJOSE_SHARED_JANSSON_LIBRARY "" CACHE FILEPATH "Jansson library for cjose")
set(CJOSE_STATIC_JANSSON_LIBRARY "" CACHE FILEPATH "Jansson library for cjose_static")

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(Jansson 2.3 REQUIRED)

cmake_push_check_state(RESET)
set(CMAKE_REQUIRED_INCLUDES "${OPENSSL_INCLUDE_DIR}")
check_include_file("openssl/fec.h" HAVE_OPENSSL_FEC_H)
cmake_pop_check_state()

set(PACKAGE_VERSION "${PROJECT_VERSION}")
set(VERSION "${PROJECT_VERSION}")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/cjose/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/cjose/version.h"
    @ONLY)

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

set(CJOSE_PRIVATE_HEADERS
    src/include/concatkdf_int.h
    src/include/header_int.h
    src/include/jwk_int.h
    src/include/jwe_int.h
    src/include/jws_int.h
    src/include/util_int.h)

set(CJOSE_PUBLIC_HEADERS
    include/cjose/cjose.h
    include/cjose/base64.h
    include/cjose/jwk.h
    include/cjose/jwe.h
    include/cjose/jws.h
    include/cjose/header.h
    include/cjose/error.h
    include/cjose/util.h)

set(CJOSE_GENERATED_PUBLIC_HEADER
    "${CMAKE_CURRENT_BINARY_DIR}/include/cjose/version.h")

set(CJOSE_ALL_PUBLIC_HEADERS
    ${CJOSE_PUBLIC_HEADERS}
    ${CJOSE_GENERATED_PUBLIC_HEADER})

add_library(cjose SHARED
    ${CJOSE_SOURCES}
    ${CJOSE_PRIVATE_HEADERS}
    ${CJOSE_ALL_PUBLIC_HEADERS})
add_library(cjose_static STATIC
    ${CJOSE_SOURCES}
    ${CJOSE_PRIVATE_HEADERS}
    ${CJOSE_ALL_PUBLIC_HEADERS})

add_library(cjose::cjose ALIAS cjose)
add_library(cjose::shared ALIAS cjose)
add_library(cjose::static ALIAS cjose_static)

function(cjose_configure_library target)
    set_target_properties(${target} PROPERTIES
        C_STANDARD 99
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS ON
        OUTPUT_NAME cjose
        VERSION "${PROJECT_VERSION}"
        SOVERSION 0)

    target_include_directories(${target}
        PUBLIC
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>"
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include/cjose>"
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
            "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
        PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/src")

    target_compile_definitions(${target}
        PRIVATE
            OPENSSL_API_COMPAT=0x10100000L
            $<$<BOOL:${HAVE_OPENSSL_FEC_H}>:HAVE_OPENSSL_FEC_H>)

    if(MSVC)
        target_compile_options(${target} PRIVATE /W3 /WX)
    else()
        target_compile_options(${target} PRIVATE --pedantic -Wall -Werror)
    endif()

    if(WIN32)
        target_link_libraries(${target} PRIVATE ws2_32)
    else()
        target_link_libraries(${target} PRIVATE m)
    endif()
endfunction()

cjose_configure_library(cjose)
cjose_configure_library(cjose_static)

function(cjose_link_dependency target link_scope default_target library_var include_dir)
    if(NOT "${${library_var}}" STREQUAL "")
        target_link_libraries(${target} ${link_scope} "${${library_var}}")
        if(NOT "${include_dir}" STREQUAL "")
            if(link_scope STREQUAL "PUBLIC" OR link_scope STREQUAL "INTERFACE")
                target_include_directories(${target} ${link_scope}
                    "$<BUILD_INTERFACE:${include_dir}>"
                    "$<INSTALL_INTERFACE:${include_dir}>")
            else()
                target_include_directories(${target} ${link_scope}
                    "$<BUILD_INTERFACE:${include_dir}>")
            endif()
        endif()
    else()
        target_link_libraries(${target} ${link_scope} ${default_target})
    endif()
endfunction()

cjose_link_dependency(cjose PUBLIC OpenSSL::Crypto CJOSE_SHARED_OPENSSL_CRYPTO_LIBRARY "${OPENSSL_INCLUDE_DIR}")
cjose_link_dependency(cjose_static PUBLIC OpenSSL::Crypto CJOSE_STATIC_OPENSSL_CRYPTO_LIBRARY "${OPENSSL_INCLUDE_DIR}")
cjose_link_dependency(cjose PRIVATE Jansson::Jansson CJOSE_SHARED_JANSSON_LIBRARY "${JANSSON_INCLUDE_DIR}")
cjose_link_dependency(cjose_static PRIVATE Jansson::Jansson CJOSE_STATIC_JANSSON_LIBRARY "${JANSSON_INCLUDE_DIR}")

set_target_properties(cjose PROPERTIES
    EXPORT_NAME cjose)
set_target_properties(cjose_static PROPERTIES
    EXPORT_NAME static)

if(WIN32)
    target_sources(cjose PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cjose.def")
    set_target_properties(cjose_static PROPERTIES OUTPUT_NAME cjose-static)

    if(MSVC AND CJOSE_STATIC_MSVC_STATIC_RUNTIME)
        set_property(TARGET cjose_static PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
elseif(APPLE)
    set_target_properties(cjose PROPERTIES
        FRAMEWORK TRUE
        FRAMEWORK_VERSION A
        MACOSX_FRAMEWORK_IDENTIFIER "com.cisco.cjose"
        MACOSX_FRAMEWORK_BUNDLE_VERSION "${PROJECT_VERSION}"
        MACOSX_FRAMEWORK_SHORT_VERSION_STRING "${PROJECT_VERSION}")

    set_source_files_properties(${CJOSE_ALL_PUBLIC_HEADERS}
        PROPERTIES MACOSX_PACKAGE_LOCATION "Headers/cjose")

    target_link_options(cjose PRIVATE
        "LINKER:-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/cmake/cjose.exports")
elseif(UNIX)
    target_link_options(cjose PRIVATE
        "LINKER:--version-script=${CMAKE_CURRENT_SOURCE_DIR}/cmake/cjose.map")
endif()

if(CJOSE_BUILD_TESTS)
    include(CTest)

    if(BUILD_TESTING)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(CHECK QUIET check>=0.9.4)
        endif()

        if(CHECK_FOUND)
            add_executable(check_cjose
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

            target_include_directories(check_cjose PRIVATE
                "${CMAKE_CURRENT_BINARY_DIR}/include"
                "${CMAKE_CURRENT_SOURCE_DIR}/include"
                "${CMAKE_CURRENT_SOURCE_DIR}/src"
                ${CHECK_INCLUDE_DIRS})

            target_compile_options(check_cjose PRIVATE
                $<$<NOT:$<C_COMPILER_ID:MSVC>>:--pedantic>
                $<$<NOT:$<C_COMPILER_ID:MSVC>>:-Wall>
                $<$<C_COMPILER_ID:MSVC>:/W3>
                ${CHECK_CFLAGS_OTHER})

            target_compile_definitions(check_cjose PRIVATE
                VERSION="${PROJECT_VERSION}")

            target_link_libraries(check_cjose PRIVATE
                cjose_static
                ${CHECK_LINK_LIBRARIES}
                ${CHECK_LIBRARIES})

            target_link_directories(check_cjose PRIVATE ${CHECK_LIBRARY_DIRS})
            target_link_options(check_cjose PRIVATE ${CHECK_LDFLAGS_OTHER})

            add_test(NAME check_cjose COMMAND check_cjose)
        else()
            message(STATUS "Check >= 0.9.4 not found; cjose unit tests will not be built")
        endif()
    endif()
endif()

if(CJOSE_BUILD_DOCS)
    find_package(Doxygen QUIET)

    if(Doxygen_FOUND)
        set(CJOSE_DOXYGEN_INPUT)
        foreach(header IN LISTS CJOSE_PUBLIC_HEADERS)
            list(APPEND CJOSE_DOXYGEN_INPUT "${CMAKE_CURRENT_SOURCE_DIR}/${header}")
        endforeach()
        list(APPEND CJOSE_DOXYGEN_INPUT "${CJOSE_GENERATED_PUBLIC_HEADER}")

        set(DOXYGEN_PROJECT_NAME "CJOSE")
        set(DOXYGEN_PROJECT_NUMBER "${PROJECT_VERSION}")
        set(DOXYGEN_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/doc")
        set(DOXYGEN_GENERATE_HTML YES)
        set(DOXYGEN_HTML_OUTPUT html)
        set(DOXYGEN_GENERATE_LATEX NO)
        set(DOXYGEN_GENERATE_MAN NO)
        set(DOXYGEN_HAVE_DOT NO)
        set(DOXYGEN_WARN_IF_UNDOCUMENTED NO)

        doxygen_add_docs(doxygen
            ${CJOSE_DOXYGEN_INPUT}
            USE_STAMP_FILE
            COMMENT "Generate cjose API documentation")
    else()
        message(STATUS "Doxygen not found; cjose documentation target will not be built")
    endif()
endif()

if(CJOSE_INSTALL)
    set(prefix "${CMAKE_INSTALL_PREFIX}")
    set(exec_prefix "\${prefix}")
    set(libdir "\${exec_prefix}/${CMAKE_INSTALL_LIBDIR}")
    set(includedir "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cjose.pc.in"
        "${CMAKE_CURRENT_BINARY_DIR}/cjose.pc"
        @ONLY)

    install(TARGETS cjose cjose_static
        EXPORT cjoseTargets
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        FRAMEWORK DESTINATION "${CMAKE_INSTALL_LIBDIR}")

    install(FILES ${CJOSE_ALL_PUBLIC_HEADERS}
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/cjose")

    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/cjose.pc"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

    if(CJOSE_BUILD_DOCS AND Doxygen_FOUND)
        install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/doc/html"
            DESTINATION "${CMAKE_INSTALL_DOCDIR}"
            OPTIONAL)
    endif()

    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/cjoseConfigVersion.cmake"
        VERSION "${PROJECT_VERSION}"
        COMPATIBILITY SameMajorVersion)

    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cjoseConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/cjoseConfig.cmake"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/cjose")

    install(EXPORT cjoseTargets
        NAMESPACE cjose::
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/cjose")

    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/cjoseConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/cjoseConfigVersion.cmake"
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/FindJansson.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/cjose")
endif()
