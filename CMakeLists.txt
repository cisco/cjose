cmake_minimum_required (VERSION 3.0.2)
project (cjose)

include(CheckSymbolExists)
include(CheckIncludeFile)
include(CheckTypeSize) 

option(ENABLE_Tests "Turn on Tests" ON)
option(CJOSE_BUILD_SHARED_LIBS "Build shared libraries." OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/CMakeModules")

# Build Release by default
if (NOT CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE Release)
else()
endif()

# Setup cjose version
set(CJOSE_MAJOR_VERSION 0)
set(CJOSE_MINOR_VERSION 4)
set(CJOSE_PATCH_VERSION 1)
set(PACKAGE_VERSION ${CJOSE_MAJOR_VERSION}.${CJOSE_MINOR_VERSION}.${CJOSE_PATCH_VERSION})
  
# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

# Create version.h file
configure_file (
  "${PROJECT_SOURCE_DIR}/include/cjose/version.h.in"
  "${PROJECT_BINARY_DIR}/include/cjose/version.h"
  )

# Set include directories  
include_directories(
${CMAKE_CURRENT_SOURCE_DIR}/include
${CMAKE_CURRENT_SOURCE_DIR}/src/include
${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Find dependencies
# Look for Homebrew version of OpenSSL
function(GetRootDirForHomebrew PKG_NAME)
    if ((NOT ${PKG_NAME}_INCLUDE_DIR) OR (NOT ${PKG_NAME}_LIBRARIES))
        string(TOLOWER ${PKG_NAME} PKG_NAME_LOWER)
        SET(BREW_PACKAGE_DIR /usr/local/Cellar/${PKG_NAME_LOWER})
        IF (EXISTS ${BREW_PACKAGE_DIR})
            file(GLOB HB_${PKG_NAME}_ROOT_DIRECTORIES ${BREW_PACKAGE_DIR}/*)
            list(GET HB_${PKG_NAME}_ROOT_DIRECTORIES 0 HB_${PKG_NAME}_ROOT_DIR)
            if(HB_${PKG_NAME}_ROOT_DIRECTORIES AND NOT ${PKG_NAME}_ROOT_DIR)
                SET(${PKG_NAME}_ROOT_DIR ${HB_${PKG_NAME}_ROOT_DIR} PARENT_SCOPE)
            endif(HB_${PKG_NAME}_ROOT_DIRECTORIES AND NOT ${PKG_NAME}_ROOT_DIR)
        ENDIF (EXISTS ${BREW_PACKAGE_DIR})
    endif((NOT ${PKG_NAME}_INCLUDE_DIR) OR (NOT ${PKG_NAME}_LIBRARIES))
endfunction(GetRootDirForHomebrew PKG_NAME)

if(CMAKE_C_COMPILER_ID MATCHES "AppleClang")
    GetRootDirForHomebrew(OPENSSL)
    if (ENABLE_Tests)
        GetRootDirForHomebrew(CHECK)
    endif()
    GetRootDirForHomebrew(JANSSON)
endif(CMAKE_C_COMPILER_ID MATCHES "AppleClang")

find_package(Check 0.9.4)

find_library(RT NAMES rt)
if (${RT} STREQUAL RT-NOTFOUND)
	unset(${RT})
endif(${RT} STREQUAL RT-NOTFOUND)

find_library(M NAMES m)
if (${M} STREQUAL M-NOTFOUND)
	unset(${M})
endif(${M} STREQUAL M-NOTFOUND)

check_type_size(ssize_t SSIZE_T)

# Enable test if possible
if (NOT CHECK_FOUND OR ENABLE_Tests==OFF)
	SET(ENABLE_Tests OFF)
endif(NOT CHECK_FOUND OR ENABLE_Tests==OFF)
message(STATUS "Tests Enabled............${ENABLE_Tests}")

CHECK_SYMBOL_EXISTS("random" stdlib.h HAVE_RANDOM)

# Set dependency include directories
include_directories(
  ${OPENSSL_INCLUDE_DIR}
  ${JANSSON_INCLUDE_DIR}
  ${BUILD_INCLUDES}
)

#Generate config file
configure_file (
  "${PROJECT_SOURCE_DIR}/include/cjose/config.h.in"
  "${PROJECT_BINARY_DIR}/include/cjose/cjose_config.h"
)

# Setup compilation flags for different compilers
if (MSVC)
   add_compile_options(/W2  /nologo /WX-)
   add_definitions( "/DVERSION=\"${PACKAGE_VERSION}\"")
   add_definitions( "/D_CRT_SECURE_NO_WARNINGS")
   set(DEFAULT_COMPILER_OPTIONS /Zi /DEBUG $<$<CONFIG:Debug>:/Od> $<$<CONFIG:Release>:/O2> /MP )
   set(LIB_COMPILER_OPTIONS ${DEFAULT_COMPILER_OPTIONS} /WX)
   if (STATIC_CRT)
      SET(LIB_COMPILER_OPTIONS ${LIB_COMPILER_OPTIONS} $<$<CONFIG:Debug>:/MTd> $<$<CONFIG:Release>:/MT>)
   else()
      SET(LIB_COMPILER_OPTIONS ${LIB_COMPILER_OPTIONS} $<$<CONFIG:Debug>:/MDd> $<$<CONFIG:Release>:/MD>)
   endif()
elseif(CMAKE_COMPILER_IS_GNUCC)
	add_definitions( "-DVERSION=\"${PACKAGE_VERSION}\"")
    set(DEFAULT_COMPILER_OPTIONS -std=gnu99 -g $<$<CONFIG:Release>:-O2>)
	set(LIB_COMPILER_OPTIONS ${DEFAULT_COMPILER_OPTIONS} --pedantic -Wall -Werror)
else(CMAKE_C_COMPILER_ID MATCHES "AppleClang")
	add_definitions( "-DVERSION=\"${PACKAGE_VERSION}\"")
    set(DEFAULT_COMPILER_OPTIONS -std=gnu99 -g $<$<CONFIG:Release>:-O2>)
	set(LIB_COMPILER_OPTIONS ${DEFAULT_COMPILER_OPTIONS} --pedantic -Wall -Werror)
endif(MSVC)


file(GLOB CJOSE_SRC ${PROJECT_SOURCE_DIR}/src/*.c)
file(GLOB CJOSE_HDR_PUBLIC ${PROJECT_SOURCE_DIR}/include/cjose/*.h)
file(GLOB CJOSE_HDR_PRIVATE ${PROJECT_SOURCE_DIR}/src/include/*.h)

source_group("Library Sources" FILES ${CJOSE_SRC})
source_group("Library Private Headers" FILES ${CJOSE_HDR_PRIVATE})
source_group("Library Public Headers" FILES ${CJOSE_HDR_PUBLIC})

if (CJOSE_BUILD_SHARED_LIBS)
add_library(cjose SHARED 
${CJOSE_SRC}
${CJOSE_HDR_PRIVATE}
${CJOSE_HDR_PUBLIC}
)
else()
add_library(cjose 
${CJOSE_SRC}
${CJOSE_HDR_PRIVATE}
${CJOSE_HDR_PUBLIC}
)
endif()

target_link_libraries(cjose ${JANSSON_LIBRARIES} ${OPENSSL_LIBRARIES} ${MLIB} ${RTLIB})
target_compile_options(cjose PRIVATE ${LIB_COMPILER_OPTIONS})

if (ENABLE_Tests)
file(GLOB CJOSE_TESTS_SRC ${PROJECT_SOURCE_DIR}/test/*.c)
file(GLOB CJOSE_TESTS_HDR ${PROJECT_SOURCE_DIR}/test/*.h)
include_directories(${CHECK_INCLUDE_DIRS})
source_group("Test Files " FILES ${CJOSE_TESTS_SRC} ${CJOSE_TESTS_HDR})

add_executable(tests ${CJOSE_TESTS_SRC} ${CJOSE_TESTS_HDR})
target_compile_options(tests PRIVATE ${DEFAULT_COMPILER_OPTIONS})
target_link_libraries(tests cjose ${JANSSON_LIBRARIES} ${OPENSSL_LIBRARIES} ${CHECK_LIBRARIES})
endif(ENABLE_Tests)

#install

# Allow the user to override installation directories.
set(CJOSE_INSTALL_LIB_DIR       lib CACHE PATH "Installation directory for libraries")
set(CJOSE_INSTALL_BIN_DIR       bin CACHE PATH "Installation directory for executables")
set(CJOSE_INSTALL_INCLUDE_DIR   include CACHE PATH "Installation directory for header files")


if(WIN32 AND NOT CYGWIN)
  set(DEF_INSTALL_CMAKE_DIR cmake)
else()
  set(DEF_INSTALL_CMAKE_DIR lib/cmake/cjose)
endif()

set(CJOSE_INSTALL_CMAKE_DIR ${DEF_INSTALL_CMAKE_DIR} CACHE PATH "Installation directory for CMake files")

# Create pkg-conf file.
# (We use the same files as ./configure does, so we
#  have to defined the same variables used there).
set(prefix      ${CMAKE_INSTALL_PREFIX})
set(exec_prefix ${CMAKE_INSTALL_PREFIX})
set(libdir      ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(includedir  ${CMAKE_INSTALL_PREFIX}/${CJOSE_INSTALL_INCLUDE_DIR})
set(VERSION     ${PACKAGE_VERSION})
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cjose.pc.in
               ${CMAKE_CURRENT_BINARY_DIR}/cjose.pc @ONLY)
			   
# Make sure the paths are absolute.
foreach(p LIB BIN INCLUDE CMAKE)
    set(var CJOSE_INSTALL_${p}_DIR)
    if(NOT IS_ABSOLUTE "${${var}}")
        set(${var} "${CMAKE_INSTALL_PREFIX}/${${var}}")
    endif()
endforeach()

set_target_properties(cjose PROPERTIES PUBLIC_HEADER "${CJOSE_HDR_PUBLIC}")


# Install the pkg-config.
install (FILES 
         ${CMAKE_CURRENT_BINARY_DIR}/cjose.pc
         DESTINATION ${CJOSE_INSTALL_LIB_DIR}/pkgconfig COMPONENT dev)
		 
install(TARGETS cjose
        EXPORT CjoseTargets
        LIBRARY DESTINATION "${CJOSE_INSTALL_LIB_DIR}" COMPONENT lib
        ARCHIVE DESTINATION "${CJOSE_INSTALL_LIB_DIR}" COMPONENT lib
        RUNTIME DESTINATION "${CJOSE_INSTALL_BIN_DIR}" COMPONENT lib # Windows DLLs
        PUBLIC_HEADER DESTINATION "${CJOSE_INSTALL_INCLUDE_DIR}/cjose" COMPONENT dev)

# Install exports for the install-tree.
install(EXPORT CjoseTargets 
        DESTINATION "${CJOSE_INSTALL_CMAKE_DIR}" COMPONENT dev)

# For use when simply using add_library from a parent project to build cjose.
set(CJOSE_LIBRARIES cjose CACHE STRING "Cjose libraries")
