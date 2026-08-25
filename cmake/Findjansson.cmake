include(FindPackageHandleStandardArgs)

set(jansson_FOUND FALSE)

if(NOT TARGET jansson::jansson)
    set(_jansson_config_args)
    if(jansson_FIND_VERSION_COMPLETE)
        list(APPEND _jansson_config_args "${jansson_FIND_VERSION_COMPLETE}")
    elseif(jansson_FIND_VERSION)
        list(APPEND _jansson_config_args "${jansson_FIND_VERSION}")
    endif()
    if(jansson_FIND_VERSION_EXACT)
        list(APPEND _jansson_config_args EXACT)
    endif()
    list(APPEND _jansson_config_args CONFIG QUIET)
    find_package(jansson ${_jansson_config_args})
    unset(_jansson_config_args)
endif()

if(TARGET jansson::jansson)
    set(jansson_FOUND TRUE)
    return()
endif()

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PC_JANSSON QUIET jansson)
endif()

find_path(JANSSON_INCLUDE_DIR
    NAMES jansson.h
    HINTS ${PC_JANSSON_INCLUDE_DIRS})

find_library(JANSSON_LIBRARY
    NAMES jansson libjansson
    HINTS ${PC_JANSSON_LIBRARY_DIRS})

set(JANSSON_VERSION "${PC_JANSSON_VERSION}")

if(NOT JANSSON_VERSION AND JANSSON_INCLUDE_DIR)
    file(STRINGS "${JANSSON_INCLUDE_DIR}/jansson.h" _jansson_version_define
        REGEX "^#[ \t]*define[ \t]+JANSSON_VERSION[ \t]+\"[^\"]+\"")
    string(REGEX REPLACE
        "^.*JANSSON_VERSION[ \t]+\"([^\"]+)\".*$" "\\1"
        JANSSON_VERSION "${_jansson_version_define}")
    unset(_jansson_version_define)
endif()

find_package_handle_standard_args(jansson
    REQUIRED_VARS JANSSON_LIBRARY JANSSON_INCLUDE_DIR
    VERSION_VAR JANSSON_VERSION
    HANDLE_VERSION_RANGE)

if(jansson_FOUND AND NOT TARGET jansson::jansson)
    add_library(jansson::jansson UNKNOWN IMPORTED)
    set_target_properties(jansson::jansson PROPERTIES
        IMPORTED_LOCATION "${JANSSON_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${JANSSON_INCLUDE_DIR}")
endif()

mark_as_advanced(JANSSON_INCLUDE_DIR JANSSON_LIBRARY)
