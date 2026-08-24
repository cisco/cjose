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

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Jansson
    REQUIRED_VARS JANSSON_LIBRARY JANSSON_INCLUDE_DIR
    VERSION_VAR JANSSON_VERSION)

if(Jansson_FOUND AND NOT TARGET Jansson::Jansson)
    add_library(Jansson::Jansson UNKNOWN IMPORTED)
    set_target_properties(Jansson::Jansson PROPERTIES
        IMPORTED_LOCATION "${JANSSON_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${JANSSON_INCLUDE_DIR}")
endif()

mark_as_advanced(JANSSON_INCLUDE_DIR JANSSON_LIBRARY)
