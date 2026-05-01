if (CHECK_LIBRARIES AND CHECK_INCLUDE_DIRS)
  set(CHECK_FOUND TRUE)
else (CHECK_LIBRARIES AND CHECK_INCLUDE_DIRS)
  find_path(CHECK_INCLUDE_DIR
    NAMES
      check.h
    PATHS
      ${CHECK_ROOT_DIR}/include
    NO_DEFAULT_PATH
  )

  find_path(CHECK_INCLUDE_DIR
    NAMES
      check.h
  )

find_library(CHECK_LIBRARY_CHECK
    NAMES
      check
      compat
    PATHS
    ${CHECK_ROOT_DIR}/lib
    NO_DEFAULT_PATH
  )

find_library(CHECK_LIBRARY_CHECK
    NAMES
      check
      compat
  )

find_library(CHECK_LIBRARY_COMPAT
    NAMES
      compat
    PATHS
    ${CHECK_ROOT_DIR}/lib
    NO_DEFAULT_PATH
  )

find_library(CHECK_LIBRARY_COMPAT
    NAMES
      compat
  )

if (CHECK_INCLUDE_DIR)
set(CHECK_INCLUDE_DIRS
  ${CHECK_INCLUDE_DIRS}
  ${CHECK_INCLUDE_DIR}
  )
endif(CHECK_INCLUDE_DIR)

if (CHECK_LIBRARY_CHECK)
  set(CHECK_LIBRARIES
    ${CHECK_LIBRARIES}
    ${CHECK_LIBRARY_CHECK}
    )
endif (CHECK_LIBRARY_CHECK)

if (CHECK_LIBRARY_COMPAT)
  set(CHECK_LIBRARIES
    ${CHECK_LIBRARIES}
    ${CHECK_LIBRARY_COMPAT}
    )
endif (CHECK_LIBRARY_COMPAT)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Check DEFAULT_MSG
    CHECK_LIBRARIES CHECK_INCLUDE_DIRS)

  mark_as_advanced(CHECK_INCLUDE_DIRS CHECK_LIBRARIES)

endif (CHECK_LIBRARIES AND CHECK_INCLUDE_DIRS)
