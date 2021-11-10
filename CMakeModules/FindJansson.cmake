if (JANSSON_LIBRARIES AND JANSSON_INCLUDE_DIRS)
  set(JANSSON_FOUND TRUE)
else (JANSSON_LIBRARIES AND JANSSON_INCLUDE_DIRS)
  find_path(JANSSON_INCLUDE_DIR
    NAMES
      jansson.h
    PATHS
      ${JANSSON_ROOT_DIR}/include
    NO_DEFAULT_PATH
  )

  find_path(JANSSON_INCLUDE_DIR
    NAMES
      jansson.h
  )

find_library(JANSSON_LIBRARY_RELEASE
    NAMES
      jansson
    PATHS
      ${JANSSON_ROOT_DIR}/lib
    NO_DEFAULT_PATH
  )

find_library(JANSSON_LIBRARY_RELEASE
    NAMES
      jansson
  )

find_library(JANSSON_LIBRARY_DEBUG
    NAMES
      jansson_d
    PATHS
      ${JANSSON_ROOT_DIR}/lib
    NO_DEFAULT_PATH
  )

find_library(JANSSON_LIBRARY_DEBUG
    NAMES
      jansson_d
  )

set(JANSSON_INCLUDE_DIRS
  ${JANSSON_INCLUDE_DIR}
  )

if (JANSSON_LIBRARY_DEBUG)
  set(JANSSON_LIBRARIES
    ${JANSSON_LIBRARIES}
    debug ${JANSSON_LIBRARY_DEBUG}
    )
endif (JANSSON_LIBRARY_DEBUG)

if (JANSSON_LIBRARY_RELEASE)
  if (WIN32)
    set(JANSSON_LIBRARIES ${JANSSON_LIBRARIES} optimized ${JANSSON_LIBRARY_RELEASE})
  else()
  	set(JANSSON_LIBRARIES ${JANSSON_LIBRARIES} general ${JANSSON_LIBRARY_RELEASE})
  endif(WIN32)
endif (JANSSON_LIBRARY_RELEASE)

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Jansson DEFAULT_MSG
    JANSSON_LIBRARIES JANSSON_INCLUDE_DIRS)

  mark_as_advanced(JANSSON_INCLUDE_DIRS JANSSON_LIBRARIES)

endif (JANSSON_LIBRARIES AND JANSSON_INCLUDE_DIRS)