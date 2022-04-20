# Once done these will be defined:
#
#  NGTCP2_FOUND
#  NGTCP2_INCLUDE_DIRS
#  NGTCP2_LIBRARIES
#

if(UNIX)
  find_package(PkgConfig QUIET)
  pkg_search_module(PC_NGTCP2 libngtcp2)
endif()

find_path(NGTCP2_INCLUDE_DIR ngtcp2/ngtcp2.h
  HINTS
    ${PC_NGTCP2_INCLUDEDIR}
    ${PC_NGTCP2_INCLUDE_DIRS}
)

find_library(NGTCP2_LIBRARY NAMES ngtcp2
  HINTS
    ${PC_NGTCP2_LIBDIR}
    ${PC_NGTCP2_LIBRARY_DIRS}
)

if(PC_NGTCP2_VERSION)
  set(NGTCP2_VERSION ${PC_NGTCP2_VERSION})
endif()

if(NGTCP2_FIND_COMPONENTS)
  set(NGTCP2_CRYPTO_BACKEND "")
  foreach(component IN LISTS NGTCP2_FIND_COMPONENTS)
    if(component MATCHES "^(OpenSSL|GnuTLS)")
      if(NGTCP2_CRYPTO_BACKEND)
        message(FATAL_ERROR "NGTCP2: Only one crypto library can be selected")
      endif()
      set(NGTCP2_CRYPTO_BACKEND ${component})
    endif()
  endforeach()

  if(NGTCP2_CRYPTO_BACKEND)
    string(TOLOWER "ngtcp2_crypto_${NGTCP2_CRYPTO_BACKEND}" _crypto_library)
    if(UNIX)
      pkg_search_module(PC_${_crypto_library} lib${_crypto_library})
    endif()
    find_library(${_crypto_library}_LIBRARY
      NAMES
        ${_crypto_library}
      HINTS
        ${PC_${_crypto_library}_LIBDIR}
        ${PC_${_crypto_library}_LIBRARY_DIRS}
    )
    if(${_crypto_library}_LIBRARY)
      set(NGTCP2_${NGTCP2_CRYPTO_BACKEND}_FOUND TRUE)
      set(NGTCP2_CRYPTO_LIBRARY ${${_crypto_library}_LIBRARY})
    endif()
  endif()
endif()
# use openssl crypto library for now
find_library(NGTCP2_CRYPTO_OPENSSL_LIBRARY
	NAMES
		ngtcp2_crypto_openssl
)
if (NGTCP2_CRYPTO_OPENSSL_LIBRARY)
	set(NGTCP2_CRYPTO_LIBRARY ${NGTCP2_CRYPTO_OPENSSL_LIBRARY})
	message (STATUS "ngtcp2 crypto openssl found.")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NGTCP2
  REQUIRED_VARS
    NGTCP2_LIBRARY
    NGTCP2_INCLUDE_DIR
  VERSION_VAR NGTCP2_VERSION
  HANDLE_COMPONENTS
)

if(NGTCP2_FOUND)
  set(NGTCP2_LIBRARIES    ${NGTCP2_LIBRARY} ${NGTCP2_CRYPTO_LIBRARY})
  set(NGTCP2_INCLUDE_DIRS ${NGTCP2_INCLUDE_DIR})
	message (STATUS "ngtcp2 found.")
	message (STATUS "ngtcp2 include directories: ${NGTCP2_INCLUDE_DIR}")
	message (STATUS "ngtcp2 libraries: ${NGTCP2_LIBRARY} ${NGTCP2_CRYPTO_LIBRARY}")
endif()

mark_as_advanced(NGTCP2_INCLUDE_DIRS NGTCP2_LIBRARIES)
