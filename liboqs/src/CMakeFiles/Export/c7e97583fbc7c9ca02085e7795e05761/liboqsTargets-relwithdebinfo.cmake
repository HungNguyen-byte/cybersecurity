#----------------------------------------------------------------
# Generated CMake target import file for configuration "RelWithDebInfo".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "OQS::oqs" for configuration "RelWithDebInfo"
set_property(TARGET OQS::oqs APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
set_target_properties(OQS::oqs PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELWITHDEBINFO "C"
  IMPORTED_LOCATION_RELWITHDEBINFO "${_IMPORT_PREFIX}/lib/oqs.lib"
  )

list(APPEND _cmake_import_check_targets OQS::oqs )
list(APPEND _cmake_import_check_files_for_OQS::oqs "${_IMPORT_PREFIX}/lib/oqs.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
