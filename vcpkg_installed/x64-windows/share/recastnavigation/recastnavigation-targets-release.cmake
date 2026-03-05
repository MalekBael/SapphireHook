#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "RecastNavigation::DebugUtils" for configuration "Release"
set_property(TARGET RecastNavigation::DebugUtils APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(RecastNavigation::DebugUtils PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/DebugUtils.lib"
  )

list(APPEND _cmake_import_check_targets RecastNavigation::DebugUtils )
list(APPEND _cmake_import_check_files_for_RecastNavigation::DebugUtils "${_IMPORT_PREFIX}/lib/DebugUtils.lib" )

# Import target "RecastNavigation::Detour" for configuration "Release"
set_property(TARGET RecastNavigation::Detour APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(RecastNavigation::Detour PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/Detour.lib"
  )

list(APPEND _cmake_import_check_targets RecastNavigation::Detour )
list(APPEND _cmake_import_check_files_for_RecastNavigation::Detour "${_IMPORT_PREFIX}/lib/Detour.lib" )

# Import target "RecastNavigation::DetourCrowd" for configuration "Release"
set_property(TARGET RecastNavigation::DetourCrowd APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(RecastNavigation::DetourCrowd PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/DetourCrowd.lib"
  )

list(APPEND _cmake_import_check_targets RecastNavigation::DetourCrowd )
list(APPEND _cmake_import_check_files_for_RecastNavigation::DetourCrowd "${_IMPORT_PREFIX}/lib/DetourCrowd.lib" )

# Import target "RecastNavigation::DetourTileCache" for configuration "Release"
set_property(TARGET RecastNavigation::DetourTileCache APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(RecastNavigation::DetourTileCache PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/DetourTileCache.lib"
  )

list(APPEND _cmake_import_check_targets RecastNavigation::DetourTileCache )
list(APPEND _cmake_import_check_files_for_RecastNavigation::DetourTileCache "${_IMPORT_PREFIX}/lib/DetourTileCache.lib" )

# Import target "RecastNavigation::Recast" for configuration "Release"
set_property(TARGET RecastNavigation::Recast APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(RecastNavigation::Recast PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/Recast.lib"
  )

list(APPEND _cmake_import_check_targets RecastNavigation::Recast )
list(APPEND _cmake_import_check_files_for_RecastNavigation::Recast "${_IMPORT_PREFIX}/lib/Recast.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
