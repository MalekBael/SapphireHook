#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "RecastNavigation::DebugUtils" for configuration "Debug"
set_property(TARGET RecastNavigation::DebugUtils APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(RecastNavigation::DebugUtils PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "CXX"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/debug/lib/DebugUtils-d.lib"
  )

list(APPEND _cmake_import_check_targets RecastNavigation::DebugUtils )
list(APPEND _cmake_import_check_files_for_RecastNavigation::DebugUtils "${_IMPORT_PREFIX}/debug/lib/DebugUtils-d.lib" )

# Import target "RecastNavigation::Detour" for configuration "Debug"
set_property(TARGET RecastNavigation::Detour APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(RecastNavigation::Detour PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "CXX"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/debug/lib/Detour-d.lib"
  )

list(APPEND _cmake_import_check_targets RecastNavigation::Detour )
list(APPEND _cmake_import_check_files_for_RecastNavigation::Detour "${_IMPORT_PREFIX}/debug/lib/Detour-d.lib" )

# Import target "RecastNavigation::DetourCrowd" for configuration "Debug"
set_property(TARGET RecastNavigation::DetourCrowd APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(RecastNavigation::DetourCrowd PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "CXX"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/debug/lib/DetourCrowd-d.lib"
  )

list(APPEND _cmake_import_check_targets RecastNavigation::DetourCrowd )
list(APPEND _cmake_import_check_files_for_RecastNavigation::DetourCrowd "${_IMPORT_PREFIX}/debug/lib/DetourCrowd-d.lib" )

# Import target "RecastNavigation::DetourTileCache" for configuration "Debug"
set_property(TARGET RecastNavigation::DetourTileCache APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(RecastNavigation::DetourTileCache PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "CXX"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/debug/lib/DetourTileCache-d.lib"
  )

list(APPEND _cmake_import_check_targets RecastNavigation::DetourTileCache )
list(APPEND _cmake_import_check_files_for_RecastNavigation::DetourTileCache "${_IMPORT_PREFIX}/debug/lib/DetourTileCache-d.lib" )

# Import target "RecastNavigation::Recast" for configuration "Debug"
set_property(TARGET RecastNavigation::Recast APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(RecastNavigation::Recast PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "CXX"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/debug/lib/Recast-d.lib"
  )

list(APPEND _cmake_import_check_targets RecastNavigation::Recast )
list(APPEND _cmake_import_check_files_for_RecastNavigation::Recast "${_IMPORT_PREFIX}/debug/lib/Recast-d.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
