cmake_minimum_required(VERSION 3.22)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "In-tree builds are not supported. Run CMake from a separate directory: cmake -B build")
endif()

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake")
        set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake"
            CACHE STRING "Vcpkg toolchain file")
    endif()
endif()

set(VCPKG_TARGET_TRIPLET "x64-windows" CACHE STRING "vcpkg triplet")

project(SapphireHook VERSION 1.0.0 LANGUAGES CXX C)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 17)

if(MSVC)
    add_compile_options(
        /bigobj               
        /utf-8                
        /FS                  
        /Gy                
        /Gw                 
        /sdl-                   
        /permissive-        
    )
    
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

find_package(capstone CONFIG REQUIRED)
find_package(ZLIB REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(glm CONFIG REQUIRED)
find_package(recastnavigation CONFIG REQUIRED)
find_package(unofficial-sqlite3 CONFIG REQUIRED)
find_package(magic_enum CONFIG REQUIRED)
find_package(xxHash CONFIG REQUIRED)
find_package(minhook CONFIG REQUIRED)

set(NUGET_NLOHMANN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/packages/nlohmann.json.3.12.0/build/native")
set(NUGET_SPDLOG_DIR "${CMAKE_CURRENT_SOURCE_DIR}/packages/native.spdlog-stdfmt.1.12.0/build/native")

add_compile_definitions(SPDLOG_USE_STD_FORMAT)

set(IMGUI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/imgui")
set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/TextEditor.cpp
    ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx9.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx10.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp
    ${IMGUI_DIR}/backends/imgui_impl_dx12.cpp
    ${IMGUI_DIR}/misc/cpp/imgui_stdlib.cpp
    ${IMGUI_DIR}/misc/fonts/binary_to_compressed_c.cpp
)

set(IMPLOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/implot")
set(IMPLOT_SOURCES
    ${IMPLOT_DIR}/implot.cpp
    ${IMPLOT_DIR}/implot_items.cpp
)

set(IMGUIFD_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/ImGuiFD/ImGuiFD.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/ImGuiFD/ImGuiFDNative.cpp
)

set(HEX_EDITOR_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/hex_editor/imgui_hex.cpp
)

set(MINIZ_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/miniz/miniz.c
)

set(DATREADER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/vendor/datReader")
set(DATREADER_SOURCES
    ${DATREADER_DIR}/bparse.cpp
    ${DATREADER_DIR}/conv.cpp
    ${DATREADER_DIR}/crc32.cpp
    ${DATREADER_DIR}/Dat.cpp
    ${DATREADER_DIR}/DatCat.cpp
    ${DATREADER_DIR}/DatZlib.cpp
    ${DATREADER_DIR}/Exd.cpp
    ${DATREADER_DIR}/ExdCat.cpp
    ${DATREADER_DIR}/ExdData.cpp
    ${DATREADER_DIR}/Exh.cpp
    ${DATREADER_DIR}/File.cpp
    ${DATREADER_DIR}/GameData.cpp
    ${DATREADER_DIR}/Index.cpp
    ${DATREADER_DIR}/SqPack.cpp
    ${DATREADER_DIR}/stream.cpp
)

set(SAPPHIREHOOK_SOURCES
    src/Entry/dllmain.cpp
    
    src/Analysis/FunctionScanner.cpp
    src/Analysis/PatternScanner.cpp
    src/Analysis/ScanEnrichment.cpp
    
    src/Core/CommandInvoker.cpp
    src/Core/FunctionAnalyzer.cpp
    src/Core/FunctionDatabase.cpp
    src/Core/GameDataLookup.cpp
    src/Core/NavMeshManager.cpp
    src/Core/PacketInjector.cpp
    src/Core/ResourceLoader.cpp
    src/Core/RttiVTableFinder.cpp
    src/Core/SafeMemory.cpp
    src/Core/SettingsManager.cpp
    src/Core/SignatureDatabase.cpp
    src/Core/SimpleJSON.cpp
    src/Core/TerritoryScanner.cpp
    src/Core/WorldOverlayManager.cpp
    src/Core/ZoneLayoutManager.cpp
    
    src/Helper/CapstoneWrapper.cpp
    src/Helper/WindowsAPIWrapper.cpp
    
    src/Hooking/dynamic_hook_engine.cpp
    src/Hooking/hook_manager.cpp
    src/Hooking/HookParameterDecoder.cpp
    src/Hooking/lua_hook.cpp
    src/Hooking/MatrixCaptureHooks.cpp
    src/Hooking/NetworkHooks.cpp
    
    src/Logger/Logger.cpp
    
    src/Modules/CharacterEdit.cpp
    src/Modules/CollisionOverlayModule.cpp
    src/Modules/CommandInterface.cpp
    src/Modules/DebugCommandsModule.cpp
    src/Modules/DebugVisualsModule.cpp
    src/Modules/FunctionCallMonitor.cpp
    src/Modules/GMCommandsModule.cpp
    src/Modules/LuaGameScriptModule.cpp
    src/Modules/MemoryViewerModule.cpp
    src/Modules/NetDiagnosticsModule.cpp
    src/Modules/RetainerCacheInspectorModule.cpp
    src/Modules/NetworkHooksModule.cpp
    src/Modules/PacketSenderModule.cpp
    src/Modules/SettingsModule.cpp
    src/Modules/SignatureScannerModule.cpp
    src/Modules/Weather.cpp
    src/Modules/WorldOverlayModule.cpp
    src/Modules/ZoneLayoutViewerModule.cpp
    
    src/Monitor/NetworkMonitor.cpp
    src/Monitor/NetworkMonitorHelper.cpp
    
    src/Network/GameEnums.cpp
    src/Network/OpcodeNames.cpp
    src/Network/PacketDatabase.cpp
    src/Network/PacketDecoder.cpp
    src/Network/PacketRegistration.cpp
    src/Network/PacketRegistration.Chat.cpp
    src/Network/PacketRegistration.Generic.cpp
    src/Network/PacketRegistration.Init.cpp
    src/Network/PacketRegistration.Lobby.cpp
    src/Network/PacketRegistration.Zone.cpp
    
    src/Tools/CollisionMeshLoader.cpp
    src/Tools/D3D11MatrixCapture.cpp
    src/Tools/DebugRenderer.cpp
    src/Tools/DebugVisualServer.cpp
    src/Tools/GameCameraExtractor.cpp
    src/Tools/LiveTraceMonitor.cpp
    src/Tools/LuaGameScriptScanner.cpp
    src/Tools/MemoryScanner.cpp
    src/Tools/NavMeshLoader.cpp
    src/Tools/SqPackReader.cpp
    src/Tools/StringXrefAnalyzer.cpp
    src/Tools/ViewProjectionHook.cpp
    
    src/UI/imgui_overlay.cpp
    src/UI/UIManager.cpp
)

add_library(SapphireHookDLL SHARED
    ${SAPPHIREHOOK_SOURCES}
    ${IMGUI_SOURCES}
    ${IMPLOT_SOURCES}
    ${IMGUIFD_SOURCES}
    ${HEX_EDITOR_SOURCES}
    ${MINIZ_SOURCES}
    ${DATREADER_SOURCES}
    resources/Hashlist.rc
)

set_target_properties(SapphireHookDLL PROPERTIES
    OUTPUT_NAME "SapphireHookDLL"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

target_include_directories(SapphireHookDLL PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Core
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Modules
    ${CMAKE_CURRENT_SOURCE_DIR}/src/UI
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Hooking
    ${CMAKE_CURRENT_SOURCE_DIR}/data
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${IMPLOT_DIR}
    ${DATREADER_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/minhook
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/miniz
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/hex_editor
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/ImGuiFD
    ${NUGET_NLOHMANN_DIR}/include
    ${NUGET_SPDLOG_DIR}/include
)

target_compile_definitions(SapphireHookDLL PRIVATE
    SAPPHIREHOOK_ENABLE_ZLIB
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    $<$<CONFIG:Release>:NDEBUG>
)

target_link_libraries(SapphireHookDLL PRIVATE
    capstone::capstone
    ZLIB::ZLIB
    fmt::fmt
    glm::glm
    RecastNavigation::Detour
    RecastNavigation::Recast
    RecastNavigation::DebugUtils
    RecastNavigation::DetourCrowd
    RecastNavigation::DetourTileCache
    unofficial::sqlite3::sqlite3
    magic_enum::magic_enum
    xxHash::xxhash
    minhook::minhook
    
    kernel32
    user32
    gdi32
    winspool
    comdlg32
    advapi32
    shell32
    ole32
    oleaut32
    uuid
    odbc32
    odbccp32
    d3d11
    dxgi
)

add_custom_command(TARGET SapphireHookDLL POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_CURRENT_SOURCE_DIR}/data"
        "$<TARGET_FILE_DIR:SapphireHookDLL>/data"
    COMMENT "Copying data folder to output directory"
)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/SapphireHookInjector/injector.cpp")
    add_executable(SapphireHookInjector
        SapphireHookInjector/injector.cpp
    )
    
    set_target_properties(SapphireHookInjector PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    
    target_link_libraries(SapphireHookInjector PRIVATE
        kernel32
        user32
    )
endif()

source_group(TREE "${CMAKE_CURRENT_SOURCE_DIR}/src" PREFIX "Source Files" FILES ${SAPPHIREHOOK_SOURCES})
source_group("Vendor/ImGui" FILES ${IMGUI_SOURCES})
source_group("Vendor/ImPlot" FILES ${IMPLOT_SOURCES})
source_group("Vendor/ImGuiFD" FILES ${IMGUIFD_SOURCES})
source_group("Vendor/HexEditor" FILES ${HEX_EDITOR_SOURCES})
source_group("Vendor/miniz" FILES ${MINIZ_SOURCES})
source_group("Vendor/datReader" FILES ${DATREADER_SOURCES})

message(STATUS "SapphireHook configured successfully")
message(STATUS "  Output: ${CMAKE_BINARY_DIR}/bin/SapphireHookDLL.dll")
