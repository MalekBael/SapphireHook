# Module & Class Reference

This is a living reference of the main modules/classes in the SapphireHook codebase.

It’s intentionally “breadth-first”: the goal is to help a new contributor quickly locate the correct file/type, understand its purpose, and then drill into code.

## UI Modules (`src/Modules/`)

Each module is a self-contained feature window/tool in the ImGui overlay.

- `GMCommandsModule` (`GMCommandsModule.*`)
  - Sends GM/server commands via packet injection.

- `DebugCommandsModule` (`DebugCommandsModule.*`)
  - Debug command helpers and developer-facing utilities.

- `CommandInterface` (`CommandInterface.*`)
  - In-overlay command entry/dispatch UI.

- `CharacterEdit` (`CharacterEdit.*`)
  - Work-in-progress character modification UI.

- `Weather` (`Weather.*`)
  - Weather override UI.

- `MemoryViewerModule` (`MemoryViewerModule.*`)
  - Memory inspection UI (hex view, typed view, navigation).

- `FunctionCallMonitor` (`FunctionCallMonitor.*`)
  - Function tracing/call monitoring UI.

- `LuaGameScriptModule` (`LuaGameScriptModule.*`)
  - Lua script discovery/search UI.

- `NetDiagnosticsModule` (`NetDiagnosticsModule.*`)
  - Network diagnostics and operational visibility.

- `ZoneLayoutViewerModule` (`ZoneLayoutViewerModule.*`)
  - Visualizes zone layout data (ties into `ZoneLayoutManager`).

- `CollisionOverlayModule` (`CollisionOverlayModule.*`)
  - Renders collision overlays and related debug visuals.

- `DebugVisualsModule` (`DebugVisualsModule.*`)
  - Visual debugging tools; integrates with debug visual server/types.

- `SettingsModule` (`SettingsModule.*`)
  - Settings UI for toggles and configuration.

## UI Framework (`src/UI/`)

- `UIModule` (`UIModule.h`)
  - Base interface for all UI modules.
  - Provides name/display name and window open/close behavior.

- `UIManager` (`UIManager.h/.cpp`)
  - Owns module instances.
  - Renders the main menu and calls module render functions.

- `ImGuiOverlay` (`imgui_overlay.h/.cpp`)
  - Overlay implementation and integration with the game’s render loop.

## Core Services (`src/Core/`)

- `ServiceManager` (`ServiceManager.h`)
  - Dependency injection/service locator.
  - Prefer `ServiceManager::Get<T>()` over global singletons.

- `SafeMemory` (`SafeMemory.h/.cpp`)
  - Central memory validation helpers.
  - Used by tools that read process memory (scanners, extractors, etc.).

- `SignatureDatabase` (`SignatureDatabase.h/.cpp`)
  - Signature storage, versioning, and lookup.

- `FunctionDatabase` (`FunctionDatabase.*`)
  - Stores discovered functions and metadata for later analysis.

- `FunctionAnalyzer` (`FunctionAnalyzer.*`)
  - Higher-level analysis utilities over discovered functions.

- `CommandInvoker` (`CommandInvoker.*`)
  - Command dispatch layer used by modules that expose commands.

- `SettingsManager` (`SettingsManager.*`)
  - Loads/saves configuration.

- `ResourceLoader` (`ResourceLoader.*`)
  - Loads resources shipped with the project (including `data/` contents copied to output).

- `GameDataLookup` (`GameDataLookup.*`)
  - Lookup helpers for game-specific data tables (actions, items, territories, etc.).

- `ZoneLayoutManager` (`ZoneLayoutManager.*`)
  - Loads/manages zone layout data for visualization.

- `PacketInjector` (`PacketInjector.*`)
  - Packet injection and socket-learning utilities.
  - Used primarily by modules that send actions/commands.

- `RttiVTableFinder` (`RttiVTableFinder.*`)
  - RTTI/vtable tooling used in analysis workflows.

## Hooking (`src/Hooking/`)

- `HookManager` (`hook_manager.*`)
  - MinHook wrapper and hook lifecycle manager.

- `hook_factory_impl` (`hook_factory_impl.h`)
  - Helper templates/utilities for constructing hooks.

- `dynamic_hook_engine` (`dynamic_hook_engine.*`)
  - Dynamic hook management/dispatch support.

- `lua_hook` (`lua_hook.*`)
  - Lua-related hooks.

- `MatrixCaptureHooks` (`MatrixCaptureHooks.*`)
  - Hooks used for matrix/projection capture tooling.

## Network & Monitor

- `NetworkMonitor` (`src/Monitor/NetworkMonitor.*`)
  - Captures network packets and buffers them for UI display.

- `NetworkMonitorHelper` (`src/Monitor/NetworkMonitorHelper.*`)
  - Supporting helpers for capture/display pipeline.

- `PacketDecoder` (`src/Network/PacketDecoder.*`)
  - Decoding/rendering logic for registered packet types.

- `PacketRegistration` (`src/Network/PacketRegistration.*`)
  - Registers packet decoders by channel/opcode.

- `OpcodeNames` (`src/Network/OpcodeNames.*`)
  - Human-readable names for opcodes.

- `GameEnums` (`src/Network/GameEnums.*`)
  - Shared enums used by decoding and tools.

## Tools & Analysis

These are reusable capabilities used by modules.

- `MemoryScanner` (`src/Tools/MemoryScanner.*`)
  - Memory scanning utilities (patterns, strings, xrefs).

- `StringXrefAnalyzer` (`src/Tools/StringXrefAnalyzer.*`)
  - Finds references to strings in game code.

- `LiveTraceMonitor` (`src/Tools/LiveTraceMonitor.*`)
  - Live trace capture and display.

- `GameCameraExtractor` (`src/Tools/GameCameraExtractor.*`)
  - Camera extraction tooling.

- `SqPackReader` (`src/Tools/SqPackReader.*`)
  - Work-in-progress SqPack exploration.

- `CollisionMeshLoader` / `NavMeshLoader` (`src/Tools/*`)
  - Loads collision/navmesh data for visualization/overlay.

- `PatternScanner` (`src/Analysis/PatternScanner.*`)
  - Signature/pattern scanning logic.

- `FunctionScanner` (`src/Analysis/FunctionScanner.*`)
  - Function discovery using patterns/scanning.

## Where to Add Documentation Next

If you add a new system, please update this file by:

- Adding the new type under the correct section.
- Including the owning folder + primary `*.h/*.cpp` filenames.
- Describing the responsibility in 1–3 bullet points.
