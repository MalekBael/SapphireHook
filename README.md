# SapphireHook

A modern C++20 native hook library for Final Fantasy XIV, designed with safety-first principles and clean architecture.

## Overview

SapphireHook aims to be an  reverse engineering and analysis toolkit for Final Fantasy XIV. It provides runtime inspection, memory analysis, network monitoring, and game modification capabilities with a focus on safety and maintainability.

### Key Features

#### Network Analysis
- **181+ Packet Decoders**: Coverage of FFXIV's zone protocol
- **Real-time Packet Monitor**: Live capture with filtering, search, and export capabilities
- **Template Family Support**: Efficient handling of variable-length array packets

#### Memory & Code Analysis
- **Function Scanner**: Automated signature scanning with caching and pattern matching
- **Memory Viewer**: Live memory inspection with hex editor and data type visualization
- **Live Trace Monitor**: Real-time function call tracing with call stack analysis
- **String Cross-Reference Analyzer**: Find all references to strings in game code
- **SqPack Reader**: Analyze game data files **Work in progress**

#### Game Modification
- **GM Command Interface**: Execute server commands via packet injection
- **Character Editor**: Modify stats, appearance, position, and inventory **Work in progress**
- **Weather Control**: Override weather 
- **Debug Commands**: Sapphire debug commands via packet injection

#### Developer Tools
- **Lua Script Scanner**: Analyze Lua scripts **Work in progress**
- **Signature Database**: Organize and manage function signatures across game versions
- **Configuration System**: JSON-based settings 

## Architecture

### Core Components

- **Network Monitor** (`src/Monitor/`): Real-time packet capture and analysis with filtering
- **Packet Decoders** (`src/Network/`): FieldBuilder pattern for declarative packet parsing
- **Protocol Handlers** (`src/ProtocolHandlers/`): Struct definitions with compile-time metadata
- **Hooking Layer** (`src/Hooking/`): MinHook-based function interception with lifecycle management
- **UI Modules** (`src/Modules/`): Pluggable ImGui-based tools and editors
- **Analysis Tools** (`src/Analysis/`, `src/Tools/`): Memory scanning, function analysis, and code tracing
- **ImGui Overlay** (`src/UI/`): DirectX 11 integration with docking and multi-window support

### Feature Modules

**GMCommandsModule**: Send GM/server commands
- Execute game master commands via packet injection

**CharacterEditModule**: Modify character data
- Appearance: Sex / Race (Race is bugged currently)

**MemoryViewerModule**: Inspect process memory
- Hex editor with data type overlay (int8/16/32/64, float, etc.)
- Memory region navigation (code, data, heap, stack)
- Export to binary/text

**FunctionCallMonitor**: Trace function execution
- Real-time call stack capture
- Filter by module, function name, or address
- Performance profiling (call count, timing)
- Integration with LiveTraceMonitor for deep inspection

**MemoryScanner**: Find functions and patterns
- Signature scanning with wildcards
- String and cross-reference search
- Automatic signature database management
- Export results to JSON

**LuaGameScriptModule**: Lua script analysis
- Search across all loaded scripts

**WeatherModule**: Environmental control
- Override current weather



### Dependencies
- **MinHook**: Function hooking
- **ImGui**: UI framework
- **Capstone**: Disassembly engine
- **spdlog**: Logging with std::format
- **nlohmann/json**: Configuration and data serialization
- **zlib**: Compression support

## Usage

### Injection
```powershell
# Using the injector
.\SapphireHookInjector.exe 

# Or use manual DLL injection with your preferred tool
```

### UI Controls

**Global Hotkeys**:
- **Ins**: Toggle main menu overlay

**Packet Monitor**:
- **Filter**: Search by packet name, opcode, or field content
- **Pause/Resume**: Freeze capture for detailed analysis
- **Clear**: Empty packet buffer
- **Export**: Save selected packets to JSON
- **Auto-scroll**: Follow latest packets in real-time

**Memory Viewer**:
- **Address bar**: Jump to specific memory location
- **Data type**: View as bytes, integers, floats, or strings
- **Follow pointer**: Navigate pointer chains
- **Bookmarks**: Save frequently-accessed addresses

**Function Tracer**:
- **Module filter**: Trace only specific DLLs
- **Name filter**: Regex pattern for function names
- **Call depth**: Limit stack trace depth
- **Recording**: Start/stop trace capture



### Project Structure

```
src/
├── Analysis/          # Function analysis and scanning
├── Core/              # Signature database, JSON utilities
├── Entry/             # DLL entry point and initialization
├── Helper/            # Utility functions and helpers
├── Hooking/           # MinHook wrapper and hook management
├── Logger/            # Logging infrastructure
├── Modules/           # Feature modules (GM, Character Edit, etc.)
├── Monitor/           # Network packet monitoring
├── Network/           # Packet decoders and registration
├── ProtocolHandlers/  # Packet struct definitions
├── Tools/             # Memory scanner, Lua analyzer, etc.
└── UI/                # ImGui overlay and UI manager
```


### Key Principles
1. **Memory Safety**: All memory access validated, RAII everywhere
2. **Type Safety**: Compile-time checking via concepts and templates
3. **No Code Duplication**: Generic solutions over copy-paste
4. **Defensive Programming**: Bounds checking, size validation, error handling
5. **Modern C++**: Leverage C++20/23 features for cleaner code

## Roadmap

### Short Term
- [ ] Complete remaining 13 packet decoders (opcode discovery needed)
- [ ] Add unit tests for critical components
- [ ] Performance profiling for packet decoding
- [ ] Configuration UI improvements

### Medium Term
- [ ] Scripting API (Lua/Python) for automation
- [ ] Packet replay and simulation
- [ ] Advanced memory editing (freeze values, code injection)


## Disclaimer

This project is for educational and research purposes.
