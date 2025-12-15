# Architecture Overview

This document explains how SapphireHook is organized, how it initializes, and how the major subsystems interact.

## High-Level Mental Model

SapphireHook is a native C++20 DLL injected into the FFXIV process. Once loaded, it:

1. Initializes core services (logging, settings, signature database, etc.).
2. Sets up hooks (MinHook wrapper + hook manager).
3. Starts monitoring/decoding subsystems (notably network capture + packet decoding).
4. Presents an in-game ImGui overlay with a set of pluggable UI modules.

## Directory Map

- `src/Entry/`
  - DLL entry point and startup/shutdown sequence.
- `src/Core/`
  - Core services and “shared infrastructure” used by most features.
- `src/Hooking/`
  - Hook lifecycle management and hook helpers.
- `src/Monitor/`
  - Network capture/monitoring pipeline (ring buffers, event dispatch).
- `src/Network/`
  - Packet decoding + opcode naming + registration of decoders.
- `src/ProtocolHandlers/`
  - Packet structure definitions (Zone/Chat/Lobby) and shared protocol types.
- `src/UI/`
  - ImGui overlay plumbing and the UI module host.
- `src/Modules/`
  - Feature modules (each module is typically a window/tool in the overlay).
- `src/Tools/` and `src/Analysis/`
  - “Power tools” used by modules: scanners, extractors, trace monitors, etc.
- `src/Logger/`
  - Logging infrastructure (categories, file output).

## Initialization & Lifetime

The exact ordering lives in `src/Entry/dllmain.cpp`, but conceptually:

- Startup
  - Configure logging output directory.
  - Load settings (JSON) and data files (`data/` is copied to the output folder during build).
  - Register services into the `ServiceManager` (dependency injection).
  - Initialize hooking layer (MinHook wrapper) and install hooks.
  - Initialize UI overlay + register default UI modules.

- Runtime
  - Hooks feed events into monitors/decoders.
  - The overlay renders each frame; modules contribute menu items and windows.

- Shutdown
  - Uninstall hooks.
  - Stop worker threads and flush logs.
  - Release resources.

## Core Services

Commonly-used shared services:

- `ServiceManager` (`src/Core/ServiceManager.h`)
  - Simple DI/service locator.
  - Services are registered during startup and retrieved by type.

- `SafeMemory` (`src/Core/SafeMemory.h/.cpp`)
  - Centralizes “safe to read/write?” checks for memory access.
  - Prefer using these helpers (or wrappers built on them) over ad-hoc pointer checks.

- `SignatureDatabase` (`src/Core/SignatureDatabase.*`)
  - Stores and manages signature patterns across game versions.

- `SettingsManager` (`src/Core/SettingsManager.*`)
  - JSON-based settings, persisted across runs.

## Hooking Layer

- `HookManager` (`src/Hooking/hook_manager.*`)
  - Wraps MinHook lifecycle and tracks installed hooks.

- `dynamic_hook_engine` (`src/Hooking/dynamic_hook_engine.*`)
  - Higher-level dynamic hooking utilities.

## Network Monitoring & Packet Decoding

- Capture pipeline: `src/Monitor/`
  - Receives raw traffic, stores it in a ring buffer, and exposes it to UI.

- Decode pipeline: `src/Network/`
  - `PacketDecoder` understands how to render packet fields.
  - `PacketRegistration.*.cpp` registers decoders by opcode/channel.
  - `OpcodeNames` provides human-friendly labels.

- Protocol structures: `src/ProtocolHandlers/`
  - Contains the packet struct definitions used by decoders.

## UI System

- `UIManager` and `UIModule` (`src/UI/*`)
  - `UIManager` owns module instances, draws the menu, and calls into each module.
  - Each module implements a consistent interface: internal ID, display name, menu checkbox, and window rendering.

- The overlay implementation is in `src/UI/imgui_overlay.*`.

## Extending the System

- Add a new UI tool/window: implement a new `UIModule` under `src/Modules/` and register it with the UI manager.
- Add a new packet decoder: define a struct under `src/ProtocolHandlers/` and register a decoder in the relevant `PacketRegistration.*.cpp`.
- Add a new scanning/analysis feature: implement under `src/Tools/` (UI-facing helpers) or `src/Analysis/` (core scanning logic) and expose it via a module.
