// NetworkMonitor.h
// Lock-free fixed-slot packet logger for use inside hooks (C++20)
// Requires: Dear ImGui (for DrawImGuiSimple), C++20
//
// Author: ChatGPT
// License: MIT (free to use/modify)
//
// -----------------------------
// Usage:
//
// In your hook (send/recv wrapper):
//     SafeHookLogger::Instance().TryEnqueueFromHook(buf, len, /*outgoing=*/true, connId);
//
// In your render loop (ImGui):
//     SafeHookLogger::Instance().DrawImGuiSimple();
//
// Or drain manually:
//     std::vector<HookPacket> batch;
//     SafeHookLogger::Instance().DrainToVector(batch);
//     // do custom UI or parsing
//
// -----------------------------

#pragma once

#include <atomic>
#include <array>
#include <vector>
#include <cstdint>
#include <chrono>
#include <string>
#include <cstring>
#include "../vendor/imgui/imgui.h"

// -------- Configuration --------
constexpr size_t SLOT_COUNT = 16384;  // number of preallocated slots
constexpr size_t SLOT_PAYLOAD_CAP = 8192;   // max bytes per slot
constexpr size_t UI_BATCH_CAP = 16384;  // max packets drained to UI per frame

// -------- Data structures --------
struct HookPacket {
    bool outgoing = false; // true = send, false = recv
    uint64_t connection_id = 0;
    std::chrono::system_clock::time_point ts;

    uint32_t len = 0;
    std::array<uint8_t, SLOT_PAYLOAD_CAP> buf;
};

// Internal slot state machine
enum class SlotState : uint8_t {
    EMPTY = 0,
    WRITING = 1,
    READY = 2,
    READING = 3
};

// -------- Logger singleton --------
class SafeHookLogger {
public:
    static SafeHookLogger& Instance();

    SafeHookLogger(const SafeHookLogger&) = delete;
    SafeHookLogger& operator=(const SafeHookLogger&) = delete;

    // Called from hook context (fast, non-blocking).
    // Copies up to SLOT_PAYLOAD_CAP bytes into a preallocated slot.
    // Returns true if enqueued, false if no slot available.
    bool TryEnqueueFromHook(const void* data, size_t len,
        bool outgoing, uint64_t conn_id = 0) noexcept;

    // Called from UI/main thread.
    // Moves all READY slots into `out` and marks them EMPTY again.
    void DrainToVector(std::vector<HookPacket>& out);

    // Convenience ImGui window (simple logger view).
    // For more control, call DrainToVector() and render your own UI.
    void DrawImGuiSimple();
    void DrawImGuiSimple(bool* p_open); // with close button controlled by caller

    // Embedded content (no Begin/End) for composing with other widgets
    void DrawImGuiEmbedded();

    // hex dump helper (exposed for utility rendering helpers)
    static void DumpHexAscii(const HookPacket& hp);

private:
    SafeHookLogger();
    ~SafeHookLogger();

    static inline constexpr size_t SLOT_PROBES = 8;

    struct Slot {
        std::atomic<uint8_t> state; // SlotState
        HookPacket packet;
    };
    alignas(64) Slot slots_[SLOT_COUNT];

    std::atomic<size_t> producer_fetch_{ 0 };
};
