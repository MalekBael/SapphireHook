#pragma once
#include <cstdint>
#include <vector>

// Lightweight shared structs used by NetworkMonitor and helper validation logic.
// (Extracted from NetworkMonitor.cpp anonymous namespace to avoid duplicate / ambiguous definitions.)

struct ParsedPacket {
    bool     hdr_ok = false;
    uint64_t magic0 = 0, magic1 = 0, timestamp = 0;
    uint32_t size = 0;
    uint16_t connType = 0, segCount = 0;
    uint8_t  unknown20 = 0, isCompressed = 0;
    uint32_t unknown24 = 0;

    bool     seg_ok = false;
    uint32_t segSize = 0, src = 0, tgt = 0;
    uint16_t segType = 0, segPad = 0;

    bool     ipc_ok = false;
    uint16_t ipcReserved = 0, opcode = 0, ipcPad = 0, serverId = 0;
    uint32_t ipcTimestamp = 0, ipcPad1 = 0;
};

struct SegmentInfo {
    uint32_t offset = 0;
    uint32_t size = 0;
    uint32_t source = 0;
    uint32_t target = 0;
    uint16_t type = 0;
    uint16_t pad = 0;
    bool     hasIpc = false;
    uint16_t opcode = 0;
    uint16_t serverId = 0;
    uint32_t ipcTimestamp = 0;
};

struct SegmentView {
    const uint8_t* data = nullptr;
    size_t len = 0;
    bool compressed = false;
    bool inflated = false;
    std::vector<uint8_t> storage;
};