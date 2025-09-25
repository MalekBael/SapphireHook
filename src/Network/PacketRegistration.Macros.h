#pragma once

#include "PacketDecoder.h"
#include <functional>
#include <string>

// Helper macro to simplify registration
#define REGISTER_PACKET(connType, outgoing, opcode, PacketType, ...) \
    PacketDecoderRegistry::Instance().RegisterDecoder(connType, outgoing, opcode, \
        StructDecoder<PacketType>::Create(__VA_ARGS__))

#define FIELD(name, ...) \
    [](const auto* pkt, auto rowKV) { rowKV(name, __VA_ARGS__); }

// Generic decoder for packets without specific structure definitions
#define REGISTER_GENERIC_PACKET(connType, outgoing, opcode, name) \
    PacketDecoderRegistry::Instance().RegisterDecoder(connType, outgoing, opcode, \
        [](const uint8_t* payload, size_t payloadLen, \
           std::function<void(const char*, const std::string&)> rowKV) { \
            rowKV("Packet Type", name); \
            rowKV("Payload Size", std::to_string(payloadLen) + " bytes"); \
            if (payloadLen >= 4) { \
                uint32_t first32 = *reinterpret_cast<const uint32_t*>(payload); \
                rowKV("First 4 bytes", FormatHex(first32)); \
            } \
            if (payloadLen >= 8) { \
                uint32_t second32 = *reinterpret_cast<const uint32_t*>(payload + 4); \
                rowKV("Next 4 bytes", FormatHex(second32)); \
            } \
            if (payloadLen >= 12) { \
                uint32_t third32 = *reinterpret_cast<const uint32_t*>(payload + 8); \
                rowKV("Third 4 bytes", FormatHex(third32)); \
            } \
        })