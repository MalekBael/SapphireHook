#pragma once

#include "PacketDecoder.h"
#include <functional>
#include <string>
#include <sstream>
#include <array>
#include <span>

// Helper macro to simplify registration
#define REGISTER_PACKET(connType, outgoing, opcode, PacketType, ...) \
    PacketDecoderRegistry::Instance().RegisterDecoder(               \
        static_cast<uint16_t>(connType),                             \
        static_cast<bool>(outgoing),                                 \
        static_cast<uint16_t>(opcode),                               \
        StructDecoder<PacketType>::Create(__VA_ARGS__))

#define FIELD(name, ...) \
    [](const auto* pkt, auto rowKV) { rowKV(name, __VA_ARGS__); }

// Convenience wrappers (unused here but kept for completeness)
#define FIELD_MEMBER(PacketType, member) ::PacketDecoding::MakeField<PacketType>(#member, &PacketType::member)
#define FIELD_ARRAY(PacketType, member)  ::PacketDecoding::MakeArrayField(#member, &PacketType::member)

// Generic decoder for packets without specific structure definitions
#define REGISTER_GENERIC_PACKET(connType, outgoing, opcode, name)                     \
    PacketDecoderRegistry::Instance().RegisterDecoder(                                \
        static_cast<uint16_t>(connType), static_cast<bool>(outgoing),                 \
        static_cast<uint16_t>(opcode),                                                \
        [](const uint8_t* payload, size_t payloadLen,                                 \
           std::function<void(const char*, const std::string&)> rowKV) {              \
            rowKV("Packet Type", name);                                               \
            rowKV("Payload Size", std::to_string(payloadLen) + " bytes");             \
            if (payloadLen >= 4) {                                                    \
                uint32_t first32 = *reinterpret_cast<const uint32_t*>(payload);       \
                rowKV("First 4 bytes", FormatHex(first32));                           \
            }                                                                         \
            if (payloadLen >= 8) {                                                    \
                uint32_t second32 = *reinterpret_cast<const uint32_t*>(payload + 4);  \
                rowKV("Next 4 bytes", FormatHex(second32));                           \
            }                                                                         \
            if (payloadLen >= 12) {                                                   \
                uint32_t third32 = *reinterpret_cast<const uint32_t*>(payload + 8);   \
                rowKV("Third 4 bytes", FormatHex(third32));                           \
            }                                                                         \
        })

// Descriptor helpers (still usable if you want descriptor-based decoding)
#define PACKET_STRUCT(name, FIELD_LIST)                                                \
    struct name {                                                                      \
        FIELD_LIST(PACKET_STRUCT_FIELD_MEMBER)                                         \
    };                                                                                 \
    inline constexpr auto GetPacketFields(name*) {                                     \
        return std::to_array({ FIELD_LIST(PACKET_STRUCT_FIELD_DESCRIPTOR(name,)) });   \
    }

#define PACKET_STRUCT_FIELD_MEMBER(type, member) type member;
#define PACKET_STRUCT_FIELD_DESCRIPTOR(PacketType, type, member)                       \
    ::PacketDecoding::FieldDescriptor<PacketType>::Make(#member, &PacketType::member)

#define DECLARE_PACKET_FIELDS(PacketType, ...)                                         \
    inline const auto& GetPacketFieldEmitters(PacketType*) {                           \
        static const std::array emitters{ __VA_ARGS__ };                               \
        return emitters;                                                               \
    }

#define REGISTER_STRUCT_PACKET(connectionType, outgoing, opcode, PacketType)           \
    REGISTER_PACKET(connectionType, outgoing, opcode, PacketType,                      \
        ::PacketDecoding::MakeStructDecoder<PacketType>(                               \
            GetPacketFieldEmitters(static_cast<PacketType*>(nullptr))))

#define STRUCT_FIELD(PacketType, member) ::PacketDecoding::MakeField<PacketType>(#member, &PacketType::member)