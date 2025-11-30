#pragma once
#include <functional>
#include <unordered_map>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <algorithm>
#include <span>
#include <array>
#include <tuple>
#include <type_traits>
#include <chrono>

#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

#include "PacketRegistration.h" // for Net::ConnectionType
#include "OpcodeNames.h"        // updated signatures
#include "GameEnums.h"          // for enum lookups
#include "../Core/GameData.h"   // for item/action/etc lookups

namespace PacketDecoding {
    using RowEmitter = std::function<void(const char*, const std::string&)>;
    using DecoderFunc = std::function<void(const uint8_t* payload, size_t payloadLen,
        std::function<void(const char*, const std::string&)> rowKV)>;

// ============================================================================
// NEW: Direction & Packet Descriptor Infrastructure
// ============================================================================

    enum class Direction : uint8_t {
        ServerToClient = 0,
        ClientToServer = 1
    };

    enum class DecodePolicy : uint8_t {
        Fixed,          // Fixed size, use struct directly
        Variable,       // Variable size, needs custom decoder
        Special         // Special handling (like bidirectional opcodes)
    };

    struct PacketDescriptor {
        uint8_t channel;
        Direction direction;
        uint16_t opcode;
        const char* name;
        size_t structSize;
        DecodePolicy policy;
        DecoderFunc customDecoder;  // Only used for Variable/Special policies
        
        PacketDescriptor(
            uint8_t ch,
            Direction dir, 
            uint16_t op,
            const char* n,
            size_t size,
            DecodePolicy pol = DecodePolicy::Fixed,
            DecoderFunc decoder = nullptr)
            : channel(ch)
            , direction(dir)
            , opcode(op)
            , name(n)
            , structSize(size)
            , policy(pol)
            , customDecoder(std::move(decoder))
        {}
    };

    // Helper to create descriptors with automatic size calculation
    template<typename T>
    inline PacketDescriptor MakePacket(
        uint8_t channel,
        Direction dir,
        uint16_t opcode,
        const char* name,
        DecodePolicy policy = DecodePolicy::Fixed)
    {
        return PacketDescriptor(channel, dir, opcode, name, sizeof(T), policy);
    }

// ============================================================================
// NEW: Field Builder - Fluent API to replace FIELD macros
// ============================================================================

    class FieldBuilder {
    public:
        explicit FieldBuilder(RowEmitter emit) : m_emit(std::move(emit)) {}
        
        FieldBuilder& Field(std::string_view name, std::string value) {
            m_emit(std::string(name).c_str(), std::move(value));
            return *this;
        }
        
        FieldBuilder& Field(std::string_view name, uint64_t value) {
            return Field(name, std::to_string(value));
        }
        
        FieldBuilder& Field(std::string_view name, uint32_t value) {
            return Field(name, std::to_string(value));
        }
        
        FieldBuilder& Field(std::string_view name, int32_t value) {
            return Field(name, std::to_string(value));
        }
        
        FieldBuilder& Field(std::string_view name, uint16_t value) {
            return Field(name, std::to_string(value));
        }
        
        FieldBuilder& Field(std::string_view name, uint8_t value) {
            return Field(name, std::to_string(static_cast<unsigned>(value)));
        }
        
        // Add explicit float/double overloads to avoid ambiguity
        FieldBuilder& Field(std::string_view name, float value) {
            std::ostringstream os;
            os << std::fixed << std::setprecision(3) << value;
            return Field(name, os.str());
        }
        
        FieldBuilder& Field(std::string_view name, double value) {
            std::ostringstream os;
            os << std::fixed << std::setprecision(3) << value;
            return Field(name, os.str());
        }
        
        FieldBuilder& Hex(std::string_view name, uint64_t value) {
            std::ostringstream os;
            os << "0x" << std::hex << std::uppercase << value;
            return Field(name, os.str());
        }
        
        FieldBuilder& Position(std::string_view name, float x, float y, float z) {
            std::ostringstream os;
            os << "(" << x << ", " << y << ", " << z << ")";
            return Field(name, os.str());
        }
        
        FieldBuilder& Angle(std::string_view name, float radians) {
            float degrees = radians * (180.0f / 3.14159265f);
            std::ostringstream os;
            os << std::fixed << std::setprecision(1) << degrees << "°";
            return Field(name, os.str());
        }
        
        FieldBuilder& AngleDeg(std::string_view name, uint16_t value) {
            float degrees = value * 360.0f / 65535.0f;
            std::ostringstream os;
            os << std::fixed << std::setprecision(1) << degrees << "°";
            return Field(name, os.str());
        }
        
        FieldBuilder& String(std::string_view name, const char* str, size_t maxLen) {
            if (!str) return Field(name, "");
            size_t len = strnlen(str, maxLen);
            return Field(name, std::string(str, len));
        }
        
        template<typename T>
        FieldBuilder& Enum(std::string_view name, T value, const char* (*lookupFunc)(T)) {
            std::ostringstream os;
            os << static_cast<int>(value);
            if (auto* str = lookupFunc(value)) {
                os << " (" << str << ")";
            }
            return Field(name, os.str());
        }
        
        // ================================================================
        // GameEnums Helper Methods - Common enum lookups
        // ================================================================
        
        FieldBuilder& InventoryType(std::string_view name, uint16_t value) {
            auto inv = static_cast<GameEnums::InventoryType>(value);
            return Enum(name, inv, GameEnums::GetInventoryTypeName);
        }
        
        FieldBuilder& ObjKind(std::string_view name, uint8_t value) {
            auto kind = static_cast<GameEnums::ObjKind>(value);
            return Enum(name, kind, GameEnums::GetObjKindName);
        }
        
        FieldBuilder& ActionKind(std::string_view name, uint8_t value) {
            auto kind = static_cast<GameEnums::ActionKind>(value);
            return Enum(name, kind, GameEnums::GetActionKindName);
        }
        
        FieldBuilder& WarpType(std::string_view name, uint8_t value) {
            auto warp = static_cast<GameEnums::WarpType>(value);
            return Enum(name, warp, GameEnums::GetWarpTypeName);
        }
        
        FieldBuilder& ActorStatus(std::string_view name, uint8_t value) {
            auto status = static_cast<GameEnums::ActorStatus>(value);
            return Enum(name, status, GameEnums::GetActorStatusName);
        }
        
        FieldBuilder& ItemOperation(std::string_view name, uint8_t value) {
            auto op = static_cast<GameEnums::ItemOperationType>(value);
            return Enum(name, op, GameEnums::GetItemOperationTypeName);
        }
        
        FieldBuilder& GrandCompany(std::string_view name, uint8_t value) {
            auto gc = static_cast<GameEnums::GrandCompany>(value);
            return Enum(name, gc, GameEnums::GetGrandCompanyName);
        }
        
        FieldBuilder& GearSlot(std::string_view name, uint8_t value) {
            auto slot = static_cast<GameEnums::GearSetSlot>(value);
            return Enum(name, slot, GameEnums::GetGearSlotName);
        }
        
        FieldBuilder& HouseSize(std::string_view name, uint8_t value) {
            auto size = static_cast<GameEnums::HouseSize>(value);
            return Enum(name, size, GameEnums::GetHouseSizeName);
        }
        
        // Item lookup with GameData (catalog ID → item name)
        FieldBuilder& Item(std::string_view name, uint32_t catalogId) {
            return Field(name, GameData::FormatItem(catalogId));
        }
        
        // Action lookup with GameData
        FieldBuilder& Action(std::string_view name, uint32_t actionId) {
            return Field(name, GameData::FormatAction(actionId));
        }
        
        // Territory lookup with GameData
        FieldBuilder& Territory(std::string_view name, uint16_t territoryId) {
            return Field(name, GameData::FormatTerritory(territoryId));
        }
        
        // ClassJob lookup with GameData
        FieldBuilder& ClassJob(std::string_view name, uint8_t classJobId) {
            return Field(name, GameData::FormatClassJob(classJobId));
        }
        
        // Status effect lookup with GameData
        FieldBuilder& StatusEffect(std::string_view name, uint16_t statusId) {
            return Field(name, GameData::FormatStatus(statusId));
        }
        
        // Mount lookup with GameData
        FieldBuilder& Mount(std::string_view name, uint32_t mountId) {
            return Field(name, GameData::FormatMount(mountId));
        }
        
        // Emote lookup with GameData
        FieldBuilder& Emote(std::string_view name, uint32_t emoteId) {
            return Field(name, GameData::FormatEmote(emoteId));
        }
        
        // Quest lookup with GameData
        FieldBuilder& Quest(std::string_view name, uint32_t questId) {
            return Field(name, GameData::FormatQuest(questId));
        }
        
        // Minion lookup with GameData
        FieldBuilder& Minion(std::string_view name, uint32_t minionId) {
            return Field(name, GameData::FormatMinion(minionId));
        }

    private:
        RowEmitter m_emit;
    };

// ============================================================================
// Partial Field Builder - Supports decoding undersized packets
// Tracks struct base and payload length, marks out-of-bounds fields
// ============================================================================

    template<typename PacketT>
    class PartialFieldBuilder {
    public:
        PartialFieldBuilder(RowEmitter emit, const uint8_t* payload, size_t payloadLen)
            : m_emit(std::move(emit))
            , m_base(payload)
            , m_len(payloadLen)
            , m_structSize(sizeof(PacketT))
            , m_truncatedCount(0)
        {
            // Emit size warning at start if undersized
            if (payloadLen < sizeof(PacketT)) {
                std::ostringstream os;
                os << "Partial decode: have " << payloadLen << " of " << sizeof(PacketT) << " bytes";
                m_emit("warning", os.str());
            }
        }
        
        ~PartialFieldBuilder() {
            // Emit summary of truncated fields at end
            if (m_truncatedCount > 0) {
                std::ostringstream os;
                os << m_truncatedCount << " field(s) beyond payload boundary";
                m_emit("truncated", os.str());
            }
        }
        
        // Check if a field at given offset with given size is accessible
        [[nodiscard]] bool CanAccess(size_t offset, size_t size) const {
            return (offset + size) <= m_len;
        }
        
        // Get pointer to packet (for member access) - caller must check CanAccess first
        [[nodiscard]] const PacketT* Pkt() const {
            return reinterpret_cast<const PacketT*>(m_base);
        }
        
        // Check if a member is accessible using offsetof
        template<typename MemberT>
        [[nodiscard]] bool CanAccessMember(MemberT PacketT::*member) const {
            // Calculate offset of member within struct
            const PacketT* dummy = nullptr;
            const auto* memberPtr = &(dummy->*member);
            size_t offset = reinterpret_cast<size_t>(memberPtr);
            return CanAccess(offset, sizeof(MemberT));
        }
        
        // Field with automatic bounds checking using member pointer
        template<typename MemberT>
        PartialFieldBuilder& Field(std::string_view name, MemberT PacketT::*member) {
            size_t offset = OffsetOf(member);
            if (CanAccess(offset, sizeof(MemberT))) {
                const auto& value = Pkt()->*member;
                EmitValue(name, value);
            } else {
                m_emit(std::string(name).c_str(), "[TRUNCATED]");
                m_truncatedCount++;
            }
            return *this;
        }
        
        // Hex field with bounds checking
        template<typename MemberT>
        PartialFieldBuilder& Hex(std::string_view name, MemberT PacketT::*member) {
            size_t offset = OffsetOf(member);
            if (CanAccess(offset, sizeof(MemberT))) {
                const auto& value = Pkt()->*member;
                std::ostringstream os;
                os << "0x" << std::hex << std::uppercase << static_cast<uint64_t>(value);
                m_emit(std::string(name).c_str(), os.str());
            } else {
                m_emit(std::string(name).c_str(), "[TRUNCATED]");
                m_truncatedCount++;
            }
            return *this;
        }
        
        // String field with bounds checking
        template<size_t N>
        PartialFieldBuilder& String(std::string_view name, const char (PacketT::*member)[N]) {
            size_t offset = OffsetOf(member);
            if (CanAccess(offset, N)) {
                const char* str = &(Pkt()->*member)[0];
                size_t len = strnlen(str, N);
                m_emit(std::string(name).c_str(), std::string(str, len));
            } else if (CanAccess(offset, 1)) {
                // Partial string - show what we have
                size_t available = m_len - offset;
                const char* str = reinterpret_cast<const char*>(m_base + offset);
                size_t len = strnlen(str, available);
                std::string partial(str, len);
                partial += " [PARTIAL]";
                m_emit(std::string(name).c_str(), partial);
                m_truncatedCount++;
            } else {
                m_emit(std::string(name).c_str(), "[TRUNCATED]");
                m_truncatedCount++;
            }
            return *this;
        }
        
        // Enum field with bounds checking (member pointer version)
        template<typename MemberT, typename LookupFunc>
        PartialFieldBuilder& Enum(std::string_view name, MemberT PacketT::*member, LookupFunc lookupFunc) {
            size_t offset = OffsetOf(member);
            if (CanAccess(offset, sizeof(MemberT))) {
                const auto& value = Pkt()->*member;
                std::ostringstream os;
                os << static_cast<int>(value);
                if (auto* str = lookupFunc(value)) {
                    os << " (" << str << ")";
                }
                m_emit(std::string(name).c_str(), os.str());
            } else {
                m_emit(std::string(name).c_str(), "[TRUNCATED]");
                m_truncatedCount++;
            }
            return *this;
        }
        
        // Enum field with direct value (for when value is already accessed)
        template<typename T, typename LookupFunc>
        PartialFieldBuilder& Enum(std::string_view name, T value, LookupFunc lookupFunc) {
            std::ostringstream os;
            os << static_cast<int>(value);
            if (auto* str = lookupFunc(value)) {
                os << " (" << str << ")";
            }
            m_emit(std::string(name).c_str(), os.str());
            return *this;
        }
        
        // Direct value emit (for computed values, already-read data)
        PartialFieldBuilder& Field(std::string_view name, std::string value) {
            m_emit(std::string(name).c_str(), std::move(value));
            return *this;
        }
        
        PartialFieldBuilder& Field(std::string_view name, uint64_t value) {
            return Field(name, std::to_string(value));
        }
        
        PartialFieldBuilder& Field(std::string_view name, uint32_t value) {
            return Field(name, std::to_string(value));
        }
        
        PartialFieldBuilder& Field(std::string_view name, int32_t value) {
            return Field(name, std::to_string(value));
        }
        
        PartialFieldBuilder& Field(std::string_view name, uint16_t value) {
            return Field(name, std::to_string(value));
        }
        
        PartialFieldBuilder& Field(std::string_view name, uint8_t value) {
            return Field(name, std::to_string(static_cast<unsigned>(value)));
        }
        
        PartialFieldBuilder& Field(std::string_view name, float value) {
            std::ostringstream os;
            os << std::fixed << std::setprecision(3) << value;
            return Field(name, os.str());
        }
        
        PartialFieldBuilder& Field(std::string_view name, double value) {
            std::ostringstream os;
            os << std::fixed << std::setprecision(3) << value;
            return Field(name, os.str());
        }
        
        PartialFieldBuilder& Hex(std::string_view name, uint64_t value) {
            std::ostringstream os;
            os << "0x" << std::hex << std::uppercase << value;
            return Field(name, os.str());
        }
        
        // Position helper
        template<typename PosT>
        PartialFieldBuilder& Position(std::string_view name, PosT PacketT::*member) {
            size_t offset = OffsetOf(member);
            if (CanAccess(offset, sizeof(PosT))) {
                const auto& pos = Pkt()->*member;
                std::ostringstream os;
                os << std::fixed << std::setprecision(2) 
                   << "(" << pos.x << ", " << pos.y << ", " << pos.z << ")";
                m_emit(std::string(name).c_str(), os.str());
            } else {
                m_emit(std::string(name).c_str(), "[TRUNCATED]");
                m_truncatedCount++;
            }
            return *this;
        }
        
        // ================================================================
        // GameData Lookup Helpers - show human-readable names
        // ================================================================
        
        // Item lookup (member pointer version)
        template<typename MemberT>
        PartialFieldBuilder& Item(std::string_view name, MemberT PacketT::*member) {
            size_t offset = OffsetOf(member);
            if (CanAccess(offset, sizeof(MemberT))) {
                uint32_t id = static_cast<uint32_t>(Pkt()->*member);
                m_emit(std::string(name).c_str(), GameData::FormatItem(id));
            } else {
                m_emit(std::string(name).c_str(), "[TRUNCATED]");
                m_truncatedCount++;
            }
            return *this;
        }
        
        // Item lookup (direct value)
        PartialFieldBuilder& Item(std::string_view name, uint32_t itemId) {
            m_emit(std::string(name).c_str(), GameData::FormatItem(itemId));
            return *this;
        }
        
        // Action lookup (member pointer version)
        template<typename MemberT>
        PartialFieldBuilder& Action(std::string_view name, MemberT PacketT::*member) {
            size_t offset = OffsetOf(member);
            if (CanAccess(offset, sizeof(MemberT))) {
                uint32_t id = static_cast<uint32_t>(Pkt()->*member);
                m_emit(std::string(name).c_str(), GameData::FormatAction(id));
            } else {
                m_emit(std::string(name).c_str(), "[TRUNCATED]");
                m_truncatedCount++;
            }
            return *this;
        }
        
        // Action lookup (direct value)
        PartialFieldBuilder& Action(std::string_view name, uint32_t actionId) {
            m_emit(std::string(name).c_str(), GameData::FormatAction(actionId));
            return *this;
        }
        
        // Status effect lookup
        template<typename MemberT>
        PartialFieldBuilder& Status(std::string_view name, MemberT PacketT::*member) {
            size_t offset = OffsetOf(member);
            if (CanAccess(offset, sizeof(MemberT))) {
                uint32_t id = static_cast<uint32_t>(Pkt()->*member);
                m_emit(std::string(name).c_str(), GameData::FormatStatus(id));
            } else {
                m_emit(std::string(name).c_str(), "[TRUNCATED]");
                m_truncatedCount++;
            }
            return *this;
        }
        
        // Territory/Zone lookup
        template<typename MemberT>
        PartialFieldBuilder& Territory(std::string_view name, MemberT PacketT::*member) {
            size_t offset = OffsetOf(member);
            if (CanAccess(offset, sizeof(MemberT))) {
                uint32_t id = static_cast<uint32_t>(Pkt()->*member);
                m_emit(std::string(name).c_str(), GameData::FormatTerritory(id));
            } else {
                m_emit(std::string(name).c_str(), "[TRUNCATED]");
                m_truncatedCount++;
            }
            return *this;
        }
        
        // ClassJob lookup
        template<typename MemberT>
        PartialFieldBuilder& ClassJob(std::string_view name, MemberT PacketT::*member) {
            size_t offset = OffsetOf(member);
            if (CanAccess(offset, sizeof(MemberT))) {
                uint8_t id = static_cast<uint8_t>(Pkt()->*member);
                m_emit(std::string(name).c_str(), GameData::FormatClassJob(id));
            } else {
                m_emit(std::string(name).c_str(), "[TRUNCATED]");
                m_truncatedCount++;
            }
            return *this;
        }
        
        // ================================================================
        // Angle/Rotation Helpers - convert packed values to degrees
        // ================================================================
        
        // 16-bit packed angle (0-65535 maps to 0-360 degrees)
        template<typename MemberT>
        PartialFieldBuilder& Angle16(std::string_view name, MemberT PacketT::*member) {
            size_t offset = OffsetOf(member);
            if (CanAccess(offset, sizeof(MemberT))) {
                uint16_t raw = static_cast<uint16_t>(Pkt()->*member);
                float degrees = raw * 360.0f / 65535.0f;
                std::ostringstream os;
                os << std::fixed << std::setprecision(1) << degrees << "°";
                m_emit(std::string(name).c_str(), os.str());
            } else {
                m_emit(std::string(name).c_str(), "[TRUNCATED]");
                m_truncatedCount++;
            }
            return *this;
        }
        
        // 8-bit packed angle (0-255 maps to 0-360 degrees)  
        template<typename MemberT>
        PartialFieldBuilder& Angle8(std::string_view name, MemberT PacketT::*member) {
            size_t offset = OffsetOf(member);
            if (CanAccess(offset, sizeof(MemberT))) {
                uint8_t raw = static_cast<uint8_t>(Pkt()->*member);
                float degrees = raw * 360.0f / 255.0f;
                std::ostringstream os;
                os << std::fixed << std::setprecision(1) << degrees << "°";
                m_emit(std::string(name).c_str(), os.str());
            } else {
                m_emit(std::string(name).c_str(), "[TRUNCATED]");
                m_truncatedCount++;
            }
            return *this;
        }
        
        // Radians to degrees
        template<typename MemberT>
        PartialFieldBuilder& AngleRad(std::string_view name, MemberT PacketT::*member) {
            size_t offset = OffsetOf(member);
            if (CanAccess(offset, sizeof(MemberT))) {
                float radians = static_cast<float>(Pkt()->*member);
                float degrees = radians * (180.0f / 3.14159265f);
                std::ostringstream os;
                os << std::fixed << std::setprecision(1) << degrees << "°";
                m_emit(std::string(name).c_str(), os.str());
            } else {
                m_emit(std::string(name).c_str(), "[TRUNCATED]");
                m_truncatedCount++;
            }
            return *this;
        }
        
        // Direct angle values
        PartialFieldBuilder& Angle16(std::string_view name, uint16_t raw) {
            float degrees = raw * 360.0f / 65535.0f;
            std::ostringstream os;
            os << std::fixed << std::setprecision(1) << degrees << "°";
            m_emit(std::string(name).c_str(), os.str());
            return *this;
        }
        
        PartialFieldBuilder& Angle8(std::string_view name, uint8_t raw) {
            float degrees = raw * 360.0f / 255.0f;
            std::ostringstream os;
            os << std::fixed << std::setprecision(1) << degrees << "°";
            m_emit(std::string(name).c_str(), os.str());
            return *this;
        }
        
        // ================================================================
        // Mount/Minion/Emote Helpers
        // ================================================================
        
        template<typename MemberT>
        PartialFieldBuilder& Mount(std::string_view name, MemberT PacketT::*member) {
            size_t offset = OffsetOf(member);
            if (CanAccess(offset, sizeof(MemberT))) {
                uint32_t id = static_cast<uint32_t>(Pkt()->*member);
                m_emit(std::string(name).c_str(), GameData::FormatMount(id));
            } else {
                m_emit(std::string(name).c_str(), "[TRUNCATED]");
                m_truncatedCount++;
            }
            return *this;
        }
        
        template<typename MemberT>
        PartialFieldBuilder& Minion(std::string_view name, MemberT PacketT::*member) {
            size_t offset = OffsetOf(member);
            if (CanAccess(offset, sizeof(MemberT))) {
                uint32_t id = static_cast<uint32_t>(Pkt()->*member);
                m_emit(std::string(name).c_str(), GameData::FormatMinion(id));
            } else {
                m_emit(std::string(name).c_str(), "[TRUNCATED]");
                m_truncatedCount++;
            }
            return *this;
        }
        
        template<typename MemberT>
        PartialFieldBuilder& Emote(std::string_view name, MemberT PacketT::*member) {
            size_t offset = OffsetOf(member);
            if (CanAccess(offset, sizeof(MemberT))) {
                uint32_t id = static_cast<uint32_t>(Pkt()->*member);
                m_emit(std::string(name).c_str(), GameData::FormatEmote(id));
            } else {
                m_emit(std::string(name).c_str(), "[TRUNCATED]");
                m_truncatedCount++;
            }
            return *this;
        }
        
        template<typename MemberT>
        PartialFieldBuilder& Quest(std::string_view name, MemberT PacketT::*member) {
            size_t offset = OffsetOf(member);
            if (CanAccess(offset, sizeof(MemberT))) {
                uint32_t id = static_cast<uint32_t>(Pkt()->*member);
                m_emit(std::string(name).c_str(), GameData::FormatQuest(id));
            } else {
                m_emit(std::string(name).c_str(), "[TRUNCATED]");
                m_truncatedCount++;
            }
            return *this;
        }
        
        // ================================================================
        // GameEnums Helpers - Common enum lookups
        // ================================================================
        
        // Inventory type (direct value)
        PartialFieldBuilder& InventoryType(std::string_view name, uint16_t value) {
            auto inv = static_cast<GameEnums::InventoryType>(value);
            std::ostringstream os;
            os << value;
            if (auto* str = GameEnums::GetInventoryTypeName(inv)) {
                os << " (" << str << ")";
            }
            m_emit(std::string(name).c_str(), os.str());
            return *this;
        }
        
        // ObjKind (direct value)
        PartialFieldBuilder& ObjKind(std::string_view name, uint8_t value) {
            auto kind = static_cast<GameEnums::ObjKind>(value);
            std::ostringstream os;
            os << static_cast<int>(value);
            if (auto* str = GameEnums::GetObjKindName(kind)) {
                os << " (" << str << ")";
            }
            m_emit(std::string(name).c_str(), os.str());
            return *this;
        }
        
        // ActionKind (direct value)
        PartialFieldBuilder& ActionKind(std::string_view name, uint8_t value) {
            auto kind = static_cast<GameEnums::ActionKind>(value);
            std::ostringstream os;
            os << static_cast<int>(value);
            if (auto* str = GameEnums::GetActionKindName(kind)) {
                os << " (" << str << ")";
            }
            m_emit(std::string(name).c_str(), os.str());
            return *this;
        }
        
        // WarpType (direct value)
        PartialFieldBuilder& WarpType(std::string_view name, uint8_t value) {
            auto warp = static_cast<GameEnums::WarpType>(value);
            std::ostringstream os;
            os << static_cast<int>(value);
            if (auto* str = GameEnums::GetWarpTypeName(warp)) {
                os << " (" << str << ")";
            }
            m_emit(std::string(name).c_str(), os.str());
            return *this;
        }
        
        // ActorStatus (direct value)
        PartialFieldBuilder& ActorStatus(std::string_view name, uint8_t value) {
            auto status = static_cast<GameEnums::ActorStatus>(value);
            std::ostringstream os;
            os << static_cast<int>(value);
            if (auto* str = GameEnums::GetActorStatusName(status)) {
                os << " (" << str << ")";
            }
            m_emit(std::string(name).c_str(), os.str());
            return *this;
        }
        
        // ItemOperationType (direct value)
        PartialFieldBuilder& ItemOperationType(std::string_view name, uint8_t value) {
            auto op = static_cast<GameEnums::ItemOperationType>(value);
            std::ostringstream os;
            os << static_cast<int>(value);
            if (auto* str = GameEnums::GetItemOperationTypeName(op)) {
                os << " (" << str << ")";
            }
            m_emit(std::string(name).c_str(), os.str());
            return *this;
        }
        
        // GrandCompany (direct value)
        PartialFieldBuilder& GrandCompany(std::string_view name, uint8_t value) {
            auto gc = static_cast<GameEnums::GrandCompany>(value);
            std::ostringstream os;
            os << static_cast<int>(value);
            if (auto* str = GameEnums::GetGrandCompanyName(gc)) {
                os << " (" << str << ")";
            }
            m_emit(std::string(name).c_str(), os.str());
            return *this;
        }
        
        // GearSlot (direct value)
        PartialFieldBuilder& GearSlot(std::string_view name, uint8_t value) {
            auto slot = static_cast<GameEnums::GearSetSlot>(value);
            std::ostringstream os;
            os << static_cast<int>(value);
            if (auto* str = GameEnums::GetGearSlotName(slot)) {
                os << " (" << str << ")";
            }
            m_emit(std::string(name).c_str(), os.str());
            return *this;
        }
        
        // HouseSize (direct value)
        PartialFieldBuilder& HouseSize(std::string_view name, uint8_t value) {
            auto size = static_cast<GameEnums::HouseSize>(value);
            std::ostringstream os;
            os << static_cast<int>(value);
            if (auto* str = GameEnums::GetHouseSizeName(size)) {
                os << " (" << str << ")";
            }
            m_emit(std::string(name).c_str(), os.str());
            return *this;
        }
        
        // StatusEffect (direct value, uses GameData lookup)
        PartialFieldBuilder& StatusEffect(std::string_view name, uint16_t statusId) {
            m_emit(std::string(name).c_str(), GameData::FormatStatus(statusId));
            return *this;
        }
        
        // Get available length
        [[nodiscard]] size_t AvailableLen() const { return m_len; }
        [[nodiscard]] size_t StructSize() const { return m_structSize; }
        [[nodiscard]] bool IsComplete() const { return m_len >= m_structSize; }
        
    private:
        template<typename MemberT>
        static size_t OffsetOf(MemberT PacketT::*member) {
            return reinterpret_cast<size_t>(&(static_cast<const PacketT*>(nullptr)->*member));
        }
        
        template<typename T>
        void EmitValue(std::string_view name, const T& value) {
            if constexpr (std::is_integral_v<T>) {
                m_emit(std::string(name).c_str(), std::to_string(value));
            } else if constexpr (std::is_floating_point_v<T>) {
                std::ostringstream os;
                os << std::fixed << std::setprecision(3) << value;
                m_emit(std::string(name).c_str(), os.str());
            } else {
                m_emit(std::string(name).c_str(), "[complex type]");
            }
        }
        
        RowEmitter m_emit;
        const uint8_t* m_base;
        size_t m_len;
        size_t m_structSize;
        int m_truncatedCount;
    };

    // Move DumpBytesAsHex BEFORE any use (FieldStringifier / ValueToString)
    inline std::string DumpBytesAsHex(std::span<const uint8_t> bytes, size_t maxLen = 32) {
        std::ostringstream os;
        os << std::hex << std::uppercase << std::setfill('0');
        size_t shown = std::min(bytes.size(), maxLen);
        for (size_t i = 0; i < shown; ++i) {
            if (i) os << ' ';
            os << std::setw(2) << static_cast<int>(bytes[i]);
        }
        if (shown < bytes.size()) os << " ...";
        return os.str();
    }

    class PacketDecoderRegistry {
    public:
        static PacketDecoderRegistry& Instance() {
            static PacketDecoderRegistry instance;
            return instance;
        }
        void RegisterDecoder(uint16_t connType, bool outgoing, uint16_t opcode, DecoderFunc decoder) {
            uint64_t key = MakeKey(connType, outgoing, opcode);
            decoders_[key] = std::move(decoder);
        }
        bool TryDecode(uint16_t connType, bool outgoing, uint16_t opcode,
            const uint8_t* payload, size_t payloadLen,
            std::function<void(const char*, const std::string&)> rowKV) {
            uint64_t key = MakeKey(connType, outgoing, opcode);
            auto it = decoders_.find(key);
            if (it != decoders_.end()) {
                it->second(payload, payloadLen, std::move(rowKV));
                return true;
            }
            return false;
        }
    private:
        [[nodiscard]] static constexpr uint64_t MakeKey(uint16_t connType, bool outgoing, uint16_t opcode) noexcept {
            return (static_cast<uint64_t>(connType & 0xFFFFu) << 32) |
                   (static_cast<uint64_t>(outgoing ? 1u : 0u) << 16) |
                   static_cast<uint64_t>(opcode & 0xFFFFu);
        }
        std::unordered_map<uint64_t, DecoderFunc> decoders_;
    };

    struct FieldStringifier {
        template<typename T>
        static std::string ToString(const T& value) {
            if constexpr (std::is_same_v<T, bool>) {
                return value ? "true" : "false";
            } else if constexpr (std::is_integral_v<T> && !std::is_same_v<T,char> &&
                                 !std::is_same_v<T,signed char> && !std::is_same_v<T,unsigned char>) {
                std::ostringstream os;
                os << value << " (0x" << std::hex << std::uppercase << static_cast<uint64_t>(value) << ")";
                return os.str();
            } else if constexpr (std::is_floating_point_v<T>) {
                std::ostringstream os; os << value; return os.str();
            } else {
                return DumpBytesAsHex(std::span(reinterpret_cast<const uint8_t*>(&value), sizeof(T)));
            }
        }
        template<size_t N>
        static std::string ToString(const char (&value)[N]) {
            size_t len = strnlen(value, N);
            return std::string(value, len);
        }
        template<typename T, size_t N>
        static std::string ToString(const T(&value)[N]) {
            std::ostringstream os;
            os << "[";
            for (size_t i = 0; i < N; ++i) {
                if (i > 0) os << ", ";
                os << ToString(value[i]);
            }
            os << "]";
            return os.str();
        }
        static std::string ToStringRaw(const uint8_t* data, size_t size) {
            return DumpBytesAsHex(std::span(data, size));
        }
    };

    template<typename PacketT>
    struct FieldDescriptor {
        const char* name;
        size_t offset;
        size_t size;
        template<typename MemberT>
        static consteval FieldDescriptor Make(const char* fieldName, MemberT PacketT::*member) {
            return FieldDescriptor{ fieldName, offsetof(PacketT, member), sizeof(MemberT) };
        }
    };

    template<typename PacketT>
    struct StructDecoder {
        template<size_t N>
        static DecoderFunc Create(const std::array<FieldDescriptor<PacketT>, N>& descriptors) {
            return [descriptors](const uint8_t* payload, size_t payloadLen,
                                 std::function<void(const char*, const std::string&)> rowKV) {
                if (payloadLen < sizeof(PacketT)) {
                    std::ostringstream em;
                    em << "payload too small (have " << payloadLen
                       << ", need " << sizeof(PacketT) << ")";
                    rowKV("error", em.str());
                    return;
                }
                const PacketT* pkt = reinterpret_cast<const PacketT*>(payload);
                for (const auto& field : descriptors) {
                    const uint8_t* fieldPtr = reinterpret_cast<const uint8_t*>(pkt) + field.offset;
                    rowKV(field.name, FieldStringifier::ToStringRaw(fieldPtr, field.size));
                }
            };
        }
        template<typename... FieldEmitters>
        static std::enable_if_t<(... && std::is_invocable_v<FieldEmitters, const PacketT*, RowEmitter>), DecoderFunc>
        Create(FieldEmitters... emitters) {
            return [=](const uint8_t* payload, size_t payloadLen, RowEmitter rowKV) {
                if (payloadLen < sizeof(PacketT)) {
                    std::ostringstream em;
                    em << "payload too small (have " << payloadLen
                       << ", need " << sizeof(PacketT) << ")";
                    rowKV("error", em.str());
                    return;
                }
                const PacketT* pkt = reinterpret_cast<const PacketT*>(payload);
                (emitters(pkt, rowKV), ...);
            };
        }
    };

    template<typename T>
    std::string ValueToString(const T& value) {
        if constexpr (std::is_same_v<T,bool>) return value ? "true" : "false";
        else if constexpr (std::is_integral_v<T> && !std::is_same_v<T,char> &&
                 !std::is_same_v<T,signed char> && !std::is_same_v<T,unsigned char>) {
            std::ostringstream os;
            os << value << " (0x" << std::hex << std::uppercase << static_cast<uint64_t>(value) << ")";
            return os.str();
        } else if constexpr (std::is_floating_point_v<T>) {
            std::ostringstream os; os << value; return os.str();
        } else {
            return DumpBytesAsHex(std::span(reinterpret_cast<const uint8_t*>(&value), sizeof(T)));
        }
    }
    template<size_t N>
    std::string ValueToString(const char (&value)[N]) {
        return std::string(value, strnlen(value, N));
    }
    template<typename T, size_t N>
    std::string ValueToString(const T(&value)[N]) {
        std::ostringstream os;
        os << "[";
        for (size_t i = 0; i < N; ++i) {
            if (i > 0) os << ", ";
            os << ValueToString(value[i]);
        }
        os << "]";
        return os.str();
    }

    template<typename PacketT>
    using FieldEmitter = std::function<void(const PacketT*, const RowEmitter&)>;
    template<typename PacketT, typename MemberT>
    FieldEmitter<PacketT> MakeField(const char* name, MemberT PacketT::*member) {
        return [=](const PacketT* pkt, const RowEmitter& emit) {
            emit(name, ValueToString(pkt->*member));
        };
    }

    template<typename PacketT, size_t N>
    DecoderFunc MakeStructDecoder(const std::array<FieldEmitter<PacketT>, N>& emitters) {
        return [emitters](const uint8_t* payload, size_t payloadLen, RowEmitter rowKV) {
            if (payloadLen < sizeof(PacketT)) {
                rowKV("error", "payload too small");
                return;
            }
            const PacketT* pkt = reinterpret_cast<const PacketT*>(payload);
            for (const auto& emit : emitters) emit(pkt, rowKV);
        };
    }

    template<typename T>
    std::string FieldToString(T value) {
        if constexpr (std::is_integral_v<T>) return std::to_string(value);
        else if constexpr (std::is_floating_point_v<T>) {
            std::ostringstream os; os << std::fixed << std::setprecision(3) << value; return os.str();
        } else return "unknown";
    }

    inline std::string FormatHex(uint64_t value) {
        std::ostringstream os; os << "0x" << std::hex << std::uppercase << value; return os.str();
    }
    inline std::string FormatAngle(uint16_t value) {
        float degrees = value * 360.0f / 65535.0f;
        std::ostringstream os; os << std::fixed << std::setprecision(1) << degrees << "\u00B0"; return os.str();
    }
    inline std::string FormatAngle(float radians) {
        float degrees = (radians * 180.0f) / 3.14159265358979323846f;
        std::ostringstream os; os << std::fixed << std::setprecision(1) << degrees << "\u00B0"; return os.str();
    }
    inline std::string FormatPosition(float x, float y, float z) {
        std::ostringstream os; os << "(" << std::fixed << std::setprecision(3) << x << ", " << y << ", " << z << ")"; return os.str();
    }
    inline std::string FormatString(const char* str, size_t maxLen) {
        if (!str) return "";
        return std::string(str, strnlen(str, maxLen));
    }
    inline std::string FormatBool(bool v) { return v ? "true" : "false"; }
    inline std::string FormatPercent(float value) {
        std::ostringstream os; os << std::fixed << std::setprecision(1) << (value * 100.0f) << "%"; return os.str();
    }

    inline const char* GetActionTypeName(uint8_t type);
    inline const char* GetStatusEffectName(uint16_t id);
    inline const char* GetChatTypeName(uint16_t type);
    inline const char* GetWarpTypeName(uint8_t type);

    struct OverlayField {
        const char* name = nullptr;
        size_t offset = 0;
        size_t size = 0;
        std::string value{};
        std::string rawPreview{};
    };
    struct OverlayLayer {
        std::string name;
        size_t globalOffset = 0;
        size_t length = 0;
        std::vector<OverlayField> fields;
    };
    struct PacketOverlayContext {
        const uint8_t* fullPacket = nullptr;
        size_t fullPacketLen = 0;
        const uint8_t* packetHeader = nullptr;
        size_t packetHeaderLen = 0;
        const uint8_t* segmentHeader = nullptr;
        size_t segmentHeaderLen = 0;
        const uint8_t* ipcHeader = nullptr;
        size_t ipcHeaderLen = 0;
        const uint8_t* payload = nullptr;
        size_t payloadLen = 0;
        uint16_t connectionType = 0;
        uint16_t segmentType = 0;
        uint16_t opcode = 0;
        bool isIPC = false;
        std::vector<OverlayLayer> layersBuilt;
        bool finalized = false;
        void Reset() {
            fullPacket = packetHeader = segmentHeader = ipcHeader = payload = nullptr;
            fullPacketLen = packetHeaderLen = segmentHeaderLen = ipcHeaderLen = payloadLen = 0;
            connectionType = segmentType = opcode = 0;
            isIPC = false;
            layersBuilt.clear();
            finalized = false;
        }
    };

    PacketOverlayContext& GetOverlayContext();

    inline void BeginOverlayCapture(const uint8_t* fullPkt, size_t fullLen,
        const uint8_t* pktHdr, size_t pktHdrLen,
        const uint8_t* segHdr, size_t segHdrLen,
        const uint8_t* ipcHdr, size_t ipcHdrLen,
        const uint8_t* payloadPtr, size_t payloadLen,
        uint16_t connType, uint16_t segType, bool isIPC, uint16_t opcode)
    {
        auto& ctx = GetOverlayContext();
        ctx.Reset();
        ctx.fullPacket = fullPkt;
        ctx.fullPacketLen = fullLen;
        ctx.packetHeader = pktHdr;
        ctx.packetHeaderLen = pktHdrLen;
        ctx.segmentHeader = segHdr;
        ctx.segmentHeaderLen = segHdrLen;
        ctx.ipcHeader = ipcHdr;
        ctx.ipcHeaderLen = ipcHdrLen;
        ctx.payload = payloadPtr;
        ctx.payloadLen = payloadLen;
        ctx.connectionType = connType;
        ctx.segmentType = segType;
        ctx.isIPC = isIPC;
        ctx.opcode = opcode;
    }

    inline std::string HexPreview(const uint8_t* p, size_t len, size_t maxBytes = 8) {
        if (!p || len == 0) return "";
        std::ostringstream os;
        os << std::hex << std::uppercase << std::setfill('0');
        size_t show = (std::min)(len, maxBytes);
        for (size_t i = 0; i < show; i++) {
            if (i) os << ' ';
            os << std::setw(2) << (unsigned)p[i];
        }
        if (show < len) os << " ...";
        return os.str();
    }

    inline void PushOverlayLayer(const char* name,
        const uint8_t* /*base*/,
        size_t len,
        size_t globalOffset) {
        auto& ctx = GetOverlayContext();
        OverlayLayer L;
        L.name = name ? name : "Layer";
        L.globalOffset = globalOffset;
        L.length = len;
        ctx.layersBuilt.emplace_back(std::move(L));
    }

    inline void AddOverlayField(const char* name,
        size_t offsetWithinLayer,
        size_t size,
        const std::string& value,
        const uint8_t* layerBase)
    {
        auto& ctx = GetOverlayContext();
        if (ctx.layersBuilt.empty()) return;
        OverlayField f;
        f.name = name;
        f.offset = offsetWithinLayer;
        f.size = size;
        f.value = value;
        if (layerBase && offsetWithinLayer + size <= SIZE_MAX)
            f.rawPreview = HexPreview(layerBase + offsetWithinLayer, size);
        ctx.layersBuilt.back().fields.emplace_back(std::move(f));
    }

    inline std::vector<OverlayLayer> GetOverlayLayersSnapshot() {
        return GetOverlayContext().layersBuilt;
    }

    inline void ForEachOverlayField(const std::function<void(const OverlayLayer&, const OverlayField&)>& cb) {
        auto layers = GetOverlayLayersSnapshot();
        for (auto& L : layers)
            for (auto& F : L.fields)
                cb(L, F);
    }

    template<typename PacketT, typename MemberT, size_t N>
    constexpr auto MakeArrayField(const char* name, MemberT(PacketT::*member)[N]) {
        return [=](const PacketT* pkt, auto rowKV) {
            std::ostringstream os;
            os << "[";
            for (size_t i = 0; i < N; ++i) {
                if (i) os << ", ";
                os << FieldToString((pkt->*member)[i]);
            }
            os << "]";
            rowKV(name, os.str());
        };
    }

    struct SizeMismatchStat { uint64_t attempts=0, failures=0; };
    inline SizeMismatchStat& GetSizeMismatchStat() { static SizeMismatchStat s; return s; }

// ----- Adaptive variant helper (add near bottom of header) -----
    struct AdaptiveVariant {
        size_t size;  // canonical size of this variant
        // return false if decode should be considered failed (e.g. magic mismatch)
        std::function<bool(const uint8_t* payload, size_t len, const RowEmitter&)> decode;
        const char* name;
    };

    inline void RegisterAdaptivePacket(uint16_t connType,
                                       bool outgoing,
                                       uint16_t opcode,
                                       std::vector<AdaptiveVariant> variants,
                                       size_t minRequired = 0)
    {
        // Sort longest->shortest so longest exact match gets first chance on len >= size
        std::sort(variants.begin(), variants.end(),
                  [](auto& a, auto& b){ return a.size > b.size; });

        PacketDecoderRegistry::Instance().RegisterDecoder(
            connType, outgoing, opcode,
            [variants = std::move(variants), minRequired, opcode]
            (const uint8_t* payload, size_t len, RowEmitter emit)
            {
                if (len < minRequired) {
                    std::ostringstream os;
                    os << "payload too small (have " << len << ", need >= " << minRequired << ")";
                    emit("error", os.str());
                    return;
                }

                // Pass 1: exact size match
                for (auto& v : variants) {
                    if (len == v.size) {
                        if (v.decode(payload, len, emit)) return;
                    }
                }
                // Pass 2: largest variant whose declared size <= len
                for (auto& v : variants) {
                    if (len >= v.size) {
                        if (v.decode(payload, len, emit)) {
                            if (len != v.size) {
                                std::ostringstream os;
                                os << "note: extra tail bytes (" << (len - v.size)
                                   << ") beyond variant '" << v.name << "'";
                                emit("_tailInfo", os.str());
                            }
                            return;
                        }
                    }
                }

                std::ostringstream os;
                os << "unhandled size " << len << " for opcode 0x"
                   << std::hex << std::uppercase << opcode;
                emit("error", os.str());
            }
        );
    }

// ============================================================================
// Added helper: auto-strip outer transport/session framing to mirror external
// capture tool (find embedded IPC segment of form: [len][...header(0x10-0x14)])
// ============================================================================

    // (Removed obsolete forward declaration of LookupOpcodeName.
    //  We now rely on the typed declaration in OpcodeNames.h that
    //  accepts Net::ConnectionType plus a compatibility overload.)

    struct ExtractedIpcSegment {
        bool   valid = false;
        size_t outerSkip = 0;
        const uint8_t* segmentStart = nullptr;
        size_t segmentLen = 0;
        const uint8_t* ipcHeader = nullptr;
        size_t ipcHeaderLen = 0x14;   // current fixed assumption
        const uint8_t* payload = nullptr;
        size_t payloadLen = 0;
        uint16_t opcode = 0;
        uint16_t connectionTypeGuess = 1; // 1 = zone
    };

    inline uint32_t ReadLE32(const uint8_t* p) {
        return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
    }
    inline uint16_t ReadLE16(const uint8_t* p) {
        return (uint16_t)p[0] | ((uint16_t)p[1]<<8);
    }

    inline bool IsLikelyOpcode(uint16_t opc) {
        // Try both directions (incoming/outgoing) for zone (1) & chat(2)
        if (LookupOpcodeName(opc, false, Net::ConnectionType::Zone) != "?") return true;
        if (LookupOpcodeName(opc, true,  Net::ConnectionType::Zone) != "?") return true;
        if (LookupOpcodeName(opc, false, Net::ConnectionType::Chat) != "?") return true;
        if (LookupOpcodeName(opc, true,  Net::ConnectionType::Chat) != "?") return true;
        return false;
    }

    inline ExtractedIpcSegment TryExtractIpcSegment(const uint8_t* full, size_t fullLen) {
        ExtractedIpcSegment r;
        if (!full || fullLen < 0x20) return r;

        // Common offsets where the length field has been observed after outer framing.
        static const size_t kCandidateOffsets[] = {
            0, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28
        };

        for (size_t off : kCandidateOffsets) {
            if (off + 4 > fullLen) continue;
            uint32_t segLen = ReadLE32(full + off);
            if (segLen < 0x14) continue;                 // too small
            if (segLen > fullLen - off) continue;        // past end
            // For now require exact remainder match (mirrors external tool)
            if (segLen != fullLen - off) continue;

            // Minimum IPC header we rely on: opcode at offset +0x12 (after two 32-bit + routing shorts pattern)
            if (off + 0x12 + 2 > fullLen) continue;
            uint16_t opc = ReadLE16(full + off + 0x12);
            if (!IsLikelyOpcode(opc)) continue;

            // Assume fixed 0x14 header for now (observed)
            size_t ipcHeaderLen = 0x14;
            if (segLen < ipcHeaderLen) continue;

            r.valid        = true;
            r.outerSkip    = off;
            r.segmentStart = full + off;
            r.segmentLen   = segLen;
            r.ipcHeader    = full + off;
            r.ipcHeaderLen = ipcHeaderLen;
            r.payload      = full + off + ipcHeaderLen;
            r.payloadLen   = segLen - ipcHeaderLen;
            r.opcode       = opc;
            // Guess connection type: if opcode known only in zone table usually 1.
            r.connectionTypeGuess = 1;
            break;
        }
        return r;
    }

    inline bool StripAndDecodeIpc(const uint8_t* full, size_t fullLen,
                                  bool outgoing,
                                  RowEmitter emit,
                                  uint16_t explicitConnType = 0xFFFF)
    {
        auto seg = TryExtractIpcSegment(full, fullLen);
        if (!seg.valid) return false;

        uint16_t connType = (explicitConnType == 0xFFFF) ? seg.connectionTypeGuess : explicitConnType;

        // Overlay capture (outer framing = seg.outerSkip bytes)
        BeginOverlayCapture(full, fullLen,
                            full, seg.outerSkip,     // treat 'packetHeader' as the stripped outer region
                            nullptr, 0,              // segmentHeader unused
                            seg.ipcHeader, seg.ipcHeaderLen,
                            seg.payload, seg.payloadLen,
                            connType, /*segType*/0, true, seg.opcode);

        // Emit a few meta rows (optional)
        emit("_strip.outerSkip", std::to_string(seg.outerSkip));
        emit("_strip.segmentLen", std::to_string(seg.segmentLen));
        emit("_strip.opcode", FormatHex(seg.opcode));

        // Forward to registered decoder
        if (!PacketDecoderRegistry::Instance().TryDecode(connType, outgoing, seg.opcode,
                                                         seg.payload, seg.payloadLen, emit)) {
            emit("decoder", "no registered decoder");
        }
        return true;
    }

// ============================================================================
// ADD near the bottom (just before the closing namespace) – refined strip helpers using known ConnectionType

    // If you have a known connection type (Zone=1, Chat=2, Lobby=3) you can
    // reduce false positives by validating opcodes only against that table.
    inline bool IsLikelyOpcodeForConn(uint16_t opc, Net::ConnectionType connType) {
        // Lobby currently shares most with zone table; treat Lobby like Zone.
        Net::ConnectionType effective = (connType == Net::ConnectionType::Lobby)
            ? Net::ConnectionType::Zone : connType;
        if (LookupOpcodeName(opc, false, effective) != "?") return true;
        if (LookupOpcodeName(opc, true,  effective) != "?") return true;
        return false;
    }

    struct ExtractedIpcSegmentKnown {
        bool   valid = false;
        size_t outerSkip = 0;
        const uint8_t* segmentStart = nullptr;
        size_t segmentLen = 0;
        const uint8_t* ipcHeader = nullptr;
        size_t ipcHeaderLen = 0x14;   // current fixed assumption
        const uint8_t* payload = nullptr;
        size_t payloadLen = 0;
        uint16_t opcode = 0;
    };

    inline ExtractedIpcSegmentKnown TryExtractIpcSegmentKnown(const uint8_t* full, size_t fullLen, Net::ConnectionType connType) {
        ExtractedIpcSegmentKnown r;
        if (!full || fullLen < 0x20) return r;

        // Offsets where the 32-bit segment length has been observed (outer framing sizes).
        static const size_t kCandidateOffsets[] { 0, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28 };

        for (size_t off : kCandidateOffsets) {
            if (off + 4 > fullLen) continue;
            uint32_t segLen = ReadLE32(full + off);
            if (segLen < 0x14) continue;
            if (segLen > fullLen - off) continue;
            if (segLen != fullLen - off) continue; // require exact remainder for now

            if (off + 0x12 + 2 > fullLen) continue;
            uint16_t opc = ReadLE16(full + off + 0x12);
            if (!IsLikelyOpcodeForConn(opc, connType)) continue;

            // Basic header sanity: we often see two repeating 16-bit IDs at +0x04..0x0B; optional future check.
            r.valid        = true;
            r.outerSkip    = off;
            r.segmentStart = full + off;
            r.segmentLen   = segLen;
            r.ipcHeader    = full + off;
            r.payload      = full + off + r.ipcHeaderLen;
            r.payloadLen   = segLen - r.ipcHeaderLen;
            r.opcode       = opc;
            break;
        }
        return r;
    }

    // Public helper: strip outer frame (if present) and dispatch to registered decoder.
    // Returns true if an IPC segment was found & dispatched.
    inline bool StripAndDecodeIpcKnown(const uint8_t* full,
                                       size_t fullLen,
                                       Net::ConnectionType connectionType, // 1=Zone,2=Chat,3=Lobby
                                       bool outgoing,
                                       RowEmitter emit)
    {
        auto seg = TryExtractIpcSegmentKnown(full, fullLen, connectionType);
        if (!seg.valid) return false;

        BeginOverlayCapture(full, fullLen,
                            full, seg.outerSkip,
                            nullptr, 0,
                            seg.ipcHeader, seg.ipcHeaderLen,
                            seg.payload, seg.payloadLen,
                            Net::ToUInt(connectionType),
                            0, true, seg.opcode);

        emit("_strip.outerSkip", std::to_string(seg.outerSkip));
        emit("_strip.segmentLen", std::to_string(seg.segmentLen));
        emit("_strip.opcode", FormatHex(seg.opcode));

        if (!PacketDecoderRegistry::Instance().TryDecode(
                Net::ToUInt(connectionType), outgoing, seg.opcode,
                seg.payload, seg.payloadLen, emit))
        {
            emit("decoder", "no registered decoder");
        }
        return true;
    }

// ============================================================================
// JSON export model + PacketDecoder (minimal API used by PacketDecoder.cpp)
// ============================================================================
    struct PacketHeaderFFXIV {
        uint64_t magic0 = 0;
        uint64_t magic1 = 0;
        uint32_t size = 0;
        uint64_t timestamp = 0;
        uint16_t connType = 0;
        uint16_t segCount = 0;
        uint8_t  isCompressed = 0;
        uint8_t  unknown20 = 0;
        uint32_t unknown24 = 0;
    };

    struct SegmentHeaderFFXIV {
        uint32_t offset = 0;
        uint32_t size = 0;
        uint16_t type = 0;
        uint16_t pad = 0;
        uint32_t srcId = 0;
        uint32_t tgtId = 0;
    };

    struct SegmentData {
        SegmentHeaderFFXIV header{};
        // IPC
        uint16_t opcode = 0;
        uint16_t serverId = 0;
        uint32_t timestamp = 0;
        uint16_t ipcReserved = 0;
        uint16_t ipcPad = 0;
        // payload
        std::vector<uint8_t> data;
    };

    struct ParsedFFXIVPacket {
        uint64_t connectionId = 0;
        bool outgoing = false;
        std::chrono::steady_clock::time_point captureTime{};
        PacketHeaderFFXIV header{};
        std::vector<SegmentData> segments;
        std::vector<uint8_t> rawData;
    };

    class PacketDecoder {
    public:
        std::string ExportToEnhancedJson(const ParsedFFXIVPacket& packet) const;
        void SetIncludeRawData(bool enable) { includeRawData_ = enable; }

    private:
        // helpers implemented in cpp
        std::string BytesToHex(const std::vector<uint8_t>& data, size_t maxBytes = 0) const;
        std::string FormatTimestamp(std::chrono::steady_clock::time_point tp) const;
        const char* GetSegmentTypeName(uint16_t type) const;
        std::string FormatHex8(uint8_t value) const;
        std::string FormatHex16(uint16_t value) const;
        std::string FormatHex32(uint32_t value) const;
        std::string FormatHex64(uint64_t value) const;

        bool includeRawData_ = false;
    };

} // namespace PacketDecoding