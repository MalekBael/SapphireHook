#pragma once
#include <cstdint>
#include <cmath>
#include <string>
#include <format>

namespace PacketStructures {

    // ============================================
    // Position Structures (matching Sapphire/game)
    // ============================================

    // Common 3D position (12 bytes) - used in most network packets
    struct FFXIVARR_POSITION3 {
        float x;
        float y;
        float z;

        // Operators for convenience
        bool operator==(const FFXIVARR_POSITION3& other) const {
            return x == other.x && y == other.y && z == other.z;
        }

        bool operator!=(const FFXIVARR_POSITION3& other) const {
            return !(*this == other);
        }

        FFXIVARR_POSITION3 operator-(const FFXIVARR_POSITION3& other) const {
            return { x - other.x, y - other.y, z - other.z };
        }

        // Distance calculations
        float DistanceSquared(const FFXIVARR_POSITION3& other) const {
            float dx = x - other.x;
            float dy = y - other.y;
            float dz = z - other.z;
            return dx * dx + dy * dy + dz * dz;
        }

        float Distance(const FFXIVARR_POSITION3& other) const {
            return std::sqrt(DistanceSquared(other));
        }

        float Distance2D(const FFXIVARR_POSITION3& other) const {
            float dx = x - other.x;
            float dz = z - other.z;
            return std::sqrt(dx * dx + dz * dz);
        }

        // Format as string (for logging/display)
        std::string ToString() const {
            return std::format("({:.2f}, {:.2f}, {:.2f})", x, y, z);
        }
    };

    // Extended position with padding (16 bytes) - used in some internal structures
    struct Vector3 {
        float x;
        float y;
        float z;
        float reserve;  // Padding for 16-byte alignment

        // Conversion from FFXIVARR_POSITION3
        static Vector3 FromPosition3(const FFXIVARR_POSITION3& pos) {
            return { pos.x, pos.y, pos.z, 0.0f };
        }

        FFXIVARR_POSITION3 ToPosition3() const {
            return { x, y, z };
        }

        std::string ToString() const {
            return std::format("({:.2f}, {:.2f}, {:.2f})", x, y, z);
        }
    };

    // 3x3 rotation matrix
    struct Matrix33 {
        float m[3][3];
    };

    // Chat type enum
    enum ChatType : uint16_t {
        LogKindError = 0x0003,
        ServerDebug = 0x0004,
        ServerUrgent = 0x0005,
        ServerNotice = 0x0006,
        Say = 0x000A,
        Shout = 0x000B,
        Tell = 0x000C,
        TellReceive = 0x000D,
        Party = 0x000E,
        Alliance = 0x000F,
        Ls1 = 0x0010,
        FreeCompany = 0x0018,
        NoviceNetwork = 0x001B,
        Yell = 0x001E,
        CrossParty = 0x001F,
        PvPTeam = 0x0024,
        CrossLinkShell1 = 0x0025,
        Echo = 0x0038,
        SystemMessage = 0x0039,
    };

    // Status work structure
    struct StatusWork {
        uint16_t id;
        int16_t systemParam;
        float time;
        uint32_t source;
    };

    // Quest data structure  
    struct QuestData {
        uint8_t index;
        uint8_t a1;
        uint16_t questId;
        uint8_t a2;
        uint8_t flags;
        uint8_t a3;
        uint8_t a4;
        uint8_t a5[5];
        uint32_t a6[6];
        uint8_t a7;
    };

    // Land identifier
    struct LandIdent {
        int16_t landId;
        int16_t wardNum;
        int16_t territoryTypeId;
        int16_t worldId;
    };

    // Calc result for action effects
    struct CalcResult {
        uint8_t effectType;
        uint8_t hitSeverity;
        uint8_t param;
        uint8_t bonusPercent;
        uint16_t value;
        uint16_t padding;
    };

    // Furniture placement data
    struct Furniture {
        uint32_t itemId;
        uint16_t rotate;
        uint16_t x;
        uint16_t y;
        uint16_t z;
        uint32_t design;
        uint32_t containerIndex;
    };

    // House data
    struct House {
        uint32_t housePrice;
        uint8_t infoFlags;
        uint8_t houseIconAdd;
        uint8_t houseAppeal[3];
        char estateOwnerName[32];
    };

    // Character land data
    struct CharaLandData {
        LandIdent landIdent;
        uint8_t sharingType;
        uint8_t instance;
        uint8_t size;
        uint8_t status;
        uint32_t iconAddIcon;
    };

    // Simple profile
    struct SimpleProfile {
        uint64_t ownerId;
        char name[32];
    };

    // Housing layout
    struct HousingLayout {
        uint8_t storageIndex;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        float posX;
        float posY;
        float posZ;
        float rotY;
    };

    // Personal room profile
    struct HousingPersonalRoomProfileData {
        uint16_t roomNumber;
        uint8_t isOccupied;
        uint8_t __padding1;
        uint64_t ownerId;
        char ownerName[32];
    };

    // House buddy stable
    struct HouseBuddyStableData {
        uint64_t ownerId;
        uint32_t buddyId;
        uint8_t stain;
        uint8_t favoritePoint;
        uint8_t __padding1;
        uint8_t __padding2;
        char buddyName[21];
        char ownerName[32];
    };

} // namespace PacketStructures