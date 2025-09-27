#pragma once
#include <cstdint>

namespace Net {

// Strongly typed connection kinds used across opcode decoding & lookup.
enum class ConnectionType : uint16_t {
    Zone    = 1,       // World / zone (gameplay)
    Chat    = 2,       // Chat-only connection
    Lobby   = 3,       // Lobby / service (mostly zone-like)
    Unknown = 0xFFFF   // Unknown / probe all tables
};

constexpr uint16_t ToUInt(ConnectionType ct) noexcept {
    return static_cast<uint16_t>(ct);
}

constexpr bool IsUnknown(ConnectionType ct) noexcept {
    return ct == ConnectionType::Unknown;
}

} // namespace Net

namespace PacketDecoding {
    void RegisterZonePackets();
    void RegisterChatPackets();
    void RegisterLobbyPackets();
    void RegisterGenericPackets();
    void RegisterInitPackets();

    inline void RegisterAllPackets() {
        static bool done = false;
        if (!done) {
            RegisterZonePackets();
            RegisterChatPackets();
            RegisterLobbyPackets();
            RegisterGenericPackets();
            RegisterInitPackets();
            done = true;
        }
    }
}