#pragma once
#include <cstdint>
#include "PacketRegistration.h" // for Net::ConnectionType

// Central opcode name lookup.
// outgoing: true = client->server, false = server->client.
// connectionType: Net::ConnectionType::{Zone,Chat,Lobby,Unknown}
const char* LookupOpcodeName(uint16_t opcode,
                             bool outgoing,
                             Net::ConnectionType connectionType = Net::ConnectionType::Unknown) noexcept;

// Raw uint16_t compatibility overload
inline const char* LookupOpcodeName(uint16_t opcode,
                                    bool outgoing,
                                    uint16_t rawConnType) noexcept
{
    Net::ConnectionType ct =
        (rawConnType == 0xFFFF)
        ? Net::ConnectionType::Unknown
        : static_cast<Net::ConnectionType>(rawConnType);
    return LookupOpcodeName(opcode, outgoing, ct);
}

const char* LookupActorControlCategoryName(uint16_t category) noexcept;