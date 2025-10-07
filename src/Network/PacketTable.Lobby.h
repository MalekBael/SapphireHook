#pragma once
#include "PacketDecoder.h"
#include "../ProtocolHandlers/Lobby/ServerLobbyDef.h"
#include "../ProtocolHandlers/Lobby/ClientLobbyDef.h"
#include <vector>

namespace PacketDecoding::Tables {

using namespace PacketStructures::Client::Lobby;
using namespace PacketStructures::Server::Lobby;

// Define the lobby packet table
inline std::vector<PacketDescriptor> GetLobbyPackets() {
    std::vector<PacketDescriptor> packets;
    
    // Client lobby packets (connection type 3)
    packets.push_back(MakePacket<PacketStructures::Client::Lobby::FFXIVIpcLogin>(3, Direction::ClientToServer, 0x0002, "Login"));
    
    // Server lobby packets (connection type 3)
    packets.push_back(MakePacket<PacketStructures::Server::Lobby::FFXIVIpcLoginReply>(3, Direction::ServerToClient, 0x000C, "LoginReply"));
    
    return packets;
}

} // namespace PacketDecoding::Tables
