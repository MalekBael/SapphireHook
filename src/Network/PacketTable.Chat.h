#pragma once
#include "PacketDecoder.h"
#include "../ProtocolHandlers/Chat/ServerChatDef.h"
#include <vector>

namespace PacketDecoding::Tables {

using namespace PacketStructures::Server::Chat;

// Define the chat packet table
inline std::vector<PacketDescriptor> GetChatPackets() {
    std::vector<PacketDescriptor> packets;
    
    // Chat server packets (connection type 2)
    packets.push_back(MakePacket<FFXIVChatFrom>(2, Direction::ServerToClient, 0x0064, "ChatFrom"));
    packets.push_back(MakePacket<FFXIVIpcTellNotFound>(2, Direction::ServerToClient, 0x0066, "TellNotFound"));
    packets.push_back(MakePacket<FFXIVRecvBusyStatus>(2, Direction::ServerToClient, 0x0067, "RecvBusyStatus"));
    packets.push_back(MakePacket<FFXIVRecvFinderStatus>(2, Direction::ServerToClient, 0x006A, "RecvFinderStatus"));
    
    return packets;
}

} // namespace PacketDecoding::Tables
