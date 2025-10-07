#pragma once
#include "PacketDecoder.h"
#include "../ProtocolHandlers/Zone/ServerZoneDef.h"
#include "../ProtocolHandlers/Zone/ClientZoneDef.h"
#include <vector>

namespace PacketDecoding::Tables {

namespace ServerZone = PacketStructures::Server::Zone;
namespace ClientZone = PacketStructures::Client::Zone;

// Define the zone packet table
inline std::vector<PacketDescriptor> GetZonePackets() {
    std::vector<PacketDescriptor> packets;
    
    // === SERVER PACKETS ===
    // Core/Session
    packets.push_back(MakePacket<ServerZone::FFXIVIpcSync>(1, Direction::ServerToClient, 0x0065, "Sync"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcLogin>(1, Direction::ServerToClient, 0x0066, "Login"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcEnableLogout>(1, Direction::ServerToClient, 0x02D6, "EnableLogout"));
    
    // Chat/Social  
    packets.push_back(MakePacket<ServerZone::FFXIVIpcChat>(1, Direction::ServerToClient, 0x0067, "Chat"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcGetCommonlistResult>(1, Direction::ServerToClient, 0x00CC, "GetCommonlistResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcGetCommonlistDetailResult>(1, Direction::ServerToClient, 0x00CD, "GetCommonlistDetailResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcPcSearchResult>(1, Direction::ServerToClient, 0x00EB, "PcSearchResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcLinkshellResult>(1, Direction::ServerToClient, 0x00F0, "LinkshellResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcInviteResult>(1, Direction::ServerToClient, 0x00C9, "InviteResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcInviteReplyResult>(1, Direction::ServerToClient, 0x00CA, "InviteReplyResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcInviteUpdate>(1, Direction::ServerToClient, 0x00CB, "InviteUpdate"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcFriendlistRemoveResult>(1, Direction::ServerToClient, 0x00E6, "FriendlistRemoveResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcBlacklistAddResult>(1, Direction::ServerToClient, 0x00E1, "BlacklistAddResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcBlacklistRemoveResult>(1, Direction::ServerToClient, 0x00E2, "BlacklistRemoveResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcGetBlacklistResult>(1, Direction::ServerToClient, 0x00E3, "GetBlacklistResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcGetLinkshellListResult>(1, Direction::ServerToClient, 0x00F1, "GetLinkshellListResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcChatChannelResult>(1, Direction::ServerToClient, 0x00D2, "ChatChannelResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcSetOnlineStatus>(1, Direction::ServerToClient, 0x00D5, "SetOnlineStatus"));
    
    // Profile
    packets.push_back(MakePacket<ServerZone::FFXIVIpcSetProfileResult>(1, Direction::ServerToClient, 0x00CE, "SetProfileResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcGetProfileResult>(1, Direction::ServerToClient, 0x00CF, "GetProfileResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcGetSearchCommentResult>(1, Direction::ServerToClient, 0x00D0, "GetSearchCommentResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcGetCharacterNameResult>(1, Direction::ServerToClient, 0x00D1, "GetCharacterNameResult"));
    
    // System Messages
    packets.push_back(MakePacket<ServerZone::FFXIVIpcSendSystemMessage>(1, Direction::ServerToClient, 0x00D3, "SendSystemMessage"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcSendLoginMessage>(1, Direction::ServerToClient, 0x00D4, "SendLoginMessage"));
    
    // Achievement
    packets.push_back(MakePacket<ServerZone::FFXIVIpcAchievement>(1, Direction::ServerToClient, 0x02DD, "Achievement"));
    
    // Mail
    packets.push_back(MakePacket<ServerZone::FFXIVIpcGetLetterMessageResult>(1, Direction::ServerToClient, 0x00FB, "GetLetterMessageResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcGetLetterMessageDetailResult>(1, Direction::ServerToClient, 0x00FC, "GetLetterMessageDetailResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcLetterResult>(1, Direction::ServerToClient, 0x00FA, "LetterResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcGetLetterStatusResult>(1, Direction::ServerToClient, 0x00FD, "GetLetterStatusResult"));
    
    // Market/Item Search
    packets.push_back(MakePacket<ServerZone::FFXIVIpcGetItemSearchListResult>(1, Direction::ServerToClient, 0x0105, "GetItemSearchListResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcGetItemHistoryResult>(1, Direction::ServerToClient, 0x0109, "GetItemHistoryResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcCatalogSearchResult>(1, Direction::ServerToClient, 0x010C, "CatalogSearchResult"));
    
    // Combat/Actions
    packets.push_back(MakePacket<ServerZone::FFXIVIpcActionIntegrity>(1, Direction::ServerToClient, 0x0141, "ActionIntegrity"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcActorControl>(1, Direction::ServerToClient, 0x0142, "ActorControl"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcActorControlSelf>(1, Direction::ServerToClient, 0x0143, "ActorControlSelf"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcActorControlTarget>(1, Direction::ServerToClient, 0x0144, "ActorControlTarget"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcResting>(1, Direction::ServerToClient, 0x0145, "Resting"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcActionResult1>(1, Direction::ServerToClient, 0x0146, "ActionResult1"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcActionResult>(1, Direction::ServerToClient, 0x0147, "ActionResult"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcStatus>(1, Direction::ServerToClient, 0x0148, "Status"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcRecastGroup>(1, Direction::ServerToClient, 0x014A, "RecastGroup"));
    
    // Movement/Spawn
    packets.push_back(MakePacket<ServerZone::FFXIVIpcPlayerSpawn>(1, Direction::ServerToClient, 0x0190, "PlayerSpawn"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcActorFreeSpawn>(1, Direction::ServerToClient, 0x0191, "ActorFreeSpawn"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcActorMove>(1, Direction::ServerToClient, 0x0192, "ActorMove"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcTransfer>(1, Direction::ServerToClient, 0x0193, "Transfer"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcWarp>(1, Direction::ServerToClient, 0x0194, "Warp"));
    packets.push_back(MakePacket<ServerZone::FFXIVIpcActorCast>(1, Direction::ServerToClient, 0x0196, "ActorCast"));
    
    // Note: 0x019A is handled specially (bidirectional)
    packets.push_back(MakePacket<ServerZone::FFXIVIpcInitZone>(1, Direction::ServerToClient, 0x019A, "InitZone", DecodePolicy::Special));
    
    // === CLIENT PACKETS ===
    // Session
    packets.push_back(MakePacket<ClientZone::FFXIVIpcPingHandler>(1, Direction::ClientToServer, 0x0065, "Ping"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcLoginHandler>(1, Direction::ClientToServer, 0x0066, "LoginHandler"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcChatHandler>(1, Direction::ClientToServer, 0x0067, "ChatHandler"));
    
    // Actions
    packets.push_back(MakePacket<ClientZone::FFXIVIpcActionRequest>(1, Direction::ClientToServer, 0x0196, "ActionRequest"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcSelectGroundActionRequest>(1, Direction::ClientToServer, 0x0199, "SelectGroundAction"));
    
    // Movement - Note: 0x019A handled specially
    packets.push_back(MakePacket<ClientZone::FFXIVIpcUpdatePosition>(1, Direction::ClientToServer, 0x01A0, "UpdatePosition"));
    
    // Events
    packets.push_back(MakePacket<ClientZone::FFXIVIpcEventHandlerTalk>(1, Direction::ClientToServer, 0x01C2, "EventHandlerTalk"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcEventHandlerEmote>(1, Direction::ClientToServer, 0x01C3, "EventHandlerEmote"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcEventHandlerWithinRange>(1, Direction::ClientToServer, 0x01C4, "EventHandlerWithinRange"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcEventHandlerOutsideRange>(1, Direction::ClientToServer, 0x01C5, "EventHandlerOutsideRange"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcEnterTerritoryHandler>(1, Direction::ClientToServer, 0x01C6, "EnterTerritoryHandler"));
    
    // Item Operations
    packets.push_back(MakePacket<ClientZone::FFXIVIpcClientInventoryItemOperation>(1, Direction::ClientToServer, 0x01AE, "InventoryItemOperation"));
    
    // GM Commands
    packets.push_back(MakePacket<ClientZone::FFXIVIpcGmCommand>(1, Direction::ClientToServer, 0x0197, "GmCommand"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcGmCommandName>(1, Direction::ClientToServer, 0x0198, "GmCommandName"));
    
    // Social
    packets.push_back(MakePacket<ClientZone::FFXIVIpcInvite>(1, Direction::ClientToServer, 0x00C9, "Invite"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcInviteReply>(1, Direction::ClientToServer, 0x00CA, "InviteReply"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcGetCommonlist>(1, Direction::ClientToServer, 0x00CB, "GetCommonlist"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcGetCommonlistDetail>(1, Direction::ClientToServer, 0x00CC, "GetCommonlistDetail"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcBlacklistAdd>(1, Direction::ClientToServer, 0x00E1, "BlacklistAdd"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcBlacklistRemove>(1, Direction::ClientToServer, 0x00E2, "BlacklistRemove"));
    
    // Party
    packets.push_back(MakePacket<ClientZone::FFXIVIpcPcPartyLeave>(1, Direction::ClientToServer, 0x00DC, "PcPartyLeave"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcPcPartyDisband>(1, Direction::ClientToServer, 0x00DD, "PcPartyDisband"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcPcPartyKick>(1, Direction::ClientToServer, 0x00DE, "PcPartyKick"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcPcPartyChangeLeader>(1, Direction::ClientToServer, 0x00DF, "PcPartyChangeLeader"));
    
    // Config
    packets.push_back(MakePacket<ClientZone::FFXIVIpcConfig>(1, Direction::ClientToServer, 0x0262, "Config"));
    
    // Discovery
    packets.push_back(MakePacket<ClientZone::FFXIVIpcNewDiscovery>(1, Direction::ClientToServer, 0x0194, "NewDiscovery"));
    
    // Market Board
    packets.push_back(MakePacket<ClientZone::FFXIVIpcMarketBoardRequestItemListingInfo>(1, Direction::ClientToServer, 0x1102, "MarketBoardRequestItemListingInfo"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcMarketBoardRequestItemListings>(1, Direction::ClientToServer, 0x1103, "MarketBoardRequestItemListings"));
    
    // Housing
    packets.push_back(MakePacket<ClientZone::FFXIVIpcHousingExteriorChange>(1, Direction::ClientToServer, 0x01B0, "HousingExteriorChange"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcHousingPlaceYardItem>(1, Direction::ClientToServer, 0x01B1, "HousingPlaceYardItem"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcHousingHouseName>(1, Direction::ClientToServer, 0x026A, "HousingHouseName"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcHousingGreeting>(1, Direction::ClientToServer, 0x026B, "HousingGreeting"));
    
    // Linkshell
    packets.push_back(MakePacket<ClientZone::FFXIVIpcLinkshellJoin>(1, Direction::ClientToServer, 0x00F0, "LinkshellJoin"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcLinkshellLeave>(1, Direction::ClientToServer, 0x00F2, "LinkshellLeave"));
    
    // Content Finder
    packets.push_back(MakePacket<ClientZone::FFXIVIpcFind5Contents>(1, Direction::ClientToServer, 0x01FD, "Find5Contents"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcAcceptContent>(1, Direction::ClientToServer, 0x01FB, "AcceptContent"));
    packets.push_back(MakePacket<ClientZone::FFXIVIpcCancelFindContent>(1, Direction::ClientToServer, 0x01FC, "CancelFindContent"));
    
    return packets;
}

} // namespace PacketDecoding::Tables
