#include "OpcodeNames.h"
#include <unordered_map>

namespace {
    // Separate opcode tables by connection (zone vs chat) and direction

    // Server (zone) opcodes
    static const std::unordered_map<uint16_t, const char*> kServerZoneOpcodes = {
        { 0x0065, "SyncReply" },
        { 0x0066, "LoginReply" },
        { 0x0067, "ChatToChannel" },
        { 0x0069, "RegionInfo" },
        { 0x006A, "MoveTerritory" },
        { 0x006B, "MoveInstance" },
        { 0x0073, "SetPSNId" },
        { 0x0075, "SetBillingTime" },

        { 0x00C9, "InviteResult" },
        { 0x00CA, "InviteReplyResult" },
        { 0x00CB, "InviteUpdate" },
        { 0x00CC, "GetCommonlistResult" },
        { 0x00CD, "GetCommonlistDetailResult" },
        { 0x00CE, "SetProfileResult" },
        { 0x00CF, "GetProfileResult" },
        { 0x00E1, "BlacklistAddResult" },
        { 0x00E2, "BlacklistRemoveResult" },
        { 0x00E3, "GetBlacklistResult" },
        { 0x00DC, "PcPartyResult" },
        { 0x00DD, "PcPartyUpdate" },
        { 0x00DE, "InviteCancelResult" },

        { 0x0104, "ItemSearchResult" },
        { 0x0105, "GetItemSearchListResult" },
        { 0x0106, "GetRetainerListResult" },
        { 0x0107, "BuyMarketRetainerResult" },
        { 0x0108, "MarketStorageUpdate" },
        { 0x0109, "GetItemHistoryResult" },
        { 0x010A, "GetRetainerSalesHistoryResult" },
        { 0x010B, "MarketRetainerUpdate" },
        { 0x010C, "CatalogSearchResult" },
        { 0x010E, "FreeCompanyResult" },
        { 0x010F, "GetFcStatusResult" },

        { 0x012C, "SyncTagHeader" },
        { 0x012D, "SyncTag32" },
        { 0x012E, "SyncTag64" },
        { 0x012F, "SyncTag128" },

        { 0x0140, "HudParam" },
        { 0x0141, "ActionIntegrity" },
        { 0x0142, "Order" },
        { 0x0143, "OrderMySelf" },
        { 0x0144, "OrderTarget" },
        { 0x0145, "Resting" },
        { 0x0146, "ActionResult1" },
        { 0x0147, "ActionResult" },
        { 0x0148, "Status" },
        { 0x0149, "FreeCompany" },
        { 0x014A, "RecastGroup" },
        { 0x014B, "UpdateAlliance" },
        { 0x014C, "PartyPos" },
        { 0x014D, "AlliancePos" },
        { 0x014F, "GrandCompany" },

        { 0x0190, "Create" },
        { 0x0191, "Delete" },
        { 0x0192, "ActorMove" },
        { 0x0193, "Transfer" },
        { 0x0194, "Warp" },
        { 0x0196, "RequestCast" },
        { 0x0199, "UpdateParty" },
        { 0x019A, "InitZone" },
        { 0x019B, "HateList" },
        { 0x019C, "HaterList" },
        { 0x019D, "CreateObject" },
        { 0x019E, "DeleteObject" },
        { 0x019F, "PlayerStatusUpdate" },
        { 0x01A0, "PlayerStatus" },
        { 0x01A1, "BaseParam" },
        { 0x01A2, "FirstAttack" },
        { 0x01A3, "Condition" },
        { 0x01A4, "ChangeClass" },
        { 0x01A5, "Equip" },
        { 0x01A6, "Inspect" },
        { 0x01A7, "Name" },

        { 0x01AE, "ItemStorage" },
        { 0x01AF, "NormalItem" },
        { 0x01B0, "ItemSize" },
        { 0x01B1, "ItemOperationBatch" },
        { 0x01B2, "ItemOperation" },
        { 0x01B3, "GilItem" },
        { 0x01B4, "TradeCommand" },
        { 0x01B5, "ItemMessage" },
        { 0x01B6, "UpdateItem" },

        { 0x01B8, "OpenTreasure" },
        { 0x01B9, "LootRight" },
        { 0x01BA, "LootActionResult" },
        { 0x01BB, "GameLog" },
        { 0x01BC, "TreasureOpenRight" },
        { 0x01BD, "OpenTreasureKeyUi" },
        { 0x01BE, "LootItems" },
        { 0x01BF, "CreateTreasure" },
        { 0x01C0, "TreasureFadeOut" },

        { 0x01C1, "MonsterNoteCategory" },
        { 0x01C2, "EventPlayHeader" },
        { 0x01C3, "EventPlay2" },
        { 0x01C4, "EventPlay4" },
        { 0x01C5, "EventPlay8" },
        { 0x01C6, "EventPlay16" },
        { 0x01C7, "EventPlay32" },
        { 0x01C8, "EventPlay64" },
        { 0x01C9, "EventPlay128" },
        { 0x01CA, "EventPlay255" },

        { 0x01CE, "UpdateEventSceneHeader" },
        { 0x01CF, "UpdateEventScene2" },
        { 0x01D0, "UpdateEventScene4" },
        { 0x01D1, "UpdateEventScene8" },
        { 0x01D2, "UpdateEventScene16" },
        { 0x01D3, "UpdateEventScene32" },
        { 0x01D4, "UpdateEventScene64" },
        { 0x01D5, "UpdateEventScene128" },
        { 0x01D6, "UpdateEventScene255" },

        { 0x01D7, "ResumeEventSceneHeader" },
        { 0x01D8, "ResumeEventScene2" },
        { 0x01D9, "ResumeEventScene4" },
        { 0x01DA, "ResumeEventScene8" },
        { 0x01DB, "ResumeEventScene16" },
        { 0x01DC, "ResumeEventScene32" },
        { 0x01DD, "ResumeEventScene64" },
        { 0x01DE, "ResumeEventScene128" },
        { 0x01DF, "ResumeEventScene255" },

        { 0x0200, "Mount" },
        { 0x0226, "Director" },
        { 0x0262, "BattleTalkHeader" },
        { 0x026C, "EventReject" },
        { 0x02D6, "EnableLogout" },
        { 0x02E5, "Text" },
    };

    // Server (chat) opcodes
    static const std::unordered_map<uint16_t, const char*> kServerChatOpcodes = {
        { 0x0002, "LoginReply (Chat)" },
        { 0x0064, "ChatFrom" },
        { 0x0065, "Chat" },
        { 0x0066, "TellNotFound" },
        { 0x0067, "RecvBusyStatus" },
        { 0x0068, "GetChannelMemberListResult" },
        { 0x0069, "GetChannelListResult" },
        { 0x006A, "RecvFinderStatus" },
        { 0x00C8, "JoinChannelResult" },
        { 0x00C9, "LeaveChannelResult" },
    };

    // Client (zone) opcodes
    static const std::unordered_map<uint16_t, const char*> kClientZoneOpcodes = {
        { 0x0065, "Sync" },
        { 0x0066, "Login" },
        { 0x0067, "ChatHandler" },
        { 0x0069, "SetLanguage" },

        { 0x00C9, "Invite" },
        { 0x00CA, "InviteReply" },
        { 0x00CB, "GetCommonlist" },
        { 0x00CC, "GetCommonlistDetail" },
        { 0x00CD, "SetProfile" },
        { 0x00CE, "GetProfile" },
        { 0x00CF, "GetSearchComment" },
        { 0x00D0, "PartyRecruitAdd" },
        { 0x00D1, "JoinChatChannel" },
        { 0x00D2, "LeaveChatChannel" },
        { 0x00D3, "PartyRecruitRemove" },
        { 0x00D4, "PartyRecruitSearch" },
        { 0x00D5, "GetRecruitSearchList" },
        { 0x00D6, "GetRecruitDetail" },
        { 0x00D7, "InviteReplyRecruitParty" },
        { 0x00D8, "PartyRecruitEdit" },
        { 0x00D9, "GetPurposeLevel" },
        { 0x00DA, "AddRequestItem" },
        { 0x00DB, "RemoveRequestItem" },
        { 0x00DC, "PcPartyLeave" },
        { 0x00DD, "PcPartyDisband" },
        { 0x00DE, "PcPartyKick" },
        { 0x00DF, "PcPartyChangeLeader" },

        { 0x00E1, "BlacklistAdd" },
        { 0x00E2, "BlacklistRemove" },
        { 0x00E3, "GetBlacklist" },
        { 0x00E4, "GetRequestItemList" },
        { 0x00E5, "SendReadyCheck" },
        { 0x00E6, "FriendlistRemove" },
        { 0x00E7, "ReplyReadyCheck" },
        { 0x00E8, "GetPartyRecruitCount" },
        { 0x00E9, "FcAddJoinRequest" },
        { 0x00EA, "FcRemoveJoinRequest" },
        { 0x00EB, "PcSearch" },
        { 0x00EC, "GetFcJoinRequestComment" },
        { 0x00ED, "InviteCancel" },

        { 0x00F0, "LinkshellJoin" },
        { 0x00F1, "LinkshellJoinOfficial" },
        { 0x00F2, "LinkshellLeave" },
        { 0x00F4, "LinkshellChangeMaster" },
        { 0x00F5, "LinkshellKick" },
        { 0x00F6, "GetLinkshellList" },
        { 0x00F7, "LinkshellAddLeader" },
        { 0x00F8, "LinkshellRemoveLeader" },
        { 0x00F9, "LinkshellDeclineLeader" },

        { 0x0104, "ItemSearch" },
        { 0x0105, "GetItemSearchList" },
        { 0x0106, "GetRetainerList" },
        { 0x0107, "BuyMarketRetainer" },
        { 0x0108, "GetRetainerSalesHistory" },
        { 0x0109, "CatalogSearch" },

        { 0x0190, "ZoneJump" },
        { 0x0191, "Command" },
        { 0x0193, "PhysicalBonus" },
        { 0x0194, "NewDiscovery" },
        { 0x0195, "TargetPosCommand" },
        { 0x0196, "ActionRequest" },
        { 0x0197, "GMCommand" },
        { 0x0198, "GMCommandName" },
        { 0x0199, "SelectGroundActionRequest" },
        { 0x019A, "Move" },
        { 0x019B, "GMCommandBuddyName" },
        { 0x019C, "GMCommandNameBuddyName" },
        { 0x01A4, "RequestStorageItems" },
        { 0x01AE, "ClientItemOperation" },
        { 0x01AF, "GearSetEquip" },
        { 0x01B0, "HousingExteriorChange" },
        { 0x01B1, "HousingPlaceYardItem" },
        { 0x01B2, "HousingInteriorChange" },
        { 0x01B3, "TradeCommand" },
        { 0x01B4, "TreasureCheckCommand" },
        { 0x01B5, "SelectLootAction" },
        { 0x01B6, "OpenTreasureWithKey" },

        { 0x01C2, "StartTalkEvent" },
        { 0x01C3, "StartEmoteEvent" },
        { 0x01C8, "StartUIEvent" },
        { 0x01C9, "StartSayEvent" },

        { 0x01D6, "ReturnEventSceneHeader" },
        { 0x01D7, "ReturnEventScene2" },
        { 0x01D8, "ReturnEventScene4" },
        { 0x01D9, "ReturnEventScene8" },
        { 0x01DA, "ReturnEventScene16" },
        { 0x01DB, "ReturnEventScene32" },
        { 0x01DC, "ReturnEventScene64" },
        { 0x01DD, "ReturnEventScene128" },
        { 0x01DE, "ReturnEventScene255" },

        { 0x01DF, "YieldEventSceneHeader" },
        { 0x01E0, "YieldEventScene2" },
        { 0x01E1, "YieldEventScene4" },
        { 0x01E2, "YieldEventScene8" },
        { 0x01E3, "YieldEventScene16" },
        { 0x01E4, "YieldEventScene32" },
        { 0x01E5, "YieldEventScene64" },
        { 0x01E6, "YieldEventScene128" },
        { 0x01E7, "YieldEventScene255" },

        { 0x01EA, "YieldEventSceneStringHeader" },
        { 0x01EB, "YieldEventSceneString8" },
        { 0x01EC, "YieldEventSceneString16" },
        { 0x01ED, "YieldEventSceneString32" },
        { 0x01EE, "YieldEventSceneIntAndString" },

        { 0x0262, "Config" },
        { 0x0263, "StartLogoutCountdown" },
        { 0x0264, "CancelLogoutCountdown" },
        { 0x026A, "HousingHouseName" },
        { 0x026B, "HousingGreeting" },
        { 0x026C, "HousingChangeLayout" },
        { 0x026D, "VoteKickStart" },
        { 0x026E, "MVPRequest" },

        { 0x0078, "CFCommenceHandler" },
        { 0x1102, "MarketBoardRequestItemListingInfo" },
        { 0x1103, "MarketBoardRequestItemListings" },
        { 0x1113, "ReqExamineFcInfo" },
    };

    // Client (chat) opcodes
    static const std::unordered_map<uint16_t, const char*> kClientChatOpcodes = {
        { 0x0002, "Login (Chat)" },
        { 0x0064, "ChatTo" },
        { 0x0065, "ChatToChannel" },
        { 0x0066, "SendBusyStatus" },
        { 0x0067, "GetChannelMemberList" },
        { 0x0068, "GetChannelList" },
        { 0x0069, "SendFinderStatus" },
        { 0x006A, "ChatToCharacterID" },
        { 0x00C8, "JoinChannel" },
        { 0x00C9, "LeaveChannel" },
        { 0x00CA, "RenameChannel" },
        { 0x00CB, "GmLogin" },
        { 0x00CC, "GmLogout" },
    };

    inline bool IsChatConn(uint16_t connType) {
        // Only 2 is a chat connection. 0xFFFF means unknown.
        return (connType == 2);
    }
}

const char* LookupOpcodeName(uint16_t opcode, bool outgoing, uint16_t connectionType) noexcept
{
    const bool chat = (connectionType != 0xFFFF) ? IsChatConn(connectionType) : false;

    if (outgoing) {
        if (chat) {
            auto it = kClientChatOpcodes.find(opcode);
            if (it != kClientChatOpcodes.end()) return it->second;
        } else {
            auto it = kClientZoneOpcodes.find(opcode);
            if (it != kClientZoneOpcodes.end()) return it->second;
            // If unknown connection type, try chat table too as last resort
            if (connectionType == 0xFFFF) {
                auto itc = kClientChatOpcodes.find(opcode);
                if (itc != kClientChatOpcodes.end()) return itc->second;
            }
        }
    } else {
        if (chat) {
            auto it = kServerChatOpcodes.find(opcode);
            if (it != kServerChatOpcodes.end()) return it->second;
        } else {
            auto it = kServerZoneOpcodes.find(opcode);
            if (it != kServerZoneOpcodes.end()) return it->second;
            if (connectionType == 0xFFFF) {
                auto its = kServerChatOpcodes.find(opcode);
                if (its != kServerChatOpcodes.end()) return its->second;
            }
        }
    }
    return "?";
}
