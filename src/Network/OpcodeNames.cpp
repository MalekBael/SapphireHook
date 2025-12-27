#include "OpcodeNames.h"
#include <unordered_map>
#include <cstdint>

namespace {

inline bool IsChatConn(uint16_t connType) {
    return connType == static_cast<uint16_t>(Net::ConnectionType::Chat);
}

// Separate opcode tables by connection (zone vs chat) and direction

    // Server (zone) opcodes
    static const std::unordered_map<uint16_t, const char*> kServerZoneOpcodes = {
        // Lobby-like/system headers not present here (server uses world zone connection for most)
        { 0x0065, "SyncReply" },
        { 0x0066, "LoginReply" },
        { 0x0067, "ChatToChannel" },
        { 0x0069, "RegionInfo" },
        { 0x006A, "MoveTerritory" },
        { 0x006B, "MoveInstance" },
        { 0x0073, "SetPSNId" },
        { 0x0075, "SetBillingTime" },

        // Content Finder (Duty Finder) packets
        { 0x0078, "CFCommenceResult" },       // CF commence duty result
        { 0x0079, "CFCommenceUpdate" },        // CF commence state update
        { 0x007A, "CFContentReady" },          // CF content is ready to enter
        { 0x007B, "CFNotifyCategory9" },       // CF notification type 9
        { 0x007C, "CFNotifyCategory11" },      // CF notification type 11

        { 0x00C9, "InviteResult" },
        { 0x00CA, "InviteReplyResult" },
        { 0x00CB, "InviteUpdate" },
        { 0x00CC, "GetCommonlistResult" },
        { 0x00CD, "GetCommonlistDetailResult" },
        { 0x00CE, "SetProfileResult" },
        { 0x00CF, "GetProfileResult" },

        { 0x00D0, "GetSearchCommentResult" },
        { 0x00D1, "GetCharacterNameResult" },
        { 0x00D2, "ChatChannelResult" },
        { 0x00D3, "SendSystemMessage" },
        { 0x00D4, "SendLoginMessage" },
        { 0x00D5, "UpdateOnlineStatus" },
        { 0x00D6, "PartyRecruitResult" },
        { 0x00D7, "GetRecruitSearchListResult" },
        { 0x00D8, "GetRecruitDetailResult" },
        { 0x00D9, "RequestItemResult" },
        { 0x00DA, "AllianceReadyCheckResult" },
        { 0x00DB, "GetFcJoinRequestCommentResult" },
        { 0x00DC, "PcPartyResult" },
        { 0x00DD, "PcPartyUpdate" },
        { 0x00DE, "InviteCancelResult" },

        { 0x00E1, "BlacklistAddResult" },
        { 0x00E2, "BlacklistRemoveResult" },
        { 0x00E3, "GetBlacklistResult" },
        { 0x00E4, "RequestItemListResult" },   // Item request list from social manager
        { 0x00E5, "RequestItemUpdate" },       // Item request state update
        { 0x00E6, "FriendlistRemoveResult" },
        { 0x00E7, "AllianceReadyCheckUpdate" },  // Alliance ready check state update
        { 0x00EB, "PcSearchResult" },
        { 0x00F0, "LinkshellResult" },
        { 0x00F1, "GetLinkshellListResult" },

        { 0x00FA, "LetterResult" },
        { 0x00FB, "GetLetterMessageResult" },
        { 0x00FC, "GetLetterMessageDetailResult" },
        { 0x00FD, "GetLetterStatusResult" },

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

        { 0x0110, "GetFcInviteListResult" },
        { 0x0111, "GetFcProfileResult" },
        { 0x0112, "GetFcHeaderResult" },
        { 0x0113, "GetCompanyBoardResult" },
        { 0x0114, "GetFcHierarchyResult" },
        { 0x0115, "GetFcActivityListResult" },
        { 0x0116, "GetFcHierarchyLiteResult" },
        { 0x0117, "GetCompanyMottoResult" },
        { 0x0118, "GetFcParamsResult" },
        { 0x0119, "GetFcActionResult" },
        { 0x011A, "GetFcMemoResult" },
        { 0x011B, "GetFcReputationResult" },   // FC reputation/rank data
        { 0x011C, "FcBonusResult" },           // FC bonus status result
        { 0x011D, "FcMemberUpdate" },          // FC member data update
        { 0x0122, "InfoGMCommandResult" },

        { 0x012C, "SyncTagHeader" },
        { 0x012D, "SyncTag32" },
        { 0x012E, "SyncTag64" },
        { 0x012F, "SyncTag128" },
        { 0x0130, "SyncTag256" },
        { 0x0131, "SyncTag384" },
        { 0x0132, "SyncTag512" },
        { 0x0133, "SyncTag768" },
        { 0x0134, "SyncTag1024" },
        { 0x0135, "SyncTag1536" },
        { 0x0136, "SyncTag2048" },
        { 0x0137, "SyncTag3072" },

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
        { 0x014E, "PartyMemberPos" },        // Party member position markers (packed uint16→float)
        { 0x014F, "GrandCompany" },

        // Quest Tracker UI packets (various sized data)
        { 0x0150, "SetQuestUIFlag" },          // Sets quest UI state flags
        { 0x0151, "QuestTrackerData" },        // Full quest tracker data (0xA0 bytes)
        { 0x0152, "QuestTrackerEntry" },       // Single quest tracker entry update
        { 0x0153, "QuestTracker40" },          // Quest tracker 40-byte chunk
        { 0x0154, "QuestTracker60" },          // Quest tracker 60-byte chunk
        { 0x0155, "QuestTracker60Entry" },     // Quest tracker 60 single entry
        { 0x0156, "QuestTracker80" },          // Quest tracker 80-byte chunk
        { 0x0157, "QuestTrackerBig" },         // Quest tracker large data (365 bytes)
        { 0x0158, "QuestTrackerBigEntry" },    // Quest tracker large single entry
        { 0x0159, "QuestUIState" },            // Quest UI state bytes
        { 0x015A, "QuestFlags" },              // Quest completion flags
        { 0x015B, "QuestComplete" },           // Quest completion signal

        // Director Type 7 - Instance/Content Director packets
        // These initialize and update the instance director when entering instanced content
        // Director7Init sets Director+1512 (active flag) and Director+1513 (contentId)
        // which triggers the UI transition from ContentsFinder to ContentsInfo addon
        { 0x0168, "Director7Init" },          // Initialize instance director (contentType, contentId)
        { 0x0169, "Director7Update" },        // Update instance director state
        { 0x016A, "Director7Result" },        // Instance completion/result

        { 0x0190, "Create" },
        { 0x0191, "Delete" },
        { 0x0192, "ActorMove" },
        { 0x0193, "Transfer" },
        { 0x0194, "Warp" },
        { 0x0195, "TerritoryListData" },       // Territory list (100 entries × 72 bytes)
        { 0x0196, "RequestCast" },
        { 0x0197, "ActorModifiers" },          // Actor modifier array (26 bytes at actor+4952)
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
        { 0x01A9, "AttachMateriaRequest" },
        { 0x01AA, "RetainerList" },
        { 0x01AB, "RetainerData" },
        { 0x01AC, "MarketPriceHeader" },
        { 0x01AD, "MarketPrice" },
        { 0x01AE, "ItemStorage" },
        { 0x01AF, "NormalItem" },
        { 0x01B0, "ItemSize" },
        { 0x01B1, "ItemOperationBatch" },
        { 0x01B2, "ItemOperation" },
        { 0x01B3, "GilItem" },
        { 0x01B4, "TradeCommand" },
        { 0x01B5, "ItemMessage" },
        { 0x01B6, "UpdateItem" },
        { 0x01B7, "AliasItem" },
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
        { 0x01CB, "DebugActorData" },
        { 0x01CC, "PushEventState" },
        { 0x01CD, "PopEventState" },
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

        // Event Scene system packets
        { 0x01E0, "EventSceneInit" },          // Event scene initialization (16-byte entries)
        { 0x01E1, "EventSceneSlot" },          // Event scene slot (5 params, slot < 0x1E)
        { 0x01E2, "EventSceneData" },          // Event scene data (310 + 32 bytes)
        { 0x01E3, "EventSceneFlags" },         // Event scene flags (word + 3 bools)
        { 0x01E4, "EventScenePos" },           // Event scene position data
        { 0x01E5, "EventSceneSlot4" },         // Event scene slot variant (4 params)
        { 0x01E6, "EventSceneBulk200" },       // Event scene bulk data (200 bytes)
        { 0x01E7, "EventSceneState" },         // Event scene state (word + bool)
        { 0x01E9, "EventLogParam1" },          // Event log with 1 param
        { 0x01EA, "EventLogParam2" },          // Event log with 2 params
        { 0x01EB, "EventLogParam3" },          // Event log with 3 params
        { 0x01EC, "EventLogParam4" },          // Event log with 4 params
        { 0x01ED, "EventLogParam5" },          // Event log with 5 params
        { 0x01EE, "EventScenePad5" },          // Event scene padding (5 units)
        { 0x01EF, "InspectUpdate" },           // Inspect data update (uses dword_1505540)

        { 0x01F0, "LegacyQuestCompleteFlags" },
        { 0x01F1, "ResumeEventSceneHeaderStr" },
        { 0x01F2, "ResumeEventSceneStr32" },
        { 0x01F3, "LogText" },
        { 0x01F4, "DebugNull" },
        { 0x01F5, "DebugLog" },
        { 0x01F6, "BigData" },
        { 0x01F7, "DebugOrderHeader" },
        { 0x01F8, "DebugOrder2" },
        { 0x01F9, "DebugOrder4" },
        { 0x01FA, "DebugOrder8" },
        { 0x01FB, "DebugOrder16" },
        { 0x01FC, "DebugOrder32" },
        { 0x01FD, "DebugActionRange" },
        { 0x01FE, "ResumeEventSceneHeaderNumStr" },
        { 0x01FF, "ResumeEventScene2Str" },
        { 0x0200, "Mount" },
        { 0x0201, "ResumeEventScene4Str" },
        { 0x0226, "Director" },
        { 0x0227, "DownDebugPacket" },

        { 0x0258, "EventLogMessageHeader" },
        { 0x0259, "EventLogMessage2" },
        { 0x025A, "EventLogMessage4" },
        { 0x025B, "EventLogMessage8" },
        { 0x025C, "EventLogMessage16" },
        { 0x025D, "EventLogMessage32" },
        { 0x0262, "BattleTalkHeader" },
        { 0x0263, "BattleTalk2" },
        { 0x0264, "BattleTalk4" },
        { 0x0265, "BattleTalk8" },
        { 0x026C, "EventReject" },
        { 0x026D, "MapMarker2" },
        { 0x026E, "MapMarker4" },
        { 0x026F, "MapMarker8" },
        { 0x0270, "MapMarker16" },
        { 0x0271, "MapMarker32" },
        { 0x0272, "MapMarker64" },
        { 0x0273, "MapMarker128" },
        { 0x0276, "BalloonTalkHeader" },
        { 0x0277, "BalloonTalk2" },
        { 0x0278, "BalloonTalk4" },
        { 0x0279, "BalloonTalk8" },

        { 0x0289, "GameLoggerMessage" },
        { 0x028A, "WeatherId" },
        { 0x028B, "TitleList" },
        { 0x028C, "DiscoveryReply" },
        { 0x028D, "TimeOffset" },
        { 0x028E, "ChocoboTaxiStart" },
        { 0x028F, "GMOrderHeader" },

        // ContentFinder (Duty Finder) Notification packets
        // Handler: sub_140CC6F40 - processes queue state, match found, ready check, etc.
        // State values: 8=queue update, 9=queue op, 10=instance content, 11=instance state
        { 0x0290, "CFNotify" },              // ContentFinder notification (base)
        { 0x0291, "CFNotifyPop" },           // CF match found / pop notification
        { 0x0292, "CFNotifyEnterReady" },    // CF all players ready, entering instance
        { 0x0293, "CFNotifyMemberUpdate" },  // CF party member update
        { 0x0294, "CFNotifyStatus" },        // CF queue/duty status update
        { 0x029E, "InspectQuests" },
        { 0x029F, "InspectGuildleves" },
        { 0x02A0, "InspectReward" },
        { 0x02A1, "InspectBeastReputation" },

        { 0x02C6, "Config" },

        { 0x02D0, "NpcYell" },
        { 0x02D1, "SwapSystem" },
        { 0x02D2, "FatePcWork" },
        { 0x02D3, "LootResult" },
        { 0x02D4, "FateAccessCollectionEventObject" },
        { 0x02D5, "FateSyncLimitTime" },
        { 0x02D6, "EnableLogout" },
        { 0x02D7, "LogMessage" },
        { 0x02D8, "FateDebug" },
        { 0x02D9, "FateContextWork" },
        { 0x02DA, "FateActiveRange" },
        { 0x02DB, "UpdateFindContent" },
        { 0x02DC, "Cabinet" },
        { 0x02DD, "Achievement" },
        { 0x02DE, "NotifyFindContentStatus" },
        { 0x02DF, "ColosseumResult44" },
        { 0x02E0, "ColosseumResult88" },
        { 0x02E1, "ResponsePenalties" },
        { 0x02E2, "ContentClearFlags" },
        { 0x02E3, "ContentAttainFlags" },
        { 0x02E4, "UpdateContent" },
        { 0x02E5, "Text" },
        { 0x02E6, "SuccessFindContentAsMember5" },
        { 0x02E7, "CancelLogoutCountdown" },
        { 0x02E8, "SetEventBehavior" },
        { 0x02E9, "BallistaStart" },
        { 0x02EA, "RetainerCustomizePreset" },
        { 0x02EB, "FateReward" },

        { 0x02EC, "HouseList" },
        { 0x02ED, "House" },
        { 0x02EE, "YardObjectList" },
        { 0x02F0, "YardObject" },
        { 0x02F1, "Interior" },
        { 0x02F2, "HousingAuction" },
        { 0x02F3, "HousingProfile" },
        { 0x02F4, "HousingHouseName" },
        { 0x02F5, "HousingGreeting" },
        { 0x02F6, "CharaHousingLandData" },
        { 0x02F7, "CharaHousing" },
        { 0x02F8, "HousingWelcome" },
        { 0x02F9, "FurnitureListS" },
        { 0x02FA, "FurnitureListM" },
        { 0x02FB, "FurnitureListL" },
        { 0x02FC, "Furniture" },
        { 0x02FD, "VoteKickConfirm" },
        { 0x02FE, "HousingProfileList" },
        { 0x02FF, "HousingObjectTransform" },
        { 0x0300, "HousingObjectColor" },
        { 0x0301, "HousingObjectTransformMulti" },
        { 0x0302, "ConfusionApproach" },
        { 0x0303, "ConfusionTurn" },
        { 0x0304, "ConfusionTurnCancel" },
        { 0x0305, "ConfusionCancel" },
        { 0x0306, "MIPMemberList" },
        { 0x0307, "HousingGetPersonalRoomProfileListResult" },
        { 0x0308, "HousingGetHouseBuddyStableListResult" },
        { 0x0309, "HouseTrainBuddyData" },

        // Housing Buddy/Stable system
        { 0x030A, "HouseBuddyStableUpdate" },  // Chocobo stable update in housing
        { 0x030B, "HouseBuddyData" },          // Housing buddy data (UI component 104)
        { 0x030C, "SocialStatus8" },           // Social/party status (8 slots)
        { 0x030D, "HouseTrainBuddyResult" },   // Buddy training result
        { 0x030E, "HouseYardInfo" },           // Housing yard information
        { 0x030F, "HouseYardEntry" },          // Housing yard single entry
        { 0x0310, "HouseYardBatch" },          // Housing yard batch update

        { 0x0311, "ContentBonus" },
        { 0x0316, "FcChestLog" },
        { 0x0317, "SalvageResult" },

        { 0x0320, "DailyQuests" },
        { 0x0321, "DailyQuest" },
        { 0x0322, "QuestRepeatFlags" },

        { 0x032A, "HousingObjectTransformMultiResult" },
        { 0x032B, "HousingLogWithHouseName" },
        { 0x032C, "TreasureHuntReward" },
        { 0x032D, "HousingCombinedObjectStatus" },
        { 0x032E, "HouseBuddyModelData" },
        { 0x032F, "RetainerListBatch" },     // Retainer list (30 entries × 3 bytes per page)

        // Housing Buddy commands - need further investigation, what is housing buddy in ffxiv context?
        { 0x0330, "HouseBuddyStatus" },        // Housing buddy status
        { 0x0331, "HouseBuddyCommand" },       // Housing buddy command
        { 0x0332, "HouseBuddyEquip" },         // Housing buddy equipment
        { 0x0333, "HouseBuddyAction" },        // Housing buddy action

        { 0x0334, "Marker" },
        { 0x0335, "GroundMarker" },
        { 0x0336, "Frontline01Result" },
        { 0x0337, "Frontline01BaseInfo" },
        { 0x0338, "SocialSearchFlags" },     // Search/social flags via UI 42
        { 0x0339, "FinishContentMatchToClient" },
        { 0x033A, "ContentMatchStatus" },     // Content matching status update
        { 0x033E, "UnMountLink" },
        { 0x033F, "CameraSetPosition" },       // Camera/view position (4 floats)
        { 0x0348, "DirectorMember2" },         // Director member (2 × 104-byte entries)
        { 0x0349, "BatchListEntry" },          // Batch queue entry (72-byte, max 72)

        // Gold Saucer - Chocobo Racing (UI component 157)
        { 0x034A, "ChocoboRaceInit" },         // Race initialization
        { 0x034B, "ChocoboRaceData" },         // Race data update
        { 0x034C, "ChocoboRaceEntry" },        // Race entry data
        { 0x034D, "ChocoboRacePosition" },     // Racer position data
        { 0x034E, "ChocoboRaceResult" },       // Race result
        { 0x034F, "ChocoboRaceJockey" },       // Jockey/rider data
        { 0x0350, "ChocoboRaceStats" },        // Chocobo stats
        { 0x0351, "ChocoboRaceState" },        // Race state
        { 0x0352, "ChocoboRaceChat" },         // Race chat message (const char*)
        { 0x0353, "ChocoboRaceReward" },       // Race rewards
        { 0x0354, "ChocoboRaceRank" },         // Race ranking
        { 0x0355, "ChocoboRaceConfig" },       // Race configuration
        { 0x0356, "ChocoboRaceItem" },         // Race item usage
        { 0x0357, "ChocoboRaceAbility" },      // Race ability (unsigned __int16*)
        { 0x0358, "ChocoboRaceText" },         // Race text display (char*)
        { 0x0359, "ChocoboRaceFlag" },         // Race flags
        { 0x035A, "ChocoboRaceTimer" },        // Race timer
        { 0x035B, "ChocoboRaceProgress" },     // Race progress
        { 0x035C, "ChocoboRacePhase" },        // Race phase
        { 0x035D, "ChocoboRaceFinish" },       // Race finish
        { 0x035E, "ChocoboRaceCamera" },       // Race camera (flt_150A508)

        // Gold Saucer - Triple Triad (actor type 0x800A)
        { 0x0384, "TripleTriadInit" },         // TT game initialization (vtable[1176])
        { 0x0385, "TripleTriadData" },         // TT game data (vtable[1172])
        { 0x0386, "TripleTriadState" },        // TT game state (vtable[1176])
        { 0x0387, "TripleTriadResult" },       // TT game result (vtable[1180])
        { 0x0388, "TripleTriadAction" },       // TT player action
        { 0x0389, "TripleTriadCard" },         // TT card data
        { 0x038A, "TripleTriadHand" },         // TT hand data (unsigned __int8*)

        { 0x03B7, "ChocoboRaceComplete" },     // Final race completion handler
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

    // Client (zone + lobby) opcodes
    static const std::unordered_map<uint16_t, const char*> kClientZoneOpcodes = {
        // Lobby
        { 0x0001, "Sync" },
        { 0x0002, "Login" },
        { 0x0003, "ServiceLogin" },
        { 0x0004, "GameLogin" },
        { 0x0005, "LoginEx" },
        { 0x0006, "ShandaLogin" },
        { 0x000B, "CharaMake" },
        { 0x000C, "CharaOperation" },
        { 0x000D, "CharaRename" },
        { 0x000E, "CharaDelete" },
        { 0x000F, "UpdateRetainerSlots" },
        { 0x01F4, "DebugNull" },
        { 0x01F5, "DebugLogin" },
        { 0x01F6, "DebugLogin2" },

        // Zone
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
        { 0x00E0, "GetRequestItem" },
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
        { 0x00EE, "SetFriendlistGroup" },
        { 0x00F0, "LinkshellJoin" },
        { 0x00F1, "LinkshellJoinOfficial" },
        { 0x00F2, "LinkshellLeave" },
        { 0x00F4, "LinkshellChangeMaster" },
        { 0x00F5, "LinkshellKick" },
        { 0x00F6, "GetLinkshellList" },
        { 0x00F7, "LinkshellAddLeader" },
        { 0x00F8, "LinkshellRemoveLeader" },
        { 0x00F9, "LinkshellDeclineLeader" },
        { 0x00FA, "LetterSendMessage" },
        { 0x00FB, "LetterRemoveMessage" },
        { 0x00FC, "GetLetterMessage" },
        { 0x00FD, "GetLetterMessageDetail" },
        { 0x00FF, "LetterMoveAppendItem" },
        { 0x0100, "CheckGiftMail" },
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
        { 0x01A5, "ExchangeAttachedInactiveMateria" },
        { 0x01A6, "RetainerCustomize" },
        { 0x01AE, "ClientItemOperation" },
        { 0x01AF, "GearSetEquip" },
        { 0x01B0, "HousingExteriorChange" },
        { 0x01B1, "HousingPlaceYardItem" },
        { 0x01B2, "HousingInteriorChange" },
        { 0x01B3, "TradeCommand" },
        { 0x01B4, "TreasureCheckCommand" },
        { 0x01B5, "SelectLootAction" },
        { 0x01B6, "OpenTreasureWithKey" },
        { 0x01B7, "BuildPresetHandler" },

        { 0x01C2, "StartTalkEvent" },
        { 0x01C3, "StartEmoteEvent" },
        { 0x01C4, "StartWithinRangeEvent" },
        { 0x01C5, "StartOutsideRangeEvent" },
        { 0x01C6, "StartEnterTerritoryEvent" },
        { 0x01C7, "StartActionResultEvent" },
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
        { 0x0266, "ContentAction" },
        { 0x026A, "HousingHouseName" },
        { 0x026B, "HousingGreeting" },
        { 0x026C, "HousingChangeLayout" },
        { 0x026D, "VoteKickStart" },
        { 0x026E, "MVPRequest" },
        { 0x026F, "HousingChangeLayoutMulti" },
        { 0x0276, "ConfusionApproachEnd" },
        { 0x0277, "ConfusionTurnEnd" },
        { 0x0278, "MovePvP" },

        { 0x0078, "CFCommenceHandler" },
        { 0x1102, "MarketBoardRequestItemListingInfo" },
        { 0x1103, "MarketBoardRequestItemListings" },
        { 0x1113, "ReqExamineFcInfo" },

        { 0x01F9, "FindContent" },           // Single duty queue (with flags)
        { 0x01FA, "FindContentAsRoulette" }, // Roulette queue
        { 0x01FB, "AcceptContent" },
        { 0x01FC, "CancelFindContent" },
        { 0x01FD, "Find5Contents" },
        { 0x01FE, "FindContentAsRandom" },
        { 0x0258, "ChocoboTaxiPathEnd" },
        { 0x0259, "ChocoboTaxiSetStep" },
        { 0x025A, "ChocoboTaxiUnmount" },
        { 0x0269, "Logout" },
        { 0x02CB, "RequestPenalties" },
        { 0x02CC, "RequestBonus" },
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

    // Centralized ActorControl (Order/ActorControl) category names
    // Based on Sapphire CommonActorControl.h ActorControlType enum
    static const std::unordered_map<uint16_t, const char*> kActorControlCategories = {
        // === Core Combat & Status (0x00 - 0x1F) ===
        { 0x00, "ToggleWeapon" },           // cycleID
        { 0x01, "AutoAttack" },             // cycleID
        { 0x02, "SetStatus" },              // cycleID
        { 0x03, "CastStart" },              // cycleID
        { 0x04, "SetBattle" },              // cycleID
        { 0x05, "ClassJobChange" },         // cycleID
        { 0x06, "DefeatMsg" },
        { 0x07, "GainExpMsg" },             // cycleID (expGained, bonus)
        { 0x0A, "LevelUpEffect" },
        { 0x0B, "ClassJobLevelUp" },        // cycleID
        { 0x0C, "ExpChainMsg" },
        { 0x0D, "HpSetStat" },
        { 0x0E, "DeathAnimation" },
        { 0x0F, "CastInterrupt" },          // cycleID
        { 0x10, "SetRecastTimer" },         // cycleID (recastGroupId, cast time, recast time)
        { 0x11, "ActionStart" },            // cycleID (startResult, targetId, actionId)
        { 0x12, "StartAttackCombat" },      // cycleID
        { 0x13, "StopAttackCombat" },       // cycleID
        { 0x14, "StatusEffectGain" },
        { 0x15, "StatusEffectLose" },
        { 0x16, "SetMaxHP" },
        { 0x17, "HPFloatingText" },         // cycleID
        { 0x18, "UpdateRestedExp" },        // cycleID (expRested, bSameZone)
        { 0x19, "SetCharaGearParam" },      // cycleID
        { 0x1B, "Flee" },                   // cycleID (duration, targetId)
        { 0x1C, "LevelUpLimitBreakRate" },  // cycleID (rateAdd, skillPointReward)
        { 0x1D, "SetCasting" },             // cycleID

        // === UI & Effects (0x20 - 0x5F) ===
        { 0x22, "CombatIndicationShow" },
        { 0x25, "SpawnEffect" },
        { 0x26, "ToggleInvisible" },
        { 0x27, "DeadFadeOut" },
        { 0x29, "SetRewardFlag" },
        { 0x2B, "UpdateUiExp" },
        { 0x2D, "SetFallDamage" },
        { 0x32, "SetTarget" },
        { 0x33, "SetGp" },                  // cycleID (currentGP, maxGP)
        { 0x34, "SetGpRate" },              // cycleID
        { 0x35, "SetMountEnable" },         // cycleID
        { 0x36, "ToggleNameHidden" },
        { 0x39, "SetHomePoint" },           // cycleID (aetheryteId)
        { 0x3B, "SetFavorite" },            // cycleID (aetheryteId, slot)
        { 0x3D, "AddBlackList" },           // cycleID (serverId, contentId)
        { 0x3F, "SetAOZScore" },            // cycleID
        { 0x43, "SetEurekaStep" },          // cycleID
        { 0x47, "LimitbreakStart" },        // cycleID (LB gauge current, max)
        { 0x48, "LimitbreakPartyStart" },
        { 0x49, "BubbleText" },             // cycleID (textId, 0=common, 1=gender/race)
        { 0x50, "DamageEffect" },
        { 0x51, "RaiseAnimation" },
        { 0x54, "SetSanctuaryFlag" },       // cycleID
        { 0x57, "TreasureScreenMsg" },
        { 0x59, "SetOwnerId" },
        { 0x5A, "SetItemLevel" },           // cycleID
        { 0x5C, "ItemRepairMsg" },

        // === Actions & Learning (0x60 - 0x8F) ===
        { 0x5E, "RequestEmote" },           // cycleID (emoteId)
        { 0x5F, "SetCriticalHit" },         // cycleID
        { 0x60, "SetDirectHit" },           // cycleID
        { 0x63, "BluActionLearn" },
        { 0x64, "DirectorInit" },           // cycleID (directorId, contentId)
        { 0x65, "DirectorClear" },          // cycleID (directorId)
        { 0x66, "LeveStartAnim" },
        { 0x67, "LeveStartError" },
        { 0x69, "DirectorPopUp" },          // cycleID (popupId)
        { 0x6A, "DirectorEObjMod" },        // cycleID (layoutId, state)
        { 0x6B, "EnterContent" },           // cycleID (contentId)
        { 0x6D, "DirectorUpdate" },
        { 0x72, "SetCp" },                  // cycleID (cp, maxCp)
        { 0x73, "SetCpRate" },              // cycleID
        { 0x74, "SetFateState" },           // cycleID (fateId, progress, state)
        { 0x75, "ObtainFateItem" },
        { 0x76, "FateReqFailMsg" },
        { 0x79, "SetLfgJob" },              // cycleID
        { 0x7B, "DutyQuestScreenMsg" },
        { 0x7D, "MiniGameSetting" },        // cycleID
        { 0x80, "SetEnmityPercent" },       // cycleID
        { 0x81, "SetEnmityValue" },         // cycleID
        { 0x82, "SetContentClearFlag" },
        { 0x83, "SetContentOpenFlag" },
        { 0x84, "ItemObtainIcon" },
        { 0x85, "FateItemFailMsg" },
        { 0x86, "ItemFailMsg" },
        { 0x87, "ActionLearnMsg1" },
        { 0x8A, "FreeEventPos" },
        { 0x8D, "ActionRejected" },         // cycleID (rejectId)
        { 0x8E, "MoveType" },

        // === Daily/Quest/Fate (0x90 - 0xBF) ===
        { 0x8F, "SyncReset" },              // cycleID
        { 0x90, "DailyQuestSeed" },         // cycleID (seed)
        { 0x91, "SetBeastReputation" },     // cycleID (beastId, reputation, rank)
        { 0x93, "QuestOpenGlobalFlag" },    // cycleID
        { 0x95, "LogMessage" },             // cycleID (messageId, 5x param)
        { 0x96, "SetModelScale" },          // cycleID (scale * 128)
        { 0x9B, "SetFateProgress" },
        { 0x9D, "SetFateRank" },            // cycleID
        { 0x9E, "SetPvpRank" },             // cycleID
        { 0x9F, "SetPetHotbar" },           // cycleID
        { 0xA1, "SetBGM" },                 // cycleID (bgmId, override)
        { 0xA4, "UnlockAetherCurrentMsg" },
        { 0xA5, "SetMpRate" },              // cycleID
        { 0xA6, "SetHpRate" },              // cycleID
        { 0xA8, "RemoveName" },
        { 0xA9, "SetObjOffsetType" },       // cycleID
        { 0xAA, "ScreenFadeOut" },
        { 0xAB, "SetOnlineStatus" },        // cycleID (statusId)
        { 0xAE, "SetStatusIcon" },          // cycleID (iconId)
        { 0xAF, "RequestGcRank" },          // cycleID
        { 0xB0, "SetGcRank" },              // cycleID (gcId, rank)
        { 0xB1, "RequestGcMemberCount" },   // cycleID
        { 0xB5, "SetForceEquip" },          // cycleID

        // === Teleport & Zone (0xC0 - 0xFF) ===
        { 0xC8, "Appear" },                 // cycleID (spawnIndex)
        { 0xC9, "ZoneInDefaultPos" },
        { 0xCA, "SetZoneIntention" },       // cycleID (zoneId)
        { 0xCB, "OnExecuteTelepo" },
        { 0xCC, "OnInvitationTelepo" },
        { 0xCD, "OnExecuteTelepoAction" },
        { 0xCE, "TownTranslate" },
        { 0xCF, "WarpStart" },
        { 0xD0, "WarpEnd" },
        { 0xD1, "WarpCancel" },
        { 0xD2, "InstanceSelectDlg" },
        { 0xD4, "ActorDespawnEffect" },
        { 0xD5, "SetMount" },               // cycleID (mountId)
        { 0xD6, "SetMountSpeed" },          // cycleID (speed)
        { 0xD7, "Dismount" },               // cycleID
        { 0xD9, "SetBit" },                 // cycleID (bitIndex)
        { 0xDA, "SetWeather" },             // cycleID (weatherId)
        { 0xDB, "SetSpawnHud" },            // cycleID
        { 0xDC, "SetControllerIndex" },     // cycleID
        { 0xDD, "SetZoneProvisionalLock" }, // cycleID
        { 0xDE, "SetProvisionalLock" },     // cycleID
        { 0xDF, "SetInInstance" },          // cycleID (inContent)
        { 0xE4, "SetBuddyAction" },         // cycleID (slot, actionId)
        { 0xF0, "SetTerritoryType" },       // cycleID (territoryId)

        // === Companion/Mount (0xFD - 0x12F) ===
        { 0xFD, "CompanionUnlock" },
        { 0xFE, "ObtainBarding" },
        { 0xFF, "EquipBarding" },
        { 0x102, "CompanionMsg1" },
        { 0x103, "CompanionMsg2" },
        { 0x104, "ShowPetHotbar" },
        { 0x109, "ActionLearnMsg" },
        { 0x10A, "ActorFadeOut" },
        { 0x10B, "ActorFadeIn" },
        { 0x10C, "WithdrawMsg" },
        { 0x10D, "OrderCompanion" },
        { 0x10E, "ToggleCompanion" },
        { 0x10F, "LearnCompanion" },
        { 0x110, "ActorFateOut1" },
        { 0x111, "SetMountAction" },        // cycleID (slot, actionId)
        { 0x112, "SetPvpAction" },          // cycleID
        { 0x113, "SetMinionAction" },       // cycleID (slot, actionId)
        { 0x114, "SetOrnamentAction" },     // cycleID

        // === Emote/Pose (0x120 - 0x14F) ===
        { 0x122, "Emote" },                 // cycleID (emoteId, flipBook)
        { 0x123, "EmoteInterrupt" },
        { 0x124, "EmoteModeInterrupt" },
        { 0x125, "EmoteModeInterruptNonImmediate" },
        { 0x127, "SetPose" },               // cycleID (poseId)
        { 0x128, "SetModelState" },         // cycleID (state)
        { 0x129, "SetTargetSign" },         // cycleID (iconId, actorId)
        { 0x12A, "TargetPossible" },        // cycleID
        { 0x12C, "CraftingUnk" },
        { 0x12D, "CraftingRequestId" },     // cycleID
        { 0x12E, "CraftingQualityUp" },     // cycleID
        { 0x12F, "CraftingStatusUp" },      // cycleID

        // === Gathering/Mining (0x130 - 0x15F) ===
        { 0x130, "GatheringSenseMsg" },
        { 0x131, "PartyMsg" },
        { 0x132, "GatheringSenseMsg1" },
        { 0x133, "GatheringBonusMax" },     // cycleID
        { 0x134, "GatheringBonusPlus" },    // cycleID
        { 0x135, "GatheringBonusRate" },    // cycleID
        { 0x136, "GatheringBonusChain" },   // cycleID
        { 0x137, "GatheringBonusCraft" },   // cycleID
        { 0x138, "GatheringSenseMsg2" },
        { 0x139, "GatheringHQ" },           // cycleID
        { 0x13A, "GatheringCollectable" },  // cycleID
        { 0x13B, "GatheringIntegrity" },    // cycleID
        { 0x13C, "GatheringChain" },        // cycleID
        { 0x13D, "GatheringBoon" },         // cycleID
        { 0x13E, "GatheringYield" },        // cycleID
        { 0x13F, "GatheringAttempts" },     // cycleID

        // === Fishing (0x140 - 0x15F) ===
        { 0x140, "FishingMsg" },
        { 0x141, "FishingStart" },          // cycleID
        { 0x142, "FishingTotalFishCaught" },
        { 0x143, "FishingBiteOn" },         // cycleID (tugType)
        { 0x144, "FishingEnd" },            // cycleID
        { 0x145, "FishingBaitMsg" },
        { 0x146, "FishingCatch" },          // cycleID (fishId, isHQ, size)
        { 0x147, "FishingReachMsg" },
        { 0x148, "FishingFailMsg" },
        { 0x149, "FishingNewRecord" },      // cycleID
        { 0x14A, "FishingLog" },            // cycleID
        { 0x14B, "SpearFishingStart" },     // cycleID
        { 0x14C, "SpearFishingEnd" },       // cycleID

        // === Materia/Glamour/Dye (0x15E - 0x170) ===
        { 0x15E, "MateriaConvertMsg" },
        { 0x15F, "MeldSuccessMsg" },
        { 0x160, "MeldFailMsg" },
        { 0x161, "MeldModeToggle" },
        { 0x163, "AetherRestoreMsg" },
        { 0x164, "SetAutoAfk" },            // cycleID
        { 0x165, "SetAfk" },                // cycleID
        { 0x166, "SetWalkMode" },           // cycleID
        { 0x167, "SetDutyReady" },          // cycleID
        { 0x168, "DyeMsg" },
        { 0x16A, "ToggleCrestMsg" },
        { 0x16B, "ToggleBulkCrestMsg" },
        { 0x16C, "MateriaRemoveMsg" },
        { 0x16D, "GlamourCastMsg" },
        { 0x16E, "GlamourRemoveMsg" },

        // === Retainer/Mailbox (0x170 - 0x1FF) ===
        { 0x170, "RelicInfoMsg" },          // cycleID
        { 0x171, "OpenRetainerBag" },       // cycleID
        { 0x172, "RetainerMsg" },           // cycleID
        { 0x173, "RetainerInfoUpdate" },    // cycleID
        { 0x175, "MailArrived" },           // cycleID
        { 0x176, "MailSent" },              // cycleID
        { 0x177, "MailDeleted" },           // cycleID
        { 0x178, "MailRead" },              // cycleID
        { 0x179, "MailGetItem" },           // cycleID
        { 0x17A, "MailGetGil" },            // cycleID
        { 0x17B, "MailDeliveryQuery" },     // cycleID
        { 0x17C, "MailDeliveryStatus" },    // cycleID
        { 0x17D, "MailReturned" },          // cycleID

        // === PvP Related (0x200 - 0x2FF) ===
        { 0x200, "PvpRankUp" },             // cycleID
        { 0x201, "PvpPointGain" },          // cycleID
        { 0x202, "SetPvpSeriesLevel" },     // cycleID
        { 0x203, "SetPvpSeriesExp" },       // cycleID
        { 0x204, "SetPvpCrystalCredit" },   // cycleID
        { 0x23E, "SetGilLimit" },           // cycleID

        // === Gold Saucer (0x2A0 - 0x2CF) ===
        { 0x2A0, "GoldSaucerUpdate" },      // cycleID
        { 0x2A1, "SetMGP" },                // cycleID (mgp)
        { 0x2A2, "ChocoboRaceResult" },     // cycleID
        { 0x2A3, "SetMGPMax" },             // cycleID
        { 0x2A4, "TripleTriadUpdate" },     // cycleID
        { 0x2A5, "TripleTriadCardObtain" }, // cycleID (cardId)
        { 0x2A6, "LordOfVerminion" },       // cycleID
        { 0x2A7, "MahjongUpdate" },         // cycleID

        // === Treasure/Maps (0x2D0 - 0x2FF) ===
        { 0x2D0, "TreasureSpot" },          // cycleID
        { 0x2D1, "TreasureOpen" },          // cycleID
        { 0x2D2, "TreasureObtainMsg" },     // cycleID
        { 0x2D3, "TreasureDigging" },       // cycleID
        { 0x2D4, "TreasurePortal" },        // cycleID

        // === Housing (0x3E9 - 0x47E) ===
        { 0x3E9, "HousingPlaceItem" },      // cycleID (catalogId, slot)
        { 0x3EA, "HousingMoveItem" },       // cycleID
        { 0x3EB, "HousingRemoveItem" },     // cycleID (catalogId, slot)
        { 0x3EC, "HousingWardInfo" },       // cycleID
        { 0x3ED, "HousingUpdateLand" },     // cycleID
        { 0x3EE, "HousingFurniture" },      // cycleID
        { 0x3EF, "HousingEstateGreeting" }, // cycleID
        { 0x3F0, "HousingEstateName" },     // cycleID
        { 0x3F1, "HousingEstateTag" },      // cycleID
        { 0x3F2, "HousingDyeItem" },        // cycleID
        { 0x3F3, "HousingEditMode" },       // cycleID (enable)
        { 0x3F4, "HousingRotateItem" },     // cycleID
        { 0x3F5, "HousingStorageStatus" },  // cycleID
        { 0x3F6, "HousingUpdateObject" },   // cycleID
        { 0x3F7, "HousingPlaceYard" },      // cycleID
        { 0x3F8, "HousingRemoveYard" },     // cycleID
        { 0x3F9, "HousingMoveYard" },       // cycleID
        { 0x3FA, "HousingHousingFlag" },    // cycleID (flag)
        { 0x3FB, "HousingUpdateState" },    // cycleID
        { 0x3FC, "HousingPlace" },          // cycleID
        { 0x3FD, "HousingInternal" },       // cycleID
        { 0x400, "HousingExterior" },       // cycleID
        { 0x401, "HousingShowEstateGarden" }, // cycleID
        { 0x402, "HousingLotteryInfo" },    // cycleID
        { 0x403, "HousingLotteryResult" },  // cycleID
        { 0x404, "HousingLotteryEntry" },   // cycleID
        { 0x410, "HousingFreeCompanyWorkshop" }, // cycleID
        { 0x411, "HousingFreeCompanySubmarine" }, // cycleID
        { 0x412, "HousingFreeCompanyAirship" }, // cycleID
        { 0x464, "SetSharedGroupParam" },   // cycleID
        { 0x46E, "HousingRoomUpdate" },     // cycleID
        { 0x47E, "HousingOrchestrionPlay" }, // cycleID (songId)

        // === Doman Mahjong (0x4E0 - 0x4FF) ===
        { 0x4E0, "MahjongDiscard" },        // cycleID
        { 0x4E1, "MahjongDraw" },           // cycleID
        { 0x4E2, "MahjongMeld" },           // cycleID
        { 0x4E3, "MahjongReach" },          // cycleID
        { 0x4E4, "MahjongRon" },            // cycleID
        { 0x4E5, "MahjongTsumo" },          // cycleID
        { 0x4E6, "MahjongKan" },            // cycleID

        // === Frontline/PvP Modes (0x5E0 - 0x5EF) ===
        { 0x5DC, "SetBeastClassJob" },      // cycleID
        { 0x5DD, "OpenBeastGauge" },        // cycleID
        { 0x5E0, "PvpSetMatchingState" },   // cycleID
        { 0x5E1, "PvpFrontlineJoin" },      // cycleID
        { 0x5E2, "PvpFrontlineEnd" },       // cycleID
        { 0x5E3, "PvpFrontlineScore" },     // cycleID
        { 0x5E4, "PvpFrontlineRank" },      // cycleID
        { 0x5E5, "PvpRivalWingsJoin" },     // cycleID
        { 0x5E6, "PvpRivalWingsEnd" },      // cycleID
        { 0x5E7, "PvpRivalWingsScore" },    // cycleID
        { 0x5E8, "PvpCrystallineConflict" }, // cycleID
        { 0x5E9, "PvpCCRankPoint" },        // cycleID
        { 0x5EA, "PvpCCMatchResult" },      // cycleID
        { 0x5EB, "PvpCCSeasonEnd" },        // cycleID

        // === Island Sanctuary (0x600 - 0x6FF) ===
        { 0x600, "IslandSanctuaryInit" },   // cycleID
        { 0x601, "IslandSanctuaryGather" }, // cycleID (itemId)
        { 0x602, "IslandSanctuaryCraft" },  // cycleID
        { 0x603, "IslandSanctuaryPasture" }, // cycleID
        { 0x604, "IslandSanctuaryFarm" },   // cycleID
        { 0x605, "IslandSanctuaryWorkshop" }, // cycleID
        { 0x606, "IslandSanctuaryMinion" }, // cycleID
        { 0x607, "IslandSanctuaryWeather" }, // cycleID
        { 0x608, "IslandSanctuaryLandmark" }, // cycleID
        { 0x609, "IslandSanctuaryRank" },   // cycleID
        { 0x60A, "IslandSanctuaryVision" }, // cycleID

        // === Variant/Criterion Dungeons (0x700 - 0x7FF) ===
        { 0x700, "VariantDungeonInit" },    // cycleID
        { 0x701, "VariantDungeonRoute" },   // cycleID
        { 0x702, "VariantDungeonScore" },   // cycleID
        { 0x703, "CriterionDungeonInit" },  // cycleID
        { 0x704, "CriterionDungeonProgress" }, // cycleID
        { 0x705, "CriterionDungeonEnd" },   // cycleID

        // === Misc UI/System (0x800+) ===
        { 0x800, "SetCurrency" },           // cycleID (currencyId, amount)
        { 0x801, "SetWeeklyBonusComplete" }, // cycleID
        { 0x802, "SetDailyBonusComplete" }, // cycleID
        { 0x803, "SetSharedGroup" },        // cycleID
        { 0x810, "SetSearchInfo" },         // cycleID
        { 0x811, "SetSearchComment" },      // cycleID
        { 0x812, "SetPartySearching" },     // cycleID
        { 0x820, "DpsChallenge" },          // cycleID
        { 0x821, "DpsChallengeResult" },    // cycleID
    };
}

const char* LookupOpcodeName(uint16_t opcode,
                             bool outgoing,
                             Net::ConnectionType connectionType) noexcept
{
    const uint16_t ctRaw = static_cast<uint16_t>(connectionType);
    const bool chat = (!Net::IsUnknown(connectionType)) ? IsChatConn(ctRaw) : false;

    if (outgoing) {
        if (chat) {
            if (auto it = kClientChatOpcodes.find(opcode); it != kClientChatOpcodes.end()) return it->second;
        } else {
            if (auto it = kClientZoneOpcodes.find(opcode); it != kClientZoneOpcodes.end()) return it->second;
            if (Net::IsUnknown(connectionType)) {
                if (auto itc = kClientChatOpcodes.find(opcode); itc != kClientChatOpcodes.end()) return itc->second;
            }
        }
    } else {
        if (chat) {
            if (auto it = kServerChatOpcodes.find(opcode); it != kServerChatOpcodes.end()) return it->second;
        } else {
            if (auto it = kServerZoneOpcodes.find(opcode); it != kServerZoneOpcodes.end()) return it->second;
            if (Net::IsUnknown(connectionType)) {
                if (auto its = kServerChatOpcodes.find(opcode); its != kServerChatOpcodes.end()) return its->second;
            }
        }
    }
    return "?";
}

const char* LookupActorControlCategoryName(uint16_t category) noexcept {
    if (auto it = kActorControlCategories.find(category); it != kActorControlCategories.end())
        return it->second;
    return "?";
}
