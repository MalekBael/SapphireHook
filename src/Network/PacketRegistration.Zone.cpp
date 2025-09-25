#include "PacketRegistration.h"
#include "PacketRegistration.Macros.h"
#include "../Network/OpcodeNames.h" 

#include "../ProtocolHandlers/CommonTypes.h"
#include "../ProtocolHandlers/Zone/ServerZoneDef.h"
#include "../ProtocolHandlers/Zone/ClientZoneDef.h"

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <string>
#include <array>
#include <unordered_map>
#include <cstddef> // for offsetof

using namespace PacketDecoding;
using namespace PacketStructures;

// Helper functions for formatting (zone-specific)
namespace PacketDecoding {
    const char* GetActionTypeName(uint8_t type) {
        switch (type) {
        case 1: return "Spell";
        case 2: return "Item";
        case 3: return "KeyItem";
        case 4: return "Ability";
        case 5: return "General";
        case 6: return "Companion";
        case 7: return "Weaponskill";
        case 8: return "Trait";
        case 9: return "CompanionOrder";
        case 10: return "PetAction";
        case 11: return "FieldMarker";
        case 13: return "CraftAction";
        case 15: return "Mount";
        case 17: return "PvPAction";
        case 18: return "Waymark";
        case 19: return "ChocoboRaceAbility";
        case 20: return "ChocoboRaceItem";
        case 21: return "DutyAction";
        case 22: return "PerformanceInstrument";
        case 23: return "Fashion";
        case 24: return "LostAction";
        default: return "Unknown";
        }
    }

    const char* GetStatusEffectName(uint16_t id) {
        switch (id) {
        case 1: return "Weakness";
        case 2: return "Brink of Death";
        case 3: return "Hard Invuln";
        case 4: return "Transcendent";
        case 5: return "Sleep";
        case 6: return "Stun";
        case 7: return "Paralysis";
        case 8: return "Silence";
        case 9: return "Slow";
        case 10: return "Pacification";
        case 11: return "Heavy";
        case 12: return "Bind";
        case 143: return "Aetherflow";
        case 304: return "Energy Drain";
        case 360: return "Swiftcast";
        default: return nullptr;
        }
    }

    const char* GetChatTypeName(uint16_t type) {
        switch (type) {
        case 0x0003: return "Error";
        case 0x0004: return "ServerDebug";
        case 0x0005: return "ServerUrgent";
        case 0x0006: return "ServerNotice";
        case 0x000A: return "Say";
        case 0x000B: return "Shout";
        case 0x000C: return "Tell";
        case 0x000D: return "TellReceive";
        case 0x000E: return "Party";
        case 0x000F: return "Alliance";
        case 0x0010: return "Ls1";
        case 0x0018: return "FreeCompany";
        case 0x001B: return "NoviceNetwork";
        case 0x001E: return "Yell";
        case 0x001F: return "CrossParty";
        case 0x0024: return "PvPTeam";
        case 0x0025: return "CrossLinkShell1";
        case 0x0038: return "Echo";
        case 0x0039: return "SystemMessage";
        default: return "Unknown";
        }
    }

    const char* GetWarpTypeName(uint8_t type) {
        switch (type) {
        case 0x0: return "NON";
        case 0x1: return "NORMAL";
        case 0x2: return "NORMAL_POS";
        case 0x3: return "EXIT_RANGE";
        case 0x4: return "TELEPO";
        case 0x5: return "REISE";
        case 0x8: return "HOME_POINT";
        case 0x9: return "RENTAL_CHOCOBO";
        case 0xA: return "CHOCOBO_TAXI";
        case 0xB: return "INSTANCE_CONTENT";
        case 0xC: return "REJECT";
        case 0xD: return "CONTENT_END_RETURN";
        case 0xE: return "TOWN_TRANSLATE";
        case 0xF: return "GM";
        case 0x10: return "LOGIN";
        case 0x11: return "LAYER_SET";
        case 0x12: return "EMOTE";
        case 0x13: return "HOUSING_TELEPO";
        case 0x14: return "DEBUG";
        default: return "?";
        }
    }

    // Summaries for large arrays to keep UI readable
    template<typename T>
    std::string SummarizeArrayIds(const T* arr, size_t count, size_t maxShow = 5) {
        std::ostringstream os;
        os << count << " [";
        size_t shown = std::min(count, maxShow);
        for (size_t i = 0; i < shown; ++i) {
            if (i) os << ", ";
            os << "0x" << std::hex << std::uppercase << +arr[i];
        }
        if (count > shown) os << ", ...";
        os << "]";
        return os.str();
    }

    inline std::string SummarizeStatusWork(const StatusWork* sw, size_t count, size_t maxShow = 5) {
        std::ostringstream os;
        os << count << " [";
        size_t shown = 0;
        for (size_t i = 0; i < count && shown < maxShow; ++i) {
            if (sw[i].id == 0) continue;
            if (shown++) os << ", ";
            os << "0x" << std::hex << std::uppercase << sw[i].id;
            if (const char* n = GetStatusEffectName(sw[i].id)) os << "(" << n << ")";
        }
        if (shown == 0) os << "none";
        else if (count > shown) os << ", ...";
        os << "]";
        return os.str();
    }

    inline std::string SummarizeCalcResults(const CalcResult* cr, size_t count, size_t maxShow = 3) {
        std::ostringstream os;
        os << count << " [";
        for (size_t i = 0; i < count && i < maxShow; ++i) {
            if (i) os << ", ";
            os << "hpΔ=" << std::dec << (int)cr[i].value;
        }
        if (count > maxShow) os << ", ...";
        os << "]";
        return os.str();
    }
}

// NOTE: Removed bringing client zone namespace into scope to avoid ambiguity
void PacketDecoding::RegisterZonePackets() {
    using namespace PacketStructures::Server::Zone;
    // using namespace PacketStructures::Client::Zone; // removed to resolve ambiguous FFXIVIpcConfig / Housing* names

    // ================= CORE / SESSION =================
    REGISTER_PACKET(1, false, 0x0065, FFXIVIpcSync,
        FIELD("ClientTimeValue", FieldToString(pkt->clientTimeValue)),
        FIELD("TransmissionInterval", FieldToString(pkt->transmissionInterval)),
        FIELD("OriginEntityId", FormatHex(pkt->position.originEntityId)),
        FIELD("Position", FormatPosition(pkt->position.pos[0], pkt->position.pos[1], pkt->position.pos[2])),
        FIELD("Direction", FormatAngle(pkt->position.dir))
    );

    REGISTER_PACKET(1, false, 0x0066, FFXIVIpcLogin,
        FIELD("ClientTimeValue", FieldToString(pkt->clientTimeValue)),
        FIELD("LoginTicketId", FormatHex(pkt->loginTicketId)),
        FIELD("PlayerActorId", FormatHex(pkt->playerActorId))
    );

    REGISTER_PACKET(1, false, 0x02D6, FFXIVIpcEnableLogout,
        FIELD("Content", FieldToString(pkt->content))
    );

    // ================= CHAT / SOCIAL =================
    REGISTER_PACKET(1, false, 0x0067, FFXIVIpcChat,
        FIELD("Type", FieldToString(pkt->type) + " (" + GetChatTypeName(pkt->type) + ")"),
        FIELD("EntityId", FormatHex(pkt->entityId)),
        FIELD("CharacterId", FormatHex(pkt->characterId)),
        FIELD("Speaker", FormatString(pkt->speakerName, 32)),
        FIELD("Message", FormatString(pkt->message, std::min<size_t>(200, sizeof(pkt->message))))
    );

    REGISTER_PACKET(1, false, 0x00CC, FFXIVIpcGetCommonlistResult,
        FIELD("CommunityId", FormatHex(pkt->CommunityID)),
        FIELD("Index", FieldToString(pkt->Index)),
        FIELD("NextIndex", FieldToString(pkt->NextIndex)),
        FIELD("ListType", FieldToString(pkt->ListType)),
        FIELD("Entry0Name", FormatString(pkt->entries[0].CharacterName, 32))
    );

    REGISTER_PACKET(1, false, 0x00CD, FFXIVIpcGetCommonlistDetailResult,
        FIELD("DetailCharacterID", FormatHex(pkt->DetailCharacterID)),
        FIELD("CommunityID", FormatHex(pkt->CommunityID)),
        FIELD("SelectClassID", FormatHex(pkt->SelectClassID)),
        FIELD("SearchComment", FormatString(pkt->SearchComment, 60)),
        FIELD("FirstClassJobId", FieldToString(pkt->ClassData[0].id))
    );

    REGISTER_PACKET(1, false, 0x00EB, FFXIVIpcPcSearchResult,
        FIELD("ResultCount", FieldToString(pkt->ResultCount))
    );

    REGISTER_PACKET(1, false, 0x00F0, FFXIVIpcLinkshellResult,
        FIELD("LinkshellID", FormatHex(pkt->LinkshellID)),
        FIELD("Result", FieldToString(pkt->Result)),
        FIELD("TargetName", FormatString(pkt->TargetName, 32))
    );

    REGISTER_PACKET(1, false, 0x00C9, FFXIVIpcInviteResult,
        FIELD("Result", FieldToString(pkt->Result)),
        FIELD("AuthType", FieldToString(pkt->AuthType)),
        FIELD("TargetName", FormatString(pkt->TargetName, 32))
    );

    REGISTER_PACKET(1, false, 0x00CA, FFXIVIpcInviteReplyResult,
        FIELD("Result", FieldToString(pkt->Result)),
        FIELD("Answer", FieldToString(pkt->Answer)),
        FIELD("InviteCharacter", FormatString(pkt->InviteCharacterName, 32))
    );

    REGISTER_PACKET(1, false, 0x00CB, FFXIVIpcInviteUpdate,
        FIELD("InviteCharacterID", FormatHex(pkt->InviteCharacterID)),
        FIELD("InviteTime", FieldToString(pkt->InviteTime)),
        FIELD("InviteName", FormatString(pkt->InviteName, 32))
    );

    REGISTER_PACKET(1, false, 0x00E6, FFXIVIpcFriendlistRemoveResult,
        FIELD("RemovedCharacterID", FormatHex(pkt->RemovedCharacterID)),
        FIELD("Result", FieldToString(pkt->Result)),
        FIELD("RemovedName", FormatString(pkt->RemovedCharacterName, 32))
    );

    REGISTER_PACKET(1, false, 0x00E1, FFXIVIpcBlacklistAddResult,
        FIELD("AddedCharacterID", FormatHex(pkt->AddedCharacter.CharacterID)),
        FIELD("CharacterName", FormatString(pkt->AddedCharacter.CharacterName, 32)),
        FIELD("Result", FieldToString(pkt->Result))
    );

    REGISTER_PACKET(1, false, 0x00E2, FFXIVIpcBlacklistRemoveResult,
        FIELD("RemovedCharacterID", FormatHex(pkt->RemovedCharacter.CharacterID)),
        FIELD("CharacterName", FormatString(pkt->RemovedCharacter.CharacterName, 32)),
        FIELD("Result", FieldToString(pkt->Result))
    );

    REGISTER_PACKET(1, false, 0x00E3, FFXIVIpcGetBlacklistResult,
        FIELD("Count", FieldToString((int)20)),
        FIELD("Index", FieldToString(pkt->Index)),
        FIELD("NextIndex", FieldToString(pkt->NextIndex))
    );

    REGISTER_PACKET(1, false, 0x00F1, FFXIVIpcGetLinkshellListResult,
        FIELD("FirstLinkshellID", FormatHex(pkt->LinkshellList[0].LinkshellID))
    );

    REGISTER_PACKET(1, false, 0x00D2, FFXIVIpcChatChannelResult,
        FIELD("ChannelID", FormatHex(pkt->ChannelID)),
        FIELD("CommunityID", FormatHex(pkt->CommunityID)),
        FIELD("Result", FieldToString(pkt->Result))
    );

    REGISTER_PACKET(1, false, 0x00D5, FFXIVIpcSetOnlineStatus,
        FIELD("OnlineStatusFlags", FormatHex(pkt->onlineStatusFlags))
    );

    // Profile / Search comment
    REGISTER_PACKET(1, false, 0x00CE, FFXIVIpcSetProfileResult,
        FIELD("Result", FieldToString(pkt->Result)),
        FIELD("Region", FieldToString(pkt->Region)),
        FIELD("Comment", FormatString(pkt->SearchComment, 60))
    );

    REGISTER_PACKET(1, false, 0x00CF, FFXIVIpcGetProfileResult,
        FIELD("Region", FieldToString(pkt->Region)),
        FIELD("Comment", FormatString(pkt->SearchComment, 60))
    );

    REGISTER_PACKET(1, false, 0x00D0, FFXIVIpcGetSearchCommentResult,
        FIELD("TargetEntityID", FormatHex(pkt->TargetEntityID)),
        FIELD("Comment", FormatString(pkt->SearchComment, 60))
    );

    REGISTER_PACKET(1, false, 0x00D1, FFXIVIpcGetCharacterNameResult,
        FIELD("CharacterID", FormatHex(pkt->CharacterID)),
        FIELD("Name", FormatString(pkt->CharacterName, 32))
    );

    // System / Messages
    REGISTER_PACKET(1, false, 0x00D3, FFXIVIpcSendSystemMessage,
        FIELD("MessageParam", FieldToString(pkt->MessageParam)),
        FIELD("Message", FormatString(pkt->Message, 120))
    );

    REGISTER_PACKET(1, false, 0x00D4, FFXIVIpcSendLoginMessage,
        FIELD("MessageParam", FieldToString(pkt->MessageParam)),
        FIELD("Message", FormatString(pkt->Message, 120))
    );

    // Achievement
    REGISTER_PACKET(1, false, 0x02DD, FFXIVIpcAchievement,
        FIELD("CompleteMaskFirstByte", FormatHex(pkt->complete[0])),
        FIELD("History0", FieldToString(pkt->history[0]))
    );

    // ================= MAIL =================
    REGISTER_PACKET(1, false, 0x00FB, FFXIVIpcGetLetterMessageResult,
        FIELD("FirstSender", FormatHex(pkt->LetterMessage[0].SenderCharacterID)),
        FIELD("FirstMessage", FormatString(pkt->LetterMessage[0].Message, 40)),
        FIELD("NextIndex", FieldToString(pkt->NextIndex))
    );

    REGISTER_PACKET(1, false, 0x00FC, FFXIVIpcGetLetterMessageDetailResult,
        FIELD("SenderCharacterID", FormatHex(pkt->SenderCharacterID)),
        FIELD("Message", FormatString(pkt->Message, 80))
    );

    REGISTER_PACKET(1, false, 0x00FA, FFXIVIpcLetterResult,
        FIELD("SenderCharacterID", FormatHex(pkt->SenderCharacterID)),
        FIELD("Result", FieldToString(pkt->Result))
    );

    REGISTER_PACKET(1, false, 0x00FD, FFXIVIpcGetLetterStatusResult,
        FIELD("UnreadCount", FieldToString(pkt->UnreadCount)),
        FIELD("TotalCount", FieldToString(pkt->TotalCount)),
        FIELD("ItemCount", FieldToString(pkt->ItemCount))
    );

    // ================= MARKET / ITEM SEARCH =================
    REGISTER_PACKET(1, false, 0x0105, FFXIVIpcGetItemSearchListResult,
        FIELD("FirstCatalogID", FieldToString(pkt->ItemSearchList[0].CatalogID)),
        FIELD("FirstPrice", FieldToString(pkt->ItemSearchList[0].SellPrice)),
        FIELD("Index", FieldToString(pkt->Index))
    );

    REGISTER_PACKET(1, false, 0x0109, FFXIVIpcGetItemHistoryResult,
        FIELD("CatalogID", FieldToString(pkt->CatalogID)),
        FIELD("FirstHistoryPrice", FieldToString(pkt->ItemHistoryList[0].SellPrice))
    );

    REGISTER_PACKET(1, false, 0x010C, FFXIVIpcCatalogSearchResult,
        FIELD("FirstCatalogID", FieldToString(pkt->CatalogList[0].CatalogID)),
        FIELD("Result", FieldToString(pkt->Result)),
        FIELD("Index", FieldToString(pkt->Index))
    );

    // ================= COMBAT / ACTIONS =================
    REGISTER_PACKET(1, false, 0x0141, FFXIVIpcActionIntegrity,
        FIELD("ResultId", FieldToString(pkt->ResultId)),
        FIELD("Target", FormatHex(pkt->Target)),
        FIELD("StatusCount", FieldToString(pkt->StatusCount)),
        FIELD("FirstStatusId", FormatHex(pkt->Status[0].Id))
    );

    REGISTER_PACKET(1, false, 0x0142, FFXIVIpcActorControl,
        FIELD("Category", FieldToString(pkt->category) + " (" + std::string(::LookupActorControlCategoryName(pkt->category)) + ")"),
        FIELD("Param1", FormatHex(pkt->param1)),
        FIELD("Param2", FormatHex(pkt->param2)),
        FIELD("Param3", FormatHex(pkt->param3)),
        FIELD("Param4", FormatHex(pkt->param4))
    );

    REGISTER_PACKET(1, false, 0x0143, FFXIVIpcActorControlSelf,
        FIELD("Category", FieldToString(pkt->category) + " (" + std::string(::LookupActorControlCategoryName(pkt->category)) + ")"),
        FIELD("Param1", FormatHex(pkt->param1)),
        FIELD("Param2", FormatHex(pkt->param2)),
        FIELD("Param3", FormatHex(pkt->param3)),
        FIELD("Param4", FormatHex(pkt->param4)),
        FIELD("Param5", FormatHex(pkt->param5)),
        FIELD("Param6", FormatHex(pkt->param6))
    );

    REGISTER_PACKET(1, false, 0x0144, FFXIVIpcActorControlTarget,
        FIELD("Category", FieldToString(pkt->category) + " (" + std::string(::LookupActorControlCategoryName(pkt->category)) + ")"),
        FIELD("Param1", FormatHex(pkt->param1)),
        FIELD("Param2", FormatHex(pkt->param2)),
        FIELD("Param3", FormatHex(pkt->param3)),
        FIELD("Param4", FormatHex(pkt->param4)),
        FIELD("TargetId", FormatHex(pkt->targetId))
    );

    REGISTER_PACKET(1, false, 0x0145, FFXIVIpcResting,
        FIELD("Hp", FieldToString(pkt->Hp)),
        FIELD("Mp", FieldToString(pkt->Mp)),
        FIELD("Tp", FieldToString(pkt->Tp))
    );

    REGISTER_PACKET(1, false, 0x0146, FFXIVIpcActionResult1,
        FIELD("Action", FieldToString(pkt->Action)),
        FIELD("ActionKind", FieldToString(pkt->ActionKind)),
        FIELD("RequestId", FieldToString(pkt->RequestId)),
        FIELD("ResultId", FieldToString(pkt->ResultId)),
        FIELD("Target", FormatHex(pkt->Target)),
        FIELD("Flag", FormatHex(pkt->Flag))
    );

    REGISTER_PACKET(1, false, 0x0147, FFXIVIpcActionResult,
        FIELD("Action", FieldToString(pkt->Action)),
        FIELD("ActionKind", FieldToString(pkt->ActionKind)),
        FIELD("RequestId", FieldToString(pkt->RequestId)),
        FIELD("ResultId", FieldToString(pkt->ResultId)),
        FIELD("MainTarget", FormatHex(pkt->MainTarget)),
        FIELD("TargetCount", FieldToString(pkt->TargetCount)),
        FIELD("CalcResults", SummarizeCalcResults(pkt->CalcResult, 16))
    );

    REGISTER_PACKET(1, false, 0x0148, FFXIVIpcStatus,
        FIELD("StatusSummary", SummarizeStatusWork(pkt->effect, 30))
    );

    REGISTER_PACKET(1, false, 0x0149, FFXIVIpcFreeCompany,
        FIELD("Crest", FormatHex(pkt->Crest)),
        FIELD("Tag", FormatString(pkt->Tag, 6))
    );

    REGISTER_PACKET(1, false, 0x014A, FFXIVIpcRecastGroup,
        FIELD("FirstRecast", FieldToString(pkt->Recast[0])),
        FIELD("FirstRecastMax", FieldToString(pkt->RecastMax[0]))
    );

    // ================= PARTY / ALLIANCE =================
    REGISTER_PACKET(1, false, 0x0199, FFXIVIpcUpdateParty,
        FIELD("PartyID", FormatHex(pkt->PartyID)),
        FIELD("AllianceFlags", FormatHex(pkt->AllianceFlags)),
        FIELD("Member0Name", FormatString(pkt->Member[0].Name, 32))
    );

    REGISTER_PACKET(1, false, 0x14B, FFXIVIpcUpdateAlliance,
        FIELD("AllianceFlags", FormatHex(pkt->AllianceFlags)),
        FIELD("AllianceLocalIndex", FieldToString(pkt->AllianceLocalIndex)),
        FIELD("AllianceMemberCount", FieldToString(pkt->AllianceMemberCount))
    );

    REGISTER_PACKET(1, false, 0x14C, FFXIVIpcPartyPos,
        FIELD("Index", FieldToString(pkt->Index)),
        FIELD("TerritoryType", FieldToString(pkt->TerritoryType)),
        FIELD("Pos", FormatPosition(pkt->X, pkt->Y, pkt->Z)),
        FIELD("EntityId", FormatHex(pkt->EntityId))
    );

    REGISTER_PACKET(1, false, 0x14D, FFXIVIpcAlliancePos,
        FIELD("AllianceIndex", FieldToString(pkt->AllianceIndex)),
        FIELD("PartyIndex", FieldToString(pkt->PartyIndex)),
        FIELD("Pos", FormatPosition(pkt->X, pkt->Y, pkt->Z)),
        FIELD("EntityId", FormatHex(pkt->EntityId))
    );

    REGISTER_PACKET(1, false, 0x14F, FFXIVIpcGrandCompany,
        FIELD("GrandCompany", FieldToString(pkt->GrandCompany)),
        FIELD("Rank", FieldToString(pkt->GrandCompanyRank))
    );

    // ================= MOVEMENT / SPAWN =================
    REGISTER_PACKET(1, false, 0x0190, FFXIVIpcPlayerSpawn,
        FIELD("LayoutId", FieldToString(pkt->LayoutId)),
        FIELD("NameId", FieldToString(pkt->NameId)),
        FIELD("ObjKind", FieldToString(pkt->ObjKind)),
        FIELD("ClassJob", FieldToString(pkt->ClassJob)),
        FIELD("Level", FieldToString(pkt->Lv)),
        FIELD("HP", FieldToString(pkt->Hp)),
        FIELD("Pos", FormatPosition(pkt->Pos[0], pkt->Pos[1], pkt->Pos[2]))
    );

    REGISTER_PACKET(1, false, 0x0191, FFXIVIpcActorFreeSpawn,
        FIELD("SpawnId", FormatHex(pkt->spawnId)),
        FIELD("ActorId", FormatHex(pkt->actorId))
    );

    REGISTER_PACKET(1, false, 0x0192, FFXIVIpcActorMove,
        FIELD("Dir", FieldToString(pkt->dir)),
        FIELD("Flag", FormatHex(pkt->flag)),
        FIELD("Speed", FieldToString(pkt->speed)),
        FIELD("Pos", std::string("(") + std::to_string(pkt->pos[0]) + "," + std::to_string(pkt->pos[1]) + "," + std::to_string(pkt->pos[2]) + ")")
    );

    REGISTER_PACKET(1, false, 0x0193, FFXIVIpcTransfer,
        FIELD("Dir", FieldToString(pkt->dir)),
        FIELD("Duration", FieldToString(pkt->duration)),
        FIELD("Flag", FormatHex(pkt->flag))
    );

    REGISTER_PACKET(1, false, 0x0194, FFXIVIpcWarp,
        FIELD("Dir", FieldToString(pkt->Dir)),
        FIELD("Type", FieldToString(pkt->Type) + " (" + GetWarpTypeName(pkt->Type) + ")"),
        FIELD("LayerSet", FormatHex(pkt->LayerSet)),
        FIELD("Pos", FormatPosition(pkt->x, pkt->y, pkt->z))
    );

    REGISTER_PACKET(1, false, 0x0196, FFXIVIpcActorCast,
        FIELD("Action", FieldToString(pkt->Action)),
        FIELD("ActionKind", FieldToString(pkt->ActionKind)),
        FIELD("ActionKey", FieldToString(pkt->ActionKey)),
        FIELD("CastTime", FieldToString(pkt->CastTime)),
        FIELD("Target", FormatHex(pkt->Target))
    );

    // ================= ZONE / PLAYER STATE =================
    REGISTER_PACKET(1, false, 0x019A, FFXIVIpcInitZone,
        FIELD("ZoneId", FieldToString(pkt->ZoneId)),
        FIELD("TerritoryType", FieldToString(pkt->TerritoryType)),
        FIELD("LayerSetId", FormatHex(pkt->LayerSetId)),
        FIELD("LayoutId", FieldToString(pkt->LayoutId)),
        FIELD("WeatherId", FieldToString(pkt->WeatherId)),
        FIELD("Pos", FormatPosition(pkt->Pos[0], pkt->Pos[1], pkt->Pos[2]))
    );

    REGISTER_PACKET(1, false, 0x01A0, FFXIVIpcPlayerStatus,
        FIELD("CharaId", FormatHex(pkt->CharaId)),
        FIELD("ClassJob", FieldToString(pkt->ClassJob)),
        FIELD("Race", FieldToString(pkt->Race)),
        FIELD("FirstLevel", FieldToString(pkt->Lv[0])),
        FIELD("AetheryteMask0", FormatHex(pkt->Aetheryte[0]))
    );

    REGISTER_PACKET(1, false, 0x01A1, FFXIVIpcBaseParam,
        FIELD("Param0", FieldToString(pkt->Param[0])),
        FIELD("Param1", FieldToString(pkt->Param[1])),
        FIELD("Original0", FieldToString(pkt->OriginalParam[0]))
    );

    REGISTER_PACKET(1, false, 0x01A2, FFXIVIpcFirstAttack,
        FIELD("Type", FieldToString(pkt->Type)),
        FIELD("Id", FormatHex(pkt->Id))
    );

    REGISTER_PACKET(1, false, 0x01A3, FFXIVIpcCondition,
        FIELD("FlagBytesFirst", FormatHex(pkt->flags[0])),
        FIELD("Padding", FormatHex(pkt->padding))
    );

    REGISTER_PACKET(1, false, 0x01A4, FFXIVIpcChangeClass,
        FIELD("ClassJob", FieldToString(pkt->ClassJob)),
        FIELD("Penalty", FieldToString(pkt->Penalty)),
        FIELD("Lv", FieldToString(pkt->Lv)),
        FIELD("BorrowAction0", FieldToString(pkt->BorrowAction[0]))
    );

    REGISTER_PACKET(1, false, 0x01A5, FFXIVIpcEquip,
        FIELD("MainWeapon", FormatHex(pkt->MainWeapon)),
        FIELD("SubWeapon", FormatHex(pkt->SubWeapon)),
        FIELD("CrestEnable", FieldToString(pkt->CrestEnable)),
        FIELD("Equipment0", FormatHex(pkt->Equipment[0]))
    );

    REGISTER_PACKET(1, false, 0x01A6, FFXIVIpcInspect,
        FIELD("Name", FormatString(pkt->Name, 32)),
        FIELD("ClassJob", FieldToString(pkt->ClassJob)),
        FIELD("Lv", FieldToString(pkt->Lv)),
        FIELD("ItemLv", FieldToString(pkt->ItemLv)),
        FIELD("FirstEquipCatalogId", FieldToString(pkt->Equipment[0].CatalogId))
    );

    REGISTER_PACKET(1, false, 0x01A7, FFXIVIpcName,
        FIELD("ContentId", FormatHex(pkt->contentId)),
        FIELD("Name", FormatString(pkt->name, 32))
    );

    // ================= INVENTORY / ITEMS =================
    REGISTER_PACKET(1, false, 0x01AE, FFXIVIpcItemStorage,
        FIELD("ContextId", FormatHex(pkt->contextId)),
        FIELD("StorageId", FieldToString(pkt->storage.storageId)),
        FIELD("ContainerSize", FieldToString(pkt->storage.containerSize))
    );

    REGISTER_PACKET(1, false, 0x01AF, FFXIVIpcNormalItem,
        FIELD("ContextId", FormatHex(pkt->contextId)),
        FIELD("StorageId", FieldToString(pkt->item.storageId)),
        FIELD("ContainerIndex", FieldToString(pkt->item.containerIndex)),
        FIELD("Stack", FieldToString(pkt->item.stack)),
        FIELD("CatalogId", FieldToString(pkt->item.catalogId)),
        FIELD("Durability", FieldToString(pkt->item.durability)),
        FIELD("Refine", FieldToString(pkt->item.refine)),
        FIELD("Stain", FieldToString(pkt->item.stain)),
        FIELD("Pattern", FormatHex(pkt->item.pattern)),
        FIELD("MateriaTypes0_4", FieldToString(pkt->item.materiaType[0]) + "," +
                                 FieldToString(pkt->item.materiaType[1]) + "," +
                                 FieldToString(pkt->item.materiaType[2]) + "," +
                                 FieldToString(pkt->item.materiaType[3]) + "," +
                                 FieldToString(pkt->item.materiaType[4])),
        FIELD("MateriaGrades0_4", FieldToString(pkt->item.materiaGrade[0]) + "," +
                                  FieldToString(pkt->item.materiaGrade[1]) + "," +
                                  FieldToString(pkt->item.materiaGrade[2]) + "," +
                                  FieldToString(pkt->item.materiaGrade[3]) + "," +
                                  FieldToString(pkt->item.materiaGrade[4]))
    );

    REGISTER_PACKET(1, false, 0x01B6, FFXIVIpcUpdateItem,
        FIELD("ContextId", FormatHex(pkt->contextId)),
        FIELD("StorageId", FieldToString(pkt->item.storageId)),
        FIELD("CatalogId", FieldToString(pkt->item.catalogId)),
        FIELD("Stack", FieldToString(pkt->item.stack))
    );

    REGISTER_PACKET(1, false, 0x01B0, FFXIVIpcItemSize,
        FIELD("ContextId", FormatHex(pkt->contextId)),
        FIELD("StorageId", FieldToString(pkt->storageId)),
        FIELD("Size", FieldToString(pkt->size))
    );

    REGISTER_PACKET(1, false, 0x01B1, FFXIVIpcItemOperationBatch,
        FIELD("ContextId", FormatHex(pkt->contextId)),
        FIELD("OperationId", FieldToString(pkt->operationId)),
        FIELD("OperationType", FieldToString(pkt->operationType)),
        FIELD("ErrorType", FieldToString(pkt->errorType)),
        FIELD("PacketNum", FieldToString(pkt->packetNum)),
        FIELD("_all", DumpAllFields(pkt, gItemOperationBatchFields,
                                    std::size(gItemOperationBatchFields)))
    );

    REGISTER_PACKET(1, false, 0x01B2, FFXIVIpcItemOperation,
        FIELD("OperationTypeRaw", FieldToString(pkt->operationType)),
        FIELD("Heuristic", ClassifyItemOperation(pkt)),                   // keep your heuristic
        FIELD("_all", DumpAllFields(pkt, gItemOperationFields,
                                    std::size(gItemOperationFields))),
        FIELD("Raw48Bytes", DumpBytes(pkt, sizeof(*pkt)))
    );

    REGISTER_PACKET(1, false, 0x01B3, FFXIVIpcGilItem,
        FIELD("ContextId", FormatHex(pkt->contextId)),
        FIELD("StorageId", FieldToString(pkt->item.storageId)),
        FIELD("Stack", FieldToString(pkt->item.stack))
    );

    // ================= EVENT / QUESTS =================
    REGISTER_PACKET(1, false, 0x01C1, FFXIVIpcMonsterNoteCategory,
        FIELD("ContextId", FormatHex(pkt->contextId)),
        FIELD("CategoryIndex", FieldToString(pkt->categoryIndex)),
        FIELD("CurrentRank", FieldToString(pkt->currentRank)),
        FIELD("CompleteFlags", FormatHex(pkt->completeFlags))
    );

    REGISTER_PACKET(1, false, 0x01CC, FFXIVIpcEventStart,
        FIELD("TargetId", FormatHex(pkt->targetId)),
        FIELD("HandlerId", FieldToString(pkt->handlerId)),
        FIELD("Event", FieldToString(pkt->event)),
        FIELD("Flags", FormatHex(pkt->flags)),
        FIELD("EventArg", FormatHex(pkt->eventArg))
    );

    REGISTER_PACKET(1, false, 0x01CD, FFXIVIpcEventFinish,
        FIELD("HandlerId", FieldToString(pkt->handlerId)),
        FIELD("Event", FieldToString(pkt->event)),
        FIELD("Result", FieldToString(pkt->result)),
        FIELD("EventArg", FormatHex(pkt->eventArg))
    );

    REGISTER_PACKET(1, false, 0x01E0, FFXIVIpcQuests,
        FIELD("FirstQuestId", FieldToString(pkt->activeQuests[0].questId)),
        FIELD("Quest0Index", FieldToString(pkt->activeQuests[0].index))
    );

    REGISTER_PACKET(1, false, 0x01E1, FFXIVIpcQuest,
        FIELD("Index", FieldToString(pkt->index)),
        FIELD("QuestId", FieldToString(pkt->questInfo.questId)),
        FIELD("QuestIndex", FieldToString(pkt->questInfo.index))
    );

    REGISTER_PACKET(1, false, 0x01E2, FFXIVIpcQuestCompleteList,
        FIELD("QuestCompleteMask0", FormatHex(pkt->questCompleteMask[0])),
        FIELD("UnknownMask0", FormatHex(pkt->unknownCompleteMask[0]))
    );

    REGISTER_PACKET(1, false, 0x01E3, FFXIVIpcQuestFinish,
        FIELD("QuestId", FieldToString(pkt->questId)),
        FIELD("Flag1", FieldToString(pkt->flag1)),
        FIELD("Flag2", FieldToString(pkt->flag2))
    );

    REGISTER_PACKET(1, false, 0x0320, FFXIVIpcDailyQuests,
        FIELD("Update", FieldToString(pkt->update)),
        FIELD("FirstDailyQuestId", FieldToString(pkt->dailyQuestArray[0].questId))
    );

    REGISTER_PACKET(1, false, 0x0322, FFXIVIpcQuestRepeatFlags,
        FIELD("Update", FieldToString(pkt->update)),
        FIELD("FirstRepeatFlagByte", FormatHex(pkt->repeatFlagArray[0]))
    );

    REGISTER_PACKET(1, false, 0x1EE, FFXIVIpcQuestTracker,
        FIELD("Entry0Active", FieldToString(pkt->entry[0].active)),
        FIELD("Entry0QuestIndex", FieldToString(pkt->entry[0].questIndex))
    );

    // ================= WEATHER / DISCOVERY =================
    REGISTER_PACKET(1, false, 0x28A, FFXIVIpcWeatherId,
        FIELD("WeatherId", FieldToString(pkt->WeatherId)),
        FIELD("TransitionTime", FieldToString(pkt->TransitionTime))
    );

    REGISTER_PACKET(1, false, 0x28C, FFXIVIpcDiscoveryReply,
        FIELD("MapPartId", FieldToString(pkt->mapPartId)),
        FIELD("MapId", FieldToString(pkt->mapId))
    );

    // ================= MOVES / TERRITORY =================
    REGISTER_PACKET(1, false, 0x006A, FFXIVIpcMoveTerritory,
        FIELD("Index", FieldToString(pkt->index)),
        FIELD("TerritoryType", FieldToString(pkt->territoryType)),
        FIELD("ZoneId", FieldToString(pkt->zoneId)),
        FIELD("WorldName", FormatString(pkt->worldName, 32))
    );

    REGISTER_PACKET(1, false, 0x006B, FFXIVIpcMoveInstance,
        FIELD("CharacterId", FormatHex(pkt->characterId)),
        FIELD("EntityId", FormatHex(pkt->entityId)),
        FIELD("WorldId", FieldToString(pkt->worldId))
    );

    // ================= DUTY / MATCHING =================
    REGISTER_PACKET(1, false, 0x2E4, FFXIVIpcUpdateContent,
        FIELD("TerritoryType", FieldToString(pkt->territoryType)),
        FIELD("Kind", FieldToString(pkt->kind)),
        FIELD("Value1", FieldToString(pkt->value1)),
        FIELD("Value2", FieldToString(pkt->value2))
    );

    REGISTER_PACKET(1, false, 0x2DB, FFXIVIpcUpdateFindContent,
        FIELD("Kind", FieldToString(pkt->kind)),
        FIELD("Value1", FieldToString(pkt->value1)),
        FIELD("TerritoryType", FieldToString(pkt->territoryType))
    );

    REGISTER_PACKET(1, false, 0x2DE, FFXIVIpcNotifyFindContentStatus,
        FIELD("TerritoryType", FieldToString(pkt->territoryType)),
        FIELD("Status", FieldToString(pkt->status)),
        FIELD("TankCount", FieldToString(pkt->tankRoleCount)),
        FIELD("HealerCount", FieldToString(pkt->healerRoleCount)),
        FIELD("DpsCount", FieldToString(pkt->dpsRoleCount))
    );

    REGISTER_PACKET(1, false, 0x339, FFXIVIpcFinishContentMatchToClient,
        FIELD("ClassJob", FieldToString(pkt->classJob)),
        FIELD("Progress", FieldToString(pkt->progress)),
        FIELD("PlayerNum", FieldToString(pkt->playerNum)),
        FIELD("TerritoryType", FieldToString(pkt->territoryType))
    );

    REGISTER_PACKET(1, false, 0x02E3, FFXIVIpcContentAttainFlags,
        FIELD("RaidFlags0", FormatHex(pkt->raidAttainFlag[0])),
        FIELD("DungeonFlags0", FormatHex(pkt->dungeonAttainFlag[0]))
    );

    REGISTER_PACKET(1, false, 0x311, FFXIVIpcContentBonus,
        FIELD("BonusRoles0", FormatHex(pkt->bonusRoles[0]))
    );

    REGISTER_PACKET(1, false, 0x2E1, FFXIVIpcResponsePenalties,
        FIELD("Penalty0", FieldToString(pkt->penalties[0])),
        FIELD("Penalty1", FieldToString(pkt->penalties[1]))
    );

    // ================= CONFIG / TIME =================
    REGISTER_PACKET(1, false, 0x2C6, FFXIVIpcConfig,
        FIELD("Flag", FormatHex(pkt->flag))
    );

    REGISTER_PACKET(1, false, 0x28D, FFXIVIpcEorzeaTimeOffset,
        FIELD("Timestamp", FieldToString(pkt->timestamp))
    );

    // ================= MOUNT / DIRECTOR =================
    REGISTER_PACKET(1, false, 0x0200, FFXIVIpcMount,
        FIELD("MountId", FieldToString(pkt->id))
    );

    REGISTER_PACKET(1, false, 0x226, FFXIVIpcDirectorVars,
        FIELD("DirectorId", FormatHex(pkt->directorId)),
        FIELD("Sequence", FieldToString(pkt->sequence)),
        FIELD("Flags", FormatHex(pkt->flags))
    );

    // ================= HOUSING =================
    REGISTER_PACKET(1, false, 0x2EC, FFXIVIpcHouseList,
        FIELD("Subdivision", FieldToString(pkt->Subdivision)),
        FIELD("FirstHousePrice", FieldToString(pkt->Houses[0].housePrice))
    );

    REGISTER_PACKET(1, false, 0x2ED, FFXIVIpcHouse,
        FIELD("Block", FieldToString(pkt->Block)),
        FIELD("HousePrice", FieldToString(pkt->House.housePrice)),
        FIELD("InfoFlags", FieldToString(pkt->House.infoFlags))
    );

    REGISTER_PACKET(1, false, 0x2EE, FFXIVIpcYardObjectList,
        FIELD("PacketIndex", FieldToString(pkt->PacketIndex)),
        FIELD("FirstObjectItemId", FieldToString(pkt->YardObjects[0].itemId))
    );

    REGISTER_PACKET(1, false, 0x2F0, FFXIVIpcYardObject,
        FIELD("PacketIndex", FieldToString(pkt->PacketIndex)),
        FIELD("ItemId", FieldToString(pkt->YardObject.itemId))
    );

    REGISTER_PACKET(1, false, 0x2F1, FFXIVIpcInterior,
        FIELD("Window", FieldToString(pkt->Window)),
        FIELD("Door", FieldToString(pkt->Door)),
        FIELD("InteriorItem0", FieldToString(pkt->Interior[0]))
    );

    REGISTER_PACKET(1, false, 0x2F2, FFXIVIpcHousingAuction,
        FIELD("Price", FieldToString(pkt->Price)),
        FIELD("Timer", FieldToString(pkt->Timer))
    );

    REGISTER_PACKET(1, false, 0x2F3, FFXIVIpcHousingProfile,
        FIELD("LandId", FieldToString(pkt->LandId.landId)),
        FIELD("OwnerId", FormatHex(pkt->OwnerId)),
        FIELD("Like", FieldToString(pkt->Like)),
        FIELD("Name", FormatString(pkt->Name, 23))
    );

    REGISTER_PACKET(1, false, 0x2F4, FFXIVIpcHousingHouseName,
        FIELD("LandId", FieldToString(pkt->LandId.landId)),
        FIELD("Name", FormatString(pkt->Name, 23))
    );

    REGISTER_PACKET(1, false, 0x2F5, FFXIVIpcHousingGreeting,
        FIELD("LandId", FieldToString(pkt->LandId.landId)),
        FIELD("GreetingFirstBytes", FieldToString(pkt->Greeting[0]))
    );

    REGISTER_PACKET(1, false, 0x2F6, FFXIVIpcCharaHousingLandData,
        FIELD("Index", FieldToString(pkt->Index)),
        FIELD("LandId", FieldToString(pkt->LandData.landIdent.landId))
    );

    REGISTER_PACKET(1, false, 0x2F7, FFXIVIpcCharaHousing,
        FIELD("FcLandId", FieldToString(pkt->FcLands.landIdent.landId)), // Change landId to landIdent.landId
        FIELD("CharaLandId", FieldToString(pkt->CharaLands.landIdent.landId)) // Change landId to landIdent.landId
    );

    REGISTER_PACKET(1, false, 0x2F8, FFXIVIpcHousingWelcome,
        FIELD("Welcome", FieldToString(pkt->Welcome)),
        FIELD("LandId", FieldToString(pkt->LandId.landId))
    );

    REGISTER_PACKET(1, false, 0x2F9, FFXIVIpcFurnitureListS,
        FIELD("LandId", FieldToString(pkt->LandId.landId)),
        FIELD("CountSegment", FieldToString((int)100)),
        FIELD("FirstFurnitureItemId", FieldToString(pkt->Furnitures[0].itemId))
    );

    REGISTER_PACKET(1, false, 0x2FA, FFXIVIpcFurnitureListM,
        FIELD("LandId", FieldToString(pkt->LandId.landId)),
        FIELD("FirstFurnitureItemId", FieldToString(pkt->Furnitures[0].itemId))
    );

    REGISTER_PACKET(1, false, 0x2FB, FFXIVIpcFurnitureListL,
        FIELD("LandId", FieldToString(pkt->LandId.landId)),
        FIELD("FirstFurnitureItemId", FieldToString(pkt->Furnitures[0].itemId))
    );

    REGISTER_PACKET(1, false, 0x2FC, FFXIVIpcFurniture,
        FIELD("StorageId", FieldToString(pkt->StorageId)),
        FIELD("FurnitureItemId", FieldToString(pkt->Furniture.itemId))
    );

    REGISTER_PACKET(1, false, 0x2FE, FFXIVIpcHousingProfileList,
        FIELD("LandSetId", FieldToString(pkt->LandSetId.landId)),
        FIELD("Profile0Name", FormatString(pkt->ProfileList[0].name, 23))
    );

    REGISTER_PACKET(1, false, 0x2FF, FFXIVIpcHousingObjectTransform,
        FIELD("Dir", FieldToString(pkt->Dir)),
        FIELD("ContainerIndex", FieldToString(pkt->ContainerIndex)),
        FIELD("Pos", std::string("(") + std::to_string(pkt->Pos[0]) + "," + std::to_string(pkt->Pos[1]) + "," + std::to_string(pkt->Pos[2]) + ")")
    );

    REGISTER_PACKET(1, false, 0x300, FFXIVIpcHousingObjectColor,
        FIELD("Color", FieldToString(pkt->Color)),
        FIELD("StorageId", FieldToString(pkt->StorageId)),
        FIELD("ContainerIndex", FieldToString(pkt->ContainerIndex))
    );

    REGISTER_PACKET(1, false, 0x301, FFXIVIpcHousingObjectTransformMulti,
        FIELD("LandId", FieldToString(pkt->LandId.landId)),
        FIELD("FirstLayoutStorageId", FieldToString(pkt->LayoutInfos[0].storageIndex))
    );

    REGISTER_PACKET(1, false, 0x307, FFXIVIpcHousingGetPersonalRoomProfileListResult,
        FIELD("CharacterID", FormatHex(pkt->CharacterID)),
        FIELD("HouseLandId", FieldToString(pkt->HouseLandID.landId)),
        FIELD("TopRoomID", FieldToString(pkt->TopRoomID))
    );

    REGISTER_PACKET(1, false, 0x308, FFXIVIpcHousingGetHouseBuddyStableListResult,
        FIELD("CharacterID", FormatHex(pkt->CharacterID)),
        FIELD("LandId", FieldToString(pkt->LandID.landId)),
        FIELD("IsMyBuddy", FieldToString(pkt->IsMyBuddy))
    );

    REGISTER_PACKET(1, false, 0x309, FFXIVIpcHouseTrainBuddyData,
        FIELD("OwnerRace", FieldToString(pkt->OwnerRace)),
        FIELD("OwnerSex", FieldToString(pkt->OwnerSex)),
        FIELD("Stain", FieldToString(pkt->Stain))
    );

    REGISTER_PACKET(1, false, 0x32A, FFXIVIpcHousingObjectTransformMultiResult,
        FIELD("LandId", FieldToString(pkt->LandId.landId)),
        FIELD("Result", FieldToString(pkt->Result))
    );

    REGISTER_PACKET(1, false, 0x32B, FFXIVIpcHousingLogWithHouseName,
        FIELD("LogId", FieldToString(pkt->LogId)),
        FIELD("Name", FormatString(reinterpret_cast<const char*>(pkt->Name), 23))
    );

    REGISTER_PACKET(1, false, 0x32D, FFXIVIpcHousingCombinedObjectStatus,
        FIELD("AddressData", FieldToString(pkt->AddressData)),
        FIELD("Kind0", FieldToString(pkt->Kind[0])),
        FIELD("Status0", FieldToString(pkt->Status[0]))
    );

    REGISTER_PACKET(1, false, 0x32E, FFXIVIpcHouseBuddyModelData,
        FIELD("AddressData", FieldToString(pkt->AddressData)),
        FIELD("BuddyScale", FieldToString(pkt->BuddyScale)),
        FIELD("ModelEquip0", FormatHex(pkt->ModelEquips[0]))
    );

    // ================= OBJECTS (NON-PLAYER) =================
    REGISTER_PACKET(1, false, 0x019D, FFXIVIpcCreateObject,
        FIELD("Index", FieldToString(pkt->Index)),
        FIELD("Kind", FieldToString(pkt->Kind)),
        FIELD("BaseId", FieldToString(pkt->BaseId)),
        FIELD("EntityId", FormatHex(pkt->EntityId)),
        FIELD("Pos", FormatPosition(pkt->Pos.x, pkt->Pos.y, pkt->Pos.z))
    );

    REGISTER_PACKET(1, false, 0x019E, FFXIVIpcDeleteObject,
        FIELD("Index", FieldToString(pkt->Index))
    );

    // ================= COMPANY / FREE COMPANY =================
    REGISTER_PACKET(1, false, 0x10E, FFXIVIpcFreeCompanyResult,
        FIELD("FreeCompanyID", FormatHex(pkt->FreeCompanyID)),
        FIELD("Result", FieldToString(pkt->Result)),
        FIELD("FcName", FormatString(pkt->FreeCompanyName, 32))
    );

    REGISTER_PACKET(1, false, 0x10F, FFXIVIpcGetFcStatusResult,
        FIELD("FreeCompanyID", FormatHex(pkt->FreeCompanyID)),
        FIELD("FcRank", FieldToString(pkt->FcRank)),
        FIELD("FcStatus", FieldToString(pkt->FcStatus))
    );

    REGISTER_PACKET(1, false, 0x110, FFXIVIpcGetFcInviteListResult,
        FIELD("FreeCompanyID", FormatHex(pkt->FreeCompanyID)),
        FIELD("MasterCharacter", FormatString(pkt->MasterCharacter.CharacterName, 32)),
        FIELD("InviteCount", FieldToString((int)3))
    );

    REGISTER_PACKET(1, false, 0x111, FFXIVIpcGetFcProfileResult,
        FIELD("FreeCompanyID", FormatHex(pkt->FreeCompanyID)),
        FIELD("TotalMembers", FieldToString(pkt->TotalMemberCount)),
        FIELD("FcRank", FieldToString(pkt->FcRank)),
        FIELD("FcName", FormatString(pkt->FreeCompanyName, 22))
    );

    REGISTER_PACKET(1, false, 0x112, FFXIVIpcGetFcHeaderResult,
        FIELD("FreeCompanyID", FormatHex(pkt->FreeCompanyID)),
        FIELD("FcCredit", FieldToString(pkt->FcCredit)),
        FIELD("FcRank", FieldToString(pkt->FcRank))
    );

    REGISTER_PACKET(1, false, 0x113, FFXIVIpcGetCompanyBoardResult,
        FIELD("Type", FieldToString(pkt->Type)),
        FIELD("BoardExcerpt", FormatString(pkt->CompanyBoard, 60))
    );

    REGISTER_PACKET(1, false, 0x114, FFXIVIpcGetFcHierarchyResult,
        FIELD("MasterCharacterName", FormatString(pkt->MasterCharacterName, 32)),
        FIELD("FirstHierarchyName", FormatString(pkt->FcHierarchyList[0].HierarchyName, 46))
    );

    REGISTER_PACKET(1, false, 0x115, FFXIVIpcGetFcActivityListResult,
        FIELD("NextIndex", FieldToString(pkt->NextIndex)),
        FIELD("FirstActivityCharacter", FormatString(pkt->ActivityList[0].CharacterName, 32))
    );

    REGISTER_PACKET(1, false, 0x116, FFXIVIpcGetFcHierarchyLiteResult,
        FIELD("FirstAuthorityList", FormatHex(pkt->FcHierarchyList[0].AuthorityList))
    );

    REGISTER_PACKET(1, false, 0x117, FFXIVIpcGetCompanyMottoResult,
        FIELD("Type", FieldToString(pkt->Type)),
        FIELD("MottoExcerpt", FormatString(pkt->CompanyMotto, 60))
    );

    REGISTER_PACKET(1, false, 0x118, FFXIVIpcGetFcParamsResult,
        FIELD("CharacterID", FormatHex(pkt->CharacterID)),
        FIELD("FcRank", FieldToString(pkt->FcRank)),
        FIELD("FcPoint", FieldToString(pkt->FcPoint))
    );

    REGISTER_PACKET(1, false, 0x119, FFXIVIpcGetFcActionResult,
        FIELD("CharacterID", FormatHex(pkt->CharacterID)),
        FIELD("ActiveAction0", FieldToString(pkt->ActiveActionList[0])),
        FIELD("StockAction0", FieldToString(pkt->StockActionList[0]))
    );

    REGISTER_PACKET(1, false, 0x11A, FFXIVIpcGetFcMemoResult,
        FIELD("CharacterID", FormatHex(pkt->CharacterID)),
        FIELD("UpdateDate", FieldToString(pkt->UpdateDate)),
        FIELD("MemoExcerpt", FormatString(pkt->FcMemo, 40))
    );

    REGISTER_PACKET(1, false, 0x0140, FFXIVIpcHudParam,
        FIELD("ClassJob", FieldToString(pkt->ClassJob)),
        FIELD("Level", FieldToString(pkt->Lv)),
        FIELD("Hp", FieldToString(pkt->Hp)),
        FIELD("Mp", FieldToString(pkt->Mp)),
        FIELD("StatusSummary", SummarizeStatusWork(pkt->effect, 30))
    );

    // -----------------------------------------------------------------------------
    // Minimal local inventory snapshot + classifier (single-file, no external deps)
    // -----------------------------------------------------------------------------
    namespace {
        struct InvSlot { uint32_t catalogId=0; uint32_t stack=0; };
        inline uint64_t MakeKey(uint32_t storageId, int16_t slot) {
            return (uint64_t(storageId) << 32) | (uint16_t)slot;
        }
        static std::unordered_map<uint64_t, InvSlot> gInv;

        // Update snapshot from NormalItem / UpdateItem (pre/post state used by heuristics)
        inline void SnapshotNormalItem(const PacketStructures::Server::Zone::FFXIVIpcNormalItem* p) {
            gInv[MakeKey(p->item.storageId, p->item.containerIndex)] = { p->item.catalogId, p->item.stack };
        }
        inline void SnapshotUpdateItem(const PacketStructures::Server::Zone::FFXIVIpcUpdateItem* p) {
            gInv[MakeKey(p->item.storageId, p->item.containerIndex)] = { p->item.catalogId, p->item.stack };
        }

        // Simple heuristic classifier (only uses PRE state; we do not mutate here)
        inline std::string ClassifyItemOperation(const PacketStructures::Server::Zone::FFXIVIpcItemOperation* p) {
            auto keySrc = MakeKey(p->srcStorageId, p->srcContainerIndex);
            auto keyDst = MakeKey(p->dstStorageId, p->dstContainerIndex);

            InvSlot srcBefore{}, dstBefore{};
            bool haveSrc = false, haveDst = false;
            if (auto it = gInv.find(keySrc); it != gInv.end()) { srcBefore = it->second; haveSrc = true; }
            if (auto it = gInv.find(keyDst); it != gInv.end()) { dstBefore = it->second; haveDst = true; }

            // Heuristic patterns (ordered from more specific to more generic)
            if (haveSrc && p->dstCatalogId==0 && p->dstStack==0 && p->srcStack < srcBefore.stack)
                return "Use/Consume? (srcBefore=" + std::to_string(srcBefore.stack) + ")";
            if (haveSrc && !haveDst &&                      // dest was empty
                p->dstCatalogId == p->srcCatalogId &&
                p->srcStack < srcBefore.stack)
                return "Split? (srcBefore=" + std::to_string(srcBefore.stack) + ")";
            if (haveSrc && haveDst &&
                p->srcCatalogId == p->dstCatalogId &&
                p->srcStack < srcBefore.stack &&
                p->dstStack > dstBefore.stack)
                return "Merge? (srcBefore=" + std::to_string(srcBefore.stack) +
                       ", dstBefore=" + std::to_string(dstBefore.stack) + ")";
            if (haveSrc && haveDst &&
                p->srcCatalogId != p->dstCatalogId &&
                p->srcStack == srcBefore.stack &&
                p->dstStack == dstBefore.stack)
                return "Swap?";
            if (haveSrc && p->srcStack == 0 &&              // source vanished
                p->dstCatalogId == 0 && p->dstStack == 0)
                return "Discard?";
            if (p->srcEntity != p->dstEntity && p->dstEntity != 0)
                return "XferEntity?";
            return "Unknown";
        }

        // Optional raw dump (cap length for UI)
        inline std::string DumpBytes(const void* data, size_t len, size_t maxShow = 32) {
            const uint8_t* b = static_cast<const uint8_t*>(data);
            std::ostringstream os; os << std::hex << std::setfill('0');
            size_t show = std::min(len, maxShow);
            for (size_t i=0;i<show;i++) {
                if (i) os << ' ';
                os << std::setw(2) << (unsigned)b[i];
            }
            if (show < len) os << " ...";
            return os.str();
        }

        // If you still want a placeholder name (we deliberately avoid guessing):
        inline const char* GetItemOperationTypeName(uint8_t) { return "-"; }
        inline std::string FormatStack(uint32_t v) { return std::to_string(v); }
    } // anonymous namespace

// ----------------------------------------------------------------------------
// Pseudo-reflection support (descriptor tables) at file scope
// ----------------------------------------------------------------------------
namespace PacketDecoding {

    enum class PFKind : uint8_t { U8, U16, U32, S16, S32, F32, HEX32 };

    struct PacketFieldDesc {
        const char* name;
        size_t      offset;
        size_t      size;
        PFKind      kind;
    };

    template<typename T>
    static std::string FormatField(const void* base, const PacketFieldDesc& d) {
        const uint8_t* p = static_cast<const uint8_t*>(base) + d.offset;
        std::ostringstream os;
        switch (d.kind) {
        case PFKind::U8:    os << +*reinterpret_cast<const uint8_t*>(p); break;
        case PFKind::U16:   os << +*reinterpret_cast<const uint16_t*>(p); break;
        case PFKind::U32:   os << +*reinterpret_cast<const uint32_t*>(p); break;
        case PFKind::S16:   os << +*reinterpret_cast<const int16_t*>(p);  break;
        case PFKind::S32:   os << +*reinterpret_cast<const int32_t*>(p);  break;
        case PFKind::F32:   os << *reinterpret_cast<const float*>(p);     break;
        case PFKind::HEX32: os << "0x" << std::hex << std::uppercase
                               << *reinterpret_cast<const uint32_t*>(p);  break;
        }
        return os.str();
    }

    #define PF_ITEM(structType, fieldName, kindEnum) \
        { #fieldName, offsetof(structType, fieldName), sizeof(((structType*)0)->fieldName), kindEnum }

    #define FFXIV_ITEM_OPERATION_FIELDS(structType) \
        PF_ITEM(structType, contextId,        PFKind::HEX32), \
        PF_ITEM(structType, operationType,    PFKind::U8),    \
        PF_ITEM(structType, srcEntity,        PFKind::HEX32), \
        PF_ITEM(structType, srcStorageId,     PFKind::U32),   \
        PF_ITEM(structType, srcContainerIndex,PFKind::S16),   \
        PF_ITEM(structType, srcStack,         PFKind::U32),   \
        PF_ITEM(structType, srcCatalogId,     PFKind::U32),   \
        PF_ITEM(structType, dstEntity,        PFKind::HEX32), \
        PF_ITEM(structType, dstStorageId,     PFKind::U32),   \
        PF_ITEM(structType, dstContainerIndex,PFKind::S16),   \
        PF_ITEM(structType, dstStack,         PFKind::U32),   \
        PF_ITEM(structType, dstCatalogId,     PFKind::U32)

    #define FFXIV_ITEM_OPERATION_BATCH_FIELDS(structType) \
        PF_ITEM(structType, contextId,     PFKind::HEX32), \
        PF_ITEM(structType, operationId,   PFKind::U32),   \
        PF_ITEM(structType, operationType, PFKind::U8),    \
        PF_ITEM(structType, errorType,     PFKind::U8),    \
        PF_ITEM(structType, packetNum,     PFKind::U8)

    static const PacketFieldDesc gItemOperationFields[] = {
        FFXIV_ITEM_OPERATION_FIELDS(PacketStructures::Server::Zone::FFXIVIpcItemOperation)
    };
    static const PacketFieldDesc gItemOperationBatchFields[] = {
        FFXIV_ITEM_OPERATION_BATCH_FIELDS(PacketStructures::Server::Zone::FFXIVIpcItemOperationBatch)
    };

    template<typename T>
    static std::string DumpAllFields(const T* pkt, const PacketFieldDesc* table, size_t count) {
        std::ostringstream os;
        for (size_t i=0;i<count;i++) {
            if (i) os << " | ";
            os << table[i].name << "=" << FormatField<T>(pkt, table[i]);
        }
        return os.str();
    }

} // namespace PacketDecoding

static_assert(sizeof(PacketStructures::Server::Zone::FFXIVIpcItemOperation) == 48,
              "ItemOperation layout changed – update descriptor table");