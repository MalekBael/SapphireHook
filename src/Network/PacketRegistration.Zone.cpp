#include "PacketRegistration.h"
#include "PacketRegistration.Macros.h"
#include "../Network/OpcodeNames.h"
#include "../ProtocolHandlers/CommonTypes.h"
#include "../ProtocolHandlers/Zone/ServerZoneDef.h"
#include "../ProtocolHandlers/Zone/ClientZoneDef.h"

#ifndef ENABLE_PACKET_LAYERS
#define ENABLE_PACKET_LAYERS 0
#endif

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <string>
#include <array>
#include <unordered_map>
#include <cstddef>
#include <iterator>
#include <cstring> // for std::memcpy

using namespace PacketDecoding;
using namespace PacketStructures;


namespace {
    std::string ClassifyItemOperation(const PacketStructures::Server::Zone::FFXIVIpcItemOperation* p);
    std::string DumpBytes(const void* data, size_t len, size_t maxShow = 32);

    // Function implementations
    std::string ClassifyItemOperation(const PacketStructures::Server::Zone::FFXIVIpcItemOperation* p) {
        if (!p) return "null";

        std::ostringstream os;

        // Classify based on operation type and source/destination data
        switch (p->operationType) {
        case 1: os << "Move"; break;
        case 2: os << "Split"; break;
        case 3: os << "Combine"; break;
        case 4: os << "Discard"; break;
        case 5: os << "Use"; break;
        default: os << "Op" << p->operationType; break;
        }

        // Add source/destination context
        if (p->srcStorageId != p->dstStorageId) {
            os << "(Storage:" << p->srcStorageId << "→" << p->dstStorageId << ")";
        }

        if (p->srcStack > 0 || p->dstStack > 0) {
            os << "(Stack:" << p->srcStack << "→" << p->dstStack << ")";
        }

        return os.str();
    }

    std::string DumpBytes(const void* data, size_t len, size_t maxShow) {
        if (!data || len == 0) return "[]";

        std::ostringstream os;
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        size_t showLen = std::min(len, maxShow);

        os << "[" << std::hex << std::uppercase << std::setfill('0');
        for (size_t i = 0; i < showLen; ++i) {
            if (i > 0) os << " ";
            os << std::setw(2) << static_cast<unsigned>(bytes[i]);
        }
        if (len > maxShow) {
            os << "...+" << std::dec << (len - maxShow) << "more";
        }
        os << "]";

        return os.str();
    }
}

// Formatting helpers
namespace PacketDecoding {
    const char* GetActionTypeName(uint8_t type) {
        switch (type) {
        case 1: return "Spell"; case 2: return "Item"; case 3: return "KeyItem"; case 4: return "Ability";
        case 5: return "General"; case 6: return "Companion"; case 7: return "Weaponskill"; case 8: return "Trait";
        case 9: return "CompanionOrder"; case 10: return "PetAction"; case 11: return "FieldMarker";
        case 13: return "CraftAction"; case 15: return "Mount"; case 17: return "PvPAction"; case 18: return "Waymark";
        case 19: return "ChocoboRaceAbility"; case 20: return "ChocoboRaceItem"; case 21: return "DutyAction";
        case 22: return "PerformanceInstrument"; case 23: return "Fashion"; case 24: return "LostAction";
        default: return "Unknown";
        }
    }

    const char* GetStatusEffectName(uint16_t id) {
        switch (id) {
        case 1: return "Weakness"; case 2: return "Brink of Death"; case 3: return "Hard Invuln"; case 4: return "Transcendent";
        case 5: return "Sleep"; case 6: return "Stun"; case 7: return "Paralysis"; case 8: return "Silence";
        case 9: return "Slow"; case 10: return "Pacification"; case 11: return "Heavy"; case 12: return "Bind";
        case 143: return "Aetherflow"; case 304: return "Energy Drain"; case 360: return "Swiftcast";
        default: return nullptr;
        }
    }

    const char* GetChatTypeName(uint16_t type) {
        switch (type) {
        case 0x0003: return "Error"; case 0x0004: return "ServerDebug"; case 0x0005: return "ServerUrgent";
        case 0x0006: return "ServerNotice"; case 0x000A: return "Say"; case 0x000B: return "Shout";
        case 0x000C: return "Tell"; case 0x000D: return "TellReceive"; case 0x000E: return "Party";
        case 0x000F: return "Alliance"; case 0x0010: return "Ls1"; case 0x0018: return "FreeCompany";
        case 0x001B: return "NoviceNetwork"; case 0x001E: return "Yell"; case 0x001F: return "CrossParty";
        case 0x0024: return "PvPTeam"; case 0x0025: return "CrossLinkShell1"; case 0x0038: return "Echo";
        case 0x0039: return "SystemMessage"; default: return "Unknown";
        }
    }

    const char* GetWarpTypeName(uint8_t type) {
        switch (type) {
        case 0x0: return "NON"; case 0x1: return "NORMAL"; case 0x2: return "NORMAL_POS"; case 0x3: return "EXIT_RANGE";
        case 0x4: return "TELEPO"; case 0x5: return "REISE"; case 0x8: return "HOME_POINT"; case 0x9: return "RENTAL_CHOCOBO";
        case 0xA: return "CHOCOBO_TAXI"; case 0xB: return "INSTANCE_CONTENT"; case 0xC: return "REJECT";
        case 0xD: return "CONTENT_END_RETURN"; case 0xE: return "TOWN_TRANSLATE"; case 0xF: return "GM";
        case 0x10: return "LOGIN"; case 0x11: return "LAYER_SET"; case 0x12: return "EMOTE";
        case 0x13: return "HOUSING_TELEPO"; case 0x14: return "DEBUG"; default: return "?";
        }
    }

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

// ================= REGISTER PACKETS =================
void PacketDecoding::RegisterZonePackets() {
    using namespace PacketStructures::Server::Zone;

    // CORE / SESSION
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

    // CHAT / SOCIAL
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

    // PROFILE
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

    // SYSTEM MESSAGES
    REGISTER_PACKET(1, false, 0x00D3, FFXIVIpcSendSystemMessage,
        FIELD("MessageParam", FieldToString(pkt->MessageParam)),
        FIELD("Message", FormatString(pkt->Message, 120))
    );

    REGISTER_PACKET(1, false, 0x00D4, FFXIVIpcSendLoginMessage,
        FIELD("MessageParam", FieldToString(pkt->MessageParam)),
        FIELD("Message", FormatString(pkt->Message, 120))
    );

    // ACHIEVEMENT
    REGISTER_PACKET(1, false, 0x02DD, FFXIVIpcAchievement,
        FIELD("CompleteMaskFirstByte", FormatHex(pkt->complete[0])),
        FIELD("History0", FieldToString(pkt->history[0]))
    );

    // MAIL
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

    // MARKET / ITEM SEARCH
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

    // COMBAT / ACTIONS
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

    // PARTY / ALLIANCE
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

    // MOVEMENT / SPAWN
    REGISTER_PACKET(1, false, 0x0190, FFXIVIpcPlayerSpawn,
        FIELD("LayoutId", FieldToString(pkt->LayoutId)),
        FIELD("NameId", FieldToString(pkt->NameId)),
        FIELD("ObjKind", FieldToString(pkt->ClassJob)),
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

    // ZONE / PLAYER STATE
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

    // INVENTORY / ITEMS (server → client)
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

    // --- MODIFIED: ItemOperationBatch now exposes discovered raw fields in Decoded Payload ---
#if ENABLE_PACKET_LAYERS
    REGISTER_PACKET(1, false, 0x01B1, FFXIVIpcItemOperationBatch,
        FIELD("ContextId",        FormatHex(pkt->contextId)),
        FIELD("OperationId",      FieldToString(pkt->operationId)),
        FIELD("OperationTypeHdr", FieldToString(pkt->operationType)),
        FIELD("ErrorType",        FieldToString(pkt->errorType)),
        FIELD("PacketNum",        FieldToString(pkt->packetNum)),

        /* Newly exposed raw offsets (heuristic layout) */
        FIELD("storageId(+0x04)", FieldToString(*reinterpret_cast<const uint32_t*>(
              reinterpret_cast<const uint8_t*>(pkt) + 0x04))),
        FIELD("sourceId(+0x08)",  FieldToString(*reinterpret_cast<const uint32_t*>(
              reinterpret_cast<const uint8_t*>(pkt) + 0x08))),
        FIELD("stackSize(+0x14)", FieldToString(*reinterpret_cast<const uint32_t*>(
              reinterpret_cast<const uint8_t*>(pkt) + 0x14))),
        FIELD("itemId(+0x18)",    FieldToString(*reinterpret_cast<const uint32_t*>(
              reinterpret_cast<const uint8_t*>(pkt) + 0x18))),

        FIELD("_layers",      LayerSideEffect_ItemOperationBatch(pkt)),
        FIELD("_layers_raw",  LayerSideEffect_ItemOperationBatchRaw(pkt))
    );
#else
    REGISTER_PACKET(1, false, 0x01B1, FFXIVIpcItemOperationBatch,
        FIELD("ContextId",        FormatHex(pkt->contextId)),
        FIELD("OperationId",      FieldToString(pkt->operationId)),
        FIELD("OperationTypeHdr", FieldToString(pkt->operationType)),
        FIELD("ErrorType",        FieldToString(pkt->errorType)),
        FIELD("PacketNum",        FieldToString(pkt->packetNum)),
        FIELD("storageId(+0x04)", FieldToString(*reinterpret_cast<const uint32_t*>(
              reinterpret_cast<const uint8_t*>(pkt) + 0x04))),
        FIELD("sourceId(+0x08)",  FieldToString(*reinterpret_cast<const uint32_t*>(
              reinterpret_cast<const uint8_t*>(pkt) + 0x08))),
        FIELD("stackSize(+0x14)", FieldToString(*reinterpret_cast<const uint32_t*>(
              reinterpret_cast<const uint8_t*>(pkt) + 0x14))),
        FIELD("itemId(+0x18)",    FieldToString(*reinterpret_cast<const uint32_t*>(
              reinterpret_cast<const uint8_t*>(pkt) + 0x18)))
    );
#endif

// 2) Server -> Client ItemOperation (opcode 0x01B2)
// Keep full detailed decode AND ensure core raw inventory movement fields are visible.
#if ENABLE_PACKET_LAYERS
    REGISTER_PACKET(1, false, 0x01B2, FFXIVIpcItemOperation,
        FIELD("ContextId",          FormatHex(pkt->contextId)),
        FIELD("OperationTypeRaw",   FieldToString(pkt->operationType)),

        // Source
        FIELD("SrcEntity",          FormatHex(pkt->srcEntity)),
        FIELD("SrcStorageId",       FieldToString(pkt->srcStorageId)),
        FIELD("SrcContainerIndex",  FieldToString(pkt->srcContainerIndex)),
        FIELD("SrcStack",           FieldToString(pkt->srcStack)),
        FIELD("SrcCatalogId",       FieldToString(pkt->srcCatalogId)),

        // Destination
        FIELD("DstEntity",          FormatHex(pkt->dstEntity)),
        FIELD("DstStorageId",       FieldToString(pkt->dstStorageId)),
        FIELD("DstContainerIndex",  FieldToString(pkt->dstContainerIndex)),
        FIELD("DstStack",           FieldToString(pkt->dstStack)),
        FIELD("DstCatalogId",       FieldToString(pkt->dstCatalogId)),

        // Heuristic + raw
        FIELD("Heuristic",          ClassifyItemOperation(pkt)),
        FIELD("Raw48Bytes",         DumpBytes(pkt, sizeof(*pkt))),
        FIELD("_layers",            LayerSideEffect_ItemOperation(pkt)),
        FIELD("_layers_rawBatchView", LayerSideEffect_ItemOperationBatchRaw(
              reinterpret_cast<const PacketStructures::Server::Zone::FFXIVIpcItemOperationBatch*>(pkt)))
    );
#else
    REGISTER_PACKET(1, false, 0x01B2, FFXIVIpcItemOperation,
        FIELD("ContextId",          FormatHex(pkt->contextId)),
        FIELD("OperationTypeRaw",   FieldToString(pkt->operationType)),
        FIELD("SrcEntity",          FormatHex(pkt->srcEntity)),
        FIELD("SrcStorageId",       FieldToString(pkt->srcStorageId)),
        FIELD("SrcContainerIndex",  FieldToString(pkt->srcContainerIndex)),
        FIELD("SrcStack",           FieldToString(pkt->srcStack)),
        FIELD("SrcCatalogId",       FieldToString(pkt->srcCatalogId)),
        FIELD("DstEntity",          FormatHex(pkt->dstEntity)),
        FIELD("DstStorageId",       FieldToString(pkt->dstStorageId)),
        FIELD("DstContainerIndex",  FieldToString(pkt->dstContainerIndex)),
        FIELD("DstStack",           FieldToString(pkt->dstStack)),
        FIELD("DstCatalogId",       FieldToString(pkt->dstCatalogId)),
        FIELD("Heuristic",          ClassifyItemOperation(pkt)),
        FIELD("Raw48Bytes",         DumpBytes(pkt, sizeof(*pkt)))
    );
#endif

// 3) Client -> Server ClientItemOperation (opcode 0x01AE, outgoing)
// Add raw-offset fields exactly as user requested (storageId, stackSize @ two offsets, itemId)
REGISTER_PACKET(1, true, 0x01AE, PacketStructures::Client::Zone::FFXIVIpcClientInventoryItemOperation,
    FIELD("ContextId",              FieldToString(pkt->ContextId)),
    FIELD("OperationType",          FieldToString(pkt->OperationType)),

    // Requested raw logical fields
    FIELD("storageId(+0x04)",       FieldToString(pkt->SrcStorageId)), // maps to +0x04 in observed raw
    FIELD("stackSize_pre(+0x14)",   FieldToString(pkt->SrcStack)),     // assuming SrcStack at +0x14
    FIELD("stackSize_post(+0x28)",  FieldToString(pkt->DstStack)),     // second stack at +0x28
    FIELD("itemId(+0x2C)",          FieldToString(pkt->DstCatalogId)), // item/catalog id at +0x2C

    // (Optional) keep full context
    FIELD("SrcActorId",             FormatHex(pkt->SrcActorId)),
    FIELD("SrcContainerIndex",      FieldToString(pkt->SrcContainerIndex)),
    FIELD("SrcCatalogId",           FieldToString(pkt->SrcCatalogId)),
    FIELD("DstActorId",             FormatHex(pkt->DstActorId)),
    FIELD("DstStorageId",           FieldToString(pkt->DstStorageId)),
    FIELD("DstContainerIndex",      FieldToString(pkt->DstContainerIndex)),
    FIELD("DstCatalogId",           FieldToString(pkt->DstCatalogId))
);

}  // End of RegisterZonePackets() function