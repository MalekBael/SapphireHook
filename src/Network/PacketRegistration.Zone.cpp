#include "../Network/OpcodeNames.h"
#include "../ProtocolHandlers/CommonTypes.h"
#include "../ProtocolHandlers/Zone/ClientZoneDef.h"
#include "../ProtocolHandlers/Zone/ServerZoneDef.h"
#include "PacketRegistration.h"
#include "PacketRegistration.Macros.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring> // for std::memcpy
#include <iomanip>
#include <iterator>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

#ifndef ENABLE_PACKET_LAYERS
#define ENABLE_PACKET_LAYERS 0
#endif

#ifdef __INTELLISENSE__
// IntelliSense-friendly fallbacks: prevent deep macro expansion noise
#ifdef REGISTER_PACKET
#undef REGISTER_PACKET
#endif
#ifdef FIELD
#undef FIELD
#endif

// Make REGISTER_PACKET syntactically valid while exposing 'pkt' for member browsing
#define REGISTER_PACKET(Channel, Outgoing, Opcode, StructType, ...) \
        if constexpr (false) { const StructType* pkt = nullptr; (void)pkt; }

    // Suppress FIELD macro bodies
#define FIELD(Name, Expr)
#endif

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
    // Don't use blanket "using namespace" to avoid ambiguity
    namespace ServerZone = PacketStructures::Server::Zone;
    namespace ClientZone = PacketStructures::Client::Zone;

    // ================= REGISTER SERVER PACKETS =================
    // CORE / SESSION
    REGISTER_PACKET(1, false, 0x0065, ServerZone::FFXIVIpcSync,
        FIELD("ClientTimeValue", FieldToString(pkt->clientTimeValue)),
        FIELD("TransmissionInterval", FieldToString(pkt->transmissionInterval)),
        FIELD("OriginEntityId", FormatHex(pkt->position.originEntityId)),
        FIELD("Position", FormatPosition(pkt->position.pos[0], pkt->position.pos[1], pkt->position.pos[2])),
        FIELD("Direction", FormatAngle(pkt->position.dir))
    );

    REGISTER_PACKET(1, false, 0x0066, ServerZone::FFXIVIpcLogin,
        FIELD("ClientTimeValue", FieldToString(pkt->clientTimeValue)),
        FIELD("LoginTicketId", FormatHex(pkt->loginTicketId)),
        FIELD("PlayerActorId", FormatHex(pkt->playerActorId))
    );

    REGISTER_PACKET(1, false, 0x02D6, ServerZone::FFXIVIpcEnableLogout,
        FIELD("Content", FieldToString(pkt->content))
    );

    // CHAT / SOCIAL
    REGISTER_PACKET(1, false, 0x0067, ServerZone::FFXIVIpcChat,
        FIELD("Type", FieldToString(pkt->type) + " (" + GetChatTypeName(pkt->type) + ")"),
        FIELD("EntityId", FormatHex(pkt->entityId)),
        FIELD("CharacterId", FormatHex(pkt->characterId)),
        FIELD("Speaker", FormatString(pkt->speakerName, 32)),
        FIELD("Message", FormatString(pkt->message, std::min<size_t>(200, sizeof(pkt->message))))
    );

    REGISTER_PACKET(1, false, 0x00CC, ServerZone::FFXIVIpcGetCommonlistResult,
        FIELD("CommunityId", FormatHex(pkt->CommunityID)),
        FIELD("Index", FieldToString(pkt->Index)),
        FIELD("NextIndex", FieldToString(pkt->NextIndex)),
        FIELD("ListType", FieldToString(pkt->ListType)),
        FIELD("Entry0Name", FormatString(pkt->entries[0].CharacterName, 32))
    );

    REGISTER_PACKET(1, false, 0x00CD, ServerZone::FFXIVIpcGetCommonlistDetailResult,
        FIELD("DetailCharacterID", FormatHex(pkt->DetailCharacterID)),
        FIELD("CommunityID", FormatHex(pkt->CommunityID)),
        FIELD("SelectClassID", FormatHex(pkt->SelectClassID)),
        FIELD("SearchComment", FormatString(pkt->SearchComment, 60)),
        FIELD("FirstClassJobId", FieldToString(pkt->ClassData[0].id))
    );

    REGISTER_PACKET(1, false, 0x00EB, ServerZone::FFXIVIpcPcSearchResult,
        FIELD("ResultCount", FieldToString(pkt->ResultCount))
    );

    REGISTER_PACKET(1, false, 0x00F0, ServerZone::FFXIVIpcLinkshellResult,
        FIELD("LinkshellID", FormatHex(pkt->LinkshellID)),
        FIELD("Result", FieldToString(pkt->Result)),
        FIELD("TargetName", FormatString(pkt->TargetName, 32))
    );

    REGISTER_PACKET(1, false, 0x00C9, ServerZone::FFXIVIpcInviteResult,
        FIELD("Result", FieldToString(pkt->Result)),
        FIELD("AuthType", FieldToString(pkt->AuthType)),
        FIELD("TargetName", FormatString(pkt->TargetName, 32))
    );

    REGISTER_PACKET(1, false, 0x00CA, ServerZone::FFXIVIpcInviteReplyResult,
        FIELD("Result", FieldToString(pkt->Result)),
        FIELD("Answer", FieldToString(pkt->Answer)),
        FIELD("InviteCharacter", FormatString(pkt->InviteCharacterName, 32))
    );

    REGISTER_PACKET(1, false, 0x00CB, ServerZone::FFXIVIpcInviteUpdate,
        FIELD("InviteCharacterID", FormatHex(pkt->InviteCharacterID)),
        FIELD("InviteTime", FieldToString(pkt->InviteTime)),
        FIELD("InviteName", FormatString(pkt->InviteName, 32))
    );

    REGISTER_PACKET(1, false, 0x00E6, ServerZone::FFXIVIpcFriendlistRemoveResult,
        FIELD("RemovedCharacterID", FormatHex(pkt->RemovedCharacterID)),
        FIELD("Result", FieldToString(pkt->Result)),
        FIELD("RemovedName", FormatString(pkt->RemovedCharacterName, 32))
    );

    REGISTER_PACKET(1, false, 0x00E1, ServerZone::FFXIVIpcBlacklistAddResult,
        FIELD("AddedCharacterID", FormatHex(pkt->AddedCharacter.CharacterID)),
        FIELD("CharacterName", FormatString(pkt->AddedCharacter.CharacterName, 32)),
        FIELD("Result", FieldToString(pkt->Result))
    );

    REGISTER_PACKET(1, false, 0x00E2, ServerZone::FFXIVIpcBlacklistRemoveResult,
        FIELD("RemovedCharacterID", FormatHex(pkt->RemovedCharacter.CharacterID)),
        FIELD("CharacterName", FormatString(pkt->RemovedCharacter.CharacterName, 32)),
        FIELD("Result", FieldToString(pkt->Result))
    );

    REGISTER_PACKET(1, false, 0x00E3, ServerZone::FFXIVIpcGetBlacklistResult,
        FIELD("Count", FieldToString((int)20)),
        FIELD("Index", FieldToString(pkt->Index)),
        FIELD("NextIndex", FieldToString(pkt->NextIndex))
    );

    REGISTER_PACKET(1, false, 0x00F1, ServerZone::FFXIVIpcGetLinkshellListResult,
        FIELD("FirstLinkshellID", FormatHex(pkt->LinkshellList[0].LinkshellID))
    );

    REGISTER_PACKET(1, false, 0x00D2, ServerZone::FFXIVIpcChatChannelResult,
        FIELD("ChannelID", FormatHex(pkt->ChannelID)),
        FIELD("CommunityID", FormatHex(pkt->CommunityID)),
        FIELD("Result", FieldToString(pkt->Result))
    );

    REGISTER_PACKET(1, false, 0x00D5, ServerZone::FFXIVIpcSetOnlineStatus,
        FIELD("OnlineStatusFlags", FormatHex(pkt->onlineStatusFlags))
    );

    // PROFILE
    REGISTER_PACKET(1, false, 0x00CE, ServerZone::FFXIVIpcSetProfileResult,
        FIELD("Result", FieldToString(pkt->Result)),
        FIELD("Region", FieldToString(pkt->Region)),
        FIELD("Comment", FormatString(pkt->SearchComment, 60))
    );

    REGISTER_PACKET(1, false, 0x00CF, ServerZone::FFXIVIpcGetProfileResult,
        FIELD("Region", FieldToString(pkt->Region)),
        FIELD("Comment", FormatString(pkt->SearchComment, 60))
    );

    REGISTER_PACKET(1, false, 0x00D0, ServerZone::FFXIVIpcGetSearchCommentResult,
        FIELD("TargetEntityID", FormatHex(pkt->TargetEntityID)),
        FIELD("Comment", FormatString(pkt->SearchComment, 60))
    );

    REGISTER_PACKET(1, false, 0x00D1, ServerZone::FFXIVIpcGetCharacterNameResult,
        FIELD("CharacterID", FormatHex(pkt->CharacterID)),
        FIELD("Name", FormatString(pkt->CharacterName, 32))
    );

    // SYSTEM MESSAGES
    REGISTER_PACKET(1, false, 0x00D3, ServerZone::FFXIVIpcSendSystemMessage,
        FIELD("MessageParam", FieldToString(pkt->MessageParam)),
        FIELD("Message", FormatString(pkt->Message, 120))
    );

    REGISTER_PACKET(1, false, 0x00D4, ServerZone::FFXIVIpcSendLoginMessage,
        FIELD("MessageParam", FieldToString(pkt->MessageParam)),
        FIELD("Message", FormatString(pkt->Message, 120))
    );

    // ACHIEVEMENT
    REGISTER_PACKET(1, false, 0x02DD, ServerZone::FFXIVIpcAchievement,
        FIELD("CompleteMaskFirstByte", FormatHex(pkt->complete[0])),
        FIELD("History0", FieldToString(pkt->history[0]))
    );

    // MAIL
    REGISTER_PACKET(1, false, 0x00FB, ServerZone::FFXIVIpcGetLetterMessageResult,
        FIELD("FirstSender", FormatHex(pkt->LetterMessage[0].SenderCharacterID)),
        FIELD("FirstMessage", FormatString(pkt->LetterMessage[0].Message, 40)),
        FIELD("NextIndex", FieldToString(pkt->NextIndex))
    );

    REGISTER_PACKET(1, false, 0x00FC, ServerZone::FFXIVIpcGetLetterMessageDetailResult,
        FIELD("SenderCharacterID", FormatHex(pkt->SenderCharacterID)),
        FIELD("Message", FormatString(pkt->Message, 80))
    );

    REGISTER_PACKET(1, false, 0x00FA, ServerZone::FFXIVIpcLetterResult,
        FIELD("SenderCharacterID", FormatHex(pkt->SenderCharacterID)),
        FIELD("Result", FieldToString(pkt->Result))
    );

    REGISTER_PACKET(1, false, 0x00FD, ServerZone::FFXIVIpcGetLetterStatusResult,
        FIELD("UnreadCount", FieldToString(pkt->UnreadCount)),
        FIELD("TotalCount", FieldToString(pkt->TotalCount)),
        FIELD("ItemCount", FieldToString(pkt->ItemCount))
    );

    // MARKET / ITEM SEARCH
    REGISTER_PACKET(1, false, 0x0105, ServerZone::FFXIVIpcGetItemSearchListResult,
        FIELD("FirstCatalogID", FieldToString(pkt->ItemSearchList[0].CatalogID)),
        FIELD("FirstPrice", FieldToString(pkt->ItemSearchList[0].SellPrice)),
        FIELD("Index", FieldToString(pkt->Index))
    );

    REGISTER_PACKET(1, false, 0x0109, ServerZone::FFXIVIpcGetItemHistoryResult,
        FIELD("CatalogID", FieldToString(pkt->CatalogID)),
        FIELD("FirstHistoryPrice", FieldToString(pkt->ItemHistoryList[0].SellPrice))
    );

    REGISTER_PACKET(1, false, 0x010C, ServerZone::FFXIVIpcCatalogSearchResult,
        FIELD("FirstCatalogID", FieldToString(pkt->CatalogList[0].CatalogID)),
        FIELD("Result", FieldToString(pkt->Result)),
        FIELD("Index", FieldToString(pkt->Index))
    );

    // COMBAT / ACTIONS
    REGISTER_PACKET(1, false, 0x0141, ServerZone::FFXIVIpcActionIntegrity,
        FIELD("ResultId", FieldToString(pkt->ResultId)),
        FIELD("Target", FormatHex(pkt->Target)),
        FIELD("StatusCount", FieldToString(pkt->StatusCount)),
        FIELD("FirstStatusId", FormatHex(pkt->Status[0].Id))
    );

    REGISTER_PACKET(1, false, 0x0142, ServerZone::FFXIVIpcActorControl,
        FIELD("Category", FieldToString(pkt->category) + " (" + std::string(::LookupActorControlCategoryName(pkt->category)) + ")"),
        FIELD("Param1", FormatHex(pkt->param1)),
        FIELD("Param2", FormatHex(pkt->param2)),
        FIELD("Param3", FormatHex(pkt->param3)),
        FIELD("Param4", FormatHex(pkt->param4))
    );

    REGISTER_PACKET(1, false, 0x0143, ServerZone::FFXIVIpcActorControlSelf,
        FIELD("Category", FieldToString(pkt->category) + " (" + std::string(::LookupActorControlCategoryName(pkt->category)) + ")"),
        FIELD("Param1", FormatHex(pkt->param1)),
        FIELD("Param2", FormatHex(pkt->param2)),
        FIELD("Param3", FormatHex(pkt->param3)),
        FIELD("Param4", FormatHex(pkt->param4)),
        FIELD("Param5", FormatHex(pkt->param5)),
        FIELD("Param6", FormatHex(pkt->param6))
    );

    REGISTER_PACKET(1, false, 0x0144, ServerZone::FFXIVIpcActorControlTarget,
        FIELD("Category", FieldToString(pkt->category) + " (" + std::string(::LookupActorControlCategoryName(pkt->category)) + ")"),
        FIELD("Param1", FormatHex(pkt->param1)),
        FIELD("Param2", FormatHex(pkt->param2)),
        FIELD("Param3", FormatHex(pkt->param3)),
        FIELD("Param4", FormatHex(pkt->param4)),
        FIELD("TargetId", FormatHex(pkt->targetId))
    );

    REGISTER_PACKET(1, false, 0x0145, ServerZone::FFXIVIpcResting,
        FIELD("Hp", FieldToString(pkt->Hp)),
        FIELD("Mp", FieldToString(pkt->Mp)),
        FIELD("Tp", FieldToString(pkt->Tp))
    );

    REGISTER_PACKET(1, false, 0x0146, ServerZone::FFXIVIpcActionResult1,
        FIELD("Action", FieldToString(pkt->Action)),
        FIELD("ActionKind", FieldToString(pkt->ActionKind)),
        FIELD("RequestId", FieldToString(pkt->RequestId)),
        FIELD("ResultId", FieldToString(pkt->ResultId)),
        FIELD("Target", FormatHex(pkt->Target)),
        FIELD("Flag", FormatHex(pkt->Flag))
    );

    REGISTER_PACKET(1, false, 0x0147, ServerZone::FFXIVIpcActionResult,
        FIELD("Action", FieldToString(pkt->Action)),
        FIELD("ActionKind", FieldToString(pkt->ActionKind)),
        FIELD("RequestId", FieldToString(pkt->RequestId)),
        FIELD("ResultId", FieldToString(pkt->ResultId)),
        FIELD("MainTarget", FormatHex(pkt->MainTarget)),
        FIELD("TargetCount", FieldToString(pkt->TargetCount)),
        FIELD("CalcResults", SummarizeCalcResults(pkt->CalcResult, 16))
    );

    REGISTER_PACKET(1, false, 0x0148, ServerZone::FFXIVIpcStatus,
        FIELD("StatusSummary", SummarizeStatusWork(pkt->effect, 30))
    );

    REGISTER_PACKET(1, false, 0x0149, ServerZone::FFXIVIpcFreeCompany,
        FIELD("Crest", FormatHex(pkt->Crest)),
        FIELD("Tag", FormatString(pkt->Tag, 6))
    );

    REGISTER_PACKET(1, false, 0x014A, ServerZone::FFXIVIpcRecastGroup,
        FIELD("FirstRecast", FieldToString(pkt->Recast[0])),
        FIELD("FirstRecastMax", FieldToString(pkt->RecastMax[0]))
    );

    // PARTY / ALLIANCE
    REGISTER_PACKET(1, false, 0x0199, ServerZone::FFXIVIpcUpdateParty,
        FIELD("PartyID", FormatHex(pkt->PartyID)),
        FIELD("AllianceFlags", FormatHex(pkt->AllianceFlags)),
        FIELD("Member0Name", FormatString(pkt->Member[0].Name, 32))
    );

    REGISTER_PACKET(1, false, 0x14B, ServerZone::FFXIVIpcUpdateAlliance,
        FIELD("AllianceFlags", FormatHex(pkt->AllianceFlags)),
        FIELD("AllianceLocalIndex", FieldToString(pkt->AllianceLocalIndex)),
        FIELD("AllianceMemberCount", FieldToString(pkt->AllianceMemberCount))
    );

    REGISTER_PACKET(1, false, 0x14C, ServerZone::FFXIVIpcPartyPos,
        FIELD("Index", FieldToString(pkt->Index)),
        FIELD("TerritoryType", FieldToString(pkt->TerritoryType)),
        FIELD("Pos", FormatPosition(pkt->X, pkt->Y, pkt->Z)),
        FIELD("EntityId", FormatHex(pkt->EntityId))
    );

    REGISTER_PACKET(1, false, 0x14D, ServerZone::FFXIVIpcAlliancePos,
        FIELD("AllianceIndex", FieldToString(pkt->AllianceIndex)),
        FIELD("PartyIndex", FieldToString(pkt->PartyIndex)),
        FIELD("Pos", FormatPosition(pkt->X, pkt->Y, pkt->Z)),
        FIELD("EntityId", FormatHex(pkt->EntityId))
    );

    REGISTER_PACKET(1, false, 0x14F, ServerZone::FFXIVIpcGrandCompany,
        FIELD("GrandCompany", FieldToString(pkt->GrandCompany)),
        FIELD("Rank", FieldToString(pkt->GrandCompanyRank))
    );

    // MOVEMENT / SPAWN
    REGISTER_PACKET(1, false, 0x0190, ServerZone::FFXIVIpcPlayerSpawn,
        FIELD("LayoutId", FieldToString(pkt->LayoutId)),
        FIELD("NameId", FieldToString(pkt->NameId)),
        FIELD("ObjKind", FieldToString(pkt->ClassJob)),
        FIELD("ClassJob", FieldToString(pkt->ClassJob)),
        FIELD("Level", FieldToString(pkt->Lv)),
        FIELD("HP", FieldToString(pkt->Hp)),
        FIELD("Pos", FormatPosition(pkt->Pos[0], pkt->Pos[1], pkt->Pos[2]))
    );

    REGISTER_PACKET(1, false, 0x0191, ServerZone::FFXIVIpcActorFreeSpawn,
        FIELD("SpawnId", FormatHex(pkt->spawnId)),
        FIELD("ActorId", FormatHex(pkt->actorId))
    );

    REGISTER_PACKET(1, false, 0x0192, ServerZone::FFXIVIpcActorMove,
        FIELD("Dir", FieldToString(pkt->dir)),
        FIELD("DirBeforeSlip", FieldToString(pkt->dirBeforeSlip)),
        FIELD("Flag", FormatHex(pkt->flag)),
        FIELD("Flag2", FormatHex(pkt->flag2)),
        FIELD("Speed", FieldToString(pkt->speed)),
        FIELD("Pos", std::string("compressed(") + std::to_string(pkt->pos[0]) + "," + std::to_string(pkt->pos[1]) + "," + std::to_string(pkt->pos[2]) + ") decoded(" + 
            std::to_string(pkt->pos[0] * 0.001f) + "," + std::to_string(pkt->pos[1] * 0.001f) + "," + std::to_string(pkt->pos[2] * 0.001f) + ")")
    );

    REGISTER_PACKET(1, false, 0x0193, ServerZone::FFXIVIpcTransfer,
        FIELD("Dir", FieldToString(pkt->dir)),
        FIELD("Duration", FieldToString(pkt->duration)),
        FIELD("Flag", FormatHex(pkt->flag))
    );

    REGISTER_PACKET(1, false, 0x0194, ServerZone::FFXIVIpcWarp,
        FIELD("Dir", FieldToString(pkt->Dir)),
        FIELD("Type", FieldToString(pkt->Type) + " (" + GetWarpTypeName(pkt->Type) + ")"),
        FIELD("LayerSet", FormatHex(pkt->LayerSet)),
        FIELD("Pos", FormatPosition(pkt->x, pkt->y, pkt->z))
    );

    REGISTER_PACKET(1, false, 0x0196, ServerZone::FFXIVIpcActorCast,
        FIELD("Action", FieldToString(pkt->Action)),
        FIELD("ActionKind", FieldToString(pkt->ActionKind)),
        FIELD("ActionKey", FieldToString(pkt->ActionKey)),
        FIELD("CastTime", FieldToString(pkt->CastTime)),
        FIELD("Target", FormatHex(pkt->Target))
    );

    // ZONE / PLAYER STATE
    // Remove the old simple REGISTER_PACKET for 0x019A InitZone here

    // --- Handle 0x019A based on direction: Client->Server = Move, Server->Client = InitZone ---
    {
        // Define the Client->Server Move packet structure
#pragma pack(push,1)
        struct FFXIVIpcClientMove {
            uint8_t dir;
            uint8_t dirBeforeSlip;
            uint8_t flag;
            uint8_t flag2;
            uint8_t speed;
            uint8_t __padding1;
            uint16_t pos[3];  // Compressed position (similar to ActorMove)
        };
#pragma pack(pop)
        static_assert(sizeof(FFXIVIpcClientMove) == 12, "ClientMove must be 12 bytes");

        // Register decoder for CLIENT->SERVER 0x019A (Move)
        PacketDecoding::PacketDecoderRegistry::Instance().RegisterDecoder(
            1, true, 0x019A,  // Note: true = outgoing/client->server
            [](const uint8_t* payload, size_t len, PacketDecoding::RowEmitter emit)
            {
                if (len >= sizeof(FFXIVIpcClientMove)) {
                    auto* p = reinterpret_cast<const FFXIVIpcClientMove*>(payload);
                    emit("PacketType", "ClientMove");
                    emit("Dir", PacketDecoding::FieldToString(p->dir));
                    emit("DirBeforeSlip", PacketDecoding::FieldToString(p->dirBeforeSlip));
                    emit("Flag", PacketDecoding::FormatHex(p->flag));
                    emit("Flag2", PacketDecoding::FormatHex(p->flag2));
                    emit("Speed", PacketDecoding::FieldToString(p->speed));
                    
                    // Decode compressed position
                    float x = p->pos[0] * 0.001f;
                    float y = p->pos[1] * 0.001f;
                    float z = p->pos[2] * 0.001f;
                    emit("Pos_Compressed", std::string("(") + std::to_string(p->pos[0]) + "," + 
                         std::to_string(p->pos[1]) + "," + std::to_string(p->pos[2]) + ")");
                    emit("Pos_Decoded", PacketDecoding::FormatPosition(x, y, z));
                }
                else {
                    emit("error", "ClientMove packet too small (expected >= 12 bytes, got " + std::to_string(len) + ")");
                }
            }
        );

        // Register decoder for SERVER->CLIENT 0x019A (InitZone) 
        PacketDecoding::PacketDecoderRegistry::Instance().RegisterDecoder(
            1, false, 0x019A,  // Note: false = incoming/server->client
            [](const uint8_t* payload, size_t len, PacketDecoding::RowEmitter emit)
            {
                if (len >= sizeof(ServerZone::FFXIVIpcInitZone)) {
                    auto* p = reinterpret_cast<const ServerZone::FFXIVIpcInitZone*>(payload);
                    emit("PacketType", "InitZone");
                    emit("ZoneId",        PacketDecoding::FieldToString(p->ZoneId));
                    emit("TerritoryType", PacketDecoding::FieldToString(p->TerritoryType));
                    emit("TerritoryIndex",PacketDecoding::FieldToString(p->TerritoryIndex));
                    emit("LayerSetId",    PacketDecoding::FormatHex(p->LayerSetId));
                    emit("LayoutId",      PacketDecoding::FieldToString(p->LayoutId));
                    emit("WeatherId",     PacketDecoding::FieldToString(p->WeatherId));
                    emit("Flag",          PacketDecoding::FieldToString(p->Flag));
                    emit("FestivalEid0",  PacketDecoding::FieldToString(p->FestivalEid0));
                    emit("FestivalPid0",  PacketDecoding::FieldToString(p->FestivalPid0));
                    emit("FestivalEid1",  PacketDecoding::FieldToString(p->FestivalEid1));
                    emit("FestivalPid1",  PacketDecoding::FieldToString(p->FestivalPid1));
                    emit("Pos", PacketDecoding::FormatPosition(p->Pos[0], p->Pos[1], p->Pos[2]));
                }
                else {
                    std::ostringstream os;
                    os << "InitZone packet too small (expected >= " << sizeof(ServerZone::FFXIVIpcInitZone) 
                       << " bytes, got " << len << ")";
                    emit("error", os.str());
                    // Helpful raw dump for diagnostics
                    if (len > 0) {
                        emit("raw", PacketDecoding::DumpBytesAsHex(std::span(payload, len)));
                    }
                }
            }
        );
    }

    // ================= REGISTER CLIENT PACKETS =================
    // Now register CLIENT->SERVER packets with proper structures
    using namespace PacketStructures::Client::Zone;

    // CLIENT SESSION/PING
    REGISTER_PACKET(1, true, 0x0065, ClientZone::FFXIVIpcPingHandler,
        FIELD("ClientTimeValue", FieldToString(pkt->clientTimeValue)),
        FIELD("Position", FormatPosition(pkt->position.pos[0], pkt->position.pos[1], pkt->position.pos[2])),
        FIELD("Direction", FormatAngle(pkt->position.dir))
    );

    REGISTER_PACKET(1, true, 0x0066, ClientZone::FFXIVIpcLoginHandler,
        FIELD("ClientTimeValue", FieldToString(pkt->clientTimeValue)),
        FIELD("ContentFinderStatus", FieldToString(pkt->contentFinderStatus)),
        FIELD("Name", FormatString(pkt->name, 32))
    );

    // CLIENT CHAT
    REGISTER_PACKET(1, true, 0x0067, ClientZone::FFXIVIpcChatHandler,
        FIELD("ClientTimeValue", FieldToString(pkt->clientTimeValue)),
        FIELD("ChatType", FieldToString(pkt->chatType) + " (" + GetChatTypeName(pkt->chatType) + ")"),
        FIELD("Message", FormatString(pkt->message, std::min<size_t>(200, sizeof(pkt->message)))),
        FIELD("Position", FormatPosition(pkt->position.pos[0], pkt->position.pos[1], pkt->position.pos[2]))
    );

    // CLIENT ACTIONS
    REGISTER_PACKET(1, true, 0x0196, ClientZone::FFXIVIpcActionRequest,
        FIELD("ActionKind", FieldToString(pkt->ActionKind) + " (" + GetActionTypeName(pkt->ActionKind) + ")"),
        FIELD("ActionKey", FormatHex(pkt->ActionKey)),
        FIELD("RequestId", FieldToString(pkt->RequestId)),
        FIELD("Target", FormatHex(pkt->Target)),
        FIELD("Dir", FormatAngle((uint16_t)pkt->Dir)),
        FIELD("DirTarget", FormatAngle((uint16_t)pkt->DirTarget))
    );

    REGISTER_PACKET(1, true, 0x0199, ClientZone::FFXIVIpcSelectGroundActionRequest,
        FIELD("ActionKind", FieldToString(pkt->ActionKind) + " (" + GetActionTypeName(pkt->ActionKind) + ")"),
        FIELD("ActionKey", FormatHex(pkt->ActionKey)),
        FIELD("RequestId", FieldToString(pkt->RequestId)),
        FIELD("Position", FormatPosition(pkt->Pos.x, pkt->Pos.y, pkt->Pos.z)),
        FIELD("Dir", FormatAngle((uint16_t)pkt->Dir))
    );

    // CLIENT MOVEMENT - Already handled above for 0x019A
    // but let's also add the UpdatePosition variants
    REGISTER_PACKET(1, true, 0x01A0, ClientZone::FFXIVIpcUpdatePosition,
        FIELD("Dir", FormatAngle(pkt->dir)),
        FIELD("DirBeforeSlip", FormatAngle(pkt->dirBeforeSlip)),
        FIELD("Flag", FormatHex(pkt->flag)),
        FIELD("Flag2", FormatHex(pkt->flag2)),
        FIELD("Position", FormatPosition(pkt->pos.x, pkt->pos.y, pkt->pos.z))
    );

    // CLIENT EVENTS
    REGISTER_PACKET(1, true, 0x01C2, ClientZone::FFXIVIpcEventHandlerTalk,
        FIELD("ActorId", FormatHex(pkt->actorId)),
        FIELD("EventId", FormatHex(pkt->eventId))
    );

    REGISTER_PACKET(1, true, 0x01C3, ClientZone::FFXIVIpcEventHandlerEmote,
        FIELD("ActorId", FormatHex(pkt->actorId)),
        FIELD("EventId", FormatHex(pkt->eventId)),
        FIELD("EmoteId", FieldToString(pkt->emoteId))
    );

    REGISTER_PACKET(1, true, 0x01C4, ClientZone::FFXIVIpcEventHandlerWithinRange,
        FIELD("EventId", FormatHex(pkt->eventId)),
        FIELD("Param1", FormatHex(pkt->param1)),
        FIELD("Position", FormatPosition(pkt->position.x, pkt->position.y, pkt->position.z))
    );

    REGISTER_PACKET(1, true, 0x01C5, ClientZone::FFXIVIpcEventHandlerOutsideRange,
        FIELD("EventId", FormatHex(pkt->eventId)),
        FIELD("Param1", FormatHex(pkt->param1)),
        FIELD("Position", FormatPosition(pkt->position.x, pkt->position.y, pkt->position.z))
    );

    REGISTER_PACKET(1, true, 0x01C6, ClientZone::FFXIVIpcEnterTerritoryHandler,
        FIELD("EventId", FormatHex(pkt->eventId)),
        FIELD("Param1", FieldToString(pkt->param1)),
        FIELD("Param2", FieldToString(pkt->param2))
    );

    // CLIENT ITEM OPERATIONS
    REGISTER_PACKET(1, true, 0x01AE, ClientZone::FFXIVIpcClientInventoryItemOperation,
        FIELD("ContextId", FormatHex(pkt->ContextId)),
        FIELD("OperationType", FieldToString(pkt->OperationType)),
        FIELD("SrcStorage", FieldToString(pkt->SrcStorageId)),
        FIELD("SrcContainer", FieldToString(pkt->SrcContainerIndex)),
        FIELD("DstStorage", FieldToString(pkt->DstStorageId)),
        FIELD("DstContainer", FieldToString(pkt->DstContainerIndex))
    );

    // Note: FFXIVIpcTradeCommand appears to be server-only
    // If there's a client trade packet, it might have a different structure or name

    // CLIENT GM COMMANDS
    REGISTER_PACKET(1, true, 0x0197, ClientZone::FFXIVIpcGmCommand,
        FIELD("Id", FormatHex(pkt->Id)),
        FIELD("Target", FormatHex(pkt->Target)),
        FIELD("Arg0", FormatHex(pkt->Arg0)),
        FIELD("Arg1", FormatHex(pkt->Arg1))
    );

    REGISTER_PACKET(1, true, 0x0198, ClientZone::FFXIVIpcGmCommandName,
        FIELD("Id", FormatHex(pkt->Id)),
        FIELD("Name", FormatString(pkt->Name, 32)),
        FIELD("Arg0", FormatHex(pkt->Arg0))
    );

    // CLIENT SOCIAL
    REGISTER_PACKET(1, true, 0x00C9, ClientZone::FFXIVIpcInvite,
        FIELD("AuthType", FieldToString(pkt->AuthType)),
        FIELD("TargetName", FormatString(pkt->TargetName, 32))
    );

    REGISTER_PACKET(1, true, 0x00CA, ClientZone::FFXIVIpcInviteReply,
        FIELD("InviteCharacterID", FormatHex(pkt->InviteCharacterID)),
        FIELD("AuthType", FieldToString(pkt->AuthType)),
        FIELD("Answer", FieldToString(pkt->Answer))
    );

    REGISTER_PACKET(1, true, 0x00CB, ClientZone::FFXIVIpcGetCommonlist,
        FIELD("CommunityID", FormatHex(pkt->CommunityID)),
        FIELD("ListType", FieldToString(pkt->ListType)),
        FIELD("NextIndex", FieldToString(pkt->NextIndex))
    );

    REGISTER_PACKET(1, true, 0x00CC, ClientZone::FFXIVIpcGetCommonlistDetail,
        FIELD("DetailCharacterID", FormatHex(pkt->DetailCharacterID)),
        FIELD("CommunityID", FormatHex(pkt->CommunityID)),
        FIELD("ListType", FieldToString(pkt->ListType))
    );

    REGISTER_PACKET(1, true, 0x00E1, ClientZone::FFXIVIpcBlacklistAdd,
        FIELD("TargetName", FormatString(pkt->TargetCharacterName, 32))
    );

    REGISTER_PACKET(1, true, 0x00E2, ClientZone::FFXIVIpcBlacklistRemove,
        FIELD("TargetCharacterID", FormatHex(pkt->TargetCharacterID)),
        FIELD("TargetName", FormatString(pkt->TargetCharacterName, 32))
    );

    // CLIENT PARTY
    REGISTER_PACKET(1, true, 0x00DC, ClientZone::FFXIVIpcPcPartyLeave,
        FIELD("Reserve", FieldToString(pkt->Reserve))
    );

    REGISTER_PACKET(1, true, 0x00DD, ClientZone::FFXIVIpcPcPartyDisband,
        FIELD("Reserve", FieldToString(pkt->Reserve))
    );

    REGISTER_PACKET(1, true, 0x00DE, ClientZone::FFXIVIpcPcPartyKick,
        FIELD("LeaveCharacterName", FormatString(pkt->LeaveCharacterName, 32))
    );

    REGISTER_PACKET(1, true, 0x00DF, ClientZone::FFXIVIpcPcPartyChangeLeader,
        FIELD("NextLeaderName", FormatString(pkt->NextLeaderCharacterName, 32))
    );

    // CLIENT CONFIG
    REGISTER_PACKET(1, true, 0x0262, ClientZone::FFXIVIpcConfig,
        FIELD("Flag", FormatHex(pkt->flag))
    );

    // CLIENT DISCOVERY
    REGISTER_PACKET(1, true, 0x0194, ClientZone::FFXIVIpcNewDiscovery,
        FIELD("LayoutId", FormatHex(pkt->LayoutId)),
        FIELD("Position", FormatPosition(pkt->PositionX, pkt->PositionY, pkt->PositionZ))
    );

    // CLIENT MARKET BOARD
    REGISTER_PACKET(1, true, 0x1102, ClientZone::FFXIVIpcMarketBoardRequestItemListingInfo,
        FIELD("CatalogId", FormatHex(pkt->catalogId)),
        FIELD("RequestId", FormatHex(pkt->requestId))
    );

    REGISTER_PACKET(1, true, 0x1103, ClientZone::FFXIVIpcMarketBoardRequestItemListings,
        FIELD("ItemCatalogId", FieldToString(pkt->itemCatalogId))
    );

    // CLIENT HOUSING
    REGISTER_PACKET(1, true, 0x01B0, ClientZone::FFXIVIpcHousingExteriorChange,
        FIELD("LandId", FormatHex(pkt->landIdOrIndex.landId)),
        FIELD("RemoveFlags", FormatHex(pkt->RemoveFlags))
    );

    REGISTER_PACKET(1, true, 0x01B1, ClientZone::FFXIVIpcHousingPlaceYardItem,
        FIELD("LandId", FormatHex(pkt->landIdOrIndex.landId)),
        FIELD("StorageId", FieldToString(pkt->StorageId)),
        FIELD("Position", FormatPosition(pkt->Pos.x, pkt->Pos.y, pkt->Pos.z)),
        FIELD("Rotation", FormatAngle(pkt->Rotation))
    );

    REGISTER_PACKET(1, true, 0x026A, ClientZone::FFXIVIpcHousingHouseName,
        FIELD("LandId", FormatHex(pkt->landId.landId)),
        FIELD("HouseName", FormatString(pkt->houseName, 20))
    );

    REGISTER_PACKET(1, true, 0x026B, ClientZone::FFXIVIpcHousingGreeting,
        FIELD("LandId", FormatHex(pkt->landId.landId)),
        FIELD("Greeting", FormatString(pkt->greeting, std::min<size_t>(80, sizeof(pkt->greeting))))
    );

    // CLIENT LINKSHELL
    REGISTER_PACKET(1, true, 0x00F0, ClientZone::FFXIVIpcLinkshellJoin,
        FIELD("LinkshellID", FormatHex(pkt->LinkshellID)),
        FIELD("MemberName", FormatString(pkt->MemberCharacterName, 32))
    );

    REGISTER_PACKET(1, true, 0x00F2, ClientZone::FFXIVIpcLinkshellLeave,
        FIELD("LinkshellID", FormatHex(pkt->LinkshellID))
    );

    // CLIENT CONTENT FINDER
    REGISTER_PACKET(1, true, 0x01FD, ClientZone::FFXIVIpcFind5Contents,
        FIELD("AcceptHalfway", FieldToString(pkt->acceptHalfway)),
        FIELD("Language", FieldToString(pkt->language)),
        FIELD("Territory0", FieldToString(pkt->territoryTypes[0])),
        FIELD("Territory1", FieldToString(pkt->territoryTypes[1]))
    );

    REGISTER_PACKET(1, true, 0x01FB, ClientZone::FFXIVIpcAcceptContent,
        FIELD("Accept", FieldToString(pkt->accept)),
        FIELD("TerritoryType", FieldToString(pkt->territoryType)),
        FIELD("TerritoryId", FormatHex(pkt->territoryId))
    );

    REGISTER_PACKET(1, true, 0x01FC, ClientZone::FFXIVIpcCancelFindContent,
        FIELD("Cause", FieldToString(pkt->cause))
    );

}  // End of RegisterZonePackets() function