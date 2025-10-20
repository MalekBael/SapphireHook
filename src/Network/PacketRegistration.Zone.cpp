#include "../Network/OpcodeNames.h"
#include "../ProtocolHandlers/CommonTypes.h"
#include "../ProtocolHandlers/Zone/ClientZoneDef.h"
#include "../ProtocolHandlers/Zone/ServerZoneDef.h"
#include "PacketRegistration.h"
#include "PacketRegistration.Macros.h"
#include "PacketTable.Zone.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
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
#ifdef REGISTER_PACKET
#undef REGISTER_PACKET
#endif
#ifdef FIELD
#undef FIELD
#endif
#define REGISTER_PACKET(Channel, Outgoing, Opcode, StructType, ...) \
    if constexpr(false){ const StructType* pkt=nullptr; (void)pkt; }
#define FIELD(Name, Expr)
#endif

using namespace PacketDecoding;
using namespace PacketStructures;

namespace {
    std::string ClassifyItemOperation(const PacketStructures::Server::Zone::FFXIVIpcItemOperation* p);
    std::string DumpBytes(const void* data, size_t len, size_t maxShow = 32);

    std::string ClassifyItemOperation(const PacketStructures::Server::Zone::FFXIVIpcItemOperation* p) {
        if (!p) return "null";
        std::ostringstream os;
        switch (p->operationType) {
        case 1: os << "Move"; break;
        case 2: os << "Split"; break;
        case 3: os << "Combine"; break;
        case 4: os << "Discard"; break;
        case 5: os << "Use"; break;
        default: os << "Op" << p->operationType; break;
        }
        if (p->srcStorageId != p->dstStorageId)
            os << "(Storage:" << p->srcStorageId << "→" << p->dstStorageId << ")";
        if (p->srcStack > 0 || p->dstStack > 0)
            os << "(Stack:" << p->srcStack << "→" << p->dstStack << ")";
        return os.str();
    }

    std::string DumpBytes(const void* data, size_t len, size_t maxShow) {
        if (!data || len == 0) return "[]";
        std::ostringstream os;
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        size_t showLen = std::min(len, maxShow);
        os << "[" << std::hex << std::uppercase << std::setfill('0');
        for (size_t i = 0; i < showLen; ++i) {
            if (i) os << ' ';
            os << std::setw(2) << static_cast<unsigned>(bytes[i]);
        }
        if (len > maxShow) os << "...+" << std::dec << (len - maxShow) << "more";
        os << "]";
        return os.str();
    }
}

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

// ============================================================================
// Generic Decoder Factory
// ============================================================================
namespace {
    using namespace PacketDecoding;
    namespace ServerZone = PacketStructures::Server::Zone;
    namespace ClientZone = PacketStructures::Client::Zone;

    template<typename PacketT>
    DecoderFunc MakeGenericDecoder() {
        return [](const uint8_t* payload, size_t len, RowEmitter emit) {
            if (len < sizeof(PacketT)) {
                std::ostringstream os; os << "Packet too small (have " << len
                    << ", need " << sizeof(PacketT) << ")";
                emit("error", os.str());
                return;
            }
            emit("PacketType", typeid(PacketT).name());
            };
    }

    // ================= CATEGORY 1: COMBAT =================
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcActorControl>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcActorControl)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcActorControl*>(p);
            FieldBuilder(emit)
                .Field("Category", pkt->category)
                .Enum("CategoryName", pkt->category, ::LookupActorControlCategoryName)
                .Hex("Param1", pkt->param1).Hex("Param2", pkt->param2)
                .Hex("Param3", pkt->param3).Hex("Param4", pkt->param4);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcActionResult1>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcActionResult1)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcActionResult1*>(p);
            FieldBuilder(emit)
                .Field("Action", pkt->Action)
                .Enum("ActionKind", pkt->ActionKind, GetActionTypeName)
                .Field("RequestId", pkt->RequestId)
                .Field("ResultId", pkt->ResultId)
                .Hex("MainTarget", pkt->MainTarget)
                .Hex("Target", pkt->Target)
                .Hex("Flag", pkt->Flag)
                .Field("LockTime", static_cast<double>(pkt->LockTime))
                .Field("DamageHP", static_cast<int>(pkt->CalcResult.value))
                .Hex("BallistaEntityId", pkt->BallistaEntityId);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcActionResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcActionResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcActionResult*>(p);
            FieldBuilder b(emit);
            b.Field("Action", pkt->Action)
                .Enum("ActionKind", pkt->ActionKind, GetActionTypeName)
                .Field("RequestId", pkt->RequestId)
                .Field("ResultId", pkt->ResultId)
                .Hex("MainTarget", pkt->MainTarget)
                .Field("TargetCount", pkt->TargetCount)
                .Hex("Flag", pkt->Flag)
                .Field("LockTime", static_cast<double>(pkt->LockTime));
            int show = std::min<int>(pkt->TargetCount, 3);
            for (int i = 0; i < show; i++) {
                std::ostringstream tk, dk; tk << "Target" << i; dk << "Damage" << i;
                b.Hex(tk.str(), pkt->Target[i])
                    .Field(dk.str(), static_cast<int>(pkt->CalcResult[i].value));
            }
            if (pkt->TargetCount > 3) {
                std::ostringstream os; os << "... and " << (pkt->TargetCount - 3) << " more targets";
                b.Field("MoreTargets", os.str());
            }
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcPlayerSpawn>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcPlayerSpawn)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcPlayerSpawn*>(p);
            FieldBuilder b(emit);
            b.Field("LayoutId", pkt->LayoutId)
                .Field("NameId", pkt->NameId)
                .String("Name", reinterpret_cast<const char*>(pkt->Name), 32)
                .Field("ObjKind", pkt->ObjKind)
                .Field("ObjType", pkt->ObjType)
                .Field("ClassJob", pkt->ClassJob)
                .Field("Level", pkt->Lv)
                .Field("HP", pkt->Hp).Field("HPMax", pkt->HpMax)
                .Field("MP", pkt->Mp).Field("MPMax", pkt->MpMax)
                .Position("Position", pkt->Pos[0], pkt->Pos[1], pkt->Pos[2])
                .Angle("Direction", static_cast<float>(pkt->Dir) / 65535.f * 6.283185f);
            if (pkt->GrandCompany > 0)
                b.Field("GrandCompany", pkt->GrandCompany)
                .Field("GrandCompanyRank", pkt->GrandCompanyRank);
            if (pkt->Crest != 0)
                b.Hex("FCCrest", pkt->Crest)
                .String("FCTag", reinterpret_cast<const char*>(pkt->FreeCompanyTag), 6);
            int active = 0;
            for (int i = 0; i < 30; i++) if (pkt->Status[i].id) active++;
            if (active) {
                b.Field("ActiveStatusCount", active);
                int shown = 0;
                for (int i = 0; i < 30 && shown < 5; i++) {
                    if (!pkt->Status[i].id) continue;
                    std::ostringstream k; k << "Status" << shown;
                    b.Hex(k.str(), pkt->Status[i].id);
                    if (const char* n = GetStatusEffectName(pkt->Status[i].id))
                        b.Field(k.str() + "Name", n);
                    shown++;
                }
            }
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcActorControlSelf>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcActorControlSelf)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcActorControlSelf*>(p);
            FieldBuilder(emit)
                .Field("Category", pkt->category)
                .Enum("CategoryName", pkt->category, ::LookupActorControlCategoryName)
                .Hex("Param1", pkt->param1).Hex("Param2", pkt->param2)
                .Hex("Param3", pkt->param3).Hex("Param4", pkt->param4)
                .Hex("Param5", pkt->param5).Hex("Param6", pkt->param6);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcActorControlTarget>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcActorControlTarget)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcActorControlTarget*>(p);
            FieldBuilder(emit)
                .Field("Category", pkt->category)
                .Enum("CategoryName", pkt->category, ::LookupActorControlCategoryName)
                .Hex("Param1", pkt->param1).Hex("Param2", pkt->param2)
                .Hex("Param3", pkt->param3).Hex("Param4", pkt->param4)
                .Hex("TargetId", pkt->targetId);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcResting>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcResting)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcResting*>(p);
            FieldBuilder(emit)
                .Field("Hp", pkt->Hp)
                .Field("Mp", pkt->Mp)
                .Field("Tp", pkt->Tp)
                .Field("Gp", pkt->Gp)
                .Hex("Unknown_3_2", pkt->Unknown_3_2);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcStatus>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcStatus)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcStatus*>(p);
            FieldBuilder b(emit);
            int active = 0;
            for (int i = 0; i < 30; i++) if (pkt->effect[i].id) active++;
            b.Field("ActiveStatusCount", active);
            int shown = 0;
            for (int i = 0; i < 30 && shown < 10; i++) {
                if (!pkt->effect[i].id) continue;
                std::ostringstream pfx; pfx << "Status" << shown;
                b.Hex(pfx.str() + "Id", pkt->effect[i].id);
                if (const char* n = GetStatusEffectName(pkt->effect[i].id))
                    b.Field(pfx.str() + "Name", n);
                b.Field(pfx.str() + "SystemParam", (int)pkt->effect[i].systemParam)
                    .Field(pfx.str() + "Time", pkt->effect[i].time)
                    .Hex(pfx.str() + "Source", pkt->effect[i].source);
                shown++;
            }
            if (shown < active) {
                std::ostringstream os; os << "... " << (active - shown) << " more effects";
                b.Field("MoreEffects", os.str());
            }
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcRecastGroup>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcRecastGroup)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcRecastGroup*>(p);
            FieldBuilder b(emit);
            int active = 0;
            for (int i = 0; i < 80; i++) if (pkt->Recast[i] > 0.0f) active++;
            b.Field("ActiveRecastGroups", active);
            int shown = 0;
            for (int i = 0; i < 80 && shown < 10; i++) {
                if (pkt->Recast[i] <= 0.0f) continue;
                std::ostringstream pfx; pfx << "Group" << i;
                b.Field(pfx.str() + "Recast", pkt->Recast[i])
                    .Field(pfx.str() + "RecastMax", pkt->RecastMax[i]);
                shown++;
            }
            if (shown < active) {
                std::ostringstream os; os << "... " << (active - shown) << " more groups";
                b.Field("MoreGroups", os.str());
            }
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcActorCast>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcActorCast)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcActorCast*>(p);
            float x = pkt->TargetPos[0] * 0.001f, y = pkt->TargetPos[1] * 0.001f, z = pkt->TargetPos[2] * 0.001f;
            FieldBuilder(emit)
                .Field("Action", pkt->Action)
                .Enum("ActionKind", pkt->ActionKind, GetActionTypeName)
                .Hex("ActionKey", pkt->ActionKey)
                .Field("CastTime", pkt->CastTime)
                .Hex("Target", pkt->Target)
                .Angle("Direction", pkt->Dir)
                .Hex("BallistaEntityId", pkt->BallistaEntityId)
                .Position("TargetPos", x, y, z);
            };
    }

    // ================= CATEGORY 2: MOVEMENT / SPAWN =================
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcActorMove>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcActorMove)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcActorMove*>(p);
            float x = pkt->pos[0] * 0.001f, y = pkt->pos[1] * 0.001f, z = pkt->pos[2] * 0.001f;
            FieldBuilder(emit)
                .Field("Dir", pkt->dir)
                .Field("DirBeforeSlip", pkt->dirBeforeSlip)
                .Hex("Flag", pkt->flag)
                .Hex("Flag2", pkt->flag2)
                .Field("Speed", pkt->speed)
                .Position("Position", x, y, z)
                .Field("PosRaw", std::to_string(pkt->pos[0]) + "," +
                    std::to_string(pkt->pos[1]) + "," +
                    std::to_string(pkt->pos[2]));
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcActorFreeSpawn>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcActorFreeSpawn)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcActorFreeSpawn*>(p);
            FieldBuilder(emit).Hex("SpawnId", pkt->spawnId).Hex("ActorId", pkt->actorId);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcWarp>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcWarp)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcWarp*>(p);
            FieldBuilder b(emit);
            b.Field("Dir", pkt->Dir)
                .Field("Type", pkt->Type)
                .Enum("TypeName", pkt->Type, GetWarpTypeName)
                .Field("TypeArg", pkt->TypeArg)
                .Hex("LayerSet", pkt->LayerSet)
                .Position("Position", pkt->x, pkt->y, pkt->z);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcTransfer>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcTransfer)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcTransfer*>(p);
            float x = pkt->pos[0] * 0.001f, y = pkt->pos[1] * 0.001f, z = pkt->pos[2] * 0.001f;
            FieldBuilder(emit)
                .Field("Dir", pkt->dir)
                .Field("Duration", static_cast<double>(pkt->duration))
                .Hex("Flag", pkt->flag)
                .Position("Position", x, y, z);
            };
    }

    // ================= CATEGORY 3: CORE / SESSION =================
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcSync>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcSync)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcSync*>(p);
            FieldBuilder(emit)
                .Field("ClientTimeValue", pkt->clientTimeValue)
                .Field("TransmissionInterval", pkt->transmissionInterval)
                .Hex("OriginEntityId", pkt->position.originEntityId)
                .Position("Position", pkt->position.pos[0], pkt->position.pos[1], pkt->position.pos[2])
                .Angle("Direction", pkt->position.dir);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcLogin>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcLogin)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcLogin*>(p);
            FieldBuilder(emit)
                .Field("ClientTimeValue", pkt->clientTimeValue)
                .Hex("LoginTicketId", pkt->loginTicketId)
                .Hex("PlayerActorId", pkt->playerActorId);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcChat>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcChat)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcChat*>(p);
            FieldBuilder(emit)
                .Field("Type", pkt->type)
                .Enum("TypeName", pkt->type, GetChatTypeName)
                .Hex("EntityId", pkt->entityId)
                .Hex("CharacterId", pkt->characterId)
                .String("Speaker", pkt->speakerName, 32)
                .String("Message", pkt->message, std::min<size_t>(200, sizeof(pkt->message)));
            };
    }

    // ================= CATEGORY 4: PROFILE / SEARCH =================
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetProfileResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcGetProfileResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetProfileResult*>(p);
            FieldBuilder(e)
                .Hex("OnlineStatus", pkt->OnlineStatus)
                .Hex("SelectClassID", pkt->SelectClassID)
                .Field("CurrentSelectClassID", (int)pkt->CurrentSelectClassID)
                .Field("Region", (int)pkt->Region)
                .String("SearchComment", pkt->SearchComment, std::min<size_t>(100, sizeof(pkt->SearchComment)));
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcSetProfileResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcSetProfileResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcSetProfileResult*>(p);
            FieldBuilder(e)
                .Hex("OnlineStatus", pkt->OnlineStatus)
                .Hex("SelectClassID", pkt->SelectClassID)
                .Field("Result", pkt->Result)
                .Field("CurrentSelectClassID", (int)pkt->CurrentSelectClassID)
                .Field("Region", (int)pkt->Region)
                .String("SearchComment", pkt->SearchComment, std::min<size_t>(100, sizeof(pkt->SearchComment)));
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetSearchCommentResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcGetSearchCommentResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetSearchCommentResult*>(p);
            FieldBuilder(e)
                .Hex("TargetEntityID", pkt->TargetEntityID)
                .String("SearchComment", pkt->SearchComment, std::min<size_t>(100, sizeof(pkt->SearchComment)));
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetCharacterNameResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcGetCharacterNameResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetCharacterNameResult*>(p);
            FieldBuilder(e).Hex("CharacterID", pkt->CharacterID).String("CharacterName", pkt->CharacterName, 32);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcPcSearchResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcPcSearchResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcPcSearchResult*>(p);
            FieldBuilder(e).Field("ResultCount", pkt->ResultCount);
            };
    }

    // ================= CATEGORY 5: PARTY =================
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcUpdateParty>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcUpdateParty)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcUpdateParty*>(p);
            FieldBuilder b(emit);
            b.Hex("PartyID", pkt->PartyID)
                .Hex("PartyLeaderContentID", pkt->PartyLeaderContentID)
                .Field("AllianceLocalIndex", (int)pkt->AllianceLocalIndex)
                .Field("AllianceMemberCount", (int)pkt->AllianceMemberCount)
                .Hex("AllianceFlags", pkt->AllianceFlags);
            for (int i = 0; i < 8; i++) {
                if (!pkt->Member[i].Valid) continue;
                std::string pfx = "Member" + std::to_string(i);
                b.String(pfx + "Name", pkt->Member[i].Name, 32)
                    .Hex(pfx + "CharaId", pkt->Member[i].CharaId)
                    .Hex(pfx + "EntityId", pkt->Member[i].EntityId)
                    .Field(pfx + "ClassJob", (int)pkt->Member[i].ClassJob)
                    .Field(pfx + "Lv", (int)pkt->Member[i].Lv)
                    .Field(pfx + "HP", pkt->Member[i].Hp)
                    .Field(pfx + "HPMax", pkt->Member[i].HpMax)
                    .Field(pfx + "MP", pkt->Member[i].Mp)
                    .Field(pfx + "MPMax", pkt->Member[i].MpMax)
                    .Field(pfx + "TerritoryType", pkt->Member[i].TerritoryType);
            }
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcPcPartyResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcPcPartyResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcPcPartyResult*>(p);
            FieldBuilder(e).Field("UpPacketNo", pkt->UpPacketNo).Field("Result", pkt->Result);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcPcPartyUpdate>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcPcPartyUpdate)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcPcPartyUpdate*>(p);
            const char* name = "Unknown";
            switch (pkt->UpdateStatus) {
            case 0: name = "None"; break; case 1: name = "Join"; break; case 2: name = "Leave"; break;
            case 3: name = "Kick"; break; case 4: name = "LeaderChange"; break; case 5: name = "Disband"; break;
            }
            std::ostringstream status; status << name << " (" << (int)pkt->UpdateStatus << ")";
            FieldBuilder(e)
                .Hex("ExecuteCharacterID", pkt->ExecuteCharacterID)
                .Hex("TargetCharacterID", pkt->TargetCharacterID)
                .Field("UpdateStatus", status.str())
                .Field("Count", (int)pkt->Count)
                .Field("ExecuteIdentity", (int)pkt->ExecuteIdentity)
                .Field("TargetIdentity", (int)pkt->TargetIdentity)
                .String("ExecuteName", pkt->ExecuteCharacterName, 32)
                .String("TargetName", pkt->TargetCharacterName, 32);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcPartyPos>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcPartyPos)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcPartyPos*>(p);
            FieldBuilder(e)
                .Field("Index", (int)pkt->Index)
                .Field("TerritoryType", pkt->TerritoryType)
                .Hex("EntityId", pkt->EntityId)
                .Position("Position", pkt->X, pkt->Y, pkt->Z);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcAlliancePos>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcAlliancePos)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcAlliancePos*>(p);
            FieldBuilder(e)
                .Field("AllianceIndex", (int)pkt->AllianceIndex)
                .Field("PartyIndex", (int)pkt->PartyIndex)
                .Field("TerritoryType", pkt->TerritoryType)
                .Hex("EntityId", pkt->EntityId)
                .Position("Position", pkt->X, pkt->Y, pkt->Z);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcUpdateAlliance>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcUpdateAlliance)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcUpdateAlliance*>(p);
            FieldBuilder(e)
                .Hex("AllianceFlags", pkt->AllianceFlags)
                .Field("AllianceLocalIndex", (int)pkt->AllianceLocalIndex)
                .Field("AllianceMemberCount", (int)pkt->AllianceMemberCount);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcPartyRecruitResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcPartyRecruitResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcPartyRecruitResult*>(p);
            FieldBuilder(e)
                .Hex("TargetCharacterID", pkt->TargetCharacterID)
                .Hex("Param", pkt->Param)
                .Field("Type", pkt->Type)
                .Field("Result", pkt->Result)
                .Field("Identity", (int)pkt->Identity)
                .String("TargetName", pkt->TargetName, 32);
            };
    }

    // ================= CATEGORY 6: SOCIAL / COMMUNICATION =================
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcInviteResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcInviteResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcInviteResult*>(p);
            const char* auth = "Unknown";
            switch (pkt->AuthType) {
            case 0: auth = "None"; break; case 1: auth = "Friend"; break; case 2: auth = "Party"; break;
            case 3: auth = "FreeCompany"; break; case 4: auth = "Linkshell"; break;
            }
            std::ostringstream at; at << auth << " (" << (int)pkt->AuthType << ")";
            FieldBuilder(e)
                .Field("Result", pkt->Result)
                .Field("AuthType", at.str())
                .Field("Identity", (int)pkt->Identity)
                .String("TargetName", pkt->TargetName, 32);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcInviteReplyResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcInviteReplyResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcInviteReplyResult*>(p);
            const char* auth = "Unknown";
            switch (pkt->AuthType) {
            case 0: auth = "None"; break; case 1: auth = "Friend"; break; case 2: auth = "Party"; break;
            case 3: auth = "FreeCompany"; break; case 4: auth = "Linkshell"; break;
            }
            const char* ans = pkt->Answer == 1 ? "Accept" : "Decline";
            std::ostringstream at, an; at << auth << " (" << (int)pkt->AuthType << ")"; an << ans << " (" << (int)pkt->Answer << ")";
            FieldBuilder(e)
                .Field("Result", pkt->Result)
                .Field("AuthType", at.str())
                .Field("Answer", an.str())
                .Field("Identity", (int)pkt->Identity)
                .String("InviteCharacterName", pkt->InviteCharacterName, 32);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcInviteUpdate>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcInviteUpdate)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcInviteUpdate*>(p);
            FieldBuilder(e)
                .Hex("InviteCharacterID", pkt->InviteCharacterID)
                .Field("InviteTime", pkt->InviteTime)
                .Field("AuthType", (int)pkt->AuthType)
                .Field("InviteCount", (int)pkt->InviteCount)
                .Field("Result", (int)pkt->Result)
                .Field("Identity", (int)pkt->Identity)
                .String("InviteName", pkt->InviteName, 32);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcFriendlistRemoveResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcFriendlistRemoveResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcFriendlistRemoveResult*>(p);
            FieldBuilder(e)
                .Hex("RemovedCharacterID", pkt->RemovedCharacterID)
                .Field("Result", pkt->Result)
                .Field("Identity", (int)pkt->Identity)
                .String("RemovedCharacterName", pkt->RemovedCharacterName, 32);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcLinkshellResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcLinkshellResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcLinkshellResult*>(p);
            FieldBuilder(e)
                .Hex("LinkshellID", pkt->LinkshellID)
                .Hex("TargetCharacterID", pkt->TargetCharacterID)
                .Field("UpPacketNo", pkt->UpPacketNo)
                .Field("Result", pkt->Result)
                .Field("UpdateStatus", (int)pkt->UpdateStatus)
                .Field("Identity", (int)pkt->Identity)
                .String("LinkshellName", pkt->LinkshellName, 32)
                .String("TargetName", pkt->TargetName, 32);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcBlacklistAddResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcBlacklistAddResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcBlacklistAddResult*>(p);
            FieldBuilder(e)
                .Hex("AddedCharacterID", pkt->AddedCharacter.CharacterID)
                .String("CharacterName", pkt->AddedCharacter.CharacterName, 32)
                .Field("Result", pkt->Result)
                .Field("Identity", (int)pkt->Identity);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcBlacklistRemoveResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcBlacklistRemoveResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcBlacklistRemoveResult*>(p);
            FieldBuilder(e)
                .Hex("RemovedCharacterID", pkt->RemovedCharacter.CharacterID)
                .String("CharacterName", pkt->RemovedCharacter.CharacterName, 32)
                .Field("Result", pkt->Result)
                .Field("Identity", (int)pkt->Identity);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetBlacklistResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcGetBlacklistResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetBlacklistResult*>(p);
            FieldBuilder b(e);
            b.Field("Index", (int)pkt->Index)
                .Field("NextIndex", (int)pkt->NextIndex)
                .Field("RequestKey", (int)pkt->RequestKey);
            int shown = 0;
            for (int i = 0; i < 20 && shown < 5; i++) {
                if (!pkt->Blacklist[i].CharacterID) continue;
                std::string name(pkt->Blacklist[i].CharacterName, 32);
                name = name.substr(0, name.find('\0'));
                b.Hex("Blacklist" + std::to_string(i) + "ID", pkt->Blacklist[i].CharacterID)
                    .String("Blacklist" + std::to_string(i) + "Name", name.c_str(), 32);
                shown++;
            }
            if (!shown) b.Field("BlacklistEntries", "None");
            else if (shown < 20) {
                std::ostringstream os; os << "... " << (20 - shown) << " more entries";
                b.Field("MoreEntries", os.str());
            }
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcSetOnlineStatus>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcSetOnlineStatus)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcSetOnlineStatus*>(p);
            FieldBuilder(e).Hex("OnlineStatusFlags", pkt->onlineStatusFlags);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetLinkshellListResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcGetLinkshellListResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetLinkshellListResult*>(p);
            FieldBuilder b(e);
            int shown = 0;
            for (int i = 0; i < 8; i++) {
                if (!pkt->LinkshellList[i].LinkshellID) continue;
                std::string name(pkt->LinkshellList[i].LinkshellName, 32);
                name = name.substr(0, name.find('\0'));
                b.Hex("Linkshell" + std::to_string(i) + "ID", pkt->LinkshellList[i].LinkshellID)
                    .Hex("Linkshell" + std::to_string(i) + "ChannelID", pkt->LinkshellList[i].ChannelID)
                    .Field("Linkshell" + std::to_string(i) + "HierarchyID", pkt->LinkshellList[i].HierarchyID)
                    .String("Linkshell" + std::to_string(i) + "Name", name.c_str(), 32);
                shown++;
            }
            if (!shown) b.Field("Linkshells", "None");
            };
    }

    // ================= CATEGORY 7: SYSTEM MESSAGES & MISC (single definitive copy) =================
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcSendSystemMessage>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcSendSystemMessage)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcSendSystemMessage*>(p);
            FieldBuilder(e).Field("MessageParam", (int)pkt->MessageParam)
                .String("Message", pkt->Message, std::min<size_t>(200, sizeof(pkt->Message)));
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcSendLoginMessage>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcSendLoginMessage)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcSendLoginMessage*>(p);
            FieldBuilder(e).Field("MessageParam", (int)pkt->MessageParam)
                .String("Message", pkt->Message, std::min<size_t>(200, sizeof(pkt->Message)));
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcChatChannelResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcChatChannelResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcChatChannelResult*>(p);
            FieldBuilder(e)
                .Hex("ChannelID", pkt->ChannelID)
                .Hex("CommunityID", pkt->CommunityID)
                .Hex("TargetCharacterID", pkt->TargetCharacterID)
                .Field("UpPacketNo", pkt->UpPacketNo)
                .Field("Result", pkt->Result);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcFreeCompanyResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcFreeCompanyResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcFreeCompanyResult*>(p);
            FieldBuilder(e)
                .Hex("FreeCompanyID", pkt->FreeCompanyID)
                .Hex("Arg", pkt->Arg)
                .Field("Type", pkt->Type)
                .Field("Result", pkt->Result)
                .Field("UpdateStatus", (int)pkt->UpdateStatus)
                .Field("Identity", (int)pkt->Identity)
                .String("FreeCompanyName", pkt->FreeCompanyName, 46)
                .String("TargetName", pkt->TargetName, 32);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGrandCompany>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcGrandCompany)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGrandCompany*>(p);
            const char* gc = "Unknown";
            switch (pkt->GrandCompany) {
            case 0: gc = "None"; break; case 1: gc = "Maelstrom"; break;
            case 2: gc = "Order of the Twin Adder"; break; case 3: gc = "Immortal Flames"; break;
            }
            std::ostringstream os; os << gc << " (" << (int)pkt->GrandCompany << ")";
            FieldBuilder(e).Field("GrandCompany", os.str())
                .Field("GrandCompanyRank", (int)pkt->GrandCompanyRank);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetCommonlistResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcGetCommonlistResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetCommonlistResult*>(p);
            const char* lt = "Unknown";
            switch (pkt->ListType) {
            case 1: lt = "Friend"; break; case 2: lt = "Linkshell"; break;
            case 3: lt = "PartyMember"; break; case 4: lt = "FreeCompany"; break;
            case 5: lt = "Blacklist"; break;
            }
            std::ostringstream ls; ls << lt << " (" << (int)pkt->ListType << ")";
            FieldBuilder b(e);
            b.Hex("CommunityID", pkt->CommunityID)
                .Field("NextIndex", pkt->NextIndex)
                .Field("Index", pkt->Index)
                .Field("ListType", ls.str())
                .Field("RequestKey", (int)pkt->RequestKey)
                .Field("RequestParam", (int)pkt->RequestParam);
            int shown = 0;
            for (int i = 0; i < 10 && shown < 5; i++) {
                if (!pkt->entries[i].CharacterID) continue;
                std::string name(pkt->entries[i].CharacterName, 32);
                name = name.substr(0, name.find('\0'));
                b.Hex("Entry" + std::to_string(shown) + "ID", pkt->entries[i].CharacterID)
                    .String("Entry" + std::to_string(shown) + "Name", name.c_str(), 32)
                    .Field("Entry" + std::to_string(shown) + "Level", pkt->entries[i].CurrentLevel);
                shown++;
            }
            if (!shown) b.Field("Entries", "None");
            };
    }

    // ================= CATEGORY 8: ITEM / INVENTORY =================
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcNormalItem>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcNormalItem)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcNormalItem*>(p);
            FieldBuilder b(e);
            b.Field("ContextId", pkt->contextId)
                .Field("StorageId", pkt->item.storageId)
                .Field("ContainerIndex", pkt->item.containerIndex)
                .Field("CatalogId", pkt->item.catalogId)
                .Field("Stack", pkt->item.stack);
            if (pkt->item.signatureId) b.Hex("SignatureId", pkt->item.signatureId);
            b.Hex("Flags", (uint32_t)pkt->item.flags)
                .Field("Durability", pkt->item.durability)
                .Field("Refine", pkt->item.refine)
                .Field("Stain", (int)pkt->item.stain)
                .Field("Pattern", pkt->item.pattern);
            int materia = 0;
            for (int i = 0; i < 5; i++) {
                if (!pkt->item.materiaType[i]) continue;
                b.Field("Materia" + std::to_string(i) + "Type", pkt->item.materiaType[i])
                    .Field("Materia" + std::to_string(i) + "Grade", (int)pkt->item.materiaGrade[i]);
                materia++;
            }
            if (materia) b.Field("MateriaCount", materia);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcUpdateItem>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcUpdateItem)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcUpdateItem*>(p);
            FieldBuilder(e)
                .Field("ContextId", pkt->contextId)
                .Field("StorageId", pkt->item.storageId)
                .Field("ContainerIndex", pkt->item.containerIndex)
                .Field("CatalogId", pkt->item.catalogId)
                .Field("Stack", pkt->item.stack)
                .Field("Durability", pkt->item.durability)
                .Field("Refine", pkt->item.refine);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcItemSize>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcItemSize)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcItemSize*>(p);
            FieldBuilder(e)
                .Field("ContextId", pkt->contextId)
                .Field("Size", pkt->size)
                .Field("StorageId", pkt->storageId);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcItemOperation>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcItemOperation)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcItemOperation*>(p);
            const char* op = "Unknown";
            switch (pkt->operationType) {
            case 1: op = "Move"; break; case 2: op = "Split"; break; case 3: op = "Combine"; break;
            case 4: op = "Discard"; break; case 5: op = "Use"; break; case 6: op = "Sort"; break;
            }
            std::ostringstream os; os << op << " (" << (int)pkt->operationType << ")";
            FieldBuilder b(e);
            b.Field("ContextId", pkt->contextId)
                .Field("OperationType", os.str());
            if (pkt->srcEntity) b.Hex("SrcEntity", pkt->srcEntity);
            b.Field("SrcStorageId", pkt->srcStorageId)
                .Field("SrcContainerIndex", (int)pkt->srcContainerIndex)
                .Field("SrcStack", pkt->srcStack)
                .Field("SrcCatalogId", pkt->srcCatalogId);
            if (pkt->dstEntity) b.Hex("DstEntity", pkt->dstEntity);
            b.Field("DstStorageId", pkt->dstStorageId)
                .Field("DstContainerIndex", (int)pkt->dstContainerIndex)
                .Field("DstStack", pkt->dstStack)
                .Field("DstCatalogId", pkt->dstCatalogId);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcItemOperationBatch>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcItemOperationBatch)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcItemOperationBatch*>(p);
            const char* op = "Unknown";
            switch (pkt->operationType) {
            case 0: op = "None"; break; case 1: op = "Sort"; break; case 2: op = "Consolidate"; break;
            }
            const char* err = "None";
            switch (pkt->errorType) {
            case 0: err = "None"; break; case 1: err = "InventoryFull"; break; case 2: err = "CannotMove"; break;
            }
            std::ostringstream os, es; os << op << " (" << (int)pkt->operationType << ")"; es << err << " (" << (int)pkt->errorType << ")";
            FieldBuilder(e)
                .Field("ContextId", pkt->contextId)
                .Field("OperationId", pkt->operationId)
                .Field("OperationType", os.str())
                .Field("ErrorType", es.str())
                .Field("PacketNum", (int)pkt->packetNum);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGilItem>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcGilItem)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGilItem*>(p);
            FieldBuilder(e)
                .Field("ContextId", pkt->contextId)
                .Field("StorageId", pkt->item.storageId)
                .Field("ContainerIndex", pkt->item.containerIndex)
                .Field("Amount", pkt->item.stack)
                .Field("CatalogId", pkt->item.catalogId)
                .Field("SubQuality", (int)pkt->item.subquarity);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcItemStorage>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcItemStorage)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcItemStorage*>(p);
            const char* t = "Unknown";
            switch (pkt->storage.type) {
            case 0: t = "Inventory"; break; case 1: t = "Armory"; break; case 2: t = "Retainer"; break;
            case 3: t = "FreeCompany"; break; case 4: t = "Crystal"; break;
            }
            std::ostringstream ts; ts << t << " (" << pkt->storage.type << ")";
            FieldBuilder(e)
                .Field("ContextId", pkt->contextId)
                .Field("StorageId", pkt->storage.storageId)
                .Field("Type", ts.str())
                .Field("Index", (int)pkt->storage.index)
                .Field("ContainerSize", pkt->storage.containerSize);
            };
    }

    // ================= NEW: ADDITIONAL DECODERS =================
    
    // InitZone (0x019A)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcInitZone>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcInitZone)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcInitZone*>(p);
            FieldBuilder(emit)
                .Field("ZoneId", pkt->ZoneId)
                .Field("TerritoryType", pkt->TerritoryType)
                .Field("TerritoryIndex", pkt->TerritoryIndex)
                .Hex("LayerSetId", pkt->LayerSetId)
                .Hex("LayoutId", pkt->LayoutId)
                .Field("WeatherId", (int)pkt->WeatherId)
                .Hex("Flag", pkt->Flag)
                .Field("FestivalEid0", pkt->FestivalEid0)
                .Field("FestivalPid0", pkt->FestivalPid0)
                .Field("FestivalEid1", pkt->FestivalEid1)
                .Field("FestivalPid1", pkt->FestivalPid1)
                .Position("Position", pkt->Pos[0], pkt->Pos[1], pkt->Pos[2]);
        };
    }
    
    // PlayerStatus (0x01A0) - large comprehensive packet
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcPlayerStatus>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcPlayerStatus)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcPlayerStatus*>(p);
            FieldBuilder b(emit);
            b.Hex("CharaId", pkt->CharaId)
                .Hex("Crest", pkt->Crest)
                .Hex("EntityId", pkt->EntityId)
                .Field("RestPoint", pkt->RestPoint)
                .Field("ExpansionLevel", (int)pkt->ExpansionLevel)
                .Field("Race", (int)pkt->Race)
                .Field("Tribe", (int)pkt->Tribe)
                .Field("Sex", (int)pkt->Sex)
                .Field("ClassJob", (int)pkt->ClassJob)
                .Field("FirstClass", (int)pkt->FirstClass)
                .Field("GuardianDeity", (int)pkt->GuardianDeity)
                .Field("BirthMonth", (int)pkt->BirthMonth)
                .Field("Birthday", (int)pkt->Birthday)
                .Field("StartTown", (int)pkt->StartTown)
                .Field("HomePoint", (int)pkt->HomePoint)
                .Field("GrandCompany", (int)pkt->GrandCompany)
                .Field("Pet", (int)pkt->Pet)
                .Field("BuddyRank", (int)pkt->BuddyRank)
                .String("Name", reinterpret_cast<const char*>(pkt->Name), 32)
                .String("BuddyName", pkt->BuddyName, 21)
                .Field("RetainerCount", (int)pkt->RetainerCount);
            
            // Show some level/exp data (first few classes)
            for (int i = 0; i < 5 && i < 23; ++i) {
                if (pkt->Lv[i] > 0) {
                    std::ostringstream os;
                    os << "Class" << i << "Lv";
                    b.Field(os.str(), pkt->Lv[i]);
                }
            }
        };
    }

    // BaseParam (0x01A1)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcBaseParam>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcBaseParam)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcBaseParam*>(p);
            FieldBuilder b(emit);
            
            // Show first few parameters (STR, DEX, VIT, etc.)
            const char* names[] = {"STR", "DEX", "VIT", "INT", "MND", "PIE"};
            for (int i = 0; i < 6 && i < 50; ++i) {
                b.Field(names[i], pkt->Param[i]);
            }
            
            b.Field("Param[0-5]", "Main stats shown above");
        };
    }
    
    // HudParam (0x0140)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHudParam>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHudParam)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHudParam*>(p);
            FieldBuilder b(emit);
            b.Field("ClassJob", (int)pkt->ClassJob)
                .Field("Lv", (int)pkt->Lv)
                .Field("OrgLv", (int)pkt->OrgLv)
                .Field("LvSync", (int)pkt->LvSync)
                .Field("Hp", pkt->Hp)
                .Field("HpMax", pkt->HpMax)
                .Field("Mp", pkt->Mp)
                .Field("MpMax", pkt->MpMax)
                .Field("Tp", pkt->Tp);
            
            // Show active status effects
            int active = 0;
            for (int i = 0; i < 30; ++i) if (pkt->effect[i].id) active++;
            if (active > 0) {
                b.Field("ActiveStatusCount", active);
                int shown = 0;
                for (int i = 0; i < 30 && shown < 5; ++i) {
                    if (!pkt->effect[i].id) continue;
                    std::ostringstream os;
                    os << "Status" << shown;
                    b.Hex(os.str(), pkt->effect[i].id);
                    if (const char* name = GetStatusEffectName(pkt->effect[i].id))
                        b.Field(os.str() + "Name", name);
                    shown++;
                }
            }
        };
    }

    // Mount (0x0200)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMount>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcMount)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcMount*>(p);
            // Struct currently only exposes a single field: id
            FieldBuilder(emit)
                .Field("MountId", pkt->id);
            };
    }

    // TitleList (0x028B)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcTitleList>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcTitleList)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcTitleList*>(p);
            
            // Count set bits (unlocked titles)
            int unlocked = 0;
            for (int i = 0; i < 48; ++i) {
                uint8_t byte = pkt->TitleFlagsArray[i];
                for (int bit = 0; bit < 8; ++bit) {
                    if (byte & (1 << bit)) unlocked++;
                }
            }
            
            FieldBuilder(emit)
                .Field("TotalUnlockedTitles", unlocked)
                .Field("FlagArraySize", 48);
        };
    }

    // HateList / HaterList (0x019B / 0x019C)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHateList>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHateList)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHateList*>(p);
            FieldBuilder b(emit);
            b.Field("Count", (int)pkt->Count);
            
            int shown = std::min<int>(pkt->Count, 5);
            for (int i = 0; i < shown; ++i) {
                std::ostringstream id, val;
                id << "Entry" << i << "Id";
                val << "Entry" << i << "Value";
                b.Hex(id.str(), pkt->List[i].Id)
                    .Field(val.str(), pkt->List[i].Value);
            }
            if (pkt->Count > shown) {
                b.Field("MoreEntries", "...");
            }
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHaterList>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHaterList)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHaterList*>(p);
            FieldBuilder b(emit);
            b.Field("Count", (int)pkt->Count);
            
            int shown = std::min<int>(pkt->Count, 5);
            for (int i = 0; i < shown; ++i) {
                std::ostringstream id, rate;
                id << "Entry" << i << "Id";
                rate << "Entry" << i << "Rate";
                b.Hex(id.str(), pkt->List[i].Id)
                    .Field(rate.str(), (int)pkt->List[i].Rate);
            }
            if (pkt->Count > shown) {
                b.Field("MoreEntries", "...");
            }
        };
    }

    // UpdateFindContent (0x02DB)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcUpdateFindContent>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcUpdateFindContent)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcUpdateFindContent*>(p);
            FieldBuilder(emit)
                .Field("kind", pkt->kind)
                .Field("value1", pkt->value1)
                .Field("value2", pkt->value2)
                .Field("value3", pkt->value3)
                .Field("value4", pkt->value4)
                .Field("Unknown", pkt->Unknown)
                .Field("territoryType", pkt->territoryType)
                .Field("Unknown1", pkt->Unknown1)
                .Field("Unknown2", pkt->Unknown2)
                .Field("Unknown3", pkt->Unknown3)
                .Field("Unknown4", pkt->Unknown4);
        };
    }

    // NotifyFindContentStatus (0x02DE)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcNotifyFindContentStatus>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcNotifyFindContentStatus)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcNotifyFindContentStatus*>(p);
            FieldBuilder(emit)
                .Field("territoryType", pkt->territoryType)
                .Field("status", (int)pkt->status)
                .Field("tankRoleCount", (int)pkt->tankRoleCount)
                .Field("dpsRoleCount", (int)pkt->dpsRoleCount)
                .Field("healerRoleCount", (int)pkt->healerRoleCount)
                .Field("matchingTime", (int)pkt->matchingTime);
        };
    }

    // FinishContentMatchToClient (0x0339)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcFinishContentMatchToClient>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcFinishContentMatchToClient)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcFinishContentMatchToClient*>(p);
            FieldBuilder(emit)
                .Field("classJob", (int)pkt->classJob)
                .Field("progress", (int)pkt->progress)
                .Field("playerNum", (int)pkt->playerNum)
                .Field("territoryType", pkt->territoryType)
                .Hex("flags", pkt->flags)
                .Hex("finishContentMatchFlags", pkt->finishContentMatchFlags)
                .Field("startTime", std::to_string(pkt->startTime));
        };
    }

    // ContentAttainFlags (0x02E3)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcContentAttainFlags>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcContentAttainFlags)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcContentAttainFlags*>(p);
            FieldBuilder(emit)
                .Field("raidAttainFlagSize", 28)
                .Field("dungeonAttainFlagSize", 18)
                .Field("guildOrderAttainFlagSize", 10)
                .Field("bossBattleAttainFlagSize", 6)
                .Field("colosseumAttainFlagSize", 2);
        };
    }

    // ContentBonus (0x0311)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcContentBonus>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcContentBonus)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcContentBonus*>(p);
            FieldBuilder b(emit);
            
            for (int i = 0; i < 8; ++i) {
                std::ostringstream os;
                os << "bonusRoles[" << i << "]";
                b.Field(os.str(), (int)pkt->bonusRoles[i]);
            }
        };
    }

    // ResponsePenalties (0x02E1)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcResponsePenalties>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcResponsePenalties)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcResponsePenalties*>(p);
            FieldBuilder(emit)
                .Field("penalties[0]", (int)pkt->penalties[0])
                .Field("penalties[1]", (int)pkt->penalties[1]);
        };
    }

    // UpdateContent (0x02E4)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcUpdateContent>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcUpdateContent)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcUpdateContent*>(p);
            FieldBuilder(emit)
                .Field("territoryType", pkt->territoryType)
                .Field("kind", pkt->kind)
                .Field("value1", pkt->value1)
                .Field("value2", pkt->value2);
        };
    }

    // EnableLogout (0x02D6)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcEnableLogout>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcEnableLogout)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcEnableLogout*>(p);
            FieldBuilder(emit).Field("content", (int)pkt->content);
        };
    }

    // Achievement (0x02DD)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcAchievement>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcAchievement)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcAchievement*>(p);
            
            // Count completed achievements
            int count = 0;
            for (int i = 0; i < 256; ++i) {
                if (pkt->complete[i]) count++;
            }
            
            FieldBuilder b(emit);
            b.Field("CompletedCount", count);
            
            // Show recent achievement history
            for (int i = 0; i < 5; ++i) {
                std::ostringstream os;
                os << "history[" << i << "]";
                b.Field(os.str(), pkt->history[i]);
            }
        };
    }
    
    // ================= CATEGORY 10: HOUSING =================
    
    // HouseList (0x02EC)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHouseList>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHouseList)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHouseList*>(p);
            FieldBuilder b(emit);
            b.Field("LandSetId.landId", pkt->LandSetId.landId)
             .Field("LandSetId.wardNum", pkt->LandSetId.wardNum)
             .Field("LandSetId.territoryTypeId", pkt->LandSetId.territoryTypeId)
             .Field("LandSetId.worldId", pkt->LandSetId.worldId)
             .Field("Subdivision", pkt->Subdivision);
            int shown = 0;
            for (int i = 0; i < 30 && shown < 5; ++i) {
                if (pkt->Houses[i].housePrice == 0) continue;
                std::ostringstream pfx; pfx << "House" << shown;
                b.Field(pfx.str() + "Price", pkt->Houses[i].housePrice)
                 .String(pfx.str() + "Owner", pkt->Houses[i].estateOwnerName, 32);
                shown++;
            }
            if (!shown) b.Field("Houses", "None");
        };
    }

    // House (0x02ED)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHouse>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHouse)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHouse*>(p);
            FieldBuilder(emit)
                .Field("Block", pkt->Block)
                .Field("Price", pkt->House.housePrice)
                .String("Owner", pkt->House.estateOwnerName, 32);
        };
    }

    // YardObjectList (0x02EE)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcYardObjectList>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcYardObjectList)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcYardObjectList*>(p);
            FieldBuilder(emit)
                .Field("PacketIndex", (int)pkt->PacketIndex)
                .Field("PacketEnd", (int)pkt->PacketEnd)
                .Field("ObjectCount", 400);
        };
    }

    // YardObject (0x02F0)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcYardObject>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcYardObject)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcYardObject*>(p);
            FieldBuilder(emit)
                .Field("ItemId", pkt->YardObject.itemId)
                .Field("Rotate", pkt->YardObject.rotate)
                .Field("X", pkt->YardObject.x)
                .Field("Y", pkt->YardObject.y)
                .Field("Z", pkt->YardObject.z);
        };
    }

    // Interior (0x02F1)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcInterior>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcInterior)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcInterior*>(p);
            FieldBuilder(emit)
                .Field("Window", pkt->Window)
                .Field("Door", pkt->Door)
                .Field("FirstInterior", pkt->Interior[0]);
        };
    }

    // HousingAuction (0x02F2)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHousingAuction>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHousingAuction)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHousingAuction*>(p);
            FieldBuilder(emit)
                .Field("Price", pkt->Price)
                .Field("Timer", pkt->Timer);
        };
    }

    // HousingProfile (0x02F3)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHousingProfile>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHousingProfile)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHousingProfile*>(p);
            FieldBuilder(emit)
                .Hex("OwnerId", pkt->OwnerId)
                .Field("Like", pkt->Like)
                .Field("Welcome", (int)pkt->Welcome)
                .Field("Size", (int)pkt->Size)
                .String("Name", pkt->Name, 23)
                .String("Greeting", pkt->Greeting, 60)
                .String("OwnerName", pkt->OwnerName, 31)
                .String("FCTag", pkt->FCTag, 7);
        };
    }

    // HousingHouseName (0x02F4)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHousingHouseName>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHousingHouseName)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHousingHouseName*>(p);
            FieldBuilder(emit)
                .Field("LandId.landId", pkt->LandId.landId)
                .Field("LandId.wardNum", pkt->LandId.wardNum)
                .String("Name", pkt->Name, 23);
        };
    }

    // HousingGreeting (0x02F5)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHousingGreeting>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHousingGreeting)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHousingGreeting*>(p);
            FieldBuilder(emit)
                .Field("LandId.landId", pkt->LandId.landId)
                .Field("LandId.wardNum", pkt->LandId.wardNum)
                .String("Greeting", reinterpret_cast<const char*>(pkt->Greeting), 60);
        };
    }

    // CharaHousingLandData (0x02F6)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcCharaHousingLandData>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcCharaHousingLandData)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcCharaHousingLandData*>(p);
            FieldBuilder(emit)
                .Field("Index", (int)pkt->Index)
                .Field("LandId.landId", pkt->LandData.landIdent.landId)
                .Field("Size", (int)pkt->LandData.size)
                .Field("Status", (int)pkt->LandData.status);
        };
    }

    // CharaHousing (0x02F7)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcCharaHousing>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcCharaHousing)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcCharaHousing*>(p);
            FieldBuilder(emit)
                .Field("FcLands.size", (int)pkt->FcLands.size)
                .Field("CharaLands.size", (int)pkt->CharaLands.size)
                .Field("Apartment.size", (int)pkt->apartment.size);
        };
    }

    // HousingWelcome (0x02F8)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHousingWelcome>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHousingWelcome)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHousingWelcome*>(p);
            FieldBuilder(emit)
                .Field("Welcome", (int)pkt->Welcome)
                .Field("LandId.landId", pkt->LandId.landId);
        };
    }

    // FurnitureListS (0x02F9)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcFurnitureListS>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcFurnitureListS)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcFurnitureListS*>(p);
            FieldBuilder(emit)
                .Field("PacketNum", (int)pkt->packetNum)
                .Field("PacketTotal", (int)pkt->packetTotal)
                .Field("Count", 100);
        };
    }

    // FurnitureListM (0x02FA)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcFurnitureListM>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcFurnitureListM)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcFurnitureListM*>(p);
            FieldBuilder(emit)
                .Field("PacketNum", (int)pkt->packetNum)
                .Field("PacketTotal", (int)pkt->packetTotal)
                .Field("Count", 150);
        };
    }

    // FurnitureListL (0x02FB)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcFurnitureListL>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcFurnitureListL)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcFurnitureListL*>(p);
            FieldBuilder(emit)
                .Field("PacketNum", (int)pkt->packetNum)
                .Field("PacketTotal", (int)pkt->packetTotal)
                .Field("Count", 200);
        };
    }

    // Furniture (0x02FC)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcFurniture>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcFurniture)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcFurniture*>(p);
            FieldBuilder(emit)
                .Field("StorageId", pkt->StorageId)
                .Field("ContainerIndex", (int)pkt->ContainerIndex)
                .Field("ItemId", pkt->Furniture.itemId)
                .Field("Rotate", pkt->Furniture.rotate)
                .Field("X", pkt->Furniture.x)
                .Field("Y", pkt->Furniture.y)
                .Field("Z", pkt->Furniture.z);
        };
    }

    // HousingProfileList (0x02FE)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHousingProfileList>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHousingProfileList)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHousingProfileList*>(p);
            FieldBuilder b(emit);
            b.Field("LandSetId.landId", pkt->LandSetId.landId)
                .Field("LandSetId.wardNum", pkt->LandSetId.wardNum);
            int shown = 0;
            for (int i = 0; i < 30 && shown < 5; ++i) {
                if (!pkt->ProfileList[i].ownerId) continue;
                std::ostringstream os; os << "Profile" << shown;
                b.Hex(os.str() + "OwnerId", pkt->ProfileList[i].ownerId)
                    .String(os.str() + "Name", pkt->ProfileList[i].name, 32);
                shown++;
            }
            };
    }

    // HousingObjectTransform (0x02FF)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHousingObjectTransform>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHousingObjectTransform)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHousingObjectTransform*>(p);
            float x = pkt->Pos[0] * 0.001f, y = pkt->Pos[1] * 0.001f, z = pkt->Pos[2] * 0.001f;
            FieldBuilder(emit)
                .Field("Dir", pkt->Dir)
                .Field("UserData1", (int)pkt->UserData1)
                .Field("UserData2", (int)pkt->UserData2)
                .Field("ContainerIndex", (int)pkt->ContainerIndex)
                .Position("Pos", x, y, z);
        };
    }

    // HousingObjectColor (0x0300)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHousingObjectColor>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHousingObjectColor)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHousingObjectColor*>(p);
            FieldBuilder(emit)
                .Field("Color", (int)pkt->Color)
                .Field("StorageId", pkt->StorageId)
                .Field("ContainerIndex", (int)pkt->ContainerIndex)
                .Field("UserData", (int)pkt->UserData);
        };
    }

    // HousingObjectTransformMulti (0x0301)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHousingObjectTransformMulti>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHousingObjectTransformMulti)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHousingObjectTransformMulti*>(p);
            FieldBuilder b(emit);
            b.Field("LandId.landId", pkt->LandId.landId)
             .Field("LandId.wardNum", pkt->LandId.wardNum);
            int shown = 0;
            for (int i = 0; i < 10 && shown < 3; ++i) {
                std::ostringstream os; os << "Layout" << i;
                b.Field(os.str() + ".StorageIndex", (int)pkt->LayoutInfos[i].storageIndex)
                 .Field(os.str() + ".posX", pkt->LayoutInfos[i].posX)
                 .Field(os.str() + ".posY", pkt->LayoutInfos[i].posY)
                 .Field(os.str() + ".posZ", pkt->LayoutInfos[i].posZ)
                 .Field(os.str() + ".rotY", pkt->LayoutInfos[i].rotY);
                shown++;
            }
        };
    }

    // HousingObjectTransformMultiResult (0x032A)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHousingObjectTransformMultiResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHousingObjectTransformMultiResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHousingObjectTransformMultiResult*>(p);
            FieldBuilder b(emit);
            b.Field("LandId.landId", pkt->LandId.landId)
             .Field("LandId.wardNum", pkt->LandId.wardNum)
             .Field("Result", (int)pkt->Result);
            std::ostringstream idxs;
            idxs << "[";
            bool first = true;
            for (int i = 0; i < 10; ++i) {
                if (pkt->FixIndexes[i] == 0) continue;
                if (!first) idxs << ",";
                idxs << pkt->FixIndexes[i];
                first = false;
            }
            idxs << "]";
            b.Field("FixIndexes", idxs.str());
        };
    }

    // HousingLogWithHouseName (0x032B)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHousingLogWithHouseName>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHousingLogWithHouseName)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHousingLogWithHouseName*>(p);
            FieldBuilder(emit)
                .Field("LogId", pkt->LogId)
                .String("Name", reinterpret_cast<const char*>(pkt->Name), 23);
        };
    }

    // HousingCombinedObjectStatus (0x032D)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHousingCombinedObjectStatus>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHousingCombinedObjectStatus)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHousingCombinedObjectStatus*>(p);
            FieldBuilder b(emit);
            b.Field("AddressData", pkt->AddressData);
            std::ostringstream kind, step, status;
            for (int i = 0; i < 8; ++i) {
                if (i) { kind << ","; step << ","; status << ","; }
                kind << pkt->Kind[i];
                step << (int)pkt->Step[i];
                status << (int)pkt->Status[i];
            }
            b.Field("Kind", kind.str())
             .Field("Step", step.str())
             .Field("Status", status.str());
        };
    }

    // HouseBuddyModelData (0x032E)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHouseBuddyModelData>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHouseBuddyModelData)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHouseBuddyModelData*>(p);
            FieldBuilder b(emit);
            b.Field("AddressData", pkt->AddressData)
                .Field("BuddyScale", (int)pkt->BuddyScale)
                .Field("Stain", (int)pkt->Stain)
                .Field("Invisibility", (int)pkt->Invisibility)
                .Field("ModelEquipHead", pkt->ModelEquips[0])
                .Field("ModelEquipBody", pkt->ModelEquips[1])
                .Field("ModelEquipLeg", pkt->ModelEquips[2]);
            };
    }

    // HousingGetPersonalRoomProfileListResult (0x0307)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHousingGetPersonalRoomProfileListResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHousingGetPersonalRoomProfileListResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHousingGetPersonalRoomProfileListResult*>(p);
            FieldBuilder b(emit);
            b.Hex("CharacterID", pkt->CharacterID)
             .Field("TopRoomID", pkt->TopRoomID)
             .Field("HouseLandID.landId", pkt->HouseLandID.landId);
            int shown = 0;
            for (int i = 0; i < 15 && shown < 5; ++i) {
                if (!pkt->ProfileList[i].ownerId) continue;
                std::ostringstream os; os << "Profile" << shown;
                b.Hex(os.str() + "OwnerId", pkt->ProfileList[i].ownerId)
                 .String(os.str() + "OwnerName", pkt->ProfileList[i].ownerName, 32)
                 .Field(os.str() + "RoomNumber", (int)pkt->ProfileList[i].roomNumber)
                 .Field(os.str() + "Occupied", (int)pkt->ProfileList[i].isOccupied);
                shown++;
            }
        };
    }

    // HousingGetHouseBuddyStableListResult (0x0308)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHousingGetHouseBuddyStableListResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHousingGetHouseBuddyStableListResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHousingGetHouseBuddyStableListResult*>(p);
            FieldBuilder b(emit);
            b.Hex("CharacterID", pkt->CharacterID)
             .Field("Page", (int)pkt->Page)
             .Field("IsMyBuddy", (int)pkt->IsMyBuddy)
             .Field("LandID.landId", pkt->LandID.landId);
            int shown = 0;
            for (int i = 0; i < 15 && shown < 5; ++i) {
                if (!pkt->BuddyList[i].ownerId) continue;
                std::ostringstream os; os << "Buddy" << shown;
                b.Hex(os.str() + "OwnerId", pkt->BuddyList[i].ownerId)
                 .Field(os.str() + "BuddyId", pkt->BuddyList[i].buddyId)
                 .Field(os.str() + "Stain", (int)pkt->BuddyList[i].stain)
                 .String(os.str() + "BuddyName", pkt->BuddyList[i].buddyName, 21)
                 .String(os.str() + "OwnerName", pkt->BuddyList[i].ownerName, 32);
                shown++;
            }
        };
    }

    // HouseTrainBuddyData (0x0309)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcHouseTrainBuddyData>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcHouseTrainBuddyData)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcHouseTrainBuddyData*>(p);
            FieldBuilder(emit)
                .Field("OwnerRace", (int)pkt->OwnerRace)
                .Field("OwnerSex", (int)pkt->OwnerSex)
                .Field("Stain", (int)pkt->Stain)
                .Field("EquipHead", (int)pkt->Equips[0])
                .Field("EquipBody", (int)pkt->Equips[1])
                .Field("EquipLeg", (int)pkt->Equips[2]);
        };
    }

    // =============== P1 – Batch 2 (Event/Quest/Session remainder) ===============
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcWeatherId>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcWeatherId)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcWeatherId*>(p);
            FieldBuilder(e)
                .Field("WeatherId", (int)pkt->WeatherId)
                .Field("TransitionTime", pkt->TransitionTime);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMoveTerritory>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcMoveTerritory)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcMoveTerritory*>(p);
            FieldBuilder(e)
                .Field("Index", (int)pkt->index)
                .Field("TerritoryType", (int)pkt->territoryType)
                .Field("ZoneId", (int)pkt->zoneId)
                .Field("WorldId", pkt->worldId)
                .Field("WorldId1", pkt->worldId1)
                .Hex("LandSetId", static_cast<uint64_t>(pkt->landSetId))
                .Hex("LandId", static_cast<uint64_t>(pkt->landId))
                .Hex("LandTerritoryId", static_cast<uint64_t>(pkt->landTerritoryId))
                .String("WorldName", pkt->worldName, 32);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMoveInstance>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcMoveInstance)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcMoveInstance*>(p);
            FieldBuilder(e)
                .Hex("CharacterId", pkt->characterId)
                .Hex("EntityId", pkt->entityId)
                .Field("WorldId", pkt->worldId)
                .Field("WorldId1", pkt->worldId1)
                .Hex("Unknown1", pkt->unknown1)
                .Hex("Unknown2", pkt->unknown2);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMonsterNoteCategory>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcMonsterNoteCategory)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcMonsterNoteCategory*>(p);
            // Count non-zero kills
            int nonZero = 0;
            for (int i = 0; i < 40; ++i) if (pkt->killCount[i]) nonZero++;

            // Bit counts
            auto popcnt64 = [](uint64_t v) { int c = 0; while (v) { v &= (v - 1); ++c; } return c; };
            auto popcnt32 = [](uint32_t v) { int c = 0; while (v) { v &= (v - 1); ++c; } return c; };

            FieldBuilder b(e);
            b.Field("ContextId", pkt->contextId)
                .Field("CurrentRank", (int)pkt->currentRank)
                .Field("CategoryIndex", (int)pkt->categoryIndex)
                .Field("NonZeroKills", nonZero)
                .Field("CompleteFlagsSetBits", popcnt64(pkt->completeFlags))
                .Field("IsNewFlagsSetBits", popcnt32(pkt->isNewFlags));

            // Show first up to 6 kill slots
            int shown = 0;
            for (int i = 0; i < 40 && shown < 6; ++i) {
                if (!pkt->killCount[i]) continue;
                std::ostringstream k; k << "Kill[" << i << "]";
                b.Field(k.str(), (int)pkt->killCount[i]);
                shown++;
            }
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcQuestRepeatFlags>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcQuestRepeatFlags)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcQuestRepeatFlags*>(p);
            FieldBuilder(e)
                .Field("Update", (int)pkt->update)
                .Hex("RepeatFlags", static_cast<uint64_t>(pkt->repeatFlagArray[0]));
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcDailyQuests>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcDailyQuests)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcDailyQuests*>(p);
            FieldBuilder b(e);
            b.Field("Update", (int)pkt->update);

            int active = 0;
            for (int i = 0; i < 12; ++i) if (pkt->dailyQuestArray[i].questId) active++;
            b.Field("ActiveDailyQuestCount", active);

            int shown = 0;
            for (int i = 0; i < 12 && shown < 5; ++i) {
                if (!pkt->dailyQuestArray[i].questId) continue;
                std::ostringstream pfx; pfx << "Daily[" << i << "]";
                b.Field(pfx.str() + ".QuestId", pkt->dailyQuestArray[i].questId)
                    .Hex(pfx.str() + ".Flags", (uint64_t)pkt->dailyQuestArray[i].flags);
                shown++;
            }
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcLegacyQuestCompleteList>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcLegacyQuestCompleteList)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcLegacyQuestCompleteList*>(p);
            int setBits = 0;
            for (int i = 0; i < 40; ++i) {
                uint8_t v = pkt->completeFlagArray[i];
                for (int b = 0; b < 8; ++b) if (v & (1 << b)) setBits++;
            }
            FieldBuilder(e)
                .Field("SetBits", setBits)
                .Field("TotalBits", 40 * 8)
                .Field("FirstBytes", DumpBytes(pkt->completeFlagArray, sizeof(pkt->completeFlagArray), 8));
            };
    }


    // =============== P1 – Batch 3 (Progress deltas) ===============
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcPlayerStatusUpdate>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcPlayerStatusUpdate)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcPlayerStatusUpdate*>(p);
            FieldBuilder(e)
                .Field("ClassJob", (int)pkt->ClassJob)
                .Field("Lv", pkt->Lv)
                .Field("LvOriginal", pkt->Lv1)
                .Field("LvSync", pkt->LvSync)
                .Field("Exp", pkt->Exp)
                .Field("RestPoint", pkt->RestPoint);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcChangeClass>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcChangeClass)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcChangeClass*>(p);
            FieldBuilder b(e);
            b.Field("ClassJob", (int)pkt->ClassJob)
                .Field("Penalty", (int)pkt->Penalty)
                .Field("Login", (int)pkt->Login)
                .Field("LvOriginal", pkt->Lv1)
                .Field("Lv", pkt->Lv);

            int shown = 0;
            for (int i = 0; i < 10 && shown < 5; ++i) {
                if (pkt->BorrowAction[i] == 0) continue;
                std::ostringstream k; k << "BorrowAction[" << i << "]";
                b.Field(k.str(), pkt->BorrowAction[i]);
                shown++;
            }
            if (shown > 0 && shown < 10) b.Field("BorrowActionMore", "...");
            for (int i = 0; i < 6; ++i) {
                std::ostringstream k; k << "PhysicalBonus[" << i << "]";
                b.Field(k.str(), (int)pkt->PhysicalBonus[i]);
            }
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcFirstAttack>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcFirstAttack)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcFirstAttack*>(p);
            FieldBuilder(e)
                .Field("Type", (int)pkt->Type)
                .Hex("Id", pkt->Id);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcCondition>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcCondition)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcCondition*>(p);
            int setBits = 0;
            for (int i = 0; i < 12; ++i) {
                uint8_t v = pkt->flags[i];
                for (int b = 0; b < 8; ++b) if (v & (1 << b)) setBits++;
            }
            FieldBuilder(e)
                .Field("FlagsSetBits", setBits)
                .Field("TotalBits", 12 * 8)
                .Field("FlagsFirst4Bytes", DumpBytes(pkt->flags, 4, 4));
            };
    }

    // ================= P2 – ECONOMY / MARKET / RETAINER (Batch 4) =================
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMarketPriceHeader>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcMarketPriceHeader)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcMarketPriceHeader*>(p);
            FieldBuilder(emit)
                .Hex("CatalogID", pkt->CatalogID)
                .Field("MinPrice", pkt->MinPrice)
                .Field("MaxPrice", pkt->MaxPrice);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMarketPrice>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcMarketPrice)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcMarketPrice*>(p);

            FieldBuilder b(emit);
            b.Hex("CatalogID", pkt->CatalogID)
                .Field("MinPrice", pkt->MinPrice)
                .Field("MaxPrice", pkt->MaxPrice)
                .Field("DataCount", (int)pkt->DataCount);

            int count = std::min<int>(pkt->DataCount, 10);
            int shown = std::min<int>(count, 5);
            for (int i = 0; i < shown; ++i) {
                const auto& li = pkt->Listings[i];
                std::string pfx = "Listing" + std::to_string(i);
                b.Hex(pfx + ".ItemID", li.ItemID)
                    .Hex(pfx + ".RetainerID", li.RetainerID)
                    .Hex(pfx + ".OwnerID", li.OwnerID)
                    .Field(pfx + ".UnitPrice", li.UnitPrice)
                    .Field(pfx + ".Stack", li.Stack)
                    .Field(pfx + ".TotalTax", li.TotalTax)
                    .Field(pfx + ".CityID", li.CityID)
                    .Field(pfx + ".StallID", li.StallID);

                int mcount = 0;
                for (int j = 0; j < 5; ++j) if (li.Materia[j]) mcount++;
                if (mcount > 0) {
                    b.Field(pfx + ".MateriaCount", mcount);
                    int mshow = std::min(mcount, 3);
                    int printed = 0;
                    for (int j = 0; j < 5 && printed < mshow; ++j) {
                        if (!li.Materia[j]) continue;
                        b.Field(pfx + ".Materia[" + std::to_string(j) + "]", (int)li.Materia[j]);
                        printed++;
                    }
                }
            }
            if (count > shown) b.Field("MoreListings", std::string("... ") + std::to_string(count - shown) + " more");
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcRetainerList>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcRetainerList)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcRetainerList*>(p);

            FieldBuilder b(emit);
            b.Field("RetainerCount", (int)pkt->RetainerCount);

            int count = std::min<int>(pkt->RetainerCount, 10);
            int shown = std::min<int>(count, 10);
            for (int i = 0; i < shown; ++i) {
                if (!pkt->RetainerID[i]) continue;
                std::string pfx = "Retainer" + std::to_string(i);
                b.Hex(pfx + ".ID", pkt->RetainerID[i])
                    .String(pfx + ".Name", pkt->RetainerName[i], 32);
            }
            if (pkt->RetainerCount > shown) {
                b.Field("MoreRetainers", std::string("... ") + std::to_string((int)pkt->RetainerCount - shown) + " more");
            }
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcRetainerData>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcRetainerData)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcRetainerData*>(p);

            uint32_t planned = (pkt->VentureCompleteTime >= pkt->VentureStartTime)
                ? (pkt->VentureCompleteTime - pkt->VentureStartTime) : 0;

            FieldBuilder(emit)
                .Hex("RetainerID", pkt->RetainerID)
                .Field("HireOrder", (int)pkt->HireOrder)
                .Field("ItemCount", (int)pkt->ItemCount)
                .Field("Gil", pkt->Gil)
                .Field("SellingCount", (int)pkt->SellingCount)
                .Field("CityID", (int)pkt->CityID)
                .Field("ClassJob", (int)pkt->ClassJob)
                .Field("Level", (int)pkt->Level)
                .Field("VentureID", (int)pkt->VentureID)
                .Field("VentureComplete", (int)pkt->VentureComplete)
                .Field("VentureStartTime", pkt->VentureStartTime)
                .Field("VentureCompleteTime", pkt->VentureCompleteTime)
                .Field("VenturePlannedDurationSec", planned)
                .String("RetainerName", pkt->RetainerName, 32);
            };
    }

    // ================= P2 – ECONOMY 2 (Batch 5) =================
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetItemSearchListResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcGetItemSearchListResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetItemSearchListResult*>(p);
            FieldBuilder b(e);
            b.Field("NextIndex", (int)pkt->NextIndex)
                .Field("Index", (int)pkt->Index)
                .Field("RequestKey", (int)pkt->RequestKey);

            int shown = 0;
            for (int i = 0; i < 10 && shown < 5; ++i) {
                const auto& it = pkt->ItemSearchList[i];
                if (it.ItemID == 0 && it.Stack == 0) continue;

                std::string pfx = std::string("Entry") + std::to_string(i);
                b.Hex(pfx + ".ItemID", it.ItemID)
                    .Hex(pfx + ".SellRetainerID", it.SellRetainerID)
                    .Hex(pfx + ".OwnerCharacterID", it.OwnerCharacterID)
                    .Hex(pfx + ".SignatureID", it.SignatureID)
                    .Field(pfx + ".SellPrice", it.SellPrice)
                    .Field(pfx + ".BuyTax", it.BuyTax)
                    .Field(pfx + ".Stack", it.Stack)
                    .Field(pfx + ".CatalogID", (int)it.CatalogID)
                    .Field(pfx + ".SellRealDate", it.SellRealDate)
                    .Field(pfx + ".StorageID", (int)it.StorageID)
                    .Field(pfx + ".ContainerIndex", (int)it.ContainerIndex)
                    .Field(pfx + ".Durability", (int)it.Durability)
                    .Field(pfx + ".Refine", (int)it.Refine)
                    .Field(pfx + ".SubQuality", (int)it.SubQuality)
                    .Field(pfx + ".MateriaCount", (int)it.MateriaCount)
                    .Field(pfx + ".RegisterMarket", (int)it.RegisterMarket)
                    .Field(pfx + ".Stain", (int)it.Stain)
                    .String(pfx + ".SellRetainerName", it.SellRetainerName, 32);

                int mcount = 0;
                for (int m = 0; m < 8; ++m) if (it.Materia[m]) mcount++;
                if (mcount > 0) {
                    b.Field(pfx + ".MateriaNonZero", mcount);
                    int printed = 0;
                    for (int m = 0; m < 8 && printed < 3; ++m) {
                        if (!it.Materia[m]) continue;
                        b.Field(pfx + ".Materia[" + std::to_string(m) + "]", (int)it.Materia[m]);
                        printed++;
                    }
                }
                shown++;
            }
            if (shown == 0) b.Field("Entries", "None");
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetItemHistoryResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcGetItemHistoryResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetItemHistoryResult*>(p);
            FieldBuilder b(e);
            b.Field("CatalogID", pkt->CatalogID);

            int shown = 0;
            for (int i = 0; i < 20 && shown < 5; ++i) {
                const auto& h = pkt->ItemHistoryList[i];
                if (h.SellPrice == 0 && h.Stack == 0) continue;
                std::string pfx = std::string("History") + std::to_string(i);
                b.Field(pfx + ".SellPrice", h.SellPrice)
                    .Field(pfx + ".BuyRealDate", h.BuyRealDate)
                    .Field(pfx + ".Stack", h.Stack)
                    .Field(pfx + ".SubQuality", (int)h.SubQuality)
                    .Field(pfx + ".MateriaCount", (int)h.MateriaCount)
                    .String(pfx + ".Buyer", h.BuyCharacterName, 32);
                shown++;
            }
            if (shown == 0) b.Field("HistoryEntries", "None");
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcCatalogSearchResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcCatalogSearchResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcCatalogSearchResult*>(p);
            FieldBuilder b(e);
            b.Field("NextIndex", pkt->NextIndex)
                .Field("Result", pkt->Result)
                .Field("Index", pkt->Index)
                .Field("RequestKey", (int)pkt->RequestKey)
                .Field("Type", (int)pkt->Type);

            int shown = 0;
            for (int i = 0; i < 20 && shown < 10; ++i) {
                const auto& c = pkt->CatalogList[i];
                if (c.CatalogID == 0) continue;
                std::string pfx = std::string("Catalog") + std::to_string(i);
                b.Field(pfx + ".CatalogID", (int)c.CatalogID)
                    .Field(pfx + ".StockCount", (int)c.StockCount)
                    .Field(pfx + ".RequestItemCount", (int)c.RequestItemCount);
                shown++;
            }
            if (shown == 0) b.Field("CatalogEntries", "None");
            };
    }

    // ================= LOOT (Batch 5 companion) =================
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcOpenTreasure>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcOpenTreasure)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcOpenTreasure*>(p);
            FieldBuilder(e)
                .Field("ChestID", pkt->ChestID)
                .Field("ChestType", pkt->ChestType)
                .Field("Result", pkt->Result);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcLootItems>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcLootItems)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcLootItems*>(p);
            FieldBuilder b(e);
            b.Field("ChestID", pkt->ChestID);

            int present = 0;
            for (int i = 0; i < 16; ++i) if (pkt->Items[i].ItemID || pkt->Items[i].Stack) present++;
            b.Field("ItemCount", present);

            int shown = 0;
            for (int i = 0; i < 16 && shown < 6; ++i) {
                const auto& li = pkt->Items[i];
                if (li.ItemID == 0 && li.Stack == 0) continue;
                std::string pfx = std::string("Item") + std::to_string(i);
                b.Field(pfx + ".ItemID", li.ItemID)
                    .Field(pfx + ".Stack", (int)li.Stack)
                    .Field(pfx + ".Quality", (int)li.Quality);
                shown++;
            }
            if (present > shown) b.Field("MoreItems", std::string("... ") + std::to_string(present - shown) + " more");
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcLootActionResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcLootActionResult)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcLootActionResult*>(p);
            FieldBuilder(e)
                .Field("ChestID", pkt->ChestID)
                .Field("ItemID", pkt->ItemID)
                .Field("Result", (int)pkt->Result)
                .Field("RolledValue", (int)pkt->RolledValue);
            };
    }


} // end anonymous namespace

// Registration
void PacketDecoding::RegisterZonePackets() {
    auto& r = PacketDecoderRegistry::Instance();

    // Category 1
    r.RegisterDecoder(1, false, 0x0142, MakeGenericDecoder<ServerZone::FFXIVIpcActorControl>());
    r.RegisterDecoder(1, false, 0x0143, MakeGenericDecoder<ServerZone::FFXIVIpcActorControlSelf>());
    r.RegisterDecoder(1, false, 0x0144, MakeGenericDecoder<ServerZone::FFXIVIpcActorControlTarget>());
    r.RegisterDecoder(1, false, 0x0145, MakeGenericDecoder<ServerZone::FFXIVIpcResting>());
    r.RegisterDecoder(1, false, 0x0146, MakeGenericDecoder<ServerZone::FFXIVIpcActionResult1>());
    r.RegisterDecoder(1, false, 0x0147, MakeGenericDecoder<ServerZone::FFXIVIpcActionResult>());
    r.RegisterDecoder(1, false, 0x0148, MakeGenericDecoder<ServerZone::FFXIVIpcStatus>());
    r.RegisterDecoder(1, false, 0x014A, MakeGenericDecoder<ServerZone::FFXIVIpcRecastGroup>());
    r.RegisterDecoder(1, false, 0x0196, MakeGenericDecoder<ServerZone::FFXIVIpcActorCast>());

    // Category 2
    r.RegisterDecoder(1, false, 0x0190, MakeGenericDecoder<ServerZone::FFXIVIpcPlayerSpawn>());
    r.RegisterDecoder(1, false, 0x0191, MakeGenericDecoder<ServerZone::FFXIVIpcActorFreeSpawn>());
    r.RegisterDecoder(1, false, 0x0192, MakeGenericDecoder<ServerZone::FFXIVIpcActorMove>());
    r.RegisterDecoder(1, false, 0x0193, MakeGenericDecoder<ServerZone::FFXIVIpcTransfer>());
    r.RegisterDecoder(1, false, 0x0194, MakeGenericDecoder<ServerZone::FFXIVIpcWarp>());

    // Category 3
    r.RegisterDecoder(1, false, 0x0065, MakeGenericDecoder<ServerZone::FFXIVIpcSync>());
    r.RegisterDecoder(1, false, 0x0066, MakeGenericDecoder<ServerZone::FFXIVIpcLogin>());
    r.RegisterDecoder(1, false, 0x0067, MakeGenericDecoder<ServerZone::FFXIVIpcChat>());

    // Category 4
    r.RegisterDecoder(1, false, 0x00CF, MakeGenericDecoder<ServerZone::FFXIVIpcGetProfileResult>());
    r.RegisterDecoder(1, false, 0x00CE, MakeGenericDecoder<ServerZone::FFXIVIpcSetProfileResult>());
    r.RegisterDecoder(1, false, 0x00D0, MakeGenericDecoder<ServerZone::FFXIVIpcGetSearchCommentResult>());
    r.RegisterDecoder(1, false, 0x00D1, MakeGenericDecoder<ServerZone::FFXIVIpcGetCharacterNameResult>());
    r.RegisterDecoder(1, false, 0x00EB, MakeGenericDecoder<ServerZone::FFXIVIpcPcSearchResult>());

    // Category 5
    r.RegisterDecoder(1, false, 0x0199, MakeGenericDecoder<ServerZone::FFXIVIpcUpdateParty>());
    r.RegisterDecoder(1, false, 0x00DC, MakeGenericDecoder<ServerZone::FFXIVIpcPcPartyResult>());
    r.RegisterDecoder(1, false, 0x00DD, MakeGenericDecoder<ServerZone::FFXIVIpcPcPartyUpdate>());
    r.RegisterDecoder(1, false, 0x014C, MakeGenericDecoder<ServerZone::FFXIVIpcPartyPos>());
    r.RegisterDecoder(1, false, 0x014D, MakeGenericDecoder<ServerZone::FFXIVIpcAlliancePos>());
    r.RegisterDecoder(1, false, 0x014B, MakeGenericDecoder<ServerZone::FFXIVIpcUpdateAlliance>());
    r.RegisterDecoder(1, false, 0x00D6, MakeGenericDecoder<ServerZone::FFXIVIpcPartyRecruitResult>());

    // Category 6
    r.RegisterDecoder(1, false, 0x00C9, MakeGenericDecoder<ServerZone::FFXIVIpcInviteResult>());
    r.RegisterDecoder(1, false, 0x00CA, MakeGenericDecoder<ServerZone::FFXIVIpcInviteReplyResult>());
    r.RegisterDecoder(1, false, 0x00CB, MakeGenericDecoder<ServerZone::FFXIVIpcInviteUpdate>());
    r.RegisterDecoder(1, false, 0x00E6, MakeGenericDecoder<ServerZone::FFXIVIpcFriendlistRemoveResult>());
    r.RegisterDecoder(1, false, 0x00F0, MakeGenericDecoder<ServerZone::FFXIVIpcLinkshellResult>());
    r.RegisterDecoder(1, false, 0x00E1, MakeGenericDecoder<ServerZone::FFXIVIpcBlacklistAddResult>());
    r.RegisterDecoder(1, false, 0x00E2, MakeGenericDecoder<ServerZone::FFXIVIpcBlacklistRemoveResult>());
    r.RegisterDecoder(1, false, 0x00E3, MakeGenericDecoder<ServerZone::FFXIVIpcGetBlacklistResult>());
    r.RegisterDecoder(1, false, 0x00D5, MakeGenericDecoder<ServerZone::FFXIVIpcSetOnlineStatus>());
    r.RegisterDecoder(1, false, 0x00F1, MakeGenericDecoder<ServerZone::FFXIVIpcGetLinkshellListResult>());

    // Category 7
    r.RegisterDecoder(1, false, 0x00D3, MakeGenericDecoder<ServerZone::FFXIVIpcSendSystemMessage>());
    r.RegisterDecoder(1, false, 0x00D4, MakeGenericDecoder<ServerZone::FFXIVIpcSendLoginMessage>());
    r.RegisterDecoder(1, false, 0x00D2, MakeGenericDecoder<ServerZone::FFXIVIpcChatChannelResult>());
    r.RegisterDecoder(1, false, 0x010E, MakeGenericDecoder<ServerZone::FFXIVIpcFreeCompanyResult>());
    r.RegisterDecoder(1, false, 0x014F, MakeGenericDecoder<ServerZone::FFXIVIpcGrandCompany>());
    r.RegisterDecoder(1, false, 0x00CC, MakeGenericDecoder<ServerZone::FFXIVIpcGetCommonlistResult>());

    // Category 8 (Content Finder / Duty)
    r.RegisterDecoder(1, false, 0x02DB, MakeGenericDecoder<ServerZone::FFXIVIpcUpdateFindContent>());
    r.RegisterDecoder(1, false, 0x02DE, MakeGenericDecoder<ServerZone::FFXIVIpcNotifyFindContentStatus>());
    r.RegisterDecoder(1, false, 0x0339, MakeGenericDecoder<ServerZone::FFXIVIpcFinishContentMatchToClient>());
    r.RegisterDecoder(1, false, 0x02E3, MakeGenericDecoder<ServerZone::FFXIVIpcContentAttainFlags>());
    r.RegisterDecoder(1, false, 0x0311, MakeGenericDecoder<ServerZone::FFXIVIpcContentBonus>());
    r.RegisterDecoder(1, false, 0x02E1, MakeGenericDecoder<ServerZone::FFXIVIpcResponsePenalties>());
    r.RegisterDecoder(1, false, 0x02E4, MakeGenericDecoder<ServerZone::FFXIVIpcUpdateContent>());

    // Category 9 (Items)
    r.RegisterDecoder(1, false, 0x01AF, MakeGenericDecoder<ServerZone::FFXIVIpcNormalItem>());
    r.RegisterDecoder(1, false, 0x01B6, MakeGenericDecoder<ServerZone::FFXIVIpcUpdateItem>());
    r.RegisterDecoder(1, false, 0x01B0, MakeGenericDecoder<ServerZone::FFXIVIpcItemSize>());
    r.RegisterDecoder(1, false, 0x01B2, MakeGenericDecoder<ServerZone::FFXIVIpcItemOperation>());
    r.RegisterDecoder(1, false, 0x01B1, MakeGenericDecoder<ServerZone::FFXIVIpcItemOperationBatch>());
    r.RegisterDecoder(1, false, 0x01B3, MakeGenericDecoder<ServerZone::FFXIVIpcGilItem>());
    r.RegisterDecoder(1, false, 0x01AE, MakeGenericDecoder<ServerZone::FFXIVIpcItemStorage>());

    // Additional decoders (new)
    r.RegisterDecoder(1, false, 0x019A, MakeGenericDecoder<ServerZone::FFXIVIpcInitZone>());
    r.RegisterDecoder(1, false, 0x01A0, MakeGenericDecoder<ServerZone::FFXIVIpcPlayerStatus>());
    r.RegisterDecoder(1, false, 0x01A1, MakeGenericDecoder<ServerZone::FFXIVIpcBaseParam>());
    r.RegisterDecoder(1, false, 0x0140, MakeGenericDecoder<ServerZone::FFXIVIpcHudParam>());
    r.RegisterDecoder(1, false, 0x0200, MakeGenericDecoder<ServerZone::FFXIVIpcMount>());
    r.RegisterDecoder(1, false, 0x028B, MakeGenericDecoder<ServerZone::FFXIVIpcTitleList>());
    r.RegisterDecoder(1, false, 0x019B, MakeGenericDecoder<ServerZone::FFXIVIpcHateList>());
    r.RegisterDecoder(1, false, 0x019C, MakeGenericDecoder<ServerZone::FFXIVIpcHaterList>());
    r.RegisterDecoder(1, false, 0x02D6, MakeGenericDecoder<ServerZone::FFXIVIpcEnableLogout>());
    r.RegisterDecoder(1, false, 0x02DD, MakeGenericDecoder<ServerZone::FFXIVIpcAchievement>());

    // Category 10 (Housing)
    r.RegisterDecoder(1, false, 0x02EC, MakeGenericDecoder<ServerZone::FFXIVIpcHouseList>());
    r.RegisterDecoder(1, false, 0x02ED, MakeGenericDecoder<ServerZone::FFXIVIpcHouse>());
    r.RegisterDecoder(1, false, 0x02EE, MakeGenericDecoder<ServerZone::FFXIVIpcYardObjectList>());
    r.RegisterDecoder(1, false, 0x02F0, MakeGenericDecoder<ServerZone::FFXIVIpcYardObject>());
    r.RegisterDecoder(1, false, 0x02F1, MakeGenericDecoder<ServerZone::FFXIVIpcInterior>());
    r.RegisterDecoder(1, false, 0x02F2, MakeGenericDecoder<ServerZone::FFXIVIpcHousingAuction>());
    r.RegisterDecoder(1, false, 0x02F3, MakeGenericDecoder<ServerZone::FFXIVIpcHousingProfile>());
    r.RegisterDecoder(1, false, 0x02F4, MakeGenericDecoder<ServerZone::FFXIVIpcHousingHouseName>());
    r.RegisterDecoder(1, false, 0x02F5, MakeGenericDecoder<ServerZone::FFXIVIpcHousingGreeting>());
    r.RegisterDecoder(1, false, 0x02F6, MakeGenericDecoder<ServerZone::FFXIVIpcCharaHousingLandData>());
    r.RegisterDecoder(1, false, 0x02F7, MakeGenericDecoder<ServerZone::FFXIVIpcCharaHousing>());
    r.RegisterDecoder(1, false, 0x02F8, MakeGenericDecoder<ServerZone::FFXIVIpcHousingWelcome>());
    r.RegisterDecoder(1, false, 0x02F9, MakeGenericDecoder<ServerZone::FFXIVIpcFurnitureListS>());
    r.RegisterDecoder(1, false, 0x02FA, MakeGenericDecoder<ServerZone::FFXIVIpcFurnitureListM>());
    r.RegisterDecoder(1, false, 0x02FB, MakeGenericDecoder<ServerZone::FFXIVIpcFurnitureListL>());
    r.RegisterDecoder(1, false, 0x02FC, MakeGenericDecoder<ServerZone::FFXIVIpcFurniture>());
    r.RegisterDecoder(1, false, 0x02FE, MakeGenericDecoder<ServerZone::FFXIVIpcHousingProfileList>());
    r.RegisterDecoder(1, false, 0x02FF, MakeGenericDecoder<ServerZone::FFXIVIpcHousingObjectTransform>());
    r.RegisterDecoder(1, false, 0x0300, MakeGenericDecoder<ServerZone::FFXIVIpcHousingObjectColor>());
    r.RegisterDecoder(1, false, 0x0301, MakeGenericDecoder<ServerZone::FFXIVIpcHousingObjectTransformMulti>());
    r.RegisterDecoder(1, false, 0x0307, MakeGenericDecoder<ServerZone::FFXIVIpcHousingGetPersonalRoomProfileListResult>());
    r.RegisterDecoder(1, false, 0x0308, MakeGenericDecoder<ServerZone::FFXIVIpcHousingGetHouseBuddyStableListResult>());
    r.RegisterDecoder(1, false, 0x0309, MakeGenericDecoder<ServerZone::FFXIVIpcHouseTrainBuddyData>());

    // Specifically requested P1 housing packets
    r.RegisterDecoder(1, false, 0x032A, MakeGenericDecoder<ServerZone::FFXIVIpcHousingObjectTransformMultiResult>());
    r.RegisterDecoder(1, false, 0x032B, MakeGenericDecoder<ServerZone::FFXIVIpcHousingLogWithHouseName>());
    r.RegisterDecoder(1, false, 0x032D, MakeGenericDecoder<ServerZone::FFXIVIpcHousingCombinedObjectStatus>());
    r.RegisterDecoder(1, false, 0x032E, MakeGenericDecoder<ServerZone::FFXIVIpcHouseBuddyModelData>());

    // P1 – Batch 2 (Remainder)
    r.RegisterDecoder(1, false, 0x028A, MakeGenericDecoder<ServerZone::FFXIVIpcWeatherId>());          
    r.RegisterDecoder(1, false, 0x006A, MakeGenericDecoder<ServerZone::FFXIVIpcMoveTerritory>());      
    r.RegisterDecoder(1, false, 0x006B, MakeGenericDecoder<ServerZone::FFXIVIpcMoveInstance>());       
    r.RegisterDecoder(1, false, 0x01C1, MakeGenericDecoder<ServerZone::FFXIVIpcMonsterNoteCategory>());
    r.RegisterDecoder(1, false, 0x0322, MakeGenericDecoder<ServerZone::FFXIVIpcQuestRepeatFlags>());   
    r.RegisterDecoder(1, false, 0x0320, MakeGenericDecoder<ServerZone::FFXIVIpcDailyQuests>());        
    r.RegisterDecoder(1, false, 0x01F0, MakeGenericDecoder<ServerZone::FFXIVIpcLegacyQuestCompleteList>()); 

    // P1 – Batch 3 (Progress deltas)
    r.RegisterDecoder(1, false, 0x019F, MakeGenericDecoder<ServerZone::FFXIVIpcPlayerStatusUpdate>()); 
    r.RegisterDecoder(1, false, 0x01A4, MakeGenericDecoder<ServerZone::FFXIVIpcChangeClass>());       
    r.RegisterDecoder(1, false, 0x01A2, MakeGenericDecoder<ServerZone::FFXIVIpcFirstAttack>());        
    r.RegisterDecoder(1, false, 0x01A3, MakeGenericDecoder<ServerZone::FFXIVIpcCondition>());         

    // P2 – Economy 1
    r.RegisterDecoder(1, false, 0x01AA, MakeGenericDecoder<ServerZone::FFXIVIpcRetainerList>());
    r.RegisterDecoder(1, false, 0x01AB, MakeGenericDecoder<ServerZone::FFXIVIpcRetainerData>());
    r.RegisterDecoder(1, false, 0x01AC, MakeGenericDecoder<ServerZone::FFXIVIpcMarketPriceHeader>());
    r.RegisterDecoder(1, false, 0x01AD, MakeGenericDecoder<ServerZone::FFXIVIpcMarketPrice>());

    // P2 – Economy 2
    r.RegisterDecoder(1, false, 0x0105, MakeGenericDecoder<ServerZone::FFXIVIpcGetItemSearchListResult>());
    r.RegisterDecoder(1, false, 0x0109, MakeGenericDecoder<ServerZone::FFXIVIpcGetItemHistoryResult>());
    r.RegisterDecoder(1, false, 0x010C, MakeGenericDecoder<ServerZone::FFXIVIpcCatalogSearchResult>());

    // Loot
    r.RegisterDecoder(1, false, 0x01B8, MakeGenericDecoder<ServerZone::FFXIVIpcOpenTreasure>());
    r.RegisterDecoder(1, false, 0x01BE, MakeGenericDecoder<ServerZone::FFXIVIpcLootItems>());
    r.RegisterDecoder(1, false, 0x01BA, MakeGenericDecoder<ServerZone::FFXIVIpcLootActionResult>());
}
