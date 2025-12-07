#include "../Network/OpcodeNames.h"
#include "../Network/GameEnums.h"
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
        // Use GameEnums for operation type
        auto opType = static_cast<GameEnums::ItemOperationType>(p->operationType);
        if (auto* name = GameEnums::GetItemOperationTypeName(opType)) {
            os << name;
        } else {
            os << "Op" << static_cast<int>(p->operationType);
        }
        if (p->srcStorageId != p->dstStorageId) {
            // Try to look up inventory names
            auto srcInv = static_cast<GameEnums::InventoryType>(p->srcStorageId);
            auto dstInv = static_cast<GameEnums::InventoryType>(p->dstStorageId);
            const char* srcName = GameEnums::GetInventoryTypeName(srcInv);
            const char* dstName = GameEnums::GetInventoryTypeName(dstInv);
            os << "(";
            if (srcName) os << srcName; else os << p->srcStorageId;
            os << "→";
            if (dstName) os << dstName; else os << p->dstStorageId;
            os << ")";
        }
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

    inline std::string FormatCalcResult(const CalcResult& cr) {
        auto effectType = static_cast<GameEnums::CalcResultType>(cr.effectType);
        const char* typeName = GameEnums::GetCalcResultTypeName(effectType);
        std::ostringstream os;
        if (typeName) {
            os << typeName;
        } else {
            os << "Unk" << static_cast<int>(cr.effectType);
        }
        os << ":" << static_cast<int>(cr.value);
        if (cr.hitSeverity > 0) {
            os << " (sev=" << static_cast<int>(cr.hitSeverity) << ")";
        }
        return os.str();
    }

    inline std::string SummarizeCalcResults(const CalcResult* cr, size_t count, size_t maxShow = 3) {
        std::ostringstream os;
        os << count << " [";
        for (size_t i = 0; i < count && i < maxShow; ++i) {
            if (i) os << ", ";
            os << FormatCalcResult(cr[i]);
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
            // Use partial decoding - show what we can
            PartialFieldBuilder<PacketT> b(emit, payload, len);
            b.Field("PacketType", std::string(typeid(PacketT).name()));
            // Generic decoder just shows the type name
            };
    }

    // ================= CATEGORY 1: COMBAT =================
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcActorControl>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            using PktT = ServerZone::FFXIVIpcActorControl;
            PartialFieldBuilder<PktT> b(emit, p, l);
            
            // These fields use direct offset checking via member pointers
            if (b.CanAccess(offsetof(PktT, category), sizeof(uint16_t))) {
                b.Field("Category", b.Pkt()->category);
                b.Enum("CategoryName", b.Pkt()->category, ::LookupActorControlCategoryName);
            } else {
                b.Field("Category", "[TRUNCATED]");
            }
            if (b.CanAccess(offsetof(PktT, param1), sizeof(uint32_t)))
                b.Hex("Param1", b.Pkt()->param1);
            else b.Field("Param1", "[TRUNCATED]");
            if (b.CanAccess(offsetof(PktT, param2), sizeof(uint32_t)))
                b.Hex("Param2", b.Pkt()->param2);
            else b.Field("Param2", "[TRUNCATED]");
            if (b.CanAccess(offsetof(PktT, param3), sizeof(uint32_t)))
                b.Hex("Param3", b.Pkt()->param3);
            else b.Field("Param3", "[TRUNCATED]");
            if (b.CanAccess(offsetof(PktT, param4), sizeof(uint32_t)))
                b.Hex("Param4", b.Pkt()->param4);
            else b.Field("Param4", "[TRUNCATED]");
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcActionResult1>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            using PktT = ServerZone::FFXIVIpcActionResult1;
            PartialFieldBuilder<PktT> b(emit, p, l);
            
            // Use GameData lookup for action name
            if (b.CanAccess(offsetof(PktT, Action), sizeof(uint32_t)))
                b.Action("Action", b.Pkt()->Action);
            else b.Field("Action", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, ActionKind), sizeof(uint8_t))) {
                auto kind = static_cast<GameEnums::ActionKind>(b.Pkt()->ActionKind);
                b.Enum("ActionKind", kind, GameEnums::GetActionKindName);
            } else b.Field("ActionKind", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, RequestId), sizeof(uint32_t)))
                b.Field("RequestId", b.Pkt()->RequestId);
            else b.Field("RequestId", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, ResultId), sizeof(uint32_t)))
                b.Field("ResultId", b.Pkt()->ResultId);
            else b.Field("ResultId", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, MainTarget), sizeof(uint64_t)))
                b.Hex("MainTarget", b.Pkt()->MainTarget);
            else b.Field("MainTarget", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, Target), sizeof(uint64_t)))
                b.Hex("Target", b.Pkt()->Target);
            else b.Field("Target", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, Flag), sizeof(uint32_t)))
                b.Hex("Flag", b.Pkt()->Flag);
            else b.Field("Flag", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, LockTime), sizeof(float)))
                b.Field("LockTime", static_cast<double>(b.Pkt()->LockTime));
            else b.Field("LockTime", "[TRUNCATED]");
            
            // CalcResult with effect type decoding
            if (b.CanAccess(offsetof(PktT, CalcResult), sizeof(CalcResult)))
                b.Field("Effect", FormatCalcResult(b.Pkt()->CalcResult));
            else b.Field("Effect", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, BallistaEntityId), sizeof(uint32_t)))
                b.Hex("BallistaEntityId", b.Pkt()->BallistaEntityId);
            else b.Field("BallistaEntityId", "[TRUNCATED]");
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcActionResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            using PktT = ServerZone::FFXIVIpcActionResult;
            PartialFieldBuilder<PktT> b(emit, p, l);
            
            // Use GameData lookup for action name
            if (b.CanAccess(offsetof(PktT, Action), sizeof(uint32_t)))
                b.Action("Action", b.Pkt()->Action);
            else b.Field("Action", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, ActionKind), sizeof(uint8_t))) {
                auto kind = static_cast<GameEnums::ActionKind>(b.Pkt()->ActionKind);
                b.Enum("ActionKind", kind, GameEnums::GetActionKindName);
            } else b.Field("ActionKind", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, RequestId), sizeof(uint32_t)))
                b.Field("RequestId", b.Pkt()->RequestId);
            else b.Field("RequestId", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, ResultId), sizeof(uint32_t)))
                b.Field("ResultId", b.Pkt()->ResultId);
            else b.Field("ResultId", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, MainTarget), sizeof(uint64_t)))
                b.Hex("MainTarget", b.Pkt()->MainTarget);
            else b.Field("MainTarget", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, TargetCount), sizeof(uint8_t)))
                b.Field("TargetCount", b.Pkt()->TargetCount);
            else b.Field("TargetCount", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, Flag), sizeof(uint32_t)))
                b.Hex("Flag", b.Pkt()->Flag);
            else b.Field("Flag", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, LockTime), sizeof(float)))
                b.Field("LockTime", static_cast<double>(b.Pkt()->LockTime));
            else b.Field("LockTime", "[TRUNCATED]");
            
            // Decode target effects with CalcResult type names
            if (b.CanAccess(offsetof(PktT, TargetCount), sizeof(uint8_t))) {
                int show = std::min<int>(b.Pkt()->TargetCount, 3);
                for (int i = 0; i < show; i++) {
                    size_t targetOff = offsetof(PktT, Target) + i * sizeof(uint64_t);
                    size_t calcOff = offsetof(PktT, CalcResult) + i * sizeof(CalcResult);
                    std::ostringstream tk, ek; 
                    tk << "Target" << i; 
                    ek << "Effect" << i;
                    if (b.CanAccess(targetOff, sizeof(uint64_t)))
                        b.Hex(tk.str(), b.Pkt()->Target[i]);
                    else b.Field(tk.str(), "[TRUNCATED]");
                    if (b.CanAccess(calcOff, sizeof(CalcResult)))
                        b.Field(ek.str(), FormatCalcResult(b.Pkt()->CalcResult[i]));
                    else b.Field(ek.str(), "[TRUNCATED]");
                }
                if (b.Pkt()->TargetCount > 3) {
                    std::ostringstream os; 
                    os << "... and " << (b.Pkt()->TargetCount - 3) << " more targets";
                    b.Field("MoreTargets", os.str());
                }
            }
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcPlayerSpawn>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            using PktT = ServerZone::FFXIVIpcPlayerSpawn;
            PartialFieldBuilder<PktT> b(emit, p, l);
            
            if (b.CanAccess(offsetof(PktT, LayoutId), sizeof(uint32_t)))
                b.Field("LayoutId", b.Pkt()->LayoutId);
            else b.Field("LayoutId", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, NameId), sizeof(uint32_t)))
                b.Field("NameId", b.Pkt()->NameId);
            else b.Field("NameId", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, Name), 32))
                b.Field("Name", std::string(reinterpret_cast<const char*>(b.Pkt()->Name), strnlen(reinterpret_cast<const char*>(b.Pkt()->Name), 32)));
            else b.Field("Name", "[TRUNCATED]");
            
            // ObjKind with enum lookup
            if (b.CanAccess(offsetof(PktT, ObjKind), sizeof(uint8_t))) {
                auto kind = static_cast<GameEnums::ObjKind>(b.Pkt()->ObjKind);
                b.Enum("ObjKind", kind, GameEnums::GetObjKindName);
            } else b.Field("ObjKind", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, ObjType), sizeof(uint8_t)))
                b.Field("ObjType", b.Pkt()->ObjType);
            else b.Field("ObjType", "[TRUNCATED]");
            
            // Use GameData lookup for ClassJob name
            if (b.CanAccess(offsetof(PktT, ClassJob), sizeof(uint8_t)))
                b.ClassJob("ClassJob", &PktT::ClassJob);
            else b.Field("ClassJob", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, Lv), sizeof(uint8_t)))
                b.Field("Level", b.Pkt()->Lv);
            else b.Field("Level", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, Hp), sizeof(uint32_t)))
                b.Field("HP", b.Pkt()->Hp);
            else b.Field("HP", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, HpMax), sizeof(uint32_t)))
                b.Field("HPMax", b.Pkt()->HpMax);
            else b.Field("HPMax", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, Mp), sizeof(uint16_t)))
                b.Field("MP", b.Pkt()->Mp);
            else b.Field("MP", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, MpMax), sizeof(uint16_t)))
                b.Field("MPMax", b.Pkt()->MpMax);
            else b.Field("MPMax", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, Pos), sizeof(float) * 3)) {
                std::ostringstream os;
                os << std::fixed << std::setprecision(2) 
                   << "(" << b.Pkt()->Pos[0] << ", " << b.Pkt()->Pos[1] << ", " << b.Pkt()->Pos[2] << ")";
                b.Field("Position", os.str());
            } else b.Field("Position", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, Dir), sizeof(uint16_t))) {
                float degrees = b.Pkt()->Dir * 360.0f / 65535.0f;
                std::ostringstream os;
                os << std::fixed << std::setprecision(1) << degrees << "deg";
                b.Field("Direction", os.str());
            } else b.Field("Direction", "[TRUNCATED]");
            
            // Optional fields only if accessible
            if (b.CanAccess(offsetof(PktT, GrandCompany), sizeof(uint8_t)) && b.Pkt()->GrandCompany > 0) {
                b.GrandCompany("GrandCompany", b.Pkt()->GrandCompany);
                if (b.CanAccess(offsetof(PktT, GrandCompanyRank), sizeof(uint8_t)))
                    b.Field("GrandCompanyRank", b.Pkt()->GrandCompanyRank);
            }
            
            if (b.CanAccess(offsetof(PktT, Crest), sizeof(uint64_t)) && b.Pkt()->Crest != 0) {
                b.Hex("FCCrest", b.Pkt()->Crest);
                if (b.CanAccess(offsetof(PktT, FreeCompanyTag), 6))
                    b.Field("FCTag", std::string(reinterpret_cast<const char*>(b.Pkt()->FreeCompanyTag), strnlen(reinterpret_cast<const char*>(b.Pkt()->FreeCompanyTag), 6)));
            }
            
            // Count active status effects
            if (b.CanAccess(offsetof(PktT, Status), sizeof(StatusWork) * 30)) {
                int active = 0;
                for (int i = 0; i < 30; i++) if (b.Pkt()->Status[i].id) active++;
                if (active > 0) {
                    b.Field("ActiveStatusCount", active);
                    int shown = 0;
                    for (int i = 0; i < 30 && shown < 5; i++) {
                        if (!b.Pkt()->Status[i].id) continue;
                        std::ostringstream k; k << "Status" << shown;
                        b.StatusEffect(k.str(), b.Pkt()->Status[i].id);
                        shown++;
                    }
                }
            }
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcActorControlSelf>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            using PktT = ServerZone::FFXIVIpcActorControlSelf;
            PartialFieldBuilder<PktT> b(emit, p, l);
            
            if (b.CanAccess(offsetof(PktT, category), sizeof(uint16_t))) {
                b.Field("Category", b.Pkt()->category);
                b.Enum("CategoryName", b.Pkt()->category, ::LookupActorControlCategoryName);
            } else b.Field("Category", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, param1), sizeof(uint32_t)))
                b.Hex("Param1", b.Pkt()->param1);
            else b.Field("Param1", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, param2), sizeof(uint32_t)))
                b.Hex("Param2", b.Pkt()->param2);
            else b.Field("Param2", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, param3), sizeof(uint32_t)))
                b.Hex("Param3", b.Pkt()->param3);
            else b.Field("Param3", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, param4), sizeof(uint32_t)))
                b.Hex("Param4", b.Pkt()->param4);
            else b.Field("Param4", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, param5), sizeof(uint32_t)))
                b.Hex("Param5", b.Pkt()->param5);
            else b.Field("Param5", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, param6), sizeof(uint32_t)))
                b.Hex("Param6", b.Pkt()->param6);
            else b.Field("Param6", "[TRUNCATED]");
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcActorControlTarget>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            using PktT = ServerZone::FFXIVIpcActorControlTarget;
            PartialFieldBuilder<PktT> b(emit, p, l);
            
            if (b.CanAccess(offsetof(PktT, category), sizeof(uint16_t))) {
                b.Field("Category", b.Pkt()->category);
                b.Enum("CategoryName", b.Pkt()->category, ::LookupActorControlCategoryName);
            } else b.Field("Category", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, param1), sizeof(uint32_t)))
                b.Hex("Param1", b.Pkt()->param1);
            else b.Field("Param1", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, param2), sizeof(uint32_t)))
                b.Hex("Param2", b.Pkt()->param2);
            else b.Field("Param2", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, param3), sizeof(uint32_t)))
                b.Hex("Param3", b.Pkt()->param3);
            else b.Field("Param3", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, param4), sizeof(uint32_t)))
                b.Hex("Param4", b.Pkt()->param4);
            else b.Field("Param4", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, targetId), sizeof(uint64_t)))
                b.Hex("TargetId", b.Pkt()->targetId);
            else b.Field("TargetId", "[TRUNCATED]");
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcResting>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            using PktT = ServerZone::FFXIVIpcResting;
            PartialFieldBuilder<PktT> b(emit, p, l);
            
            if (b.CanAccess(offsetof(PktT, Hp), sizeof(uint32_t)))
                b.Field("Hp", b.Pkt()->Hp);
            else b.Field("Hp", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, Mp), sizeof(uint16_t)))
                b.Field("Mp", b.Pkt()->Mp);
            else b.Field("Mp", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, Tp), sizeof(uint16_t)))
                b.Field("Tp", b.Pkt()->Tp);
            else b.Field("Tp", "[TRUNCATED]");
            
            if (b.CanAccess(offsetof(PktT, Gp), sizeof(uint16_t)))
                b.Field("Gp", b.Pkt()->Gp);
            else b.Field("Gp", "[TRUNCATED]");
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcStatus>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            using PktT = ServerZone::FFXIVIpcStatus;
            PartialFieldBuilder<PktT> b(emit, p, l);
            
            if (!b.CanAccess(offsetof(PktT, effect), sizeof(StatusWork) * 30)) {
                b.Field("effect", "[TRUNCATED - status array inaccessible]");
                return;
            }
            
            int active = 0;
            for (int i = 0; i < 30; i++) if (b.Pkt()->effect[i].id) active++;
            b.Field("ActiveStatusCount", active);
            
            int shown = 0;
            for (int i = 0; i < 30 && shown < 10; i++) {
                if (!b.Pkt()->effect[i].id) continue;
                std::ostringstream pfx; pfx << "Status" << shown;
                b.StatusEffect(pfx.str(), b.Pkt()->effect[i].id);
                b.Field(pfx.str() + "SystemParam", (int)b.Pkt()->effect[i].systemParam)
                    .Field(pfx.str() + "Time", b.Pkt()->effect[i].time)
                    .Hex(pfx.str() + "Source", b.Pkt()->effect[i].source);
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
                .Action("Action", pkt->Action)
                .ActionKind("ActionKind", pkt->ActionKind)
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
            float rotation = pkt->dir * (3.14159265f / 32768.0f);  // Convert to radians
            
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
                .WarpType("Type", pkt->Type)
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
                    .ClassJob(pfx + "ClassJob", pkt->Member[i].ClassJob)
                    .Field(pfx + "Lv", (int)pkt->Member[i].Lv)
                    .Field(pfx + "HP", pkt->Member[i].Hp)
                    .Field(pfx + "HPMax", pkt->Member[i].HpMax)
                    .Field(pfx + "MP", pkt->Member[i].Mp)
                    .Field(pfx + "MPMax", pkt->Member[i].MpMax)
                    .Territory(pfx + "Zone", pkt->Member[i].TerritoryType);
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
                .Territory("Zone", pkt->TerritoryType)
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
                .Territory("Zone", pkt->TerritoryType)
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
            FieldBuilder(e)
                .GrandCompany("GrandCompany", pkt->GrandCompany)
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
                .InventoryType("StorageId", pkt->item.storageId)
                .Field("ContainerIndex", pkt->item.containerIndex)
                .Item("Item", pkt->item.catalogId)
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
                .InventoryType("StorageId", pkt->item.storageId)
                .Field("ContainerIndex", pkt->item.containerIndex)
                .Item("Item", pkt->item.catalogId)
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
                .InventoryType("StorageId", pkt->storageId);
            };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcItemOperation>() {
        return [](const uint8_t* p, size_t l, RowEmitter e) {
            if (l < sizeof(ServerZone::FFXIVIpcItemOperation)) { e("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcItemOperation*>(p);
            FieldBuilder b(e);
            b.Field("ContextId", pkt->contextId)
                .ItemOperation("OperationType", pkt->operationType);
            if (pkt->srcEntity) b.Hex("SrcEntity", pkt->srcEntity);
            b.InventoryType("SrcStorageId", pkt->srcStorageId)
                .Field("SrcContainerIndex", (int)pkt->srcContainerIndex)
                .Field("SrcStack", pkt->srcStack)
                .Item("SrcItem", pkt->srcCatalogId);
            if (pkt->dstEntity) b.Hex("DstEntity", pkt->dstEntity);
            b.InventoryType("DstStorageId", pkt->dstStorageId)
                .Field("DstContainerIndex", (int)pkt->dstContainerIndex)
                .Field("DstStack", pkt->dstStack)
                .Item("DstItem", pkt->dstCatalogId);
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
                .InventoryType("StorageId", pkt->item.storageId)
                .Field("ContainerIndex", pkt->item.containerIndex)
                .Field("Amount", pkt->item.stack)
                .Item("Item", pkt->item.catalogId)
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
                .InventoryType("StorageId", pkt->storage.storageId)
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
                .Territory("TerritoryType", pkt->TerritoryType)
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
                .ClassJob("ClassJob", pkt->ClassJob)
                .ClassJob("FirstClass", pkt->FirstClass)
                .Field("GuardianDeity", (int)pkt->GuardianDeity)
                .Field("BirthMonth", (int)pkt->BirthMonth)
                .Field("Birthday", (int)pkt->Birthday)
                .Field("StartTown", (int)pkt->StartTown)
                .Field("HomePoint", (int)pkt->HomePoint)
                .GrandCompany("GrandCompany", pkt->GrandCompany)
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
            b.ClassJob("ClassJob", pkt->ClassJob)
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
            // Use GameData for mount name lookup
            FieldBuilder(emit)
                .Field("Mount", GameData::FormatMount(pkt->id));
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
                .Territory("Content", pkt->territoryType)
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
                .Territory("Content", pkt->territoryType)
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
                .ClassJob("classJob", pkt->classJob)
                .Field("progress", (int)pkt->progress)
                .Field("playerNum", (int)pkt->playerNum)
                .Territory("Content", pkt->territoryType)
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
                .Territory("Content", pkt->territoryType)
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
                .HouseSize("Size", pkt->LandData.size)
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

    // ================= P1 BATCH 1: EVENT / QUEST CORE =================
    
    // EventStart (0x01C2 is EventPlayHeader, not EventStart - no direct opcode found)
    // Note: EventStart struct exists but no dedicated opcode in OpcodeNames.cpp
    // Skipping for now until opcode is confirmed
    
    // EventFinish (no direct opcode found)
    // Note: EventFinish struct exists but no dedicated opcode in OpcodeNames.cpp
    // Skipping for now until opcode is confirmed
    
    // Quests (no direct opcode found)
    // Note: Quests struct exists but may be part of init/login flow
    // Skipping for now until opcode is confirmed
    
    // Quest (0x0321 is DailyQuest, need to find Quest opcode)
    // Skipping for now until opcode is confirmed
    
    // QuestCompleteList (no direct opcode found)
    // Note: 0x01F0 is LegacyQuestCompleteFlags (already implemented)
    // Skipping for now until opcode is confirmed
    
    // QuestFinish (no direct opcode found)
    // Skipping for now until opcode is confirmed
    
    // QuestTracker (no direct opcode found)
    // Skipping for now until opcode is confirmed
    
    // ================= P2 BATCH 6: LOOT / TREASURE REMAINDER =================
    
    // P3 – FREE COMPANY EXTENDED (11 packets)
    
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetFcStatusResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcGetFcStatusResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetFcStatusResult*>(p);
            FieldBuilder(emit)
                .Hex("FreeCompanyID", pkt->FreeCompanyID)
                .Hex("AuthorityList", pkt->AuthorityList)
                .Hex("ChannelID", pkt->ChannelID)
                .Hex("CrestID", pkt->CrestID)
                .Field("CharaFcState", pkt->CharaFcState)
                .Field("CharaFcParam", pkt->CharaFcParam)
                .Field("Param", pkt->Param)
                .Field("FcStatus", pkt->FcStatus)
                .Field("GrandCompanyID", pkt->GrandCompanyID)
                .Field("HierarchyType", pkt->HierarchyType)
                .Field("FcRank", pkt->FcRank)
                .Field("IsCrest", pkt->IsCrest)
                .Field("IsDecal", pkt->IsDecal)
                .Field("IsFcAction", pkt->IsFcAction)
                .Field("IsChestExt1", pkt->IsChestExt1)
                .Field("IsChestLock", pkt->IsChestLock);
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetFcInviteListResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcGetFcInviteListResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetFcInviteListResult*>(p);
            FieldBuilder(emit)
                .Hex("FreeCompanyID", pkt->FreeCompanyID)
                .Hex("CrestID", pkt->CrestID)
                .Field("CreateDate", pkt->CreateDate)
                .Field("GrandCompanyID", pkt->GrandCompanyID)
                .String("FcTag", pkt->FcTag, sizeof(pkt->FcTag))
                .String("FreeCompanyName", pkt->FreeCompanyName, sizeof(pkt->FreeCompanyName))
                .String("MasterCharacter.Name", pkt->MasterCharacter.CharacterName, sizeof(pkt->MasterCharacter.CharacterName));
            
            for (int i = 0; i < 3; ++i) {
                char key[32];
                snprintf(key, sizeof(key), "InviteCharacter[%d].Name", i);
                FieldBuilder(emit).String(key, pkt->InviteCharacter[i].CharacterName, sizeof(pkt->InviteCharacter[i].CharacterName));
            }
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetFcProfileResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcGetFcProfileResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetFcProfileResult*>(p);
            FieldBuilder(emit)
                .Hex("TargetCharacterID", pkt->TargetCharacterID)
                .Hex("FreeCompanyID", pkt->FreeCompanyID)
                .Hex("CrestID", pkt->CrestID)
                .Hex("LandID", pkt->LandID)
                .Hex("TargetEntityID", pkt->TargetEntityID)
                .Field("CreateDate", pkt->CreateDate)
                .Field("Reputation", pkt->Reputation)
                .Field("TotalMemberCount", pkt->TotalMemberCount)
                .Field("OnlineMemberCount", pkt->OnlineMemberCount)
                .Field("FcActivity", pkt->FcActivity)
                .Field("FcRole", pkt->FcRole)
                .Field("FcActiveTimeFlag", pkt->FcActiveTimeFlag)
                .Field("FcJoinRequestFlag", pkt->FcJoinRequestFlag)
                .Field("GrandCompanyID", pkt->GrandCompanyID)
                .Field("FcStatus", pkt->FcStatus)
                .Field("FcRank", pkt->FcRank)
                .Field("JoinRequestCount", pkt->JoinRequestCount)
                .String("FreeCompanyName", pkt->FreeCompanyName, sizeof(pkt->FreeCompanyName))
                .String("FcTag", pkt->FcTag, sizeof(pkt->FcTag))
                .String("MasterCharacterName", pkt->MasterCharacterName, sizeof(pkt->MasterCharacterName))
                .String("CompanyMotto", pkt->CompanyMotto, sizeof(pkt->CompanyMotto))
                .String("HouseName", pkt->HouseName, sizeof(pkt->HouseName));
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetFcHeaderResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcGetFcHeaderResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetFcHeaderResult*>(p);
            FieldBuilder(emit)
                .Hex("FreeCompanyID", pkt->FreeCompanyID)
                .Hex("CrestID", pkt->CrestID)
                .Hex("FcPoint", pkt->FcPoint)
                .Hex("FcCredit", pkt->FcCredit)
                .Field("Reputation", pkt->Reputation)
                .Field("NextPoint", pkt->NextPoint)
                .Field("CurrentPoint", pkt->CurrentPoint)
                .Field("TotalMemberCount", pkt->TotalMemberCount)
                .Field("OnlineMemberCount", pkt->OnlineMemberCount)
                .Field("GrandCompanyID", pkt->GrandCompanyID)
                .Field("FcRank", pkt->FcRank)
                .String("FreeCompanyName", pkt->FreeCompanyName, sizeof(pkt->FreeCompanyName))
                .String("FcTag", pkt->FcTag, sizeof(pkt->FcTag));
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetCompanyBoardResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcGetCompanyBoardResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetCompanyBoardResult*>(p);
            FieldBuilder(emit)
                .Field("Type", pkt->Type)
                .String("CompanyBoard", pkt->CompanyBoard, sizeof(pkt->CompanyBoard));
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetFcHierarchyResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcGetFcHierarchyResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetFcHierarchyResult*>(p);
            FieldBuilder(emit)
                .String("MasterCharacterName", pkt->MasterCharacterName, sizeof(pkt->MasterCharacterName));
            
            // Show first 8 hierarchy entries (truncate large array)
            const int maxShow = 8;
            for (int i = 0; i < maxShow && i < 16; ++i) {
                char keyAuth[48], keyCount[48], keySort[48], keyName[48];
                snprintf(keyAuth, sizeof(keyAuth), "FcHierarchyList[%d].AuthorityList", i);
                snprintf(keyCount, sizeof(keyCount), "FcHierarchyList[%d].Count", i);
                snprintf(keySort, sizeof(keySort), "FcHierarchyList[%d].SortNo", i);
                snprintf(keyName, sizeof(keyName), "FcHierarchyList[%d].HierarchyName", i);
                
                emit(keyAuth, FormatHex(pkt->FcHierarchyList[i].AuthorityList).c_str());
                emit(keyCount, std::to_string(pkt->FcHierarchyList[i].Count).c_str());
                emit(keySort, std::to_string(pkt->FcHierarchyList[i].SortNo).c_str());
                FieldBuilder(emit).String(keyName, pkt->FcHierarchyList[i].HierarchyName, sizeof(pkt->FcHierarchyList[i].HierarchyName));
            }
            if (16 > maxShow) {
                emit("More", "+8 hierarchy entries");
            }
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetFcHierarchyLiteResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcGetFcHierarchyLiteResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetFcHierarchyLiteResult*>(p);
            
            // Show first 8 hierarchy lite entries
            const int maxShow = 8;
            for (int i = 0; i < maxShow && i < 16; ++i) {
                char keyAuth[48], keyCount[48], keySort[48];
                snprintf(keyAuth, sizeof(keyAuth), "FcHierarchyList[%d].AuthorityList", i);
                snprintf(keyCount, sizeof(keyCount), "FcHierarchyList[%d].Count", i);
                snprintf(keySort, sizeof(keySort), "FcHierarchyList[%d].SortNo", i);
                
                emit(keyAuth, FormatHex(pkt->FcHierarchyList[i].AuthorityList).c_str());
                emit(keyCount, std::to_string(pkt->FcHierarchyList[i].Count).c_str());
                emit(keySort, std::to_string(pkt->FcHierarchyList[i].SortNo).c_str());
            }
            if (16 > maxShow) {
                emit("More", "+8 hierarchy entries");
            }
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetCompanyMottoResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcGetCompanyMottoResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetCompanyMottoResult*>(p);
            FieldBuilder(emit)
                .Field("FcActivity", pkt->FcActivity)
                .Field("FcRole", pkt->FcRole)
                .Field("Type", pkt->Type)
                .Field("FcActiveTimeFlag", pkt->FcActiveTimeFlag)
                .Field("FcJoinRequestFlag", pkt->FcJoinRequestFlag)
                .Field("JoinRequestCount", pkt->JoinRequestCount)
                .String("CompanyMotto", pkt->CompanyMotto, sizeof(pkt->CompanyMotto));
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetFcParamsResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcGetFcParamsResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetFcParamsResult*>(p);
            FieldBuilder(emit)
                .Hex("CharacterID", pkt->CharacterID)
                .Hex("FcPoint", pkt->FcPoint)
                .Hex("FcCredit", pkt->FcCredit)
                .Hex("FcCreditAccumu", pkt->FcCreditAccumu)
                .Field("CreateDate", pkt->CreateDate)
                .Field("NextPoint", pkt->NextPoint)
                .Field("CurrentPoint", pkt->CurrentPoint)
                .Field("Reputation[0]", pkt->Reputation[0])
                .Field("Reputation[1]", pkt->Reputation[1])
                .Field("Reputation[2]", pkt->Reputation[2])
                .Field("FcRank", pkt->FcRank);
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetFcActionResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcGetFcActionResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetFcActionResult*>(p);
            FieldBuilder(emit)
                .Hex("CharacterID", pkt->CharacterID);
            
            for (int i = 0; i < 3; ++i) {
                char keyAction[48], keyTime[48];
                snprintf(keyAction, sizeof(keyAction), "ActiveActionList[%d]", i);
                snprintf(keyTime, sizeof(keyTime), "ActiveActionLeftTime[%d]", i);
                emit(keyAction, FormatHex(pkt->ActiveActionList[i]).c_str());
                emit(keyTime, std::to_string(pkt->ActiveActionLeftTime[i]).c_str());
            }
            
            // Show first 8 stock actions
            const int maxShow = 8;
            for (int i = 0; i < maxShow && i < 15; ++i) {
                char key[48];
                snprintf(key, sizeof(key), "StockActionList[%d]", i);
                emit(key, FormatHex(pkt->StockActionList[i]).c_str());
            }
            if (15 > maxShow) {
                emit("More", "+7 stock actions");
            }
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetFcMemoResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcGetFcMemoResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetFcMemoResult*>(p);
            FieldBuilder(emit)
                .Hex("CharacterID", pkt->CharacterID)
                .Field("UIParam", pkt->UIParam)
                .Field("UpdateDate", pkt->UpdateDate)
                .String("FcMemo", pkt->FcMemo, sizeof(pkt->FcMemo));
        };
    }

    // ================= P5 MAIL / LETTERS BATCH =================
    
    // LetterResult (0x00FA)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcLetterResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcLetterResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcLetterResult*>(p);
            FieldBuilder(emit)
                .Field("UpPacketNo", pkt->UpPacketNo)
                .Hex("SenderCharacterID", pkt->SenderCharacterID)
                .Field("Date", pkt->Date)
                .Field("AppendItem.Gil.CatalogID", pkt->AppendItem.Gil.CatalogID)
                .Field("AppendItem.Gil.Stack", pkt->AppendItem.Gil.Stack)
                .Field("Result", pkt->Result);
        };
    }
    
    // GetLetterMessageResult (0x00FB)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetLetterMessageResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcGetLetterMessageResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetLetterMessageResult*>(p);
            FieldBuilder builder(emit);
            builder
                .Field("NextIndex", (int)pkt->NextIndex)
                .Field("Index", (int)pkt->Index)
                .Field("RequestKey", (int)pkt->RequestKey);
            
            // Show first 3 letters (limited for readability)
            const int maxShow = 3;
            for (int i = 0; i < maxShow && i < 5; ++i) {
                char prefix[64];
                snprintf(prefix, sizeof(prefix), "Letter[%d].", i);
                builder
                    .Hex(std::string(prefix) + "SenderID", pkt->LetterMessage[i].SenderCharacterID)
                    .Field(std::string(prefix) + "Type", (int)pkt->LetterMessage[i].Type)
                    .Field(std::string(prefix) + "IsRead", pkt->LetterMessage[i].IsRead ? "Yes" : "No")
                    .String(std::string(prefix) + "SenderName", pkt->LetterMessage[i].SenderCharacterName, 32);
            }
            if (5 > maxShow) {
                builder.Field("More", "+2 letters");
            }
        };
    }
    
    // GetLetterMessageDetailResult (0x00FC)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetLetterMessageDetailResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcGetLetterMessageDetailResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetLetterMessageDetailResult*>(p);
            FieldBuilder(emit)
                .Hex("SenderCharacterID", pkt->SenderCharacterID)
                .Field("Date", pkt->Date)
                .String("Message", pkt->Message, sizeof(pkt->Message));
        };
    }
    
    // GetLetterStatusResult (0x00FD)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGetLetterStatusResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcGetLetterStatusResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGetLetterStatusResult*>(p);
            FieldBuilder(emit)
                .Field("NoreceiveCount", pkt->NoreceiveCount)
                .Field("ItemCount", (int)pkt->ItemCount)
                .Field("UnreadCount", (int)pkt->UnreadCount)
                .Field("TotalCount", (int)pkt->TotalCount)
                .Field("GiftCount", (int)pkt->GiftCount)
                .Field("GmCount", (int)pkt->GmCount)
                .Field("UnreadGmCount", (int)pkt->UnreadGmCount)
                .Field("SupportCount", (int)pkt->SupportCount);
        };
    }

    // ================= P7 TIME / CONFIG / MISC BATCH =================
    
    // Config (0x02C6)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcConfig>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcConfig)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcConfig*>(p);
            FieldBuilder(emit)
                .Hex("flag", pkt->flag);
        };
    }
    
    // WeatherId (0x028A)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcWeatherId>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcWeatherId)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcWeatherId*>(p);
            FieldBuilder(emit)
                .Field("WeatherId", (int)pkt->WeatherId)
                .Field("TransitionTime", pkt->TransitionTime);
        };
    }
    
    // DiscoveryReply (0x028C)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcDiscoveryReply>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcDiscoveryReply)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcDiscoveryReply*>(p);
            FieldBuilder(emit)
                .Field("mapPartId", pkt->mapPartId)
                .Field("mapId", pkt->mapId);
        };
    }
    
    // OpenTreasure (0x01B8)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcOpenTreasure>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcOpenTreasure)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcOpenTreasure*>(p);
            FieldBuilder(emit)
                .Hex("ChestID", pkt->ChestID)
                .Field("ChestType", pkt->ChestType)
                .Field("Result", pkt->Result);
        };
    }

    // ================= P1 QUEST / EVENT SYSTEM =================
    
    // EventStart (opcode TBD)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcEventStart>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcEventStart)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcEventStart*>(p);
            FieldBuilder(emit)
                .Hex("targetId", pkt->targetId)
                .Hex("handlerId", pkt->handlerId)
                .Field("event", (int)pkt->event)
                .Hex("flags", pkt->flags)
                .Field("eventArg", pkt->eventArg);
        };
    }
    
    // EventFinish (opcode TBD)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcEventFinish>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcEventFinish)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcEventFinish*>(p);
            FieldBuilder(emit)
                .Hex("handlerId", pkt->handlerId)
                .Field("event", (int)pkt->event)
                .Field("result", (int)pkt->result)
                .Field("eventArg", pkt->eventArg);
        };
    }
    
    // Quests (opcode TBD) - Full active quest list
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcQuests>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcQuests)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcQuests*>(p);
            FieldBuilder builder(emit);
            
            // Count active quests and show first few
            int activeCount = 0;
            const int maxShow = 5;
            for (int i = 0; i < 30; ++i) {
                if (pkt->activeQuests[i].questId != 0) {
                    activeCount++;
                    if (activeCount <= maxShow) {
                        char prefix[64];
                        snprintf(prefix, sizeof(prefix), "Quest[%d]", i);
                        builder.Quest(prefix, pkt->activeQuests[i].questId);
                    }
                }
            }
            builder.Field("TotalActive", activeCount);
            if (activeCount > maxShow) {
                builder.Field("More", std::string("+") + std::to_string(activeCount - maxShow) + " quests");
            }
        };
    }
    
    // Quest (opcode TBD) - Single quest update
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcQuest>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcQuest)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcQuest*>(p);
            FieldBuilder(emit)
                .Field("index", (int)pkt->index)
                .Quest("Quest", pkt->questInfo.questId)
                .Hex("flags", pkt->questInfo.flags)
                .Field("a2", (int)pkt->questInfo.a2);
        };
    }
    
    // QuestCompleteList (opcode TBD) - Comprehensive completion mask
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcQuestCompleteList>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcQuestCompleteList)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcQuestCompleteList*>(p);
            
            // Count set bits in questCompleteMask
            int completedCount = 0;
            for (int i = 0; i < 310; ++i) {
                uint8_t byte = pkt->questCompleteMask[i];
                for (int bit = 0; bit < 8; ++bit) {
                    if (byte & (1 << bit)) completedCount++;
                }
            }
            
            FieldBuilder(emit)
                .Field("CompletedQuests", completedCount)
                .Field("TotalBits", 310 * 8);
        };
    }
    
    // QuestFinish (opcode TBD)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcQuestFinish>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcQuestFinish)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcQuestFinish*>(p);
            FieldBuilder(emit)
                .Quest("Quest", pkt->questId)
                .Hex("flag1", pkt->flag1)
                .Hex("flag2", pkt->flag2);
        };
    }
    
    // QuestTracker (opcode TBD) - UI quest tracker subset
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcQuestTracker>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcQuestTracker)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcQuestTracker*>(p);
            FieldBuilder builder(emit);
            
            int activeTrackers = 0;
            for (int i = 0; i < 5; ++i) {
                if (pkt->entry[i].active) {
                    activeTrackers++;
                    builder.Field(std::string("Tracker[") + std::to_string(i) + "].questIndex", (int)pkt->entry[i].questIndex);
                }
            }
            builder.Field("ActiveTrackers", activeTrackers);
        };
    }
    
    // LegacyQuestCompleteList (0x01F0) - Old format completion flags
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcLegacyQuestCompleteList>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcLegacyQuestCompleteList)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcLegacyQuestCompleteList*>(p);
            
            // Count set bits
            int completedCount = 0;
            for (int i = 0; i < 40; ++i) {
                uint8_t byte = pkt->completeFlagArray[i];
                for (int bit = 0; bit < 8; ++bit) {
                    if (byte & (1 << bit)) completedCount++;
                }
            }
            
            FieldBuilder(emit)
                .Field("CompletedQuests", completedCount)
                .Field("TotalBits", 40 * 8);
        };
    }
    
    // QuestRepeatFlags (0x0322)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcQuestRepeatFlags>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcQuestRepeatFlags)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcQuestRepeatFlags*>(p);
            FieldBuilder(emit)
                .Field("update", (int)pkt->update)
                .Field("repeatFlagArray[0]", FormatHex(pkt->repeatFlagArray[0]).c_str());
        };
    }
    
    // DailyQuests (0x0320)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcDailyQuests>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcDailyQuests)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcDailyQuests*>(p);
            FieldBuilder builder(emit);
            builder.Field("update", (int)pkt->update);
            
            // Show active daily quests (first 5)
            int activeCount = 0;
            const int maxShow = 5;
            for (int i = 0; i < 12; ++i) {
                if (pkt->dailyQuestArray[i].questId != 0) {
                    activeCount++;
                    if (activeCount <= maxShow) {
                        char prefix[64];
                        snprintf(prefix, sizeof(prefix), "Daily[%d].", i);
                        builder
                            .Field(std::string(prefix) + "questId", pkt->dailyQuestArray[i].questId)
                            .Hex(std::string(prefix) + "flags", pkt->dailyQuestArray[i].flags);
                    }
                }
            }
            builder.Field("ActiveDailies", activeCount);
            if (activeCount > maxShow) {
                builder.Field("More", std::string("+") + std::to_string(activeCount - maxShow) + " dailies");
            }
        };
    }

    // ================= P2 BATCH 6: LOOT / TREASURE REMAINDER =================
    
    // LootRight (0x01B9)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcLootRight>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcLootRight)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcLootRight*>(p);
            FieldBuilder(emit)
                .Hex("ChestID", pkt->ChestID)
                .Field("LootMode", (int)pkt->LootMode);
        };
    }
    
    // TreasureOpenRight (0x01BC)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcTreasureOpenRight>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcTreasureOpenRight)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcTreasureOpenRight*>(p);
            FieldBuilder builder(emit);
            builder.Hex("ChestID", pkt->ChestID);
            // Show up to 8 rights
            for (int i = 0; i < 8; ++i) {
                if (pkt->Rights[i] != 0) {
                    builder.Field(std::string("Right") + std::to_string(i), (int)pkt->Rights[i]);
                }
            }
        };
    }
    
    // OpenTreasureKeyUi (0x01BD)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcOpenTreasureKeyUi>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcOpenTreasureKeyUi)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcOpenTreasureKeyUi*>(p);
            FieldBuilder(emit)
                .Hex("ChestID", pkt->ChestID)
                .Field("RequiresKey", pkt->RequiresKey ? "Yes" : "No");
        };
    }
    
    // CreateTreasure (0x01BF)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcCreateTreasure>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcCreateTreasure)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcCreateTreasure*>(p);
            FieldBuilder(emit)
                .Hex("ChestID", pkt->ChestID)
                .Field("ChestType", (int)pkt->ChestType)
                .Position("Position", pkt->Position.x, pkt->Position.y, pkt->Position.z);
        };
    }
    
    // TreasureFadeOut (0x01C0)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcTreasureFadeOut>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcTreasureFadeOut)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcTreasureFadeOut*>(p);
            FieldBuilder(emit)
                .Hex("ChestID", pkt->ChestID);
        };
    }
    
    // LootItems (0x01BE)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcLootItems>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcLootItems)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcLootItems*>(p);
            FieldBuilder builder(emit);
            builder.Hex("ChestID", pkt->ChestID);
            
            // Show all 16 loot slots
            for (int i = 0; i < 16; ++i) {
                if (pkt->Items[i].ItemID != 0) {
                    std::string prefix = "Item" + std::to_string(i);
                    builder.Hex(prefix + "_ID", pkt->Items[i].ItemID)
                           .Field(prefix + "_Stack", pkt->Items[i].Stack)
                           .Field(prefix + "_Quality", (int)pkt->Items[i].Quality);
                }
            }
        };
    }
    
    // LootActionResult (0x01BA)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcLootActionResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcLootActionResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcLootActionResult*>(p);
            FieldBuilder(emit)
                .Hex("ChestID", pkt->ChestID)
                .Hex("ItemID", pkt->ItemID)
                .Field("Result", (int)pkt->Result)
                .Field("RolledValue", (int)pkt->RolledValue);
        };
    }
    
    // CatalogSearchResult (0x010C)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcCatalogSearchResult>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcCatalogSearchResult)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcCatalogSearchResult*>(p);
            FieldBuilder builder(emit);
            builder.Hex("NextIndex", pkt->NextIndex)
                   .Hex("Result", pkt->Result)
                   .Hex("Index", pkt->Index)
                   .Field("RequestKey", (int)pkt->RequestKey)
                   .Field("Type", (int)pkt->Type);
            
            // Show catalog entries
            for (int i = 0; i < 20; ++i) {
                if (pkt->CatalogList[i].CatalogID != 0) {
                    std::string prefix = "Catalog" + std::to_string(i);
                    builder.Item(prefix, pkt->CatalogList[i].CatalogID)
                           .Field(prefix + "_Stock", pkt->CatalogList[i].StockCount)
                           .Field(prefix + "_RequestCount", pkt->CatalogList[i].RequestItemCount);
                }
            }
        };
    }
    
    // GameLog (0x01BB)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcGameLog>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcGameLog)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcGameLog*>(p);
            FieldBuilder(emit)
                .Hex("MessageID", pkt->MessageID)
                .Hex("Category", pkt->Category)
                .Hex("Param1", pkt->Param1)
                .Hex("Param2", pkt->Param2)
                .Hex("Param3", pkt->Param3)
                .Hex("Param4", pkt->Param4)
                .Hex("Param5", pkt->Param5);
        };
    }
    
    // TradeCommand (0x01B4)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcTradeCommand>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcTradeCommand)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcTradeCommand*>(p);
            FieldBuilder(emit)
                .Hex("TradeID", pkt->TradeID)
                .Field("Type", (int)pkt->Type);
        };
    }
    
    // ItemMessage (0x01B5)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcItemMessage>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcItemMessage)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcItemMessage*>(p);
            FieldBuilder(emit)
                .Hex("ItemID", pkt->ItemID)
                .Field("Stack", pkt->Stack)
                .Field("Type", (int)pkt->Type);
        };
    }
    
    // AliasItem (0x01B7)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcAliasItem>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcAliasItem)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcAliasItem*>(p);
            FieldBuilder(emit)
                .Hex("ItemID", pkt->ItemID)
                .Hex("AliasID", pkt->AliasID);
        };
    }

    // ================= P6 OBJECT LIFECYCLE =================
    
    // DeleteObject (0x019E)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcDeleteObject>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcDeleteObject)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcDeleteObject*>(p);
            FieldBuilder(emit)
                .Field("Index", (int)pkt->Index);
        };
    }

    // ================= P7 CHARACTER STATE / CONFIG =================
    
    // Equip (0x01A5)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcEquip>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcEquip)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcEquip*>(p);
            FieldBuilder builder(emit);
            builder
                .Hex("MainWeapon", pkt->MainWeapon)
                .Hex("SubWeapon", pkt->SubWeapon)
                .Field("CrestEnable", (int)pkt->CrestEnable)
                .Hex("PatternInvalid", pkt->PatternInvalid);
            
            // Show first few equipment slots
            const int maxShow = 5;
            for (int i = 0; i < std::min(10, maxShow); ++i) {
                if (pkt->Equipment[i] != 0) {
                    builder.Hex(std::string("Equipment[") + std::to_string(i) + "]", pkt->Equipment[i]);
                }
            }
            if (10 > maxShow) {
                builder.Field("More", std::string("+") + std::to_string(10 - maxShow) + " slots");
            }
        };
    }
    
    // Inspect (0x01A6)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcInspect>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcInspect)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcInspect*>(p);
            FieldBuilder builder(emit);
            builder
                .Field("ObjType", (int)pkt->ObjType)
                .Field("Sex", (int)pkt->Sex)
                .ClassJob("ClassJob", pkt->ClassJob)
                .Field("Lv", (int)pkt->Lv)
                .Field("LvSync", (int)pkt->LvSync)
                .Hex("Title", pkt->Title)
                .GrandCompany("GrandCompany", pkt->GrandCompany)
                .Field("GrandCompanyRank", (int)pkt->GrandCompanyRank)
                .Field("Flag", (int)pkt->Flag)
                .Hex("Crest", pkt->Crest)
                .Field("CrestEnable", (int)pkt->CrestEnable)
                .Hex("MainWeaponModelId", pkt->MainWeaponModelId)
                .Hex("SubWeaponModelId", pkt->SubWeaponModelId)
                .Hex("PatternInvalid", pkt->PatternInvalid)
                .Field("Rank", (int)pkt->Rank)
                .Field("Exp", pkt->Exp)
                .Field("ItemLv", (int)pkt->ItemLv)
                .String("Name", pkt->Name, sizeof(pkt->Name));
            
            // Show first few equipment items (14 total)
            const int maxShow = 5;
            int shownCount = 0;
            for (int i = 0; i < 14 && shownCount < maxShow; ++i) {
                if (pkt->Equipment[i].CatalogId != 0) {
                    char prefix[64];
                    snprintf(prefix, sizeof(prefix), "Equipment[%d]", i);
                    builder
                        .Item(prefix, pkt->Equipment[i].CatalogId)
                        .Field(std::string(prefix) + ".HQ", pkt->Equipment[i].HQ ? "Yes" : "No")
                        .Field(std::string(prefix) + ".Stain", (int)pkt->Equipment[i].Stain);
                    shownCount++;
                }
            }
            if (shownCount >= maxShow && shownCount < 14) {
                builder.Field("MoreEquipment", std::string("+") + std::to_string(14 - shownCount) + " items");
            }
        };
    }

    // ================= MISSED REGULAR PACKETS (DOCUMENTED BUT NOT WIRED) =================
    
    // MoveTerritory (0x006A)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMoveTerritory>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcMoveTerritory)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcMoveTerritory*>(p);
            FieldBuilder(emit)
                .Field("index", pkt->index)
                .Territory("Territory", pkt->territoryType)
                .Field("zoneId", (int)pkt->zoneId)
                .Hex("worldId", pkt->worldId)
                .Hex("landSetId", pkt->landSetId)
                .Hex("landId", pkt->landId)
                .String("worldName", pkt->worldName, sizeof(pkt->worldName));
        };
    }
    
    // MoveInstance (0x006B)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMoveInstance>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcMoveInstance)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcMoveInstance*>(p);
            FieldBuilder(emit)
                .Hex("characterId", pkt->characterId)
                .Hex("entityId", pkt->entityId)
                .Hex("worldId", pkt->worldId);
        };
    }
    
    // MonsterNoteCategory (0x01C1)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMonsterNoteCategory>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcMonsterNoteCategory)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcMonsterNoteCategory*>(p);
            FieldBuilder(emit)
                .Field("contextId", pkt->contextId)
                .Field("currentRank", (int)pkt->currentRank)
                .Field("categoryIndex", (int)pkt->categoryIndex)
                // Note: killCount[40] array omitted for brevity
                .Field("completeFlags", pkt->completeFlags)
                .Field("isNewFlags", pkt->isNewFlags);
        };
    }
    
    // ChangeClass (0x01A4)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcChangeClass>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcChangeClass)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcChangeClass*>(p);
            FieldBuilder builder(emit);
            builder
                .ClassJob("ClassJob", pkt->ClassJob)
                .Field("Penalty", (int)pkt->Penalty)
                .Field("Login", (int)pkt->Login)
                .Field("Lv1", pkt->Lv1)
                .Field("Lv", pkt->Lv);
            
            // Show first few borrow actions
            int activeActions = 0;
            for (int i = 0; i < 10; ++i) {
                if (pkt->BorrowAction[i] != 0 && activeActions < 3) {
                    builder.Hex(std::string("BorrowAction[") + std::to_string(i) + "]", pkt->BorrowAction[i]);
                    activeActions++;
                }
            }
            if (activeActions >= 3) builder.Field("MoreActions", "...");
            
            // Show physical bonuses
            for (int i = 0; i < 6; ++i) {
                builder.Field(std::string("PhysicalBonus[") + std::to_string(i) + "]", (int)pkt->PhysicalBonus[i]);
            }
        };
    }
    
    // FirstAttack (0x01A2)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcFirstAttack>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcFirstAttack)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcFirstAttack*>(p);
            FieldBuilder(emit)
                .Field("Type", (int)pkt->Type)
                .Hex("Id", pkt->Id);
        };
    }
    
    // Condition (0x01A3)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcCondition>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcCondition)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcCondition*>(p);
            FieldBuilder builder(emit);
            
            // Count set flags
            int setFlags = 0;
            for (int i = 0; i < 12; ++i) {
                if (pkt->flags[i] != 0) setFlags++;
            }
            builder.Field("SetFlags", setFlags);
            
            // Show first few non-zero flags
            int shown = 0;
            for (int i = 0; i < 12 && shown < 5; ++i) {
                if (pkt->flags[i] != 0) {
                    builder.Field(std::string("flags[") + std::to_string(i) + "]", (int)pkt->flags[i]);
                    shown++;
                }
            }
        };
    }
    
    // PlayerStatusUpdate (0x019F)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcPlayerStatusUpdate>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcPlayerStatusUpdate)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcPlayerStatusUpdate*>(p);
            FieldBuilder(emit)
                .ClassJob("ClassJob", pkt->ClassJob)
                .Field("Lv", pkt->Lv)
                .Field("Lv1", pkt->Lv1)
                .Field("LvSync", pkt->LvSync)
                .Field("Exp", pkt->Exp)
                .Field("RestPoint", pkt->RestPoint);
        };
    }
    
    // CreateObject (0x019D)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcCreateObject>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcCreateObject)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcCreateObject*>(p);
            FieldBuilder(emit)
                .Field("Index", (int)pkt->Index)
                .ObjKind("Kind", pkt->Kind)
                .Field("Flag", (int)pkt->Flag)
                .Hex("BaseId", pkt->BaseId)
                .Hex("EntityId", pkt->EntityId)
                .Hex("LayoutId", pkt->LayoutId)
                .Hex("ContentId", pkt->ContentId)
                .Hex("OwnerId", pkt->OwnerId)
                .Field("Scale", pkt->Scale)
                .Hex("FATE", pkt->FATE)
                .Position("Pos", pkt->Pos.x, pkt->Pos.y, pkt->Pos.z);
        };
    }
    
    // Name (0x01A7)
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcName>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcName)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcName*>(p);
            FieldBuilder(emit)
                .Hex("contentId", pkt->contentId)
                .String("name", pkt->name, sizeof(pkt->name));
        };
    }
    
    // FreeCompany (0x0149) - Not FreeCompanyResult!
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcFreeCompany>() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcFreeCompany)) { emit("error", "Packet too small"); return; }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcFreeCompany*>(p);
            FieldBuilder(emit)
                .Hex("Crest", pkt->Crest)
                .String("Tag", pkt->Tag, sizeof(pkt->Tag));
        };
    }

    // ============================================================================
    // TEMPLATE FAMILY DECODERS
    // ============================================================================
    // See docs/TEMPLATE_FAMILY_STRATEGY.md for implementation rationale

    // MapMarkerN - Map marker updates with variable icon/layout/handler arrays
    template<int ArgCount>
    DecoderFunc MakeGenericDecoder_MapMarkerN() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcMapMarkerN<ArgCount>)) { 
                emit("error", "Packet too small"); 
                return; 
            }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcMapMarkerN<ArgCount>*>(p);
            
            int count = std::min((int)pkt->numOfMarkers, ArgCount);
            std::ostringstream iconIds, layoutIds, handlerIds;
            for (int i = 0; i < count; ++i) {
                if (i > 0) {
                    iconIds << ", ";
                    layoutIds << ", ";
                    handlerIds << ", ";
                }
                iconIds << pkt->iconIds[i];
                layoutIds << pkt->layoutIds[i];
                handlerIds << pkt->handlerIds[i];
            }
            
            FieldBuilder(emit)
                .Field("numOfMarkers", (int)pkt->numOfMarkers)
                .Field("iconIds", iconIds.str())
                .Field("layoutIds", layoutIds.str())
                .Field("handlerIds", handlerIds.str());
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<2>>() { return MakeGenericDecoder_MapMarkerN<2>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<4>>() { return MakeGenericDecoder_MapMarkerN<4>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<8>>() { return MakeGenericDecoder_MapMarkerN<8>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<16>>() { return MakeGenericDecoder_MapMarkerN<16>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<32>>() { return MakeGenericDecoder_MapMarkerN<32>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<64>>() { return MakeGenericDecoder_MapMarkerN<64>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<128>>() { return MakeGenericDecoder_MapMarkerN<128>(); }

    // BattleTalkN - Battle dialogue with variable arguments
    template<int ArgCount>
    DecoderFunc MakeGenericDecoder_BattleTalkN() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcBattleTalkN<ArgCount>)) { 
                emit("error", "Packet too small"); 
                return; 
            }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcBattleTalkN<ArgCount>*>(p);
            
            int count = std::min((int)pkt->numOfArgs, ArgCount);
            std::ostringstream args;
            for (int i = 0; i < count; ++i) {
                if (i > 0) args << ", ";
                args << pkt->args[i];
            }
            
            FieldBuilder(emit)
                .Field("handlerId", pkt->handlerId)
                .Field("talkerId", pkt->talkerId)
                .Field("kind", (int)pkt->kind)
                .Field("nameId", pkt->nameId)
                .Field("battleTalkId", pkt->battleTalkId)
                .Field("time", pkt->time)
                .Field("numOfArgs", (int)pkt->numOfArgs)
                .Field("args", args.str());
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcBattleTalkN<2>>() { return MakeGenericDecoder_BattleTalkN<2>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcBattleTalkN<4>>() { return MakeGenericDecoder_BattleTalkN<4>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcBattleTalkN<8>>() { return MakeGenericDecoder_BattleTalkN<8>(); }

    // EventLogMessageN - Event log messages with variable parameters
    template<int ArgCount>
    DecoderFunc MakeGenericDecoder_EventLogMessageN() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcEventLogMessageN<ArgCount>)) { 
                emit("error", "Packet too small"); 
                return; 
            }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcEventLogMessageN<ArgCount>*>(p);
            
            int count = std::min((int)pkt->numOfArgs, ArgCount);
            std::ostringstream args;
            for (int i = 0; i < count; ++i) {
                if (i > 0) args << ", ";
                args << pkt->args[i];
            }
            
            FieldBuilder(emit)
                .Field("handlerId", pkt->handlerId)
                .Field("messageId", pkt->messageId)
                .Field("numOfArgs", (int)pkt->numOfArgs)
                .Field("args", args.str());
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcEventLogMessageN<2>>() { return MakeGenericDecoder_EventLogMessageN<2>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcEventLogMessageN<4>>() { return MakeGenericDecoder_EventLogMessageN<4>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcEventLogMessageN<8>>() { return MakeGenericDecoder_EventLogMessageN<8>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcEventLogMessageN<16>>() { return MakeGenericDecoder_EventLogMessageN<16>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcEventLogMessageN<32>>() { return MakeGenericDecoder_EventLogMessageN<32>(); }

    // UpdateEventSceneN - Event scene updates with variable arguments
    template<int ArgCount>
    DecoderFunc MakeGenericDecoder_UpdateEventSceneN() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcUpdateEventSceneN<ArgCount>)) { 
                emit("error", "Packet too small"); 
                return; 
            }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcUpdateEventSceneN<ArgCount>*>(p);
            
            int count = std::min((int)pkt->numOfArgs, ArgCount);
            std::ostringstream args;
            for (int i = 0; i < count; ++i) {
                if (i > 0) args << ", ";
                args << pkt->args[i];
            }
            
            FieldBuilder(emit)
                .Field("handlerId", pkt->handlerId)
                .Field("sceneId", pkt->sceneId)
                .Field("numOfArgs", (int)pkt->numOfArgs)
                .Field("args", args.str());
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcUpdateEventSceneN<2>>() { return MakeGenericDecoder_UpdateEventSceneN<2>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcUpdateEventSceneN<4>>() { return MakeGenericDecoder_UpdateEventSceneN<4>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcUpdateEventSceneN<8>>() { return MakeGenericDecoder_UpdateEventSceneN<8>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcUpdateEventSceneN<16>>() { return MakeGenericDecoder_UpdateEventSceneN<16>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcUpdateEventSceneN<32>>() { return MakeGenericDecoder_UpdateEventSceneN<32>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcUpdateEventSceneN<64>>() { return MakeGenericDecoder_UpdateEventSceneN<64>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcUpdateEventSceneN<128>>() { return MakeGenericDecoder_UpdateEventSceneN<128>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcUpdateEventSceneN<255>>() { return MakeGenericDecoder_UpdateEventSceneN<255>(); }

    // ResumeEventSceneN - Event scene resumption with variable arguments
    template<int ArgCount>
    DecoderFunc MakeGenericDecoder_ResumeEventSceneN() {
        return [](const uint8_t* p, size_t l, RowEmitter emit) {
            if (l < sizeof(ServerZone::FFXIVIpcResumeEventSceneN<ArgCount>)) { 
                emit("error", "Packet too small"); 
                return; 
            }
            auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcResumeEventSceneN<ArgCount>*>(p);
            
            int count = std::min((int)pkt->numOfArgs, ArgCount);
            std::ostringstream args;
            for (int i = 0; i < count; ++i) {
                if (i > 0) args << ", ";
                args << pkt->args[i];
            }
            
            FieldBuilder(emit)
                .Field("handlerId", pkt->handlerId)
                .Field("sceneId", pkt->sceneId)
                .Field("resumeId", (int)pkt->resumeId)
                .Field("numOfArgs", (int)pkt->numOfArgs)
                .Field("args", args.str());
        };
    }

    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcResumeEventSceneN<2>>() { return MakeGenericDecoder_ResumeEventSceneN<2>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcResumeEventSceneN<4>>() { return MakeGenericDecoder_ResumeEventSceneN<4>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcResumeEventSceneN<8>>() { return MakeGenericDecoder_ResumeEventSceneN<8>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcResumeEventSceneN<16>>() { return MakeGenericDecoder_ResumeEventSceneN<16>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcResumeEventSceneN<32>>() { return MakeGenericDecoder_ResumeEventSceneN<32>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcResumeEventSceneN<64>>() { return MakeGenericDecoder_ResumeEventSceneN<64>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcResumeEventSceneN<128>>() { return MakeGenericDecoder_ResumeEventSceneN<128>(); }
    template<> DecoderFunc MakeGenericDecoder<ServerZone::FFXIVIpcResumeEventSceneN<255>>() { return MakeGenericDecoder_ResumeEventSceneN<255>(); }

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
    r.RegisterDecoder(1, false, 0x010C, MakeGenericDecoder<ServerZone::FFXIVIpcCatalogSearchResult>());
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

    // P2 Batch 6: Loot/Treasure/Trade packets
    r.RegisterDecoder(1, false, 0x01B9, MakeGenericDecoder<ServerZone::FFXIVIpcLootRight>());
    r.RegisterDecoder(1, false, 0x01BA, MakeGenericDecoder<ServerZone::FFXIVIpcLootActionResult>());
    r.RegisterDecoder(1, false, 0x01BC, MakeGenericDecoder<ServerZone::FFXIVIpcTreasureOpenRight>());
    r.RegisterDecoder(1, false, 0x01BD, MakeGenericDecoder<ServerZone::FFXIVIpcOpenTreasureKeyUi>());
    r.RegisterDecoder(1, false, 0x01BE, MakeGenericDecoder<ServerZone::FFXIVIpcLootItems>());
    r.RegisterDecoder(1, false, 0x01BF, MakeGenericDecoder<ServerZone::FFXIVIpcCreateTreasure>());
    r.RegisterDecoder(1, false, 0x01C0, MakeGenericDecoder<ServerZone::FFXIVIpcTreasureFadeOut>());
    r.RegisterDecoder(1, false, 0x01BB, MakeGenericDecoder<ServerZone::FFXIVIpcGameLog>());
    r.RegisterDecoder(1, false, 0x01B4, MakeGenericDecoder<ServerZone::FFXIVIpcTradeCommand>());
    r.RegisterDecoder(1, false, 0x01B5, MakeGenericDecoder<ServerZone::FFXIVIpcItemMessage>());
    r.RegisterDecoder(1, false, 0x01B7, MakeGenericDecoder<ServerZone::FFXIVIpcAliasItem>());

    // P3 – Free Company Extended (11 packets)
    r.RegisterDecoder(1, false, 0x010F, MakeGenericDecoder<ServerZone::FFXIVIpcGetFcStatusResult>());
    r.RegisterDecoder(1, false, 0x0110, MakeGenericDecoder<ServerZone::FFXIVIpcGetFcInviteListResult>());
    r.RegisterDecoder(1, false, 0x0111, MakeGenericDecoder<ServerZone::FFXIVIpcGetFcProfileResult>());
    r.RegisterDecoder(1, false, 0x0112, MakeGenericDecoder<ServerZone::FFXIVIpcGetFcHeaderResult>());
    r.RegisterDecoder(1, false, 0x0113, MakeGenericDecoder<ServerZone::FFXIVIpcGetCompanyBoardResult>());
    r.RegisterDecoder(1, false, 0x0114, MakeGenericDecoder<ServerZone::FFXIVIpcGetFcHierarchyResult>());
    r.RegisterDecoder(1, false, 0x0116, MakeGenericDecoder<ServerZone::FFXIVIpcGetFcHierarchyLiteResult>());
    r.RegisterDecoder(1, false, 0x0117, MakeGenericDecoder<ServerZone::FFXIVIpcGetCompanyMottoResult>());
    r.RegisterDecoder(1, false, 0x0118, MakeGenericDecoder<ServerZone::FFXIVIpcGetFcParamsResult>());
    r.RegisterDecoder(1, false, 0x0119, MakeGenericDecoder<ServerZone::FFXIVIpcGetFcActionResult>());
    r.RegisterDecoder(1, false, 0x011A, MakeGenericDecoder<ServerZone::FFXIVIpcGetFcMemoResult>());

    // P5 – Mail/Letters (4 packets)
    r.RegisterDecoder(1, false, 0x00FA, MakeGenericDecoder<ServerZone::FFXIVIpcLetterResult>());
    r.RegisterDecoder(1, false, 0x00FB, MakeGenericDecoder<ServerZone::FFXIVIpcGetLetterMessageResult>());
    r.RegisterDecoder(1, false, 0x00FC, MakeGenericDecoder<ServerZone::FFXIVIpcGetLetterMessageDetailResult>());
    r.RegisterDecoder(1, false, 0x00FD, MakeGenericDecoder<ServerZone::FFXIVIpcGetLetterStatusResult>());

    // P7 – Time/Config/Misc (3 packets - OpenTreasure packets already in P2 Batch 6)
    r.RegisterDecoder(1, false, 0x02C6, MakeGenericDecoder<ServerZone::FFXIVIpcConfig>());
    r.RegisterDecoder(1, false, 0x028A, MakeGenericDecoder<ServerZone::FFXIVIpcWeatherId>());
    r.RegisterDecoder(1, false, 0x028C, MakeGenericDecoder<ServerZone::FFXIVIpcDiscoveryReply>());

    // P1 – Quest/Event System (3 packets with opcodes, 7 decoders ready for when opcodes are found)
    r.RegisterDecoder(1, false, 0x01F0, MakeGenericDecoder<ServerZone::FFXIVIpcLegacyQuestCompleteList>());
    r.RegisterDecoder(1, false, 0x0322, MakeGenericDecoder<ServerZone::FFXIVIpcQuestRepeatFlags>());
    r.RegisterDecoder(1, false, 0x0320, MakeGenericDecoder<ServerZone::FFXIVIpcDailyQuests>());
    // Note: EventStart, EventFinish, Quests, Quest, QuestCompleteList, QuestFinish, QuestTracker
    // have decoders implemented but need opcode discovery before registration

    // P6 – Object Lifecycle (1 packet)
    r.RegisterDecoder(1, false, 0x019E, MakeGenericDecoder<ServerZone::FFXIVIpcDeleteObject>());

    // P7 – Character State / Config (2 packets)
    r.RegisterDecoder(1, false, 0x01A5, MakeGenericDecoder<ServerZone::FFXIVIpcEquip>());
    r.RegisterDecoder(1, false, 0x01A6, MakeGenericDecoder<ServerZone::FFXIVIpcInspect>());

    // Missed Regular Packets (documented but not wired - 10 packets)
    r.RegisterDecoder(1, false, 0x006A, MakeGenericDecoder<ServerZone::FFXIVIpcMoveTerritory>());
    r.RegisterDecoder(1, false, 0x006B, MakeGenericDecoder<ServerZone::FFXIVIpcMoveInstance>());
    r.RegisterDecoder(1, false, 0x01C1, MakeGenericDecoder<ServerZone::FFXIVIpcMonsterNoteCategory>());
    r.RegisterDecoder(1, false, 0x01A4, MakeGenericDecoder<ServerZone::FFXIVIpcChangeClass>());
    r.RegisterDecoder(1, false, 0x01A2, MakeGenericDecoder<ServerZone::FFXIVIpcFirstAttack>());
    r.RegisterDecoder(1, false, 0x01A3, MakeGenericDecoder<ServerZone::FFXIVIpcCondition>());
    r.RegisterDecoder(1, false, 0x019F, MakeGenericDecoder<ServerZone::FFXIVIpcPlayerStatusUpdate>());
    r.RegisterDecoder(1, false, 0x019D, MakeGenericDecoder<ServerZone::FFXIVIpcCreateObject>());
    r.RegisterDecoder(1, false, 0x01A7, MakeGenericDecoder<ServerZone::FFXIVIpcName>());
    r.RegisterDecoder(1, false, 0x0149, MakeGenericDecoder<ServerZone::FFXIVIpcFreeCompany>());

    // Template Families - Variable-length array packets (31 total registrations)
    // See docs/TEMPLATE_FAMILY_STRATEGY.md for implementation details

    // MapMarkerN (7 variants: 2, 4, 8, 16, 32, 64, 128)
    r.RegisterDecoder(1, false, 0x026D, MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<2>>());
    r.RegisterDecoder(1, false, 0x026E, MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<4>>());
    r.RegisterDecoder(1, false, 0x026F, MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<8>>());
    r.RegisterDecoder(1, false, 0x0270, MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<16>>());
    r.RegisterDecoder(1, false, 0x0271, MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<32>>());
    r.RegisterDecoder(1, false, 0x0272, MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<64>>());
    r.RegisterDecoder(1, false, 0x0273, MakeGenericDecoder<ServerZone::FFXIVIpcMapMarkerN<128>>());

    // BattleTalkN (3 variants: 2, 4, 8)
    r.RegisterDecoder(1, false, 0x0263, MakeGenericDecoder<ServerZone::FFXIVIpcBattleTalkN<2>>());
    r.RegisterDecoder(1, false, 0x0264, MakeGenericDecoder<ServerZone::FFXIVIpcBattleTalkN<4>>());
    r.RegisterDecoder(1, false, 0x0265, MakeGenericDecoder<ServerZone::FFXIVIpcBattleTalkN<8>>());

    // EventLogMessageN (5 variants: 2, 4, 8, 16, 32)
    r.RegisterDecoder(1, false, 0x0259, MakeGenericDecoder<ServerZone::FFXIVIpcEventLogMessageN<2>>());
    r.RegisterDecoder(1, false, 0x025A, MakeGenericDecoder<ServerZone::FFXIVIpcEventLogMessageN<4>>());
    r.RegisterDecoder(1, false, 0x025B, MakeGenericDecoder<ServerZone::FFXIVIpcEventLogMessageN<8>>());
    r.RegisterDecoder(1, false, 0x025C, MakeGenericDecoder<ServerZone::FFXIVIpcEventLogMessageN<16>>());
    r.RegisterDecoder(1, false, 0x025D, MakeGenericDecoder<ServerZone::FFXIVIpcEventLogMessageN<32>>());

    // UpdateEventSceneN (8 variants: 2, 4, 8, 16, 32, 64, 128, 255)
    r.RegisterDecoder(1, false, 0x01CF, MakeGenericDecoder<ServerZone::FFXIVIpcUpdateEventSceneN<2>>());
    r.RegisterDecoder(1, false, 0x01D0, MakeGenericDecoder<ServerZone::FFXIVIpcUpdateEventSceneN<4>>());
    r.RegisterDecoder(1, false, 0x01D1, MakeGenericDecoder<ServerZone::FFXIVIpcUpdateEventSceneN<8>>());
    r.RegisterDecoder(1, false, 0x01D2, MakeGenericDecoder<ServerZone::FFXIVIpcUpdateEventSceneN<16>>());
    r.RegisterDecoder(1, false, 0x01D3, MakeGenericDecoder<ServerZone::FFXIVIpcUpdateEventSceneN<32>>());
    r.RegisterDecoder(1, false, 0x01D4, MakeGenericDecoder<ServerZone::FFXIVIpcUpdateEventSceneN<64>>());
    r.RegisterDecoder(1, false, 0x01D5, MakeGenericDecoder<ServerZone::FFXIVIpcUpdateEventSceneN<128>>());
    r.RegisterDecoder(1, false, 0x01D6, MakeGenericDecoder<ServerZone::FFXIVIpcUpdateEventSceneN<255>>());

    // ResumeEventSceneN (8 variants: 2, 4, 8, 16, 32, 64, 128, 255)
    r.RegisterDecoder(1, false, 0x01D8, MakeGenericDecoder<ServerZone::FFXIVIpcResumeEventSceneN<2>>());
    r.RegisterDecoder(1, false, 0x01D9, MakeGenericDecoder<ServerZone::FFXIVIpcResumeEventSceneN<4>>());
    r.RegisterDecoder(1, false, 0x01DA, MakeGenericDecoder<ServerZone::FFXIVIpcResumeEventSceneN<8>>());
    r.RegisterDecoder(1, false, 0x01DB, MakeGenericDecoder<ServerZone::FFXIVIpcResumeEventSceneN<16>>());
    r.RegisterDecoder(1, false, 0x01DC, MakeGenericDecoder<ServerZone::FFXIVIpcResumeEventSceneN<32>>());
    r.RegisterDecoder(1, false, 0x01DD, MakeGenericDecoder<ServerZone::FFXIVIpcResumeEventSceneN<64>>());
    r.RegisterDecoder(1, false, 0x01DE, MakeGenericDecoder<ServerZone::FFXIVIpcResumeEventSceneN<128>>());
    r.RegisterDecoder(1, false, 0x01DF, MakeGenericDecoder<ServerZone::FFXIVIpcResumeEventSceneN<255>>());
}
