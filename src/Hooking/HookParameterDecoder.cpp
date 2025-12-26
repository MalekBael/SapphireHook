#include "HookParameterDecoder.h"
#include "../Core/GameDataLookup.h"
#include "../Core/SafeMemory.h"
#include <format>
#include <unordered_map>
#include <mutex>
#include <cstring>
#include <bit>

namespace SapphireHook {

// ============================================================================
// Static Registry for Known Signatures
// ============================================================================

namespace {
    std::mutex s_signatureMutex;
    std::unordered_map<std::string, FunctionSignature> s_signatures;
    std::unordered_map<uintptr_t, std::string> s_addressToSignature;
    
    std::string MakeKey(const std::string& className, const std::string& funcName) {
        return className + "::" + funcName;
    }
}

// ============================================================================
// ParamType ToString
// ============================================================================

const char* ToString(ParamType type) {
    switch (type) {
        case ParamType::Unknown: return "Unknown";
        case ParamType::Int8: return "Int8";
        case ParamType::Int16: return "Int16";
        case ParamType::Int32: return "Int32";
        case ParamType::Int64: return "Int64";
        case ParamType::UInt8: return "UInt8";
        case ParamType::UInt16: return "UInt16";
        case ParamType::UInt32: return "UInt32";
        case ParamType::UInt64: return "UInt64";
        case ParamType::Float: return "Float";
        case ParamType::Double: return "Double";
        case ParamType::Pointer: return "Pointer";
        case ParamType::String: return "String";
        case ParamType::Bool: return "Bool";
        case ParamType::ItemId: return "ItemId";
        case ParamType::ActionId: return "ActionId";
        case ParamType::StatusId: return "StatusId";
        case ParamType::TerritoryId: return "TerritoryId";
        case ParamType::ClassJobId: return "ClassJobId";
        case ParamType::BNpcId: return "BNpcId";
        case ParamType::ENpcId: return "ENpcId";
        case ParamType::FateId: return "FateId";
        case ParamType::QuestId: return "QuestId";
        case ParamType::AchievementId: return "AchievementId";
        case ParamType::MountId: return "MountId";
        case ParamType::MinionId: return "MinionId";
        case ParamType::EmoteId: return "EmoteId";
        case ParamType::PlaceNameId: return "PlaceNameId";
        case ParamType::WorldId: return "WorldId";
        case ParamType::AetheryteId: return "AetheryteId";
        case ParamType::ContentFinderConditionId: return "ContentFinderConditionId";
        case ParamType::WeatherId: return "WeatherId";
        case ParamType::EntityId: return "EntityId";
        case ParamType::ContentId: return "ContentId";
        case ParamType::ActorId: return "ActorId";
        case ParamType::Position3D: return "Position3D";
        case ParamType::Quaternion: return "Quaternion";
        case ParamType::Color: return "Color";
        case ParamType::Timestamp: return "Timestamp";
        case ParamType::BitFlags: return "BitFlags";
        default: return "Unknown";
    }
}

// ============================================================================
// DecodedParam Static Constructors
// ============================================================================

DecodedParam DecodedParam::FromInt(const std::string& name, int64_t value) {
    DecodedParam p;
    p.type = ParamType::Int64;
    p.name = name;
    p.rawValue = static_cast<uint64_t>(value);
    p.displayValue = std::to_string(value);
    p.isValid = true;
    return p;
}

DecodedParam DecodedParam::FromUInt(const std::string& name, uint64_t value) {
    DecodedParam p;
    p.type = ParamType::UInt64;
    p.name = name;
    p.rawValue = value;
    p.displayValue = std::format("{} (0x{:X})", value, value);
    p.isValid = true;
    return p;
}

DecodedParam DecodedParam::FromFloat(const std::string& name, float value) {
    DecodedParam p;
    p.type = ParamType::Float;
    p.name = name;
    p.rawValue = std::bit_cast<uint32_t>(value);
    p.displayValue = std::format("{:.4f}", value);
    p.isValid = true;
    return p;
}

DecodedParam DecodedParam::FromPointer(const std::string& name, void* ptr) {
    DecodedParam p;
    p.type = ParamType::Pointer;
    p.name = name;
    p.rawValue = reinterpret_cast<uint64_t>(ptr);
    if (ptr == nullptr) {
        p.displayValue = "nullptr";
    } else {
        p.displayValue = std::format("0x{:016X}", p.rawValue);
    }
    p.isValid = true;
    return p;
}

DecodedParam DecodedParam::FromItemId(const std::string& name, uint32_t itemId) {
    DecodedParam p;
    p.type = ParamType::ItemId;
    p.name = name;
    p.rawValue = itemId;
    
    if (const char* itemName = GameData::LookupItemName(itemId)) {
        p.gameName = itemName;
        p.displayValue = std::format("{} (ID: {})", itemName, itemId);
        p.isValid = true;
    } else {
        p.displayValue = std::format("Item #{}", itemId);
        p.isValid = itemId > 0;
    }
    return p;
}

DecodedParam DecodedParam::FromActionId(const std::string& name, uint32_t actionId) {
    DecodedParam p;
    p.type = ParamType::ActionId;
    p.name = name;
    p.rawValue = actionId;
    
    if (const char* actionName = GameData::LookupActionName(actionId)) {
        p.gameName = actionName;
        p.displayValue = std::format("{} (ID: {})", actionName, actionId);
        p.isValid = true;
    } else {
        p.displayValue = std::format("Action #{}", actionId);
        p.isValid = actionId > 0;
    }
    return p;
}

DecodedParam DecodedParam::FromStatusId(const std::string& name, uint32_t statusId) {
    DecodedParam p;
    p.type = ParamType::StatusId;
    p.name = name;
    p.rawValue = statusId;
    
    if (const char* statusName = GameData::LookupStatusName(statusId)) {
        p.gameName = statusName;
        p.displayValue = std::format("{} (ID: {})", statusName, statusId);
        p.isValid = true;
    } else {
        p.displayValue = std::format("Status #{}", statusId);
        p.isValid = statusId > 0;
    }
    return p;
}

DecodedParam DecodedParam::FromTerritoryId(const std::string& name, uint32_t territoryId) {
    DecodedParam p;
    p.type = ParamType::TerritoryId;
    p.name = name;
    p.rawValue = territoryId;
    
    if (const char* zoneName = GameData::LookupTerritoryName(territoryId)) {
        p.gameName = zoneName;
        p.displayValue = std::format("{} (ID: {})", zoneName, territoryId);
        p.isValid = true;
    } else {
        p.displayValue = std::format("Zone #{}", territoryId);
        p.isValid = territoryId > 0;
    }
    return p;
}

DecodedParam DecodedParam::FromClassJobId(const std::string& name, uint8_t classJobId) {
    DecodedParam p;
    p.type = ParamType::ClassJobId;
    p.name = name;
    p.rawValue = classJobId;
    
    if (const char* jobName = GameData::LookupClassJobName(classJobId)) {
        p.gameName = jobName;
        p.displayValue = std::format("{} (ID: {})", jobName, classJobId);
        p.isValid = true;
    } else {
        p.displayValue = std::format("ClassJob #{}", classJobId);
        p.isValid = classJobId > 0;
    }
    return p;
}

DecodedParam DecodedParam::FromEntityId(const std::string& name, uint32_t entityId) {
    DecodedParam p;
    p.type = ParamType::EntityId;
    p.name = name;
    p.rawValue = entityId;
    
    // Classify entity ID by range
    if (entityId >= 0x10000000 && entityId < 0x20000000) {
        p.details = "Player/Party";
    } else if (entityId >= 0x40000000 && entityId < 0x50000000) {
        p.details = "NPC/Object";
    } else if (entityId >= 0xE0000000) {
        p.details = "Environment";
    }
    
    p.displayValue = std::format("0x{:08X}", entityId);
    if (!p.details.empty()) {
        p.displayValue += " (" + p.details + ")";
    }
    p.isValid = entityId != 0 && entityId != 0xE0000000;
    return p;
}

// ============================================================================
// Main Decoding Functions
// ============================================================================

DecodedParam HookParameterDecoder::DecodeParameter(ParamType type, uint64_t rawValue, const std::string& name) {
    switch (type) {
        case ParamType::Int8:
        case ParamType::Int16:
        case ParamType::Int32:
        case ParamType::Int64:
            return DecodedParam::FromInt(name, static_cast<int64_t>(rawValue));
            
        case ParamType::UInt8:
        case ParamType::UInt16:
        case ParamType::UInt32:
        case ParamType::UInt64:
            return DecodedParam::FromUInt(name, rawValue);
            
        case ParamType::Float:
            return DecodedParam::FromFloat(name, std::bit_cast<float>(static_cast<uint32_t>(rawValue)));
            
        case ParamType::Pointer:
            return DecodedParam::FromPointer(name, reinterpret_cast<void*>(rawValue));
            
        case ParamType::Bool: {
            DecodedParam p;
            p.type = ParamType::Bool;
            p.name = name;
            p.rawValue = rawValue;
            p.displayValue = rawValue ? "true" : "false";
            p.isValid = true;
            return p;
        }
            
        case ParamType::ItemId:
            return DecodedParam::FromItemId(name, static_cast<uint32_t>(rawValue));
            
        case ParamType::ActionId:
            return DecodedParam::FromActionId(name, static_cast<uint32_t>(rawValue));
            
        case ParamType::StatusId:
            return DecodedParam::FromStatusId(name, static_cast<uint32_t>(rawValue));
            
        case ParamType::TerritoryId:
            return DecodedParam::FromTerritoryId(name, static_cast<uint32_t>(rawValue));
            
        case ParamType::ClassJobId:
            return DecodedParam::FromClassJobId(name, static_cast<uint8_t>(rawValue));
            
        case ParamType::EntityId:
        case ParamType::ActorId:
            return DecodedParam::FromEntityId(name, static_cast<uint32_t>(rawValue));
            
        // Additional game data types
        case ParamType::BNpcId: {
            DecodedParam p;
            p.type = type;
            p.name = name;
            p.rawValue = rawValue;
            if (const char* n = GameData::LookupBNpcName(static_cast<uint32_t>(rawValue))) {
                p.gameName = n;
                p.displayValue = std::format("{} (ID: {})", n, rawValue);
                p.isValid = true;
            } else {
                p.displayValue = std::format("BNpc #{}", rawValue);
            }
            return p;
        }
        
        case ParamType::ENpcId: {
            DecodedParam p;
            p.type = type;
            p.name = name;
            p.rawValue = rawValue;
            if (const char* n = GameData::LookupENpcName(static_cast<uint32_t>(rawValue))) {
                p.gameName = n;
                p.displayValue = std::format("{} (ID: {})", n, rawValue);
                p.isValid = true;
            } else {
                p.displayValue = std::format("ENpc #{}", rawValue);
            }
            return p;
        }
        
        case ParamType::FateId: {
            DecodedParam p;
            p.type = type;
            p.name = name;
            p.rawValue = rawValue;
            if (const char* n = GameData::LookupFateName(static_cast<uint32_t>(rawValue))) {
                p.gameName = n;
                p.displayValue = std::format("{} (ID: {})", n, rawValue);
                p.isValid = true;
            } else {
                p.displayValue = std::format("FATE #{}", rawValue);
            }
            return p;
        }
        
        case ParamType::QuestId: {
            DecodedParam p;
            p.type = type;
            p.name = name;
            p.rawValue = rawValue;
            if (const char* n = GameData::LookupQuestName(static_cast<uint32_t>(rawValue))) {
                p.gameName = n;
                p.displayValue = std::format("{} (ID: {})", n, rawValue);
                p.isValid = true;
            } else {
                p.displayValue = std::format("Quest #{}", rawValue);
            }
            return p;
        }
        
        case ParamType::AchievementId: {
            DecodedParam p;
            p.type = type;
            p.name = name;
            p.rawValue = rawValue;
            if (const char* n = GameData::LookupAchievementName(static_cast<uint32_t>(rawValue))) {
                p.gameName = n;
                p.displayValue = std::format("{} (ID: {})", n, rawValue);
                p.isValid = true;
            } else {
                p.displayValue = std::format("Achievement #{}", rawValue);
            }
            return p;
        }
        
        case ParamType::MountId: {
            DecodedParam p;
            p.type = type;
            p.name = name;
            p.rawValue = rawValue;
            if (const char* n = GameData::LookupMountName(static_cast<uint16_t>(rawValue))) {
                p.gameName = n;
                p.displayValue = std::format("{} (ID: {})", n, rawValue);
                p.isValid = true;
            } else {
                p.displayValue = std::format("Mount #{}", rawValue);
            }
            return p;
        }
        
        case ParamType::MinionId: {
            DecodedParam p;
            p.type = type;
            p.name = name;
            p.rawValue = rawValue;
            if (const char* n = GameData::LookupMinionName(static_cast<uint16_t>(rawValue))) {
                p.gameName = n;
                p.displayValue = std::format("{} (ID: {})", n, rawValue);
                p.isValid = true;
            } else {
                p.displayValue = std::format("Minion #{}", rawValue);
            }
            return p;
        }
        
        case ParamType::EmoteId: {
            DecodedParam p;
            p.type = type;
            p.name = name;
            p.rawValue = rawValue;
            if (const char* n = GameData::LookupEmoteName(static_cast<uint16_t>(rawValue))) {
                p.gameName = n;
                p.displayValue = std::format("{} (ID: {})", n, rawValue);
                p.isValid = true;
            } else {
                p.displayValue = std::format("Emote #{}", rawValue);
            }
            return p;
        }
        
        case ParamType::WorldId: {
            DecodedParam p;
            p.type = type;
            p.name = name;
            p.rawValue = rawValue;
            if (const char* n = GameData::LookupWorldName(static_cast<uint16_t>(rawValue))) {
                p.gameName = n;
                p.displayValue = std::format("{} (ID: {})", n, rawValue);
                p.isValid = true;
            } else {
                p.displayValue = std::format("World #{}", rawValue);
            }
            return p;
        }
        
        case ParamType::AetheryteId: {
            DecodedParam p;
            p.type = type;
            p.name = name;
            p.rawValue = rawValue;
            if (const char* n = GameData::LookupAetheryteName(static_cast<uint16_t>(rawValue))) {
                p.gameName = n;
                p.displayValue = std::format("{} (ID: {})", n, rawValue);
                p.isValid = true;
            } else {
                p.displayValue = std::format("Aetheryte #{}", rawValue);
            }
            return p;
        }
        
        case ParamType::WeatherId: {
            DecodedParam p;
            p.type = type;
            p.name = name;
            p.rawValue = rawValue;
            if (const char* n = GameData::LookupWeatherName(static_cast<uint8_t>(rawValue))) {
                p.gameName = n;
                p.displayValue = std::format("{} (ID: {})", n, rawValue);
                p.isValid = true;
            } else {
                p.displayValue = std::format("Weather #{}", rawValue);
            }
            return p;
        }
        
        default: {
            DecodedParam p;
            p.type = type;
            p.name = name;
            p.rawValue = rawValue;
            p.displayValue = std::format("0x{:X}", rawValue);
            return p;
        }
    }
}

DecodedParam HookParameterDecoder::DecodeBytes(ParamType type, const void* data, size_t length, const std::string& name) {
    if (!data || length == 0) {
        DecodedParam p;
        p.name = name;
        p.displayValue = "<null>";
        return p;
    }
    
    if (type == ParamType::String) {
        DecodedParam p;
        p.type = ParamType::String;
        p.name = name;
        // Safe string read
        const char* str = static_cast<const char*>(data);
        size_t strLen = strnlen(str, length);
        p.displayValue = std::string(str, strLen);
        p.rawValue = reinterpret_cast<uint64_t>(data);
        p.isValid = true;
        return p;
    }
    
    if (type == ParamType::Position3D && length >= 12) {
        const float* pos = static_cast<const float*>(data);
        DecodedParam p;
        p.type = ParamType::Position3D;
        p.name = name;
        p.displayValue = std::format("({:.2f}, {:.2f}, {:.2f})", pos[0], pos[1], pos[2]);
        p.isValid = true;
        return p;
    }
    
    if (type == ParamType::Quaternion && length >= 16) {
        const float* q = static_cast<const float*>(data);
        DecodedParam p;
        p.type = ParamType::Quaternion;
        p.name = name;
        p.displayValue = std::format("({:.3f}, {:.3f}, {:.3f}, {:.3f})", q[0], q[1], q[2], q[3]);
        p.isValid = true;
        return p;
    }
    
    // Default: read as raw value
    uint64_t rawValue = 0;
    std::memcpy(&rawValue, data, (std::min)(length, sizeof(uint64_t)));
    return DecodeParameter(type, rawValue, name);
}

std::vector<DecodedParam> HookParameterDecoder::DecodeFunctionCall(
    const FunctionSignature& sig,
    const uint64_t* registers,
    const void* stack) 
{
    std::vector<DecodedParam> results;
    
    // x64 calling convention: first 4 args in RCX, RDX, R8, R9
    // Additional args on stack
    size_t regCount = (std::min)(sig.parameters.size(), size_t(4));
    
    for (size_t i = 0; i < sig.parameters.size(); ++i) {
        const auto& param = sig.parameters[i];
        uint64_t value;
        
        if (i < 4 && registers) {
            value = registers[i];
        } else if (stack) {
            // Stack args start after shadow space (32 bytes) and return address
            const uint64_t* stackArgs = static_cast<const uint64_t*>(stack);
            value = stackArgs[i - 4 + 5]; // +5 for shadow + return addr
        } else {
            continue;
        }
        
        results.push_back(DecodeParameter(param.type, value, param.name));
    }
    
    return results;
}

std::vector<DecodedParam> HookParameterDecoder::AutoDecodeParameters(
    const uint64_t* values,
    size_t count) 
{
    std::vector<DecodedParam> results;
    
    for (size_t i = 0; i < count; ++i) {
        uint64_t value = values[i];
        ParamType inferredType = InferType(value);
        
        std::string name = std::format("arg{}", i);
        results.push_back(DecodeParameter(inferredType, value, name));
    }
    
    return results;
}

std::string HookParameterDecoder::FormatParameter(const DecodedParam& param, bool verbose) {
    std::string result;
    
    if (!param.name.empty()) {
        result = param.name + "=";
    }
    
    result += param.displayValue;
    
    if (verbose) {
        result += std::format(" [{}]", ToString(param.type));
        if (!param.details.empty()) {
            result += " " + param.details;
        }
    }
    
    return result;
}

std::string HookParameterDecoder::FormatFunctionCall(
    const std::string& functionName,
    const std::vector<DecodedParam>& params) 
{
    std::string result = functionName + "(";
    
    for (size_t i = 0; i < params.size(); ++i) {
        if (i > 0) result += ", ";
        result += FormatParameter(params[i], false);
    }
    
    result += ")";
    return result;
}

// ============================================================================
// Signature Registry
// ============================================================================

void HookParameterDecoder::RegisterSignature(const FunctionSignature& sig) {
    std::lock_guard<std::mutex> lock(s_signatureMutex);
    std::string key = MakeKey(sig.className, sig.functionName);
    s_signatures[key] = sig;
}

std::optional<FunctionSignature> HookParameterDecoder::GetSignature(uintptr_t address) {
    std::lock_guard<std::mutex> lock(s_signatureMutex);
    
    auto addrIt = s_addressToSignature.find(address);
    if (addrIt == s_addressToSignature.end()) {
        return std::nullopt;
    }
    
    auto sigIt = s_signatures.find(addrIt->second);
    if (sigIt == s_signatures.end()) {
        return std::nullopt;
    }
    
    return sigIt->second;
}

std::optional<FunctionSignature> HookParameterDecoder::GetSignature(
    const std::string& className,
    const std::string& functionName) 
{
    std::lock_guard<std::mutex> lock(s_signatureMutex);
    
    std::string key = MakeKey(className, functionName);
    auto it = s_signatures.find(key);
    if (it == s_signatures.end()) {
        return std::nullopt;
    }
    
    return it->second;
}

void HookParameterDecoder::MapAddressToSignature(
    uintptr_t address,
    const std::string& className,
    const std::string& functionName) 
{
    std::lock_guard<std::mutex> lock(s_signatureMutex);
    s_addressToSignature[address] = MakeKey(className, functionName);
}

void HookParameterDecoder::LoadFromSignatureDatabase() {
    // TODO: Load from SignatureDatabase::GetResolvedFunctionsWithInfo()
    // and convert to FunctionSignature entries
}

// ============================================================================
// Type Inference Helpers
// ============================================================================

ParamType HookParameterDecoder::InferType(uint64_t value) {
    uint32_t low32 = static_cast<uint32_t>(value);
    
    // Check for pointer (high bits set, in valid address range)
    if (LooksLikePointer(value)) {
        return ParamType::Pointer;
    }
    
    // Check for entity ID patterns
    if (LooksLikeEntityId(low32)) {
        return ParamType::EntityId;
    }
    
    // Check game data types
    if (LooksLikeActionId(low32)) {
        return ParamType::ActionId;
    }
    if (LooksLikeItemId(low32)) {
        return ParamType::ItemId;
    }
    if (LooksLikeStatusId(low32)) {
        return ParamType::StatusId;
    }
    if (LooksLikeTerritoryId(low32)) {
        return ParamType::TerritoryId;
    }
    
    // Default to integer
    if (value <= 0xFFFFFFFF) {
        return ParamType::UInt32;
    }
    return ParamType::UInt64;
}

bool HookParameterDecoder::LooksLikePointer(uint64_t value) {
    // Check if high bits are set (64-bit address space)
    // Typical user-mode addresses: 0x00000000`00000000 - 0x00007FFF`FFFFFFFF
    // Kernel addresses start at 0xFFFF...
    return (value >= 0x10000 && value <= 0x00007FFFFFFFFFFF);
}

bool HookParameterDecoder::LooksLikeEntityId(uint32_t value) {
    // Entity IDs typically 0x10000000+ or 0x40000000+ or 0xE0000000+
    return (value >= 0x10000000 && value < 0x20000000) ||
           (value >= 0x40000000 && value < 0x50000000) ||
           (value >= 0xE0000000);
}

bool HookParameterDecoder::LooksLikeItemId(uint32_t value) {
    // Items 1-50000, HQ items 1000000+
    if (value >= 1 && value <= 50000) {
        return GameData::LookupItemName(value) != nullptr;
    }
    if (value >= 1000000 && value <= 1050000) {
        return GameData::LookupItemName(value - 1000000) != nullptr;
    }
    return false;
}

bool HookParameterDecoder::LooksLikeActionId(uint32_t value) {
    if (value >= 1 && value <= 50000) {
        return GameData::LookupActionName(value) != nullptr;
    }
    return false;
}

bool HookParameterDecoder::LooksLikeStatusId(uint32_t value) {
    if (value >= 1 && value <= 5000) {
        return GameData::LookupStatusName(value) != nullptr;
    }
    return false;
}

bool HookParameterDecoder::LooksLikeTerritoryId(uint32_t value) {
    if (value >= 100 && value <= 2500) {
        return GameData::LookupTerritoryName(value) != nullptr;
    }
    return false;
}

} // namespace SapphireHook
