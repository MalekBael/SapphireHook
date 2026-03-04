#pragma once
#include <string>
#include <vector>
#include <variant>
#include <cstdint>
#include <optional>
#include <functional>

namespace SapphireHook {

enum class ParamType {
    Unknown,
    Int8,
    Int16,
    Int32,
    Int64,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Float,
    Double,
    Pointer,
    String,
    Bool,
    ItemId,
    ActionId,
    StatusId,
    TerritoryId,
    ClassJobId,
    BNpcId,
    ENpcId,
    FateId,
    QuestId,
    AchievementId,
    MountId,
    MinionId,
    EmoteId,
    PlaceNameId,
    WorldId,
    AetheryteId,
    ContentFinderConditionId,
    WeatherId,
    EntityId,              
    ContentId,          
    ActorId,           
    Position3D,       
    Quaternion,       
    Color,            
    Timestamp,        
    BitFlags            
};

struct DecodedParam {
    ParamType type = ParamType::Unknown;
    std::string name;                       
    uint64_t rawValue = 0;                    
    std::string displayValue;             
    std::string gameName;                     
    std::string details;                  
    bool isValid = false;                  
    
    static DecodedParam FromInt(const std::string& name, int64_t value);
    static DecodedParam FromUInt(const std::string& name, uint64_t value);
    static DecodedParam FromFloat(const std::string& name, float value);
    static DecodedParam FromPointer(const std::string& name, void* ptr);
    static DecodedParam FromItemId(const std::string& name, uint32_t itemId);
    static DecodedParam FromActionId(const std::string& name, uint32_t actionId);
    static DecodedParam FromStatusId(const std::string& name, uint32_t statusId);
    static DecodedParam FromTerritoryId(const std::string& name, uint32_t territoryId);
    static DecodedParam FromClassJobId(const std::string& name, uint8_t classJobId);
    static DecodedParam FromEntityId(const std::string& name, uint32_t entityId);
};

struct ParamDef {
    std::string name;
    ParamType type;
    size_t offset = 0;           
    size_t size = 0;           
    bool isOptional = false;
};

struct FunctionSignature {
    std::string className;
    std::string functionName;
    std::vector<ParamDef> parameters;
    ParamDef returnType;
    std::string description;
};

class HookParameterDecoder {
public:
    static DecodedParam DecodeParameter(ParamType type, uint64_t rawValue, const std::string& name = "");
    
    static DecodedParam DecodeBytes(ParamType type, const void* data, size_t length, const std::string& name = "");
    
    static std::vector<DecodedParam> DecodeFunctionCall(
        const FunctionSignature& sig,
        const uint64_t* registers,
        const void* stack = nullptr);
    
    static std::vector<DecodedParam> AutoDecodeParameters(
        const uint64_t* values,
        size_t count);
    
    static std::string FormatParameter(const DecodedParam& param, bool verbose = false);
    
    static std::string FormatFunctionCall(
        const std::string& functionName,
        const std::vector<DecodedParam>& params);
    
    static void RegisterSignature(const FunctionSignature& sig);
    
    static std::optional<FunctionSignature> GetSignature(uintptr_t address);
    
    static std::optional<FunctionSignature> GetSignature(
        const std::string& className,
        const std::string& functionName);
    
    static void MapAddressToSignature(
        uintptr_t address,
        const std::string& className,
        const std::string& functionName);
    
    static void LoadFromSignatureDatabase();
    
private:
    static ParamType InferType(uint64_t value);
    
    static bool LooksLikeItemId(uint32_t value);
    static bool LooksLikeActionId(uint32_t value);
    static bool LooksLikeStatusId(uint32_t value);
    static bool LooksLikeTerritoryId(uint32_t value);
    static bool LooksLikeEntityId(uint32_t value);
    static bool LooksLikePointer(uint64_t value);
};

const char* ToString(ParamType type);

}   
