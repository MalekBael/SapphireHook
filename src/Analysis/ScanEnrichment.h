#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <unordered_map>
#include <variant>

namespace SapphireHook {

enum class GameConstantType {
    Unknown,
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
    ContentFinderConditionId,
    OrcodeValue       
};

struct EnrichedConstant {
    uint32_t value = 0;
    GameConstantType type = GameConstantType::Unknown;
    std::string name;               
    std::string category;          
    float confidence = 0.0f;           
    
    bool IsIdentified() const { return type != GameConstantType::Unknown; }
};

struct EnrichedFunction {
    uintptr_t address = 0;
    std::string suggestedName;                 
    std::vector<std::string> stringRefs;       
    std::vector<EnrichedConstant> constants;     
    std::string category;                         
    float nameConfidence = 0.0f;                 
};

enum class CodeContext {
    Unknown,
    NetworkPacketHandler,          
    NetworkPacketBuilder,           
    ItemLookup,                   
    ActionHandler,                
    StatusEffectHandler,           
    ZoneTransition,               
    UIHandler,                     
    ChatHandler,                   
    CombatCalculation,            
    InventoryOperation,           
    QuestHandler,                  
    FateHandler,                   
    ContentHandler,                
    CharacterData,                 
    NpcInteraction                 
};

const char* ToString(CodeContext context);

class ScanEnrichment {
public:
    static EnrichedConstant IdentifyConstant(uint32_t value);
    
    static std::vector<EnrichedConstant> IdentifyConstantMultiple(uint32_t value);
    
    static std::vector<EnrichedConstant> AnalyzeFunctionConstants(
        uintptr_t functionAddress, 
        size_t maxScanBytes = 512);
    
    static EnrichedFunction EnrichFunction(
        uintptr_t functionAddress,
        size_t maxScanBytes = 0x400);
    
    static CodeContext InferCodeContext(
        const std::vector<std::string>& stringRefs,
        const std::vector<EnrichedConstant>& constants);
    
    static std::string GenerateSuggestedName(
        const std::vector<std::string>& stringRefs,
        const std::vector<EnrichedConstant>& constants,
        CodeContext context);
    
    static bool LooksLikeOpcode(uint32_t value);
    
    static bool LooksLikeEntityId(uint32_t value);
    
    static bool IsFunctionPrologue(const uint8_t* bytes, size_t length);

private:
    static float ScoreAsItemId(uint32_t value);
    static float ScoreAsActionId(uint32_t value);
    static float ScoreAsStatusId(uint32_t value);
    static float ScoreAsTerritoryId(uint32_t value);
    static float ScoreAsQuestId(uint32_t value);
};

}   
