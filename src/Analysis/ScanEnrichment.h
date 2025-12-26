#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <unordered_map>
#include <variant>

namespace SapphireHook {

// ============================================================================
// Pattern Scan Result Enrichment with Game Data
// ============================================================================

/// @brief Possible types of game data constants found in code
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
    OrcodeValue     // Network opcode
};

/// @brief Result of enriching a constant with game data
struct EnrichedConstant {
    uint32_t value = 0;
    GameConstantType type = GameConstantType::Unknown;
    std::string name;           // Human-readable name from EXD
    std::string category;       // Additional category info
    float confidence = 0.0f;    // 0.0 - 1.0 confidence in the identification
    
    bool IsIdentified() const { return type != GameConstantType::Unknown; }
};

/// @brief Enriched function analysis result
struct EnrichedFunction {
    uintptr_t address = 0;
    std::string suggestedName;              // Auto-generated name suggestion
    std::vector<std::string> stringRefs;    // String literals referenced
    std::vector<EnrichedConstant> constants; // Game data constants found
    std::string category;                   // Inferred category (Combat, UI, Network, etc.)
    float nameConfidence = 0.0f;            // Confidence in the suggested name
};

/// @brief Code pattern context (what kind of code this appears to be)
enum class CodeContext {
    Unknown,
    NetworkPacketHandler,       // Handles incoming/outgoing packets
    NetworkPacketBuilder,       // Builds packets for sending
    ItemLookup,                 // Item-related operations
    ActionHandler,              // Action/skill processing
    StatusEffectHandler,        // Status effect processing
    ZoneTransition,             // Zone loading/transitions
    UIHandler,                  // UI related code
    ChatHandler,                // Chat message processing
    CombatCalculation,          // Damage/healing calculations
    InventoryOperation,         // Inventory management
    QuestHandler,               // Quest related operations
    FateHandler,                // FATE related operations
    ContentHandler,             // Duty Finder content
    CharacterData,              // Character info access
    NpcInteraction              // NPC interaction handling
};

/// @brief Convert CodeContext to string
const char* ToString(CodeContext context);

/// @brief Scan enrichment utilities
class ScanEnrichment {
public:
    /// @brief Try to identify what type of game constant this value might be
    /// @param value The constant value to identify
    /// @return EnrichedConstant with identification if found
    static EnrichedConstant IdentifyConstant(uint32_t value);
    
    /// @brief Try to identify multiple possible interpretations of a constant
    /// @param value The constant value
    /// @return All possible identifications, sorted by confidence
    static std::vector<EnrichedConstant> IdentifyConstantMultiple(uint32_t value);
    
    /// @brief Analyze a function's code to identify constants it uses
    /// @param functionAddress Start address of the function
    /// @param maxScanBytes How many bytes to scan (default 512)
    /// @return List of identified constants
    static std::vector<EnrichedConstant> AnalyzeFunctionConstants(
        uintptr_t functionAddress, 
        size_t maxScanBytes = 512);
    
    /// @brief Enrich a function with game data context
    /// @param functionAddress Start address of the function
    /// @param maxScanBytes How many bytes to scan
    /// @return Enriched function information
    static EnrichedFunction EnrichFunction(
        uintptr_t functionAddress,
        size_t maxScanBytes = 0x400);
    
    /// @brief Infer code context from string references and constants
    /// @param stringRefs Strings referenced by the code
    /// @param constants Constants identified in the code
    /// @return Most likely code context
    static CodeContext InferCodeContext(
        const std::vector<std::string>& stringRefs,
        const std::vector<EnrichedConstant>& constants);
    
    /// @brief Generate a suggested function name from analysis
    /// @param stringRefs String references found
    /// @param constants Constants found  
    /// @param context Inferred context
    /// @return Suggested name like "ProcessActionRequest" or "HandleZoneInit"
    static std::string GenerateSuggestedName(
        const std::vector<std::string>& stringRefs,
        const std::vector<EnrichedConstant>& constants,
        CodeContext context);
    
    /// @brief Check if a constant looks like a network opcode
    /// @param value The value to check
    /// @return True if it's in a valid opcode range
    static bool LooksLikeOpcode(uint32_t value);
    
    /// @brief Check if a constant looks like an entity ID (object ID in game)
    /// @param value The value to check
    /// @return True if it matches entity ID patterns
    static bool LooksLikeEntityId(uint32_t value);
    
    /// @brief Check if bytes look like a function prologue
    /// @param bytes Pointer to code bytes
    /// @param length Length available to read
    /// @return True if this looks like a function start
    static bool IsFunctionPrologue(const uint8_t* bytes, size_t length);

private:
    // Heuristics for constant identification
    static float ScoreAsItemId(uint32_t value);
    static float ScoreAsActionId(uint32_t value);
    static float ScoreAsStatusId(uint32_t value);
    static float ScoreAsTerritoryId(uint32_t value);
    static float ScoreAsQuestId(uint32_t value);
};

} // namespace SapphireHook
