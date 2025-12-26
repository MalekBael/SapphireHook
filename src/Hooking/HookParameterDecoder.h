#pragma once
#include <string>
#include <vector>
#include <variant>
#include <cstdint>
#include <optional>
#include <functional>

namespace SapphireHook {

// ============================================================================
// Hook Parameter Decoding with Game Data
// ============================================================================

/// @brief Types of decoded parameter values
enum class ParamType {
    Unknown,
    // Primitive types
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
    // Game data types (decoded using EXD)
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
    // Game object types
    EntityId,       // 32-bit object ID (0x10000000 range for players)
    ContentId,      // 64-bit unique content ID
    ActorId,        // Actor (character) ID
    // Composite types
    Position3D,     // float[3] position
    Quaternion,     // float[4] rotation
    Color,          // RGBA color
    Timestamp,      // Unix timestamp
    BitFlags        // Flags that need decoding
};

/// @brief Decoded parameter value with game data enrichment
struct DecodedParam {
    ParamType type = ParamType::Unknown;
    std::string name;                   // Parameter name (if known)
    uint64_t rawValue = 0;              // Raw value as uint64 for storage
    std::string displayValue;           // Human-readable value
    std::string gameName;               // EXD-looked-up name (e.g., "Potion" for ItemId)
    std::string details;                // Additional context
    bool isValid = false;               // Was successfully decoded
    
    // Helper constructors
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

/// @brief Function parameter definition (for known signatures)
struct ParamDef {
    std::string name;
    ParamType type;
    size_t offset = 0;      // Offset in struct if applicable
    size_t size = 0;        // Size in bytes
    bool isOptional = false;
};

/// @brief Known function signature with parameter info
struct FunctionSignature {
    std::string className;
    std::string functionName;
    std::vector<ParamDef> parameters;
    ParamDef returnType;
    std::string description;
};

/// @brief Hook Parameter Decoder for real-time parameter enrichment
class HookParameterDecoder {
public:
    /// @brief Decode a single parameter value based on its type hint
    /// @param type The expected type
    /// @param rawValue The raw value (register or memory)
    /// @param name Optional parameter name
    /// @return Decoded parameter with EXD enrichment
    static DecodedParam DecodeParameter(ParamType type, uint64_t rawValue, const std::string& name = "");
    
    /// @brief Decode raw bytes as a specific type
    /// @param type The expected type
    /// @param data Pointer to raw data
    /// @param length Length of data
    /// @param name Optional parameter name
    /// @return Decoded parameter
    static DecodedParam DecodeBytes(ParamType type, const void* data, size_t length, const std::string& name = "");
    
    /// @brief Decode function parameters using a known signature
    /// @param sig The function signature
    /// @param registers Array of register values (rcx, rdx, r8, r9, ...)
    /// @param stack Stack pointer for additional args
    /// @return Vector of decoded parameters
    static std::vector<DecodedParam> DecodeFunctionCall(
        const FunctionSignature& sig,
        const uint64_t* registers,
        const void* stack = nullptr);
    
    /// @brief Try to auto-detect parameter types from values
    /// @param values Array of raw values
    /// @param count Number of values
    /// @return Vector of best-guess decoded parameters
    static std::vector<DecodedParam> AutoDecodeParameters(
        const uint64_t* values,
        size_t count);
    
    /// @brief Format a decoded parameter for display
    /// @param param The decoded parameter
    /// @param verbose Include extra details
    /// @return Formatted string
    static std::string FormatParameter(const DecodedParam& param, bool verbose = false);
    
    /// @brief Format all decoded parameters as a function call string
    /// @param functionName Function name
    /// @param params Decoded parameters
    /// @return String like "FunctionName(param1=value, param2=value)"
    static std::string FormatFunctionCall(
        const std::string& functionName,
        const std::vector<DecodedParam>& params);
    
    // ========== Known Signature Registry ==========
    
    /// @brief Register a known function signature for parameter decoding
    static void RegisterSignature(const FunctionSignature& sig);
    
    /// @brief Get signature by function address (if mapped)
    static std::optional<FunctionSignature> GetSignature(uintptr_t address);
    
    /// @brief Get signature by class and function name
    static std::optional<FunctionSignature> GetSignature(
        const std::string& className,
        const std::string& functionName);
    
    /// @brief Map an address to a known signature
    static void MapAddressToSignature(
        uintptr_t address,
        const std::string& className,
        const std::string& functionName);
    
    /// @brief Load signatures from SignatureDatabase
    static void LoadFromSignatureDatabase();
    
private:
    /// @brief Infer type from value heuristics
    static ParamType InferType(uint64_t value);
    
    /// @brief Check if value looks like a specific type
    static bool LooksLikeItemId(uint32_t value);
    static bool LooksLikeActionId(uint32_t value);
    static bool LooksLikeStatusId(uint32_t value);
    static bool LooksLikeTerritoryId(uint32_t value);
    static bool LooksLikeEntityId(uint32_t value);
    static bool LooksLikePointer(uint64_t value);
};

/// @brief Convert ParamType to string
const char* ToString(ParamType type);

} // namespace SapphireHook
