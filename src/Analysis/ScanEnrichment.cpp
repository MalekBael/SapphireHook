#include "ScanEnrichment.h"
#include "../Core/GameDataLookup.h"
#include "../Core/SafeMemory.h"
#include "../Logger/Logger.h"
#include "PatternScanner.h"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace SapphireHook {

const char* ToString(CodeContext context) {
    switch (context) {
        case CodeContext::NetworkPacketHandler: return "NetworkPacketHandler";
        case CodeContext::NetworkPacketBuilder: return "NetworkPacketBuilder";
        case CodeContext::ItemLookup: return "ItemLookup";
        case CodeContext::ActionHandler: return "ActionHandler";
        case CodeContext::StatusEffectHandler: return "StatusEffectHandler";
        case CodeContext::ZoneTransition: return "ZoneTransition";
        case CodeContext::UIHandler: return "UIHandler";
        case CodeContext::ChatHandler: return "ChatHandler";
        case CodeContext::CombatCalculation: return "CombatCalculation";
        case CodeContext::InventoryOperation: return "InventoryOperation";
        case CodeContext::QuestHandler: return "QuestHandler";
        case CodeContext::FateHandler: return "FateHandler";
        case CodeContext::ContentHandler: return "ContentHandler";
        case CodeContext::CharacterData: return "CharacterData";
        case CodeContext::NpcInteraction: return "NpcInteraction";
        default: return "Unknown";
    }
}

// ============================================================================
// Scoring Functions - Heuristics for identifying constant types
// ============================================================================

float ScanEnrichment::ScoreAsItemId(uint32_t value) {
    // Item IDs typically range from 1 to ~40000 for regular items
    // HQ items add 1000000, collectables add other offsets
    if (value >= 1 && value <= 50000) {
        if (GameData::LookupItemName(value) != nullptr) {
            return 1.0f; // Definite match
        }
        return 0.3f; // In range but not found
    }
    // HQ item IDs (base + 1000000)
    if (value >= 1000000 && value <= 1050000) {
        if (GameData::LookupItemName(value - 1000000) != nullptr) {
            return 0.9f; // HQ version of known item
        }
    }
    return 0.0f;
}

float ScanEnrichment::ScoreAsActionId(uint32_t value) {
    // Action IDs typically range from 1 to ~40000
    if (value >= 1 && value <= 50000) {
        if (GameData::LookupActionName(value) != nullptr) {
            return 1.0f;
        }
        return 0.2f;
    }
    return 0.0f;
}

float ScanEnrichment::ScoreAsStatusId(uint32_t value) {
    // Status IDs are generally smaller, 1-5000 range
    if (value >= 1 && value <= 5000) {
        if (GameData::LookupStatusName(value) != nullptr) {
            return 1.0f;
        }
        return 0.3f;
    }
    return 0.0f;
}

float ScanEnrichment::ScoreAsTerritoryId(uint32_t value) {
    // Territory IDs are generally in the 100-2000 range
    if (value >= 100 && value <= 2500) {
        if (GameData::LookupTerritoryName(value) != nullptr) {
            return 1.0f;
        }
        return 0.2f;
    }
    return 0.0f;
}

float ScanEnrichment::ScoreAsQuestId(uint32_t value) {
    // Quest IDs are typically larger numbers, 65536+
    if (value >= 65536 && value <= 75000) {
        if (GameData::LookupQuestName(value) != nullptr) {
            return 1.0f;
        }
        return 0.3f;
    }
    return 0.0f;
}

// ============================================================================
// Main Implementation
// ============================================================================

EnrichedConstant ScanEnrichment::IdentifyConstant(uint32_t value) {
    auto candidates = IdentifyConstantMultiple(value);
    if (!candidates.empty()) {
        return candidates.front();
    }
    return EnrichedConstant{ value, GameConstantType::Unknown, "", "", 0.0f };
}

std::vector<EnrichedConstant> ScanEnrichment::IdentifyConstantMultiple(uint32_t value) {
    std::vector<EnrichedConstant> results;
    
    // Skip common non-game values
    if (value == 0 || value == 1 || value == 0xFFFFFFFF || value == 0x7FFFFFFF) {
        return results;
    }
    
    // Try each type and score it
    struct TypeScorer {
        GameConstantType type;
        float (*scorer)(uint32_t);
        const char* (*namer)(uint32_t) noexcept;
    };
    
    // Check Item
    if (float score = ScoreAsItemId(value); score > 0.5f) {
        EnrichedConstant ec;
        ec.value = value;
        ec.type = GameConstantType::ItemId;
        ec.confidence = score;
        if (auto* name = GameData::LookupItemName(value)) {
            ec.name = name;
        } else if (value >= 1000000) {
            if (auto* name = GameData::LookupItemName(value - 1000000)) {
                ec.name = std::string(name) + " (HQ)";
            }
        }
        ec.category = "Item";
        results.push_back(ec);
    }
    
    // Check Action
    if (float score = ScoreAsActionId(value); score > 0.5f) {
        EnrichedConstant ec;
        ec.value = value;
        ec.type = GameConstantType::ActionId;
        ec.confidence = score;
        if (auto* name = GameData::LookupActionName(value)) {
            ec.name = name;
        }
        ec.category = "Action";
        results.push_back(ec);
    }
    
    // Check Status
    if (float score = ScoreAsStatusId(value); score > 0.5f) {
        EnrichedConstant ec;
        ec.value = value;
        ec.type = GameConstantType::StatusId;
        ec.confidence = score;
        if (auto* name = GameData::LookupStatusName(value)) {
            ec.name = name;
        }
        ec.category = "Status";
        results.push_back(ec);
    }
    
    // Check Territory
    if (float score = ScoreAsTerritoryId(value); score > 0.5f) {
        EnrichedConstant ec;
        ec.value = value;
        ec.type = GameConstantType::TerritoryId;
        ec.confidence = score;
        if (auto* name = GameData::LookupTerritoryName(value)) {
            ec.name = name;
        }
        ec.category = "Territory";
        results.push_back(ec);
    }
    
    // Check Quest
    if (float score = ScoreAsQuestId(value); score > 0.5f) {
        EnrichedConstant ec;
        ec.value = value;
        ec.type = GameConstantType::QuestId;
        ec.confidence = score;
        if (auto* name = GameData::LookupQuestName(value)) {
            ec.name = name;
        }
        ec.category = "Quest";
        results.push_back(ec);
    }
    
    // Check other types with simple lookups
    if (auto* name = GameData::LookupClassJobName(static_cast<uint8_t>(value)); 
        name && value < 50) {
        EnrichedConstant ec;
        ec.value = value;
        ec.type = GameConstantType::ClassJobId;
        ec.name = name;
        ec.category = "ClassJob";
        ec.confidence = 0.9f;
        results.push_back(ec);
    }
    
    if (auto* name = GameData::LookupBNpcName(value)) {
        EnrichedConstant ec;
        ec.value = value;
        ec.type = GameConstantType::BNpcId;
        ec.name = name;
        ec.category = "BNpc";
        ec.confidence = 1.0f;
        results.push_back(ec);
    }
    
    if (auto* name = GameData::LookupFateName(value)) {
        EnrichedConstant ec;
        ec.value = value;
        ec.type = GameConstantType::FateId;
        ec.name = name;
        ec.category = "FATE";
        ec.confidence = 1.0f;
        results.push_back(ec);
    }
    
    // Sort by confidence
    std::sort(results.begin(), results.end(), 
        [](const auto& a, const auto& b) { return a.confidence > b.confidence; });
    
    return results;
}

std::vector<EnrichedConstant> ScanEnrichment::AnalyzeFunctionConstants(
    uintptr_t functionAddress, 
    size_t maxScanBytes) 
{
    std::vector<EnrichedConstant> results;
    
    if (!IsValidMemoryAddress(functionAddress, maxScanBytes)) {
        return results;
    }
    
    const uint8_t* code = reinterpret_cast<const uint8_t*>(functionAddress);
    
    // Look for immediate values in common instruction patterns
    // mov reg, imm32: 0xB8-0xBF followed by 4-byte immediate
    // mov [mem], imm32: various patterns with ModR/M
    // cmp reg, imm32: 0x81 /7 or 0x3D
    // push imm32: 0x68
    
    for (size_t i = 0; i < maxScanBytes - 4; ++i) {
        uint32_t value = 0;
        bool foundImmediate = false;
        
        // mov eax/ecx/edx/ebx, imm32 (0xB8-0xBB)
        if (code[i] >= 0xB8 && code[i] <= 0xBB) {
            value = *reinterpret_cast<const uint32_t*>(&code[i + 1]);
            foundImmediate = true;
            i += 4;
        }
        // push imm32 (0x68)
        else if (code[i] == 0x68) {
            value = *reinterpret_cast<const uint32_t*>(&code[i + 1]);
            foundImmediate = true;
            i += 4;
        }
        // mov r32, imm32 (REX.W prefix + 0xB8-0xBF) - 64-bit
        else if (code[i] == 0x48 && i + 5 < maxScanBytes && 
                 code[i + 1] >= 0xB8 && code[i + 1] <= 0xBF) {
            // 8-byte immediate, but we only care about lower 32 bits
            value = *reinterpret_cast<const uint32_t*>(&code[i + 2]);
            foundImmediate = true;
            i += 9;
        }
        
        if (foundImmediate && value > 0 && value < 0x10000000) {
            auto identified = IdentifyConstantMultiple(value);
            for (auto& ec : identified) {
                // Check if we already have this value
                bool exists = false;
                for (const auto& existing : results) {
                    if (existing.value == ec.value && existing.type == ec.type) {
                        exists = true;
                        break;
                    }
                }
                if (!exists) {
                    results.push_back(std::move(ec));
                }
            }
        }
    }
    
    return results;
}

EnrichedFunction ScanEnrichment::EnrichFunction(
    uintptr_t functionAddress,
    size_t maxScanBytes) 
{
    EnrichedFunction result;
    result.address = functionAddress;
    
    // Get string references using PatternScanner
    auto xrefResult = PatternScanner::GuessNameFromStringReferences(functionAddress, maxScanBytes);
    if (xrefResult) {
        result.stringRefs.push_back(xrefResult->text);
    }
    
    // Get constants
    result.constants = AnalyzeFunctionConstants(functionAddress, maxScanBytes);
    
    // Infer context
    auto context = InferCodeContext(result.stringRefs, result.constants);
    result.category = ToString(context);
    
    // Generate suggested name
    result.suggestedName = GenerateSuggestedName(result.stringRefs, result.constants, context);
    
    // Calculate confidence based on amount of information
    float confidence = 0.0f;
    if (!result.stringRefs.empty()) confidence += 0.4f;
    if (!result.constants.empty()) {
        float avgConstConfidence = 0.0f;
        for (const auto& c : result.constants) {
            avgConstConfidence += c.confidence;
        }
        avgConstConfidence /= result.constants.size();
        confidence += avgConstConfidence * 0.4f;
    }
    if (context != CodeContext::Unknown) confidence += 0.2f;
    result.nameConfidence = confidence;
    
    return result;
}

CodeContext ScanEnrichment::InferCodeContext(
    const std::vector<std::string>& stringRefs,
    const std::vector<EnrichedConstant>& constants) 
{
    // Count constant types
    int itemCount = 0, actionCount = 0, statusCount = 0, territoryCount = 0;
    int questCount = 0, fateCount = 0;
    
    for (const auto& c : constants) {
        switch (c.type) {
            case GameConstantType::ItemId: itemCount++; break;
            case GameConstantType::ActionId: actionCount++; break;
            case GameConstantType::StatusId: statusCount++; break;
            case GameConstantType::TerritoryId: territoryCount++; break;
            case GameConstantType::QuestId: questCount++; break;
            case GameConstantType::FateId: fateCount++; break;
            default: break;
        }
    }
    
    // Check string references for keywords
    for (const auto& str : stringRefs) {
        std::string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        
        if (lower.find("packet") != std::string::npos || 
            lower.find("opcode") != std::string::npos ||
            lower.find("network") != std::string::npos) {
            return CodeContext::NetworkPacketHandler;
        }
        if (lower.find("chat") != std::string::npos || 
            lower.find("message") != std::string::npos) {
            return CodeContext::ChatHandler;
        }
        if (lower.find("zone") != std::string::npos || 
            lower.find("territory") != std::string::npos) {
            return CodeContext::ZoneTransition;
        }
        if (lower.find("inventory") != std::string::npos || 
            lower.find("item") != std::string::npos) {
            return CodeContext::InventoryOperation;
        }
        if (lower.find("quest") != std::string::npos) {
            return CodeContext::QuestHandler;
        }
        if (lower.find("fate") != std::string::npos) {
            return CodeContext::FateHandler;
        }
        if (lower.find("duty") != std::string::npos || 
            lower.find("content") != std::string::npos) {
            return CodeContext::ContentHandler;
        }
        if (lower.find("ui") != std::string::npos || 
            lower.find("addon") != std::string::npos ||
            lower.find("window") != std::string::npos) {
            return CodeContext::UIHandler;
        }
    }
    
    // Infer from constant types
    if (actionCount > 0 && (statusCount > 0 || actionCount > 2)) {
        return CodeContext::ActionHandler;
    }
    if (statusCount > 2) {
        return CodeContext::StatusEffectHandler;
    }
    if (itemCount > 2) {
        return CodeContext::ItemLookup;
    }
    if (territoryCount > 0) {
        return CodeContext::ZoneTransition;
    }
    if (questCount > 0) {
        return CodeContext::QuestHandler;
    }
    if (fateCount > 0) {
        return CodeContext::FateHandler;
    }
    
    return CodeContext::Unknown;
}

std::string ScanEnrichment::GenerateSuggestedName(
    const std::vector<std::string>& stringRefs,
    const std::vector<EnrichedConstant>& constants,
    CodeContext context) 
{
    std::string prefix;
    std::string subject;
    
    // Determine prefix from context
    switch (context) {
        case CodeContext::NetworkPacketHandler: prefix = "Handle"; break;
        case CodeContext::NetworkPacketBuilder: prefix = "Build"; break;
        case CodeContext::ItemLookup: prefix = "Get"; subject = "Item"; break;
        case CodeContext::ActionHandler: prefix = "Process"; subject = "Action"; break;
        case CodeContext::StatusEffectHandler: prefix = "Apply"; subject = "Status"; break;
        case CodeContext::ZoneTransition: prefix = "Init"; subject = "Zone"; break;
        case CodeContext::UIHandler: prefix = "Update"; subject = "UI"; break;
        case CodeContext::ChatHandler: prefix = "Process"; subject = "Chat"; break;
        case CodeContext::CombatCalculation: prefix = "Calc"; subject = "Damage"; break;
        case CodeContext::InventoryOperation: prefix = "Update"; subject = "Inventory"; break;
        case CodeContext::QuestHandler: prefix = "Process"; subject = "Quest"; break;
        case CodeContext::FateHandler: prefix = "Handle"; subject = "Fate"; break;
        case CodeContext::ContentHandler: prefix = "Process"; subject = "Content"; break;
        case CodeContext::CharacterData: prefix = "Get"; subject = "Character"; break;
        case CodeContext::NpcInteraction: prefix = "Interact"; subject = "Npc"; break;
        default: prefix = "Sub"; break;
    }
    
    // Try to extract meaningful words from string refs
    for (const auto& str : stringRefs) {
        // Look for PascalCase words in the string
        if (str.length() > 3 && str.length() < 30) {
            // Clean up the string - take first meaningful segment
            std::string clean;
            bool prevUpper = false;
            for (char c : str) {
                if (std::isalnum(c)) {
                    clean += c;
                } else if (!clean.empty()) {
                    break; // Stop at first non-alnum
                }
            }
            if (clean.length() >= 3 && std::isupper(clean[0])) {
                return prefix + clean;
            }
        }
    }
    
    // Use constant type names
    if (!constants.empty() && !constants.front().name.empty()) {
        // Try to make a reasonable name from the first identified constant
        std::string constName = constants.front().name;
        // Take first word only
        size_t spacePos = constName.find(' ');
        if (spacePos != std::string::npos) {
            constName = constName.substr(0, spacePos);
        }
        // Capitalize first letter
        if (!constName.empty()) {
            constName[0] = static_cast<char>(std::toupper(constName[0]));
        }
        return prefix + constName;
    }
    
    return prefix + subject;
}

bool ScanEnrichment::LooksLikeOpcode(uint32_t value) {
    // Opcodes are typically 16-bit values, 0x0001 - 0x03FF range roughly
    return value >= 0x0001 && value <= 0x0500;
}

bool ScanEnrichment::LooksLikeEntityId(uint32_t value) {
    // Entity IDs (actor IDs) are typically 0x10000000+ for players
    // NPCs/objects are in various ranges
    return (value >= 0x10000000 && value <= 0x1FFFFFFF) ||
           (value >= 0x40000000 && value <= 0x4FFFFFFF);
}

bool ScanEnrichment::IsFunctionPrologue(const uint8_t* bytes, size_t length) {
    if (length < 3) return false;
    
    // Common x64 function prologues:
    // push rbp (55)
    // push rbx (53)
    // sub rsp, imm8 (48 83 EC xx)
    // mov [rsp+...], rbx (48 89 5C 24 xx)
    
    if (bytes[0] == 0x55) return true; // push rbp
    if (bytes[0] == 0x53) return true; // push rbx
    if (length >= 4 && bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC) {
        return true; // sub rsp, imm8
    }
    if (length >= 5 && bytes[0] == 0x48 && bytes[1] == 0x89 && 
        (bytes[2] == 0x5C || bytes[2] == 0x6C || bytes[2] == 0x74 || bytes[2] == 0x7C)) {
        return true; // mov [rsp+offset], r64
    }
    
    return false;
}

} // namespace SapphireHook
