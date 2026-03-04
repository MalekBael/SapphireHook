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

float ScanEnrichment::ScoreAsItemId(uint32_t value) {
    if (value >= 1 && value <= 50000) {
        if (GameData::LookupItemName(value) != nullptr) {
            return 1.0f;   
        }
        return 0.3f;      
    }
    if (value >= 1000000 && value <= 1050000) {
        if (GameData::LookupItemName(value - 1000000) != nullptr) {
            return 0.9f;      
        }
    }
    return 0.0f;
}

float ScanEnrichment::ScoreAsActionId(uint32_t value) {
    if (value >= 1 && value <= 50000) {
        if (GameData::LookupActionName(value) != nullptr) {
            return 1.0f;
        }
        return 0.2f;
    }
    return 0.0f;
}

float ScanEnrichment::ScoreAsStatusId(uint32_t value) {
    if (value >= 1 && value <= 5000) {
        if (GameData::LookupStatusName(value) != nullptr) {
            return 1.0f;
        }
        return 0.3f;
    }
    return 0.0f;
}

float ScanEnrichment::ScoreAsTerritoryId(uint32_t value) {
    if (value >= 100 && value <= 2500) {
        if (GameData::LookupTerritoryName(value) != nullptr) {
            return 1.0f;
        }
        return 0.2f;
    }
    return 0.0f;
}

float ScanEnrichment::ScoreAsQuestId(uint32_t value) {
    if (value >= 65536 && value <= 75000) {
        if (GameData::LookupQuestName(value) != nullptr) {
            return 1.0f;
        }
        return 0.3f;
    }
    return 0.0f;
}

EnrichedConstant ScanEnrichment::IdentifyConstant(uint32_t value) {
    auto candidates = IdentifyConstantMultiple(value);
    if (!candidates.empty()) {
        return candidates.front();
    }
    return EnrichedConstant{ value, GameConstantType::Unknown, "", "", 0.0f };
}

std::vector<EnrichedConstant> ScanEnrichment::IdentifyConstantMultiple(uint32_t value) {
    std::vector<EnrichedConstant> results;
    
    if (value == 0 || value == 1 || value == 0xFFFFFFFF || value == 0x7FFFFFFF) {
        return results;
    }
    
    struct TypeScorer {
        GameConstantType type;
        float (*scorer)(uint32_t);
        const char* (*namer)(uint32_t) noexcept;
    };
    
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
    
    for (size_t i = 0; i < maxScanBytes - 4; ++i) {
        uint32_t value = 0;
        bool foundImmediate = false;
        
        if (code[i] >= 0xB8 && code[i] <= 0xBB) {
            value = *reinterpret_cast<const uint32_t*>(&code[i + 1]);
            foundImmediate = true;
            i += 4;
        }
        else if (code[i] == 0x68) {
            value = *reinterpret_cast<const uint32_t*>(&code[i + 1]);
            foundImmediate = true;
            i += 4;
        }
        else if (code[i] == 0x48 && i + 5 < maxScanBytes && 
                 code[i + 1] >= 0xB8 && code[i + 1] <= 0xBF) {
            value = *reinterpret_cast<const uint32_t*>(&code[i + 2]);
            foundImmediate = true;
            i += 9;
        }
        
        if (foundImmediate && value > 0 && value < 0x10000000) {
            auto identified = IdentifyConstantMultiple(value);
            for (auto& ec : identified) {
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
    
    auto xrefResult = PatternScanner::GuessNameFromStringReferences(functionAddress, maxScanBytes);
    if (xrefResult) {
        result.stringRefs.push_back(xrefResult->text);
    }
    
    result.constants = AnalyzeFunctionConstants(functionAddress, maxScanBytes);
    
    auto context = InferCodeContext(result.stringRefs, result.constants);
    result.category = ToString(context);
    
    result.suggestedName = GenerateSuggestedName(result.stringRefs, result.constants, context);
    
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
    
    for (const auto& str : stringRefs) {
        if (str.length() > 3 && str.length() < 30) {
            std::string clean;
            bool prevUpper = false;
            for (char c : str) {
                if (std::isalnum(c)) {
                    clean += c;
                } else if (!clean.empty()) {
                    break;     
                }
            }
            if (clean.length() >= 3 && std::isupper(clean[0])) {
                return prefix + clean;
            }
        }
    }
    
    if (!constants.empty() && !constants.front().name.empty()) {
        std::string constName = constants.front().name;
        size_t spacePos = constName.find(' ');
        if (spacePos != std::string::npos) {
            constName = constName.substr(0, spacePos);
        }
        if (!constName.empty()) {
            constName[0] = static_cast<char>(std::toupper(constName[0]));
        }
        return prefix + constName;
    }
    
    return prefix + subject;
}

bool ScanEnrichment::LooksLikeOpcode(uint32_t value) {
    return value >= 0x0001 && value <= 0x0500;
}

bool ScanEnrichment::LooksLikeEntityId(uint32_t value) {
    return (value >= 0x10000000 && value <= 0x1FFFFFFF) ||
           (value >= 0x40000000 && value <= 0x4FFFFFFF);
}

bool ScanEnrichment::IsFunctionPrologue(const uint8_t* bytes, size_t length) {
    if (length < 3) return false;
    
    if (bytes[0] == 0x55) return true;   
    if (bytes[0] == 0x53) return true;   
    if (length >= 4 && bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC) {
        return true;    
    }
    if (length >= 5 && bytes[0] == 0x48 && bytes[1] == 0x89 && 
        (bytes[2] == 0x5C || bytes[2] == 0x6C || bytes[2] == 0x74 || bytes[2] == 0x7C)) {
        return true;    
    }
    
    return false;
}

}   
