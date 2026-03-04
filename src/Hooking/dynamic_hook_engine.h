#pragma once
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace SapphireHook {

    enum class HookProtoFamily {
        Exd_GetById,         
        Exd_RowCount        
    };

    struct DynamicHookSpec {
        std::string name;          
        uintptr_t   address;      
        HookProtoFamily family;
    };

    bool InstallDynamicHook(const DynamicHookSpec& spec);

    std::optional<HookProtoFamily> InferFamilyFromName(const std::string& name);

}   