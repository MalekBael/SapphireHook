#pragma once
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace SapphireHook {

    // Family of generic prototypes we support dynamically.
    enum class HookProtoFamily {
        Exd_GetById,   // e.g., Client::ExdData::getClassJob (this, id) -> u64
        Exd_RowCount   // e.g., Client::ExdData::getX::rowCount (this) -> u32
    };

    struct DynamicHookSpec {
        std::string name;     // logical function name (from signatures)
        uintptr_t   address;  // resolved address from signatures
        HookProtoFamily family;
    };

    // Install a hook using the generic pool for the given family.
    // Returns true if created+enabled. The hook is registered with HookManager.
    bool InstallDynamicHook(const DynamicHookSpec& spec);

    // Convenience: heuristically pick family from name (ExdData patterns).
    std::optional<HookProtoFamily> InferFamilyFromName(const std::string& name);

} // namespace SapphireHook