#pragma once
#include <vector>
#include <string_view>
#include <cstdint>
#include <windows.h>

namespace rtti {

    struct VTableInfo {
        uintptr_t vtable;  // address of first function pointer slot
        uintptr_t col;     // CompleteObjectLocator address
        size_t    methods; // consecutive pointers into .text
    };

    // Find MSVC RTTI vtables for a fully-qualified type name (e.g., "Client::UI::UIModule")
    // in the given module (use GetModuleHandleW(nullptr) for the game EXE).
    std::vector<VTableInfo> FindVTablesForType(HMODULE mod, std::string_view fqName);

} // namespace rtti