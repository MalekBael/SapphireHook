#pragma once
#include "hook_manager.h"
#include "../Core/patternscanner.h"
#include "../Core/WindowsAPIWrapper.h"  // For GetModuleHandleW, GetModuleInformation
#include "../Logger/Logger.h"
#include <Psapi.h>  // For MODULEINFO
#include <sstream>

namespace SapphireHook {

    // Declaration only - implementation is in hook_manager.cpp
    extern bool GetMainModuleInfo(uintptr_t& baseAddress, size_t& moduleSize);

    // ===== HookFactory Template Implementations =====

    template<typename TDelegate>
    std::shared_ptr<IHook> HookFactory::CreateFunctionHook(const std::string& name,
        uintptr_t address,
        TDelegate detour,
        const std::string& assemblyName)
    {
        LogInfo("Creating function hook: " + name + " at 0x" + std::to_string(address));

        // Validate the address before creating the hook
        if (!HookManager::ValidateHookAddress(address))
        {
            LogError("Invalid address for hook: " + name);
            return nullptr;
        }

        // Check if hook already exists
        if (HookManager::IsAddressHooked(address))
        {
            LogWarning("Address already hooked: " + name);
            return nullptr;
        }

        // Create the hook using HookManager
        auto hook = HookManager::CreateHook(name, address, detour, assemblyName);

        if (hook)
        {
            // ...
        }

        return hook;
    }

} // namespace SapphireHook