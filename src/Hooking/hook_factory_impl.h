#pragma once

#include "hook_manager.h"          // Must provide IHook, HookManager::CreateHook, ValidateHookAddress, IsAddressHooked
#include "../Logger/Logger.h"

#include <memory>
#include <string>
#include <cstdint>

namespace SapphireHook {

// Provided by another translation unit (implemented in hook_manager.cpp or similar)
extern bool GetMainModuleInfo(uintptr_t& baseAddress, size_t& moduleSize);

// HookFactory: creates hooks given a detour function pointer.
// TDelegate is the detour function pointer type (e.g. decltype(&MyDetour)).
class HookFactory {
public:
    HookFactory() = default;

    template<typename TDelegate>
    std::shared_ptr<IHook> CreateFunctionHook(const std::string& name,
                                              uintptr_t address,
                                              TDelegate detour,
                                              const std::string& assemblyName = {})
    {
        LogInfo("Creating function hook: " + name + " at 0x" + std::to_string(address));

        if (address == 0) {
            LogError("HookFactory: address is null for " + name);
            return nullptr;
        }

        if (!HookManager::ValidateHookAddress(address)) {
            LogError("HookFactory: invalid address for " + name);
            return nullptr;
        }

        if (HookManager::IsAddressHooked(address)) {
            LogWarning("HookFactory: address already hooked for " + name);
            return nullptr;
        }

        auto hook = HookManager::CreateHook(name, address,
                                            reinterpret_cast<void*>(detour),
                                            assemblyName);
        if (!hook) {
            LogError("HookFactory: failed to create hook for " + name);
            return nullptr;
        }

        return hook;
    }
};

} // namespace SapphireHook