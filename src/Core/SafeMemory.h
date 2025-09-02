#pragma once
#include <memory>
#include <span>
#include <string>
#include <cstdint>
#include <windows.h>

namespace SapphireHook {

    // RAII wrapper for memory operations (inspired by Dalamud's safety)
    class SafeMemoryRegion {
    private:
        uintptr_t m_address;
        size_t m_size;
        DWORD m_old_protect;
        bool m_is_protected;

    public:
        SafeMemoryRegion(uintptr_t address, size_t size);
        ~SafeMemoryRegion();

        // Non-copyable but movable (modern C++)
        SafeMemoryRegion(const SafeMemoryRegion&) = delete;
        SafeMemoryRegion& operator=(const SafeMemoryRegion&) = delete;
        SafeMemoryRegion(SafeMemoryRegion&&) noexcept;
        SafeMemoryRegion& operator=(SafeMemoryRegion&&) noexcept;

        // Safe memory access
        std::span<uint8_t> GetWritableSpan();
        std::span<const uint8_t> GetReadableSpan() const;

        // Validation
        bool IsValid() const;
        bool IsWritable() const;
    };

    // Memory validation functions (like Dalamud's validation)
    bool IsValidMemoryAddress(uintptr_t address, size_t size = 1);
    bool IsExecutableMemory(uintptr_t address);
    bool IsWithinModuleBounds(uintptr_t address, const std::string& module_name = "");

}