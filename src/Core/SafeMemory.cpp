#include "SafeMemory.h"
#include <windows.h>
#include <Psapi.h>

namespace SapphireHook {

    // SafeMemoryRegion implementation
    SafeMemoryRegion::SafeMemoryRegion(uintptr_t address, size_t size)
        : m_address(address), m_size(size), m_old_protect(0), m_is_protected(false)
    {

        // Make memory writable
        if (VirtualProtect(reinterpret_cast<LPVOID>(address), size, PAGE_EXECUTE_READWRITE, &m_old_protect))
        {
            m_is_protected = true;
        }
    }

    SafeMemoryRegion::~SafeMemoryRegion()
    {
        if (m_is_protected)
        {
            DWORD dummy;
            VirtualProtect(reinterpret_cast<LPVOID>(m_address), m_size, m_old_protect, &dummy);
        }
    }

    SafeMemoryRegion::SafeMemoryRegion(SafeMemoryRegion&& other) noexcept
        : m_address(other.m_address), m_size(other.m_size),
        m_old_protect(other.m_old_protect), m_is_protected(other.m_is_protected)
    {
        other.m_is_protected = false;
    }

    SafeMemoryRegion& SafeMemoryRegion::operator=(SafeMemoryRegion&& other) noexcept
    {
        if (this != &other)
        {
            if (m_is_protected)
            {
                DWORD dummy;
                VirtualProtect(reinterpret_cast<LPVOID>(m_address), m_size, m_old_protect, &dummy);
            }

            m_address = other.m_address;
            m_size = other.m_size;
            m_old_protect = other.m_old_protect;
            m_is_protected = other.m_is_protected;
            other.m_is_protected = false;
        }
        return *this;
    }

    std::span<uint8_t> SafeMemoryRegion::GetWritableSpan()
    {
        if (!IsValid()) return {};
        return std::span<uint8_t>(reinterpret_cast<uint8_t*>(m_address), m_size);
    }

    std::span<const uint8_t> SafeMemoryRegion::GetReadableSpan() const
    {
        if (!IsValid()) return {};
        return std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(m_address), m_size);
    }

    bool SafeMemoryRegion::IsValid() const
    {
        return m_is_protected && IsValidMemoryAddress(m_address, m_size);
    }

    bool SafeMemoryRegion::IsWritable() const
    {
        return IsValid();
    }

    // Memory validation functions implementation
    bool IsValidMemoryAddress(uintptr_t address, size_t size)
    {
		// CHANGE NOTE (2025-12-15): Strengthen range validation.
		// - Reject PAGE_GUARD/PAGE_NOACCESS, and require an actually-readable page protection.
		// - Use overflow-safe end computation before comparing against region bounds.
        if (address == 0 || size == 0) return false;

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0)
            return false;

        if (mbi.State != MEM_COMMIT) return false;
        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;

        const DWORD acc = (mbi.Protect & 0xFF);
        const bool readable =
            acc == PAGE_READONLY || acc == PAGE_READWRITE ||
            acc == PAGE_WRITECOPY ||
            acc == PAGE_EXECUTE_READ || acc == PAGE_EXECUTE_READWRITE ||
            acc == PAGE_EXECUTE_WRITECOPY;
        if (!readable) return false;

        const uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const uintptr_t regionEnd = regionBase + static_cast<uintptr_t>(mbi.RegionSize);
        if (address < regionBase) return false;
        if (address > regionEnd) return false;
        const uintptr_t end = address + static_cast<uintptr_t>(size);
        if (end < address) return false; // overflow
        return end <= regionEnd;
    }

    bool IsExecutableMemory(uintptr_t address)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0)
        {
            return false;
        }

        return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    }

    bool IsWithinModuleBounds(uintptr_t address, const std::string& module_name)
    {
        HMODULE hModule = module_name.empty() ? GetModuleHandleW(NULL) : GetModuleHandleA(module_name.c_str());
        if (!hModule) return false;

        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo)))
        {
            return false;
        }

        uintptr_t moduleBase = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
        return (address >= moduleBase && address < moduleBase + modInfo.SizeOfImage);
    }

} // namespace SapphireHook