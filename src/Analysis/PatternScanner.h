#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>
#include <memory>
#include <string>
#include <cstring>
#include <span>
#include <string_view>
#include <optional>
#include <concepts>
#include <map>
#include <unordered_map>
#include <unordered_set>

// Windows PE headers for string xref functionality
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winnt.h>

// Protect against Windows max macro
#ifdef max
#undef max
#endif

#ifdef min
#undef min
#endif

// C++23 feature detection and fallbacks
#if __cpp_lib_expected >= 202202L
#include <expected>
#define SAPPHIRE_HAS_EXPECTED 1
#else
#define SAPPHIRE_HAS_EXPECTED 0
#endif

#if __cpp_lib_stacktrace >= 202011L
#include <stacktrace>
#define SAPPHIRE_HAS_STACKTRACE 1
#else
#define SAPPHIRE_HAS_STACKTRACE 0
#endif

#if __cpp_lib_print >= 202207L
#include <print>
#define SAPPHIRE_HAS_PRINT 1
#else
#define SAPPHIRE_HAS_PRINT 0
#include <cstdio>  // Fallback to printf
#endif

namespace SapphireHook {

    // Error types for better error handling
    enum class ScanError {
        InvalidPattern,
        NotFound,
        MemoryAccessViolation,
        InvalidAddress,
        CacheCorrupted,
        ModuleNotFound
    };

    // Helper to convert ScanError to string
    inline const char* ToString(ScanError error)
    {
        switch (error)
        {
        case ScanError::InvalidPattern: return "Invalid Pattern";
        case ScanError::NotFound: return "Pattern Not Found";
        case ScanError::MemoryAccessViolation: return "Memory Access Violation";
        case ScanError::InvalidAddress: return "Invalid Address";
        case ScanError::CacheCorrupted: return "Cache Corrupted";
        case ScanError::ModuleNotFound: return "Module Not Found";
        default: return "Unknown Error";
        }
    }

#if SAPPHIRE_HAS_EXPECTED
    // C++23 std::expected
    template<typename T>
    using Expected = std::expected<T, ScanError>;
#else
    // Fallback: custom expected-like class with proper initialization
    template<typename T>
    class Expected {
        std::optional<T> m_value;
        ScanError m_error = ScanError::NotFound;
        bool m_hasError;

    public:
        Expected(T value) : m_value(std::move(value)), m_hasError(false) {}
        Expected(ScanError error) : m_error(error), m_hasError(true) {}

        bool has_value() const { return !m_hasError; }
        explicit operator bool() const { return has_value(); }

        const T& value() const { return *m_value; }
        T& value() { return *m_value; }
        const T& operator*() const { return value(); }
        T& operator*() { return value(); }

        ScanError error() const { return m_error; }
    };
#endif

    // Modern C++20/23 memory buffer class
    class MemoryBuffer {
    private:
        std::unique_ptr<uint8_t[]> m_data;
        size_t m_size;

    public:
        explicit MemoryBuffer(size_t size) : m_size(size)
        {
            m_data = std::make_unique<uint8_t[]>(size);
        }

        // C++20 span interface
        std::span<uint8_t> GetSpan() const
        {
            return std::span<uint8_t>(m_data.get(), m_size);
        }

        std::span<const uint8_t> GetConstSpan() const
        {
            return std::span<const uint8_t>(m_data.get(), m_size);
        }

        // Raw access
        uint8_t* Data() const { return m_data.get(); }
        size_t Size() const { return m_size; }

        // Iterator support for C++20 ranges
        uint8_t* begin() const { return m_data.get(); }
        uint8_t* end() const { return m_data.get() + m_size; }

        // Element access
        uint8_t& operator[](size_t index) { return m_data[index]; }
        const uint8_t& operator[](size_t index) const { return m_data[index]; }

        // Utility methods
        void Zero() { std::memset(m_data.get(), 0, m_size); }
        void Fill(uint8_t value) { std::memset(m_data.get(), value, m_size); }
    };

    // C++20 concept for scannable memory ranges
    template<typename T>
    concept ScanableMemory = requires(T t)
    {
        { t.data() } -> std::convertible_to<const uint8_t*>;
        { t.size() } -> std::convertible_to<size_t>;
    };

    // ===== STRING XREF FUNCTIONALITY =====

    // String cross-reference result
    struct StringXrefResult {
        std::string text;
        uintptr_t stringAddress = 0;
        uintptr_t referenceAddress = 0;
        bool isUtf16 = false;
        
        explicit operator bool() const { return !text.empty() && stringAddress != 0; }
    };

    // Function to strings mapping result
    struct FunctionStringMap {
        // Function start -> strings it references
        std::unordered_map<uintptr_t, std::vector<std::string>> functionsToStrings;
        // String text -> function starts referencing it
        std::unordered_map<std::string, std::vector<uintptr_t>> stringsToFunctions;
        size_t asciiStringCount = 0;
        size_t utf16StringCount = 0;
    };

    // PE section information
    struct PESection {
        std::byte* baseAddress = nullptr;
        size_t size = 0;
        std::string name;
        
        explicit operator bool() const { return baseAddress != nullptr && size > 0; }
    };



    // Legacy PatternScanner class - enhanced with caching support
    class PatternScanner {
    public:
        // Pattern result with proper initialization
        struct ScanResult {
            uintptr_t address = 0;
            size_t offset = 0;
            std::vector<uint8_t> matched_bytes;
            bool fromCache = false;

            // Default constructor
            ScanResult() = default;

            // Constructor with parameters
            ScanResult(uintptr_t addr, size_t off) : address(addr), offset(off) {}

            explicit operator bool() const { return address != 0; }
        };

        // Modern pattern parsing with string_view
        static std::optional<std::vector<int>> PatternToBytes(std::string_view pattern);

        // Enhanced pattern scanning with multiple overloads (C++20 style)
        static std::optional<ScanResult> ScanPattern(uintptr_t start, size_t length, std::string_view pattern);
        static std::optional<ScanResult> ScanPattern(const MemoryBuffer& buffer, std::string_view pattern);

        // C++20 concepts-based scanning
        template<ScanableMemory T>
        static std::optional<ScanResult> ScanPattern(const T& memory, std::string_view pattern)
        {
            return ScanPattern(reinterpret_cast<uintptr_t>(memory.data()), memory.size(), pattern);
        }

        // Find all pattern matches
        static std::vector<ScanResult> ScanAllPatterns(uintptr_t start, size_t length, std::string_view pattern);
        static std::vector<ScanResult> ScanAllPatterns(const MemoryBuffer& buffer, std::string_view pattern);

        // Advanced pattern matching with masks
        static std::optional<ScanResult> ScanPatternWithMask(uintptr_t start, size_t length,
            std::span<const uint8_t> pattern,
            std::span<const bool> mask);

        // Module scanning utilities
        static std::optional<ScanResult> ScanModule(const wchar_t* moduleName, std::string_view pattern);
        static std::optional<ScanResult> ScanMainModule(std::string_view pattern);

        // C++23 style expected variants
        static Expected<ScanResult> ScanPatternExpected(uintptr_t start, size_t length, std::string_view pattern);
        static Expected<ScanResult> ScanPatternExpected(const MemoryBuffer& buffer, std::string_view pattern);

        // C++23 concepts-based expected scanning
        template<ScanableMemory T>
        static Expected<ScanResult> ScanPatternExpected(const T& memory, std::string_view pattern)
        {
            return ScanPatternExpected(reinterpret_cast<uintptr_t>(memory.data()), memory.size(), pattern);
        }

        // ===== STRING XREF FUNCTIONALITY =====

        // PE section utilities
        static PESection GetPESection(HMODULE module, const char* sectionName);
        
        // String enumeration
        static std::vector<std::pair<uintptr_t, std::string>> EnumerateAsciiStrings(
            HMODULE module, size_t minLength = 6);
        static std::vector<std::pair<uintptr_t, std::string>> EnumerateUtf16Strings(
            HMODULE module, size_t minLength = 6);
        
        // RIP-relative instruction analysis
        static bool ParseRipRelativeInstruction(const std::byte* instruction, 
            uintptr_t& target, size_t& instructionLength);
        static std::vector<uintptr_t> FindRipReferencesTo(HMODULE module, uintptr_t targetAddress);
        
        // Function analysis
        static uintptr_t GetFunctionStartFromRva(HMODULE module, uint32_t rva);
        static std::vector<uintptr_t> FindFunctionsReferencingString(HMODULE module, std::string_view searchString);
        
        // High-level string cross-reference mapping
        static FunctionStringMap MapFunctionsToStrings(HMODULE module, size_t minStringLength = 6);
        static std::optional<StringXrefResult> GuessNameFromStringReferences(
            uintptr_t functionAddress, size_t maxScanBytes = 0x300);

        // Enhanced error logging (with fallback)
        static void LogScanError(ScanError error, std::string_view context);

    private:
        static bool CompareBytes(const uint8_t* data, const std::vector<int>& pattern);
        
        // String xref helpers
        static std::vector<std::byte*> FindAsciiInBuffer(std::byte* buffer, size_t length, std::string_view needle);
        static std::vector<std::byte*> FindUtf16InBuffer(std::byte* buffer, size_t length, std::wstring_view needle);
    };

} // namespace SapphireHook

// Legacy C-style functions for backward compatibility
extern "C" {
    bool PatternToBytes(const char* pattern, std::vector<int>& bytes);
    uintptr_t patternscan(uintptr_t start, size_t length, const char* pattern);
    uintptr_t GetModuleBaseAddress(const wchar_t* moduleName, size_t& outSize);
}