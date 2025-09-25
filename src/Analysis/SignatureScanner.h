#pragma once
#include <optional>
#include <string_view>
#include <unordered_map>
#include <filesystem>

namespace SapphireHook {

    class SignatureScanner {
    private:
        struct CachedSignature {
            uintptr_t address;
            std::string signature;
            std::chrono::time_point<std::chrono::system_clock> timestamp;
        };

        static inline std::unordered_map<std::string, CachedSignature> s_signature_cache;
        static inline std::filesystem::path s_cache_file = "signatures.cache";

    public:
        // Main scanning function with caching
        static std::optional<uintptr_t> ScanSignature(std::string_view signature, std::string_view name = "");

        // Text section scanning (safer)
        static std::optional<uintptr_t> ScanTextSection(std::string_view signature);

        // Data section scanning
        static std::optional<uintptr_t> ScanDataSection(std::string_view signature);

        // Cache management (inspired by Dalamud)
        static void LoadCache();
        static void SaveCache();
        static void ClearCache();

        // Validation and safety
        static bool ValidateSignature(std::string_view signature);
        static bool IsAddressInTextSection(uintptr_t address);
    };

}