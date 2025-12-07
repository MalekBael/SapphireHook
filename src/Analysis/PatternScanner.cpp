#include "PatternScanner.h"
#include "../Logger/Logger.h"
#include "../Helper/WindowsAPIWrapper.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <Psapi.h>
#pragma comment(lib, "psapi.lib")

namespace SapphireHook {

    std::optional<std::vector<int>> PatternScanner::PatternToBytes(std::string_view pattern)
    {
        std::vector<int> bytes;
        std::string patternStr(pattern);

        size_t start = 0;
        size_t end = 0;

        while (end != std::string::npos)
        {
            end = patternStr.find(' ', start);
            std::string token = patternStr.substr(start, (end == std::string::npos) ? std::string::npos : end - start);

            token.erase(0, token.find_first_not_of(" \t\r\n"));
            token.erase(token.find_last_not_of(" \t\r\n") + 1);

            if (!token.empty())
            {
                if (token == "?" || token == "??")
                {
                    bytes.push_back(-1);
                }
                else
                {
                    try
                    {
                        int byte = std::stoi(token, nullptr, 16);
                        if (byte >= 0 && byte <= 255)
                        {
                            bytes.push_back(byte);
                        }
                        else
                        {
                            return std::nullopt;
                        }
                    }
                    catch (...)
                    {
                        return std::nullopt;
                    }
                }
            }

            start = (end == std::string::npos) ? end : end + 1;
        }

        return bytes;
    }

    std::optional<PatternScanner::ScanResult> PatternScanner::ScanPattern(uintptr_t start, size_t length, std::string_view pattern)
    {
        auto bytes = PatternToBytes(pattern);
        if (!bytes) return std::nullopt;

        const uint8_t* memory = reinterpret_cast<const uint8_t*>(start);

        for (size_t i = 0; i <= length - bytes->size(); ++i)
        {
            if (CompareBytes(memory + i, *bytes))
            {
                ScanResult result;
                result.address = start + i;
                result.offset = i;
                result.matched_bytes.assign(memory + i, memory + i + bytes->size());
                return result;
            }
        }

        return std::nullopt;
    }

    std::optional<PatternScanner::ScanResult> PatternScanner::ScanPattern(const MemoryBuffer& buffer, std::string_view pattern)
    {
        return ScanPattern(reinterpret_cast<uintptr_t>(buffer.Data()), buffer.Size(), pattern);
    }

    std::vector<PatternScanner::ScanResult> PatternScanner::ScanAllPatterns(uintptr_t start, size_t length, std::string_view pattern)
    {
        std::vector<ScanResult> results;
        auto bytes = PatternToBytes(pattern);
        if (!bytes) return results;

        const uint8_t* memory = reinterpret_cast<const uint8_t*>(start);

        for (size_t i = 0; i <= length - bytes->size(); ++i)
        {
            if (CompareBytes(memory + i, *bytes))
            {
                ScanResult result;
                result.address = start + i;
                result.offset = i;
                result.matched_bytes.assign(memory + i, memory + i + bytes->size());
                results.push_back(result);
            }
        }

        return results;
    }

    std::vector<PatternScanner::ScanResult> PatternScanner::ScanAllPatterns(const MemoryBuffer& buffer, std::string_view pattern)
    {
        return ScanAllPatterns(reinterpret_cast<uintptr_t>(buffer.Data()), buffer.Size(), pattern);
    }

    std::optional<PatternScanner::ScanResult> PatternScanner::ScanPatternWithMask(uintptr_t start, size_t length,
        std::span<const uint8_t> pattern, std::span<const bool> mask)
    {
        if (pattern.size() != mask.size()) return std::nullopt;

        const uint8_t* memory = reinterpret_cast<const uint8_t*>(start);

        for (size_t i = 0; i <= length - pattern.size(); ++i)
        {
            bool match = true;
            for (size_t j = 0; j < pattern.size(); ++j)
            {
                if (mask[j] && memory[i + j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                ScanResult result;
                result.address = start + i;
                result.offset = i;
                result.matched_bytes.assign(memory + i, memory + i + pattern.size());
                return result;
            }
        }

        return std::nullopt;
    }

    std::optional<PatternScanner::ScanResult> PatternScanner::ScanModule(const wchar_t* moduleName, std::string_view pattern)
    {
        size_t moduleSize = 0;
        uintptr_t moduleBase = GetModuleBaseAddress(moduleName, moduleSize);

        if (moduleBase == 0) return std::nullopt;

        return ScanPattern(moduleBase, moduleSize, pattern);
    }

    std::optional<PatternScanner::ScanResult> PatternScanner::ScanMainModule(std::string_view pattern)
    {
        return ScanModule(L"ffxiv_dx11.exe", pattern);
    }

    Expected<PatternScanner::ScanResult> PatternScanner::ScanPatternExpected(uintptr_t start, size_t length, std::string_view pattern)
    {
        auto result = ScanPattern(start, length, pattern);
        if (result)
        {
            return Expected<ScanResult>(*result);
        }
        else
        {
            return Expected<ScanResult>(ScanError::NotFound);
        }
    }

    Expected<PatternScanner::ScanResult> PatternScanner::ScanPatternExpected(const MemoryBuffer& buffer, std::string_view pattern)
    {
        return ScanPatternExpected(reinterpret_cast<uintptr_t>(buffer.Data()), buffer.Size(), pattern);
    }

    void PatternScanner::LogScanError(ScanError error, std::string_view context)
    {
#if SAPPHIRE_HAS_PRINT && SAPPHIRE_HAS_STACKTRACE
        auto trace = std::stacktrace::current();
        std::println("[PatternScanner] Error: {} in context: {}", ToString(error), context);
        std::println("Stack trace:");
        for (const auto& entry : trace)
        {
            std::println("  {}", entry.description());
        }
#elif SAPPHIRE_HAS_PRINT
        std::println("[PatternScanner] Error: {} in context: {}", ToString(error), context);
#else
        printf("[PatternScanner] Error: %s in context: %.*s\n",
            ToString(error), static_cast<int>(context.size()), context.data());
#endif
    }

    bool PatternScanner::CompareBytes(const uint8_t* data, const std::vector<int>& pattern)
    {
        for (size_t i = 0; i < pattern.size(); ++i)
        {
            if (pattern[i] != -1 && static_cast<uint8_t>(pattern[i]) != data[i])
            {
                return false;
            }
        }
        return true;
    }

    // ===== STRING XREF FUNCTIONALITY =====

    PESection PatternScanner::GetPESection(HMODULE module, const char* sectionName)
    {
        PESection result;

        auto base = reinterpret_cast<std::byte*>(module);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return result;

        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return result;

        auto sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            char secName[9] = { 0 };
            std::memcpy(secName, sec[i].Name, 8);

            if (std::string_view(secName) == sectionName)
            {
                result.baseAddress = base + sec[i].VirtualAddress;
                result.size = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
                result.name = secName;
                break;
            }
        }

        return result;
    }

    std::vector<std::byte*> PatternScanner::FindAsciiInBuffer(std::byte* buffer, size_t length, std::string_view needle)
    {
        std::vector<std::byte*> hits;
        if (needle.empty() || !buffer || length < needle.size()) return hits;

        auto* b = reinterpret_cast<const char*>(buffer);
        auto* e = b + length - needle.size() + 1;

        for (auto* p = b; p < e; ++p)
        {
            if (p[0] == needle[0] && std::memcmp(p, needle.data(), needle.size()) == 0)
            {
                hits.push_back(reinterpret_cast<std::byte*>(const_cast<char*>(p)));
            }
        }

        return hits;
    }

    std::vector<std::byte*> PatternScanner::FindUtf16InBuffer(std::byte* buffer, size_t length, std::wstring_view needle)
    {
        std::vector<std::byte*> hits;
        if (needle.empty() || !buffer) return hits;

        const size_t needleBytes = needle.size() * sizeof(wchar_t);
        if (length < needleBytes) return hits;

        auto* b = reinterpret_cast<const wchar_t*>(buffer);
        auto wlen = length / sizeof(wchar_t);
        auto* e = b + wlen - needle.size() + 1;

        for (auto* p = b; p < e; ++p)
        {
            if (p[0] == needle[0] && std::memcmp(p, needle.data(), needleBytes) == 0)
            {
                hits.push_back(reinterpret_cast<std::byte*>(const_cast<wchar_t*>(p)));
            }
        }

        return hits;
    }

    bool PatternScanner::ParseRipRelativeInstruction(const std::byte* instruction, uintptr_t& target, size_t& instructionLength)
    {
        const bool hasRex = (instruction[0] >= std::byte{ 0x40 } && instruction[0] <= std::byte{ 0x4F });
        const size_t opOffset = hasRex ? 1 : 0;
        const size_t modrmOffset = opOffset + 1;
        const size_t dispOffset = modrmOffset + 1;
        const size_t minLength = hasRex ? 7 : 6;

        const std::byte opcode = instruction[opOffset];
        if (!(opcode == std::byte{ 0x8D } || opcode == std::byte{ 0x8B })) return false;

        const unsigned modrm = static_cast<unsigned>(instruction[modrmOffset]);
        const unsigned mod = (modrm >> 6) & 0x3;
        const unsigned rm = modrm & 0x7;
        if (!(mod == 0 && rm == 5)) return false;

        const int32_t displacement = *reinterpret_cast<const int32_t*>(instruction + dispOffset);
        const auto* nextInstruction = instruction + minLength;
        const auto nextAddress = reinterpret_cast<uintptr_t>(nextInstruction);

        target = static_cast<uintptr_t>(static_cast<intptr_t>(nextAddress) + displacement);
        instructionLength = minLength;
        return true;
    }

    std::vector<uintptr_t> PatternScanner::FindRipReferencesTo(HMODULE module, uintptr_t targetAddress)
    {
        std::vector<uintptr_t> references;

        auto textSection = GetPESection(module, ".text");
        if (!textSection || textSection.size < 6) return references;

        const auto* begin = textSection.baseAddress;
        const auto* end = textSection.baseAddress + textSection.size - 6;

        for (const auto* p = begin; p <= end; ++p)
        {
            uintptr_t target = 0;
            size_t instructionLength = 0;

            if (!ParseRipRelativeInstruction(p, target, instructionLength)) continue;

            if (target == targetAddress)
            {
                references.push_back(reinterpret_cast<uintptr_t>(p));
            }
        }

        return references;
    }

    uintptr_t PatternScanner::GetFunctionStartFromRva(HMODULE module, uint32_t rva)
    {
        auto base = reinterpret_cast<std::byte*>(module);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);

        const IMAGE_DATA_DIRECTORY& exceptionDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (exceptionDir.VirtualAddress == 0 || exceptionDir.Size == 0) return 0;

        using RUNTIME_FUNCTION = IMAGE_RUNTIME_FUNCTION_ENTRY;
        auto* runtimeFunctions = reinterpret_cast<RUNTIME_FUNCTION*>(base + exceptionDir.VirtualAddress);
        auto count = exceptionDir.Size / sizeof(RUNTIME_FUNCTION);

        size_t low = 0, high = count;
        while (low < high)
        {
            size_t mid = (low + high) / 2;
            auto begin = runtimeFunctions[mid].BeginAddress;
            auto end = runtimeFunctions[mid].EndAddress;

            if (rva < begin)
            {
                high = mid;
            }
            else if (rva >= end)
            {
                low = mid + 1;
            }
            else
            {
                return reinterpret_cast<uintptr_t>(module) + begin;
            }
        }
        return 0;
    }

    std::vector<std::pair<uintptr_t, std::string>> PatternScanner::EnumerateAsciiStrings(HMODULE module, size_t minLength)
    {
        std::vector<std::pair<uintptr_t, std::string>> result;

        auto rdataSection = GetPESection(module, ".rdata");
        if (!rdataSection) return result;

        const auto* bytes = reinterpret_cast<const unsigned char*>(rdataSection.baseAddress);
        size_t i = 0;

        while (i < rdataSection.size)
        {
            size_t start = i;
            size_t length = 0;

            while (i < rdataSection.size)
            {
                unsigned char c = bytes[i];
                if (c >= 0x20 && c <= 0x7E)
                {
                    ++i;
                    ++length;
                }
                else
                {
                    break;
                }
            }

            if (length >= minLength && i < rdataSection.size && bytes[i] == 0x00)
            {
                auto address = reinterpret_cast<uintptr_t>(rdataSection.baseAddress + start);
                std::string text(reinterpret_cast<const char*>(bytes + start), length);
                result.emplace_back(address, std::move(text));
                ++i;
            }
            else
            {
                if (i < rdataSection.size && bytes[i] == 0x00) ++i;
                else i = start + 1;
            }
        }

        return result;
    }

    std::vector<std::pair<uintptr_t, std::string>> PatternScanner::EnumerateUtf16Strings(HMODULE module, size_t minLength)
    {
        std::vector<std::pair<uintptr_t, std::string>> result;

        auto rdataSection = GetPESection(module, ".rdata");
        if (!rdataSection || rdataSection.size < 4) return result;

        const auto* bytes = reinterpret_cast<const unsigned char*>(rdataSection.baseAddress);
        size_t i = 0;

        while (i + 1 < rdataSection.size)
        {
            size_t start = i;
            size_t charCount = 0;

            while (i + 1 < rdataSection.size)
            {
                unsigned char low = bytes[i];
                unsigned char high = bytes[i + 1];

                if (high == 0x00 && low >= 0x20 && low <= 0x7E)
                {
                    i += 2;
                    ++charCount;
                }
                else
                {
                    break;
                }
            }

            if (charCount >= minLength && i + 1 < rdataSection.size &&
                bytes[i] == 0x00 && bytes[i + 1] == 0x00)
            {
                auto address = reinterpret_cast<uintptr_t>(rdataSection.baseAddress + start);

                std::string text;
                text.reserve(charCount);
                for (size_t j = 0; j < charCount; ++j)
                {
                    text.push_back(static_cast<char>(bytes[start + j * 2]));
                }

                result.emplace_back(address, std::move(text));
                i += 2;
            }
            else
            {
                if (i + 1 < rdataSection.size && bytes[i] == 0x00 && bytes[i + 1] == 0x00) i += 2;
                else ++i;
            }
        }

        return result;
    }

    std::vector<uintptr_t> PatternScanner::FindFunctionsReferencingString(HMODULE module, std::string_view searchString)
    {
        std::vector<uintptr_t> result;

        auto rdataSection = GetPESection(module, ".rdata");
        if (!rdataSection) return result;

        auto asciiHits = FindAsciiInBuffer(rdataSection.baseAddress, rdataSection.size, searchString);

        std::wstring wideNeedle(searchString.begin(), searchString.end());
        auto utf16Hits = FindUtf16InBuffer(rdataSection.baseAddress, rdataSection.size, wideNeedle);

        std::vector<uintptr_t> targets;
        targets.reserve(asciiHits.size() + utf16Hits.size());

        for (auto* ptr : asciiHits)
        {
            targets.push_back(reinterpret_cast<uintptr_t>(ptr));
        }
        for (auto* ptr : utf16Hits)
        {
            targets.push_back(reinterpret_cast<uintptr_t>(ptr));
        }

        for (auto address : targets)
        {
            auto references = FindRipReferencesTo(module, address);
            for (auto ref : references)
            {
                auto rva = static_cast<uint32_t>(ref - reinterpret_cast<uintptr_t>(module));
                auto functionStart = GetFunctionStartFromRva(module, rva);
                if (functionStart != 0)
                {
                    result.push_back(functionStart);
                }
            }
        }

        std::sort(result.begin(), result.end());
        result.erase(std::unique(result.begin(), result.end()), result.end());

        return result;
    }

    FunctionStringMap PatternScanner::MapFunctionsToStrings(HMODULE module, size_t minStringLength)
    {
        FunctionStringMap result;

        auto asciiStrings = EnumerateAsciiStrings(module, minStringLength);
        auto utf16Strings = EnumerateUtf16Strings(module, minStringLength);

        result.asciiStringCount = asciiStrings.size();
        result.utf16StringCount = utf16Strings.size();

        std::unordered_set<std::string> functionStringsSeen;
        std::unordered_map<uintptr_t, std::unordered_set<std::string>> functionStringsMap;

        auto processString = [&](uintptr_t stringAddress, const std::string& text)
            {
                auto references = FindRipReferencesTo(module, stringAddress);
                for (auto ref : references)
                {
                    auto rva = static_cast<uint32_t>(ref - reinterpret_cast<uintptr_t>(module));
                    auto functionStart = GetFunctionStartFromRva(module, rva);
                    if (!functionStart) continue;

                    auto& seenStrings = functionStringsMap[functionStart];
                    if (seenStrings.insert(text).second)
                    {
                        result.functionsToStrings[functionStart].push_back(text);
                    }

                    auto& functionVector = result.stringsToFunctions[text];
                    if (functionVector.empty() || functionVector.back() != functionStart)
                    {
                        functionVector.push_back(functionStart);
                    }
                }
            };

        for (const auto& [addr, text] : asciiStrings)
        {
            processString(addr, text);
        }
        for (const auto& [addr, text] : utf16Strings)
        {
            processString(addr, text);
        }

        for (auto& [func, strings] : result.functionsToStrings)
        {
            std::sort(strings.begin(), strings.end());
            strings.erase(std::unique(strings.begin(), strings.end()), strings.end());
        }
        for (auto& [text, functions] : result.stringsToFunctions)
        {
            std::sort(functions.begin(), functions.end());
            functions.erase(std::unique(functions.begin(), functions.end()), functions.end());
        }

        return result;
    }

    std::optional<StringXrefResult> PatternScanner::GuessNameFromStringReferences(uintptr_t functionAddress, size_t maxScanBytes)
    {
        auto textSection = GetPESection(GetModuleHandleW(nullptr), ".text");
        auto rdataSection = GetPESection(GetModuleHandleW(nullptr), ".rdata");
        if (!textSection || !rdataSection) return std::nullopt;

        if (functionAddress < reinterpret_cast<uintptr_t>(textSection.baseAddress) ||
            functionAddress >= reinterpret_cast<uintptr_t>(textSection.baseAddress) + textSection.size)
        {
            return std::nullopt;
        }

        const auto* code = reinterpret_cast<const std::byte*>(functionAddress);
        const auto* textEnd = textSection.baseAddress + textSection.size;
        const size_t maxScan = std::min(maxScanBytes,
            static_cast<size_t>(textEnd - reinterpret_cast<const std::byte*>(code)));

        std::string bestCandidate;
        uintptr_t bestStringAddress = 0;
        uintptr_t bestReferenceAddress = 0;
        bool bestIsUtf16 = false;

        for (size_t i = 0; i + 6 <= maxScan; )
        {
            uintptr_t target = 0;
            size_t instructionLength = 0;

            if (!ParseRipRelativeInstruction(code + i, target, instructionLength))
            {
                ++i;
                continue;
            }
            i += instructionLength;

            if (target < reinterpret_cast<uintptr_t>(rdataSection.baseAddress) ||
                target >= reinterpret_cast<uintptr_t>(rdataSection.baseAddress) + rdataSection.size)
            {
                continue;
            }

            const char* str = reinterpret_cast<const char*>(target);
            std::string candidate;

            size_t maxLen = std::min<size_t>(128,
                reinterpret_cast<const char*>(rdataSection.baseAddress + rdataSection.size) - str);

            for (size_t j = 0; j < maxLen; ++j)
            {
                char c = str[j];
                if (c == '\0') break;
                if (c < 0x20 || c > 0x7E)
                {
                    candidate.clear();
                    break;
                }
                candidate.push_back(c);
            }

            bool isUtf16 = false;
            if (candidate.empty())
            {
                const unsigned char* ptr = reinterpret_cast<const unsigned char*>(target);
                std::string utf8Candidate;
                maxLen = std::min<size_t>(256,
                    reinterpret_cast<const unsigned char*>(rdataSection.baseAddress + rdataSection.size) - ptr);

                for (size_t j = 0; j + 1 < maxLen; j += 2)
                {
                    unsigned char low = ptr[j], high = ptr[j + 1];
                    if (low == 0x00 && high == 0x00) break;
                    if (high != 0x00 || low < 0x20 || low > 0x7E)
                    {
                        utf8Candidate.clear();
                        break;
                    }
                    utf8Candidate.push_back(static_cast<char>(low));
                }

                if (!utf8Candidate.empty())
                {
                    candidate = std::move(utf8Candidate);
                    isUtf16 = true;
                }
                else
                {
                    continue;
                }
            }

            while (!candidate.empty() &&
                (candidate.back() == '.' || candidate.back() == ':' || candidate.back() == ' '))
            {
                candidate.pop_back();
            }

            if (!candidate.empty() && (bestCandidate.empty() || candidate.size() > bestCandidate.size()))
            {
                bestCandidate = candidate;
                bestStringAddress = target;
                bestReferenceAddress = functionAddress + i - instructionLength;
                bestIsUtf16 = isUtf16;
            }
        }

        if (bestCandidate.empty()) return std::nullopt;

        StringXrefResult result;
        result.text = bestCandidate;
        result.stringAddress = bestStringAddress;
        result.referenceAddress = bestReferenceAddress;
        result.isUtf16 = bestIsUtf16;

        return result;
    }

} // namespace SapphireHook

extern "C" {
    bool PatternToBytes(const char* pattern, std::vector<int>& bytes)
    {
        auto result = SapphireHook::PatternScanner::PatternToBytes(pattern);
        if (result)
        {
            bytes = *result;
            return true;
        }
        return false;
    }

    uintptr_t patternscan(uintptr_t start, size_t length, const char* pattern)
    {
        auto result = SapphireHook::PatternScanner::ScanPattern(start, length, pattern);
        return result ? result->address : 0;
    }

    uintptr_t GetModuleBaseAddress(const wchar_t* moduleName, size_t& outSize)
    {
        HMODULE hModule = GetModuleHandleW(moduleName);
        if (!hModule)
        {
            outSize = 0;
            return 0;
        }

        MODULEINFO moduleInfo = {};
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo)))
        {
            outSize = 0;
            return 0;
        }

        outSize = moduleInfo.SizeOfImage;
        return reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
    }
}
