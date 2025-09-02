#pragma once
// Ensure macro hygiene even if some TU forgot to define these
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <winnt.h>
#include <cstddef>     // std::byte
#include <cstdint>
#include <cstring>     // strnlen, memcmp
#include <vector>
#include <string_view>
#include <string>
#include <algorithm>
#include <span>
#include <unordered_map>
#include <unordered_set>
#include <optional> // add this

namespace xref {

    // Simple PE section lookup
    inline std::pair<std::byte*, size_t> getSection(HMODULE module, const char* name)
    {
        auto base = reinterpret_cast<std::byte*>(module);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return { nullptr, 0 };
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return { nullptr, 0 };
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            if (std::string_view(reinterpret_cast<char*>(sec[i].Name), strnlen(reinterpret_cast<char*>(sec[i].Name), 8)) == name)
            {
                auto ptr = base + sec[i].VirtualAddress;
                size_t vsz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
                return { ptr, static_cast<size_t>(vsz) };
            }
        }
        return { nullptr, 0 };
    }

    // Find ASCII occurrences in a buffer
    inline std::vector<std::byte*> findAscii(std::byte* hay, size_t len, std::string_view needle)
    {
        std::vector<std::byte*> hits;
        if (needle.empty() || !hay || len < needle.size()) return hits;
        auto* b = reinterpret_cast<const char*>(hay);
        auto* e = b + len - needle.size() + 1;
        for (auto* p = b; p < e; ++p)
        {
            if (p[0] == needle[0] && std::memcmp(p, needle.data(), needle.size()) == 0)
            {
                hits.push_back(reinterpret_cast<std::byte*>(const_cast<char*>(p)));
            }
        }
        return hits;
    }

    // Find UTF-16LE occurrences in a buffer
    inline std::vector<std::byte*> findUtf16(std::byte* hay, size_t len, std::wstring_view needle)
    {
        std::vector<std::byte*> hits;
        if (needle.empty() || !hay) return hits;
        const size_t nbytes = needle.size() * sizeof(wchar_t);
        if (len < nbytes) return hits;
        auto* b = reinterpret_cast<const wchar_t*>(hay);
        auto wlen = len / sizeof(wchar_t);
        auto* e = b + wlen - needle.size() + 1;
        for (auto* p = b; p < e; ++p)
        {
            if (p[0] == needle[0] && std::memcmp(p, needle.data(), nbytes) == 0)
            {
                hits.push_back(reinterpret_cast<std::byte*>(const_cast<wchar_t*>(p)));
            }
        }
        return hits;
    }

    // Resolve function start for an RVA using .pdata (x64 exception directory)
    inline std::uintptr_t functionStartFromRva(HMODULE module, std::uint32_t rva)
    {
        auto base = reinterpret_cast<std::byte*>(module);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);

        const IMAGE_DATA_DIRECTORY& excDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excDir.VirtualAddress == 0 || excDir.Size == 0) return 0;

        using RUNTIME_FUNCTION = IMAGE_RUNTIME_FUNCTION_ENTRY;
        auto* rf = reinterpret_cast<RUNTIME_FUNCTION*>(base + excDir.VirtualAddress);
        auto count = excDir.Size / sizeof(RUNTIME_FUNCTION);

        // Binary search over sorted RUNTIME_FUNCTION entries
        size_t lo = 0, hi = count;
        while (lo < hi)
        {
            size_t mid = (lo + hi) / 2;
            auto begin = rf[mid].BeginAddress;
            auto end = rf[mid].EndAddress;
            if (rva < begin)
            {
                hi = mid;
            }
            else if (rva >= end)
            {
                lo = mid + 1;
            }
            else
            {
                return reinterpret_cast<std::uintptr_t>(module) + begin;
            }
        }
        return 0;
    }

    // Decode common RIP-relative forms (REX? 8D/MOV 8B) to get absolute target
    inline bool tryRipRelTarget(const std::byte* p, std::uintptr_t& target, size_t& insLen)
    {
        // Layouts:
        //  [REX] 8D ModRM(00 101 r) disp32  -> LEA r64, [RIP+disp32]
        //  [REX] 8B ModRM(00 101 r) disp32  -> MOV r64, [RIP+disp32]
        // Where REX is optional (0x40-0x4F). Length is 6 (no REX) or 7 (with REX).
        const bool hasRex = (p[0] >= std::byte{ 0x40 } && p[0] <= std::byte{ 0x4F });
        const size_t opOff = hasRex ? 1 : 0;
        const size_t modrmOff = opOff + 1;
        const size_t dispOff = modrmOff + 1;
        const size_t minLen = hasRex ? 7 : 6;

        const std::byte op = p[opOff];
        if (!(op == std::byte{ 0x8D } || op == std::byte{ 0x8B })) return false;

        const unsigned modrm = static_cast<unsigned>(p[modrmOff]);
        const unsigned mod = (modrm >> 6) & 0x3;
        const unsigned rm = modrm & 0x7;
        if (!(mod == 0 && rm == 5)) return false; // RIP-relative

        const int32_t disp = *reinterpret_cast<const int32_t*>(p + dispOff);
        const auto* next = p + minLen;
        const auto nextAbs = reinterpret_cast<std::uintptr_t>(next);
        target = static_cast<std::uintptr_t>(static_cast<std::intptr_t>(nextAbs) + disp);
        insLen = minLen;
        return true;
    }

    // Backward-compatible: now finds LEA/MOV RIP-relative references
    inline std::vector<std::uintptr_t> findRipRefsTo(HMODULE module, std::uintptr_t target)
    {
        std::vector<std::uintptr_t> refs;
        auto [text, textSize] = getSection(module, ".text");
        if (!text || textSize < 6) return refs;

        const auto* b = text;
        const auto* e = text + textSize - 6; // shortest
        for (const auto* p = b; p <= e; ++p)
        {
            std::uintptr_t abs{};
            size_t ilen{};
            if (!tryRipRelTarget(p, abs, ilen)) continue;
            if (abs == target)
            {
                refs.push_back(reinterpret_cast<std::uintptr_t>(p));
            }
        }
        return refs;
    }

    // Enumerate zero-terminated ASCII strings in .rdata
    inline std::vector<std::pair<std::uintptr_t, std::string>>
        enumerateAsciiStrings(HMODULE module, size_t minLen = 6)
    {
        std::vector<std::pair<std::uintptr_t, std::string>> out;
        auto [rdata, rlen] = getSection(module, ".rdata");
        if (!rdata || rlen == 0) return out;

        const auto* bytes = reinterpret_cast<const unsigned char*>(rdata);
        size_t i = 0;
        while (i < rlen)
        {
            size_t start = i;
            size_t len = 0;
            while (i < rlen)
            {
                unsigned char c = bytes[i];
                if (c >= 0x20 && c <= 0x7E)
                { // printable ASCII
                    ++i; ++len;
                    continue;
                }
                break;
            }
            // Require NUL terminator
            if (len >= minLen && i < rlen && bytes[i] == 0x00)
            {
                auto addr = reinterpret_cast<std::uintptr_t>(rdata + start);
                out.emplace_back(addr, std::string(reinterpret_cast<const char*>(bytes + start), len));
                ++i; // skip NUL
            }
            else
            {
                // Skip until after NUL if present, else advance one
                if (i < rlen && bytes[i] == 0x00) ++i;
                else i = start + 1;
            }
        }
        return out;
    }

    // Enumerate zero-terminated UTF-16LE strings in .rdata (ASCII subset)
    inline std::vector<std::pair<std::uintptr_t, std::string>>
        enumerateUtf16Strings(HMODULE module, size_t minLen = 6)
    {
        std::vector<std::pair<std::uintptr_t, std::string>> out;
        auto [rdata, rlen] = getSection(module, ".rdata");
        if (!rdata || rlen < 4) return out;

        const auto* b = reinterpret_cast<const unsigned char*>(rdata);
        size_t i = 0;
        while (i + 1 < rlen)
        {
            size_t start = i;
            size_t chars = 0;
            // Collect ASCII-range UTF-16LE chars (xx 00)
            while (i + 1 < rlen)
            {
                unsigned char lo = b[i];
                unsigned char hi = b[i + 1];
                if (hi == 0x00 && lo >= 0x20 && lo <= 0x7E)
                {
                    i += 2; ++chars;
                    continue;
                }
                break;
            }
            // Require wchar NUL terminator (00 00)
            if (chars >= minLen && i + 1 < rlen && b[i] == 0x00 && b[i + 1] == 0x00)
            {
                auto addr = reinterpret_cast<std::uintptr_t>(rdata + start);
                std::string narrow;
                narrow.reserve(chars);
                for (size_t j = 0; j < chars; ++j) narrow.push_back(static_cast<char>(b[start + j * 2]));
                out.emplace_back(addr, std::move(narrow));
                i += 2; // skip terminator
            }
            else
            {
                // If terminator present, skip it; else advance one byte to catch unaligned sequences too
                if (i + 1 < rlen && b[i] == 0x00 && b[i + 1] == 0x00) i += 2;
                else ++i;
            }
        }
        return out;
    }

    // High-level: given an ASCII key, return function starts that reference it
    inline std::vector<std::uintptr_t> findFunctionsReferencingString(HMODULE module, std::string_view ascii)
    {
        std::vector<std::uintptr_t> result;

        auto [rdata, rdataSize] = getSection(module, ".rdata");
        if (!rdata) return result;

        auto asciiHits = findAscii(rdata, rdataSize, ascii);

        // Also check UTF-16LE (common in MSVC binaries)
        std::wstring wneedle(ascii.begin(), ascii.end());
        auto utf16Hits = findUtf16(rdata, rdataSize, wneedle);

        std::vector<std::uintptr_t> targets;
        targets.reserve(asciiHits.size() + utf16Hits.size());
        for (auto* p : asciiHits)  targets.push_back(reinterpret_cast<std::uintptr_t>(p));
        for (auto* p : utf16Hits)  targets.push_back(reinterpret_cast<std::uintptr_t>(p));

        // For each target string address, find RIP-relative references and map to function starts
        for (auto addr : targets)
        {
            for (auto ref : findRipRefsTo(module, addr))
            {
                auto rva = static_cast<std::uint32_t>(ref - reinterpret_cast<std::uintptr_t>(module));
                auto fn = functionStartFromRva(module, rva);
                if (fn != 0) result.push_back(fn);
            }
        }

        // Deduplicate and sort
        std::sort(result.begin(), result.end());
        result.erase(std::unique(result.begin(), result.end()), result.end());
        return result;
    }

    // New: Build reverse-XREF maps for ALL strings in .rdata
    struct StringXrefResult {
        // Function start -> strings it references
        std::unordered_map<std::uintptr_t, std::vector<std::string>> functionsToStrings;
        // String text -> function starts referencing it
        std::unordered_map<std::string, std::vector<std::uintptr_t>> stringsToFunctions;
        size_t asciiCount{};
        size_t utf16Count{};
    };

    inline StringXrefResult mapFunctionsToStrings(HMODULE module, size_t minLen = 6)
    {
        StringXrefResult result;

        // Enumerate strings
        auto ascii = enumerateAsciiStrings(module, minLen);
        auto utf16 = enumerateUtf16Strings(module, minLen);
        result.asciiCount = ascii.size();
        result.utf16Count = utf16.size();

        // For dedup per function
        std::unordered_map<std::uintptr_t, std::unordered_set<std::string>> f2sDedup;

        auto processString = [&](std::uintptr_t strAddr, const std::string& text)
            {
                auto refs = findRipRefsTo(module, strAddr);
                for (auto ref : refs)
                {
                    auto rva = static_cast<std::uint32_t>(ref - reinterpret_cast<std::uintptr_t>(module));
                    auto fn = functionStartFromRva(module, rva);
                    if (!fn) continue;
                    auto& seen = f2sDedup[fn];
                    if (seen.insert(text).second)
                    {
                        result.functionsToStrings[fn].push_back(text);
                    }
                    auto& vec = result.stringsToFunctions[text];
                    if (vec.empty() || vec.back() != fn)
                    {
                        // keep order roughly grouped; dedup simple
                        vec.push_back(fn);
                    }
                }
            };

        for (const auto& [addr, text] : ascii) processString(addr, text);
        for (const auto& [addr, text] : utf16) processString(addr, text);

        // Optionally sort vectors for determinism
        for (auto& [fn, vec] : result.functionsToStrings)
        {
            std::sort(vec.begin(), vec.end());
            vec.erase(std::unique(vec.begin(), vec.end()), vec.end());
        }
        for (auto& [txt, vec] : result.stringsToFunctions)
        {
            std::sort(vec.begin(), vec.end());
            vec.erase(std::unique(vec.begin(), vec.end()), vec.end());
        }

        return result;
    }

    // Add a simple result type and scanner class
    struct XrefName {
        std::string text;
        std::uintptr_t stringAddr{};
        std::uintptr_t refAt{};
        bool utf16{};
    };

    class StringXrefScanner {
    public:
        // Scan the first maxBytes of a function for RIP-relative references to strings
        static std::optional<XrefName> GuessNameFromXrefs(std::uintptr_t funcAddr, size_t maxBytes = 0x300)
        {
            auto [textBase, textSize] = getSection(GetModuleHandleW(nullptr), ".text");
            auto [rdataBase, rdataSize] = getSection(GetModuleHandleW(nullptr), ".rdata");
            if (!textBase || !rdataBase) return std::nullopt;

            // Bound the scan to .text
            if (funcAddr < reinterpret_cast<std::uintptr_t>(textBase) ||
                funcAddr >= reinterpret_cast<std::uintptr_t>(textBase) + textSize)
                return std::nullopt;

            const auto* code = reinterpret_cast<const std::byte*>(funcAddr);
            const auto* textEnd = textBase + textSize;
            const size_t maxScan = (std::min)(maxBytes,
                static_cast<size_t>(textEnd - reinterpret_cast<const std::byte*>(code)));

            std::string best;
            std::uintptr_t bestStr = 0;
            std::uintptr_t bestRef = 0;
            bool bestIsUtf16 = false;

            for (size_t i = 0; i + 6 <= maxScan; )
            {
                std::uintptr_t target{};
                size_t ilen{};
                if (!tryRipRelTarget(code + i, target, ilen)) {
                    ++i; // advance one byte if not a match
                    continue;
                }
                i += ilen;

                // Check if target is in .rdata
                if (target < reinterpret_cast<std::uintptr_t>(rdataBase) ||
                    target >= reinterpret_cast<std::uintptr_t>(rdataBase) + rdataSize)
                    continue;

                // Read ASCII (simple verification: printable and NUL-terminated within 128 bytes)
                auto isPrintable = [](unsigned char c){ return c >= 0x20 && c <= 0x7E; };

                const char* as = reinterpret_cast<const char*>(target);
                std::string candidate;
                // Safe: bound to rdata end
                size_t maxLen = std::min<size_t>(128, reinterpret_cast<const char*>(rdataBase + rdataSize) - as);
                for (size_t j = 0; j < maxLen; ++j) {
                    char c = as[j];
                    if (c == '\0') break;
                    if (!isPrintable(static_cast<unsigned char>(c))) { candidate.clear(); break; }
                    candidate.push_back(c);
                }
                if (candidate.empty()) {
                    // Try naive UTF-16LE ASCII subset
                    const unsigned char* p = reinterpret_cast<const unsigned char*>(target);
                    std::string u8;
                    maxLen = std::min<size_t>(256, reinterpret_cast<const unsigned char*>(rdataBase + rdataSize) - p);
                    for (size_t j = 0; j + 1 < maxLen; j += 2) {
                        unsigned char lo = p[j], hi = p[j + 1];
                        if (lo == 0x00 && hi == 0x00) break;
                        if (hi != 0x00 || !isPrintable(lo)) { u8.clear(); break; }
                        u8.push_back(static_cast<char>(lo));
                    }
                    if (!u8.empty()) {
                        candidate = std::move(u8);
                        bestIsUtf16 = true;
                    } else {
                        continue;
                    }
                }

                // Normalize a bit
                while (!candidate.empty() && (candidate.back() == '.' || candidate.back() == ':' || candidate.back()==' ')) candidate.pop_back();

                if (!candidate.empty() && (best.empty() || candidate.size() > best.size())) {
                    best = candidate;
                    bestStr = target;
                    bestRef = funcAddr + i - ilen;
                }
            }

            if (best.empty()) return std::nullopt;
            XrefName out{ best, bestStr, bestRef, bestIsUtf16 };
            return out;
        }
    };

} // namespace xref