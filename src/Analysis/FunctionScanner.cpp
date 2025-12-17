#include "FunctionScanner.h"
#include "FunctionDatabase.h"
#include "SignatureDatabase.h"
#include "../Logger/Logger.h"
#include <Windows.h>
#include <Psapi.h>
#include <algorithm>
#include <cstring>
#include <cctype>
#include <vector>
#include <set>
#include <string>
#include <string_view>
#include <unordered_set>
#include <unordered_map>
#include <mutex>

namespace SapphireHook {

    class MemoryValidator {
    public:
        static bool CanRead(const void* addr, size_t size)
        {
            if (!addr) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;

            const DWORD readable =
                PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

            return (mbi.State == MEM_COMMIT) && (mbi.Protect & readable);
        }

        static bool CanExecute(const void* addr)
        {
            if (!addr) return false;
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;

            const DWORD executable =
                PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

            return (mbi.State == MEM_COMMIT) && (mbi.Protect & executable);
        }
    };

    static void UniqueSortPtrVec(std::vector<uintptr_t>& v)
    {
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
    }

    static std::vector<uintptr_t> ToUniqueFunctionAddresses(const std::vector<StringScanResult>& hits)
    {
        std::vector<uintptr_t> addrs;
        addrs.reserve(hits.size());
        for (const auto& h : hits)
        {
            if (h.nearbyFunctionAddress) addrs.push_back(h.nearbyFunctionAddress);
        }
        UniqueSortPtrVec(addrs);
        return addrs;
    }

    static bool GetMainModuleBaseAndSize(uintptr_t& base, size_t& size)
    {
        HMODULE hModule = GetModuleHandle(nullptr);
        if (!hModule) return false;

        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &mi, sizeof(mi)))
            return false;

        base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
        size = static_cast<size_t>(mi.SizeOfImage);
        return base != 0 && size != 0;
    }

    static IMAGE_NT_HEADERS* GetNtHeaders(uintptr_t moduleBase)
    {
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleBase);
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(moduleBase + dos->e_lfanew);
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
        return nt;
    }

    static bool GetSectionRange(uintptr_t moduleBase, const char* name, uintptr_t& secBase, size_t& secSize)
    {
        auto nt = GetNtHeaders(moduleBase);
        if (!nt) return false;

        auto sections = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        {
            char sectName[9] = {};
            std::memcpy(sectName, sections[i].Name, 8);
            if (_stricmp(sectName, name) == 0)
            {
                secBase = moduleBase + sections[i].VirtualAddress;
                secSize = sections[i].Misc.VirtualSize;
                return true;
            }
        }
        return false;
    }

    static const uint8_t* FindBytes(const uint8_t* hay, size_t hayLen, const char* needle, size_t neeLen)
    {
        if (neeLen == 0 || hayLen < neeLen) return nullptr;
        const uint8_t first = static_cast<uint8_t>(needle[0]);

        for (size_t i = 0; i <= hayLen - neeLen; ++i)
        {
            if (hay[i] != first) continue;
            if (std::memcmp(hay + i, needle, neeLen) == 0)
                return hay + i;
        }
        return nullptr;
    }

    static bool IsRipRelativeRefTo(uintptr_t ip, uintptr_t textEnd, uintptr_t targetAddress)
    {
        if (ip + 7 > textEnd) return false;

        const uint8_t* p = reinterpret_cast<const uint8_t*>(ip);
        bool match =
            (p[0] == 0x48 && p[1] == 0x8D && (p[2] & 0xC7) == 0x05) ||
            (p[0] == 0x48 && p[1] == 0x8B && (p[2] & 0xC7) == 0x05) ||
            (p[0] == 0x4C && p[1] == 0x8D && (p[2] & 0xC7) == 0x05);

        if (!match) return false;

        int32_t disp = *reinterpret_cast<const int32_t*>(p + 3);
        uintptr_t nextIp = ip + 7;
        uintptr_t computed = static_cast<uintptr_t>(static_cast<int64_t>(nextIp) + disp);
        return computed >= targetAddress - 8 && computed <= targetAddress + 8;
    }

    static std::vector<uintptr_t> FindCodeRefsToString(uintptr_t textBase, size_t textSize, uintptr_t strAddr, size_t maxRefs = 32)
    {
        std::vector<uintptr_t> refs;
        uintptr_t end = textBase + textSize;

        for (uintptr_t ip = textBase; ip + 7 < end; ++ip)
        {
            if (IsRipRelativeRefTo(ip, end, strAddr))
            {
                refs.push_back(ip);
                if (refs.size() >= maxRefs) break;
            }
        }
        return refs;
    }

    static std::string StripNonAlnum(const std::string& s)
    {
        std::string out;
        out.reserve(s.size());
        for (unsigned char c : s)
        {
            if (std::isalnum(c)) out.push_back(static_cast<char>(c));
        }
        return out;
    }

    static std::string_view BasenameFromQualified(std::string_view name) {
        size_t pos = name.find_last_of("::");
        if (pos != std::string_view::npos)
        {
            size_t dbl = name.rfind("::");
            if (dbl != std::string_view::npos)
                return name.substr(dbl + 2);
        }
        size_t dot = name.find_last_of('.');
        if (dot != std::string_view::npos)
            return name.substr(dot + 1);
        return name;
    }

    static std::vector<std::string> SplitCamelCaseTokens(const std::string& s)
    {
        std::vector<std::string> tokens;
        std::string cur;
        for (size_t i = 0; i < s.size(); ++i)
        {
            char c = s[i];
            if (i > 0 && std::isupper(static_cast<unsigned char>(c)) && !cur.empty())
            {
                tokens.push_back(cur);
                cur.clear();
            }
            cur.push_back(c);
        }
        if (!cur.empty()) tokens.push_back(cur);
        return tokens;
    }

    static bool IsGenericWord(const std::string& t)
    {
        static const std::unordered_set<std::string> generic = {
            "Get","Set","Is","Has","Can","Should","Will","Do","Run","Func","Function",
            "Update","Init","Main","Process","Handle","Manager","System","Module","Service"
        };
        return generic.find(t) != generic.end();
    }

    static std::vector<std::string> BuildAnchorsFromNames(
        const std::vector<std::string>& names,
        std::unordered_map<std::string, std::string>& anchorToOriginalName)
    {
        std::unordered_set<std::string> anchors;
        anchors.reserve(names.size() * 3);
        anchorToOriginalName.reserve(names.size() * 3);

        for (const auto& full : names)
        {
            const std::string base = std::string(BasenameFromQualified(full));
            const std::string baseClean = StripNonAlnum(base);
            if (baseClean.size() >= 4)
            {
                anchors.insert(baseClean);
                anchorToOriginalName.emplace(baseClean, full);
            }

            auto toks = SplitCamelCaseTokens(baseClean);
            for (auto& t : toks)
            {
                if (t.size() >= 4 && !IsGenericWord(t))
                {
                    anchors.insert(t);
                    anchorToOriginalName.emplace(t, full);
                }
            }

            std::string lower = baseClean;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            if (lower.size() >= 4)
            {
                anchors.insert(lower);
                anchorToOriginalName.emplace(lower, full);
            }
        }

        std::vector<std::string> out;
        out.reserve(anchors.size());
        for (const auto& a : anchors) out.push_back(a);
        return out;
    }

    class FunctionScanner::Impl {
    public:
        std::shared_ptr<FunctionDatabase> functionDatabase;
        std::shared_ptr<SignatureDatabase> signatureDatabase;

        std::map<uintptr_t, std::string> detectedFunctionNames;
        mutable std::mutex detectedNamesMutex;

        struct ScanState {
            std::atomic<bool> inProgress{ false };
            std::atomic<bool> stopRequested{ false };
        } scanState;
    };

    FunctionScanner::FunctionScanner() : m_impl(std::make_unique<Impl>()) {}
    FunctionScanner::~FunctionScanner() = default;

    bool FunctionScanner::IsSafeMemoryAddress(const void* address, size_t size) const
    {
        return MemoryValidator::CanRead(address, size);
    }

    bool FunctionScanner::IsCommittedMemory(uintptr_t address, size_t size) const
    {
        return MemoryValidator::CanRead(reinterpret_cast<const void*>(address), size);
    }

    bool FunctionScanner::IsExecutableMemory(uintptr_t address) const
    {
        return MemoryValidator::CanExecute(reinterpret_cast<const void*>(address));
    }

    bool FunctionScanner::IsValidMemoryAddress(uintptr_t address, size_t size) const
    {
        return MemoryValidator::CanRead(reinterpret_cast<const void*>(address), size);
    }

    bool FunctionScanner::IsValidString(const char* str, size_t maxLen) const
    {
        if (!IsSafeMemoryAddress(str, 1)) return false;
        for (size_t i = 0; i < maxLen; ++i)
        {
            if (!IsSafeMemoryAddress(str + i, 1)) return false;
            if (str[i] == '\0') return true;
            if (!isprint(static_cast<unsigned char>(str[i]))) return false;
        }
        return false;
    }

    std::string FunctionScanner::ExtractFunctionNameFromMemory(uintptr_t address) const
    {
        if (m_impl->functionDatabase && m_impl->functionDatabase->HasFunction(address))
            return m_impl->functionDatabase->GetFunctionName(address);
        return "sub_" + std::to_string(address);
    }

    std::string FunctionScanner::ScanForNearbyStrings(uintptr_t address, size_t) const
    {
        if (!address || !IsSafeMemoryAddress(reinterpret_cast<const void*>(address), 1))
            return "";
        return "";
    }

    bool FunctionScanner::IsLikelyFunctionStart(uintptr_t address) const
    {
        if (!IsExecutableMemory(address)) return false;
        const uint8_t* code = reinterpret_cast<const uint8_t*>(address);
        return IsLikelyFunctionStart(code, 16);
    }

    bool FunctionScanner::IsLikelyFunctionStart(const uint8_t* code, size_t maxSize) const
    {
        if (!IsSafeMemoryAddress(code, (std::min)(maxSize, size_t(16)))) return false;
        if (code[0] == 0x48 && code[1] == 0x89) return true;
        if (code[0] == 0x48 && code[1] == 0x83) return true;
        if (code[0] == 0x40 && code[1] >= 0x53 && code[1] <= 0x57) return true;
        if (code[0] == 0x48 && code[1] == 0x8B) return true;
        if (code[0] == 0x55) return true;
        if (code[0] == 0x53) return true;
        return false;
    }

    uintptr_t FunctionScanner::FindFunctionStart(uintptr_t address) const
    {
        uintptr_t start = address;
        uintptr_t lower = (address > 0x1000) ? (address - 0x1000) : 0;
        for (uintptr_t scan = address; scan >= lower; --scan)
        {
            if (IsLikelyFunctionStart(scan))
                start = scan;
            if (scan == 0) break;
        }
        return start;
    }

    std::vector<StringScanResult> FunctionScanner::ScanMemoryForFunctionStrings(
        const std::vector<std::string>& targetStrings,
        ProgressCallback progress) const
    {
        std::vector<StringScanResult> results;

        uintptr_t base = 0; size_t size = 0;
        if (!GetMainModuleBaseAndSize(base, size))
        {
            LogError("FunctionScanner: cannot get main module info");
            return results;
        }

        uintptr_t textBase = 0, rdataBase = 0, dataBase = 0;
        size_t textSize = 0, rdataSize = 0, dataSize = 0;

        GetSectionRange(base, ".text", textBase, textSize);
        GetSectionRange(base, ".rdata", rdataBase, rdataSize);
        GetSectionRange(base, ".data", dataBase, dataSize);

        if (!textBase || !textSize)
        {
            textBase = base; textSize = size;
        }

        struct Region { uintptr_t base; size_t size; };
        std::vector<Region> dataRegions;
        if (rdataBase && rdataSize) dataRegions.push_back({ rdataBase, rdataSize });
        if (dataBase && dataSize) dataRegions.push_back({ dataBase, dataSize });

        if (dataRegions.empty())
        {
            dataRegions.push_back({ base, size });
        }

        auto isReadableProt = [](DWORD prot) {
            const DWORD readable =
                PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
            return (prot & readable) != 0;
            };

        size_t processed = 0;
        size_t total = targetStrings.size();

        // Reset stop flag at start of scan
        m_impl->scanState.stopRequested = false;
        m_impl->scanState.inProgress = true;

        for (const auto& s : targetStrings)
        {
            // Check for cancellation
            if (m_impl->scanState.stopRequested.load(std::memory_order_relaxed)) {
                m_impl->scanState.inProgress = false;
                return results;
            }

            if (!s.empty())
            {
                for (const auto& region : dataRegions) {
                    uintptr_t regionBegin = region.base;
                    uintptr_t regionEnd = region.base + region.size;

                    while (regionBegin < regionEnd) {
                        // Check for cancellation in inner loop
                        if (m_impl->scanState.stopRequested.load(std::memory_order_relaxed)) {
                            m_impl->scanState.inProgress = false;
                            return results;
                        }

                        MEMORY_BASIC_INFORMATION mbi{};
                        if (VirtualQuery(reinterpret_cast<LPCVOID>(regionBegin), &mbi, sizeof(mbi)) == 0)
                            break;

                        uintptr_t segStart = regionBegin;
                        uintptr_t segEnd = (std::min)(regionEnd, regionBegin + static_cast<uintptr_t>(mbi.RegionSize));

                        if (mbi.State == MEM_COMMIT && isReadableProt(mbi.Protect)) {
                            const uint8_t* segPtr = reinterpret_cast<const uint8_t*>(segStart);
                            size_t segLen = static_cast<size_t>(segEnd - segStart);

                            if (segLen > 0 && segLen <= size) {
                                const uint8_t* cur = segPtr;
                                const uint8_t* end = segPtr + segLen;
                                while (cur < end) {
                                    size_t remain = static_cast<size_t>(end - cur);
                                    if (remain < s.size()) break;
                                    const uint8_t* found = FindBytes(cur, remain, s.c_str(), s.size());
                                    if (!found) break;

                                    uintptr_t strAddr = reinterpret_cast<uintptr_t>(found);
                                    auto refs = FindCodeRefsToString(textBase, textSize, strAddr);
                                    for (auto refIp : refs) {
                                        uintptr_t func = FindFunctionStart(refIp);
                                        results.emplace_back(strAddr, func, s, "RIP-REL", 100);
                                    }
                                    cur = found + 1;
                                }
                            }
                        }

                        regionBegin = segEnd;
                    }
                }
            }

            processed++;
            if (progress && total > 0)
                progress(processed, total, "StringScan");
        }

        m_impl->scanState.inProgress = false;

        std::sort(results.begin(), results.end(), [](const auto& a, const auto& b)
            {
                if (a.nearbyFunctionAddress != b.nearbyFunctionAddress)
                    return a.nearbyFunctionAddress < b.nearbyFunctionAddress;
                return a.stringAddress < b.stringAddress;
            });
        results.erase(std::unique(results.begin(), results.end(), [](const auto& a, const auto& b)
            {
                return a.stringAddress == b.stringAddress && a.nearbyFunctionAddress == b.nearbyFunctionAddress;
            }), results.end());

        return results;
    }

    std::vector<uintptr_t> FunctionScanner::ScanForFunctionsByStrings(
        const std::vector<std::string>& searchStrings,
        ProgressCallback progress) const
    {
        return ToUniqueFunctionAddresses(ScanMemoryForFunctionStrings(searchStrings, progress));
    }

    std::vector<uintptr_t> FunctionScanner::ScanForAllInterestingFunctions(
        const ScanConfig& config,
        ProgressCallback progress,
        ResultCallback onResult) const
    {
        uintptr_t base = 0; size_t size = 0;
        if (!GetMainModuleBaseAndSize(base, size)) return {};

        uintptr_t textBase = 0; size_t textSize = 0;
        if (!GetSectionRange(base, ".text", textBase, textSize))
        {
            textBase = base; textSize = size;
        }

        std::vector<uintptr_t> results;
        results.reserve(10000);

        // Reset stop flag at start of scan
        m_impl->scanState.stopRequested = false;
        m_impl->scanState.inProgress = true;

        size_t total = textSize;
        for (size_t off = 0; off + 16 < textSize; ++off)
        {
            // Check for cancellation
            if (m_impl->scanState.stopRequested.load(std::memory_order_relaxed)) {
                m_impl->scanState.inProgress = false;
                return results;
            }

            uintptr_t addr = textBase + off;
            if (IsLikelyFunctionStart(addr))
            {
                results.push_back(addr);
                
                // Stream result to callback if provided
                if (onResult) {
                    onResult(addr);
                }
                
                if (results.size() >= config.maxResults) break;
            }

            if (progress && (off % 0x10000) == 0)
                progress(off, total, ".text/prologue-scan");
        }

        m_impl->scanState.inProgress = false;
        UniqueSortPtrVec(results);
        return results;
    }

    std::vector<uintptr_t> FunctionScanner::ScanForAllFunctions(
        const ScanConfig& config,
        ProgressCallback progress) const
    {
        return ScanForAllInterestingFunctions(config, progress);
    }

    std::future<std::vector<uintptr_t>> FunctionScanner::StartAsyncScan(
        const ScanConfig& config,
        ProgressCallback progress)
    {
        return std::async(std::launch::async, [this, config, progress]()
            {
                return ScanForAllFunctions(config, progress);
            });
    }

    std::future<std::vector<uintptr_t>> FunctionScanner::StartAsyncScanWithStrings(
        const std::vector<std::string>& targetStrings,
        const ScanConfig&,
        ProgressCallback progress)
    {
        return std::async(std::launch::async, [this, targetStrings, progress]()
            {
                return ToUniqueFunctionAddresses(ScanMemoryForFunctionStrings(targetStrings, progress));
            });
    }

    void FunctionScanner::StopScan()
    {
        m_impl->scanState.stopRequested = true;
    }

    bool FunctionScanner::IsScanInProgress() const
    {
        return m_impl->scanState.inProgress;
    }

    void FunctionScanner::ScanSafeRegion(uintptr_t baseAddr, size_t size, std::vector<uintptr_t>& functions) const
    {
        if (!baseAddr || !size) return;
        for (uintptr_t p = baseAddr; p + 16 < baseAddr + size; ++p)
        {
            if (IsLikelyFunctionStart(p))
                functions.push_back(p);
        }
        UniqueSortPtrVec(functions);
    }

    void FunctionScanner::ScanForFunctionPrologues(uintptr_t moduleBase, size_t moduleSize, std::vector<uintptr_t>& functions) const
    {
        uintptr_t textBase = 0; size_t textSize = 0;
        if (!GetSectionRange(moduleBase, ".text", textBase, textSize))
        {
            textBase = moduleBase; textSize = moduleSize;
        }
        ScanSafeRegion(textBase, textSize, functions);
    }

    void FunctionScanner::ScanExportedFunctions(std::vector<uintptr_t>& functions) const
    {
        uintptr_t base = 0; size_t size = 0;
        if (!GetMainModuleBaseAndSize(base, size)) return;

        auto nt = GetNtHeaders(base);
        if (!nt) return;

        const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dir.VirtualAddress == 0 || dir.Size == 0) return;

        auto exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
        if (!IsSafeMemoryAddress(exp, sizeof(IMAGE_EXPORT_DIRECTORY))) return;

        DWORD* funcRVAs = reinterpret_cast<DWORD*>(base + exp->AddressOfFunctions);
        if (!funcRVAs || !IsSafeMemoryAddress(funcRVAs, exp->NumberOfFunctions * sizeof(DWORD)))
            return;

        std::set<uintptr_t> uniq;
        for (DWORD i = 0; i < exp->NumberOfFunctions; ++i)
        {
            DWORD rva = funcRVAs[i];
            if (rva == 0) continue;
            uintptr_t addr = base + rva;
            if (addr >= base && addr < base + size && IsExecutableMemory(addr))
            {
                uniq.insert(addr);
            }
        }

        functions.insert(functions.end(), uniq.begin(), uniq.end());
    }

    void FunctionScanner::ScanCallTargets(uintptr_t moduleBase, size_t moduleSize, std::vector<uintptr_t>& functions) const
    {
        uintptr_t textBase = 0; size_t textSize = 0;
        if (!GetSectionRange(moduleBase, ".text", textBase, textSize))
        {
            textBase = moduleBase; textSize = moduleSize;
        }

        std::set<uintptr_t> uniq;
        const uintptr_t textEnd = textBase + textSize;

        for (uintptr_t ip = textBase; ip + 5 <= textEnd; ++ip)
        {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(ip);
            if (p[0] == 0xE8)
            {
                int32_t rel = *reinterpret_cast<const int32_t*>(p + 1);
                uintptr_t next = ip + 5;
                uintptr_t target = static_cast<uintptr_t>(static_cast<int64_t>(next) + rel);

                if (target >= moduleBase && target < moduleBase + moduleSize)
                {
                    uintptr_t fn = FindFunctionStart(target);
                    if (fn && IsExecutableMemory(fn))
                        uniq.insert(fn);
                }
                ip += 4;
            }
        }

        functions.insert(functions.end(), uniq.begin(), uniq.end());
    }

    static void ScanCategory(const FunctionScanner& self,
        const char* prefix,
        const std::vector<std::string>& anchors,
        std::map<uintptr_t, std::string>& namedFunctions)
    {
        auto hits = self.ScanMemoryForFunctionStrings(anchors, nullptr);
        for (const auto& h : hits)
        {
            if (!h.nearbyFunctionAddress) continue;
            if (namedFunctions.count(h.nearbyFunctionAddress)) continue;

            namedFunctions[h.nearbyFunctionAddress] = std::string(prefix) + "::" + h.foundString;
        }
    }

    void FunctionScanner::ScanForUIFunctions(const uint8_t*, size_t, std::map<uintptr_t, std::string>& namedFunctions) const
    {
        static const std::vector<std::string> uiAnchors = {
            "AtkUnit","AtkResNode","Agent","Addon","Tooltip","Rapture","UI","Window","Widget"
        };
        ScanCategory(*this, "UI", uiAnchors, namedFunctions);
    }

    void FunctionScanner::ScanForNetworkFunctions(const uint8_t*, size_t, std::map<uintptr_t, std::string>& namedFunctions) const
    {
        static const std::vector<std::string> netAnchors = {
            "socket","SOCKET","WSA","recv","send","Connect","HTTP","SSL","Network","Packet"
        };
        ScanCategory(*this, "Net", netAnchors, namedFunctions);
    }

    void FunctionScanner::ScanForGameplayFunctions(const uint8_t*, size_t, std::map<uintptr_t, std::string>& namedFunctions) const
    {
        static const std::vector<std::string> gameAnchors = {
            "Action","Inventory","Quest","Chara","Battle","Actor","Ability","Skill","Status","Event"
        };
        ScanCategory(*this, "Game", gameAnchors, namedFunctions);
    }

    void FunctionScanner::SetFunctionDatabase(std::shared_ptr<FunctionDatabase> database)
    {
        m_impl->functionDatabase = database;
    }

    void FunctionScanner::SetSignatureDatabase(std::shared_ptr<SignatureDatabase> database)
    {
        m_impl->signatureDatabase = database;
    }

    void FunctionScanner::UpdateTemporaryFunctionDatabase(const std::map<uintptr_t, std::string>& detectedFunctions)
    {
        m_impl->detectedFunctionNames = detectedFunctions;
    }

    const std::map<uintptr_t, std::string>& FunctionScanner::GetDetectedFunctionNames() const
    {
        return m_impl->detectedFunctionNames;
    }

    std::vector<NameScanResult> FunctionScanner::AutoScanFunctionsByNames(
        const std::vector<std::string>& functionNames,
        ProgressCallback progress) const
    {
        std::unordered_map<std::string, std::string> anchorToName;
        auto anchors = BuildAnchorsFromNames(functionNames, anchorToName);

        if (anchors.empty())
        {
            LogWarning("AutoScanFunctionsByNames: no anchors derived from names");
            return {};
        }

        LogInfo("AutoScanFunctionsByNames: scanning with " + std::to_string(anchors.size()) + " anchors");
        auto hits = ScanMemoryForFunctionStrings(anchors, progress);

        std::vector<NameScanResult> results;
        results.reserve(hits.size());

        for (const auto& h : hits)
        {
            auto it = anchorToName.find(h.foundString);
            if (it == anchorToName.end()) continue;

            NameScanResult r;
            r.functionAddress = h.nearbyFunctionAddress;
            r.matchedName = it->second;
            r.anchor = h.foundString;
            r.confidence = 90;

            if (r.functionAddress && IsExecutableMemory(r.functionAddress) && IsLikelyFunctionStart(r.functionAddress))
            {
                results.push_back(r);
            }
        }

        std::sort(results.begin(), results.end(), [](const auto& a, const auto& b) {
            if (a.functionAddress != b.functionAddress) return a.functionAddress < b.functionAddress;
            return a.matchedName < b.matchedName;
            });
        results.erase(std::unique(results.begin(), results.end(), [](const auto& a, const auto& b) {
            return a.functionAddress == b.functionAddress && a.matchedName == b.matchedName;
            }), results.end());

        LogInfo("AutoScanFunctionsByNames: found " + std::to_string(results.size()) + " candidate functions");
        return results;
    }

    std::vector<NameScanResult> FunctionScanner::AutoScanFunctionsFromDatabase(
        ProgressCallback progress) const
    {
        if (!m_impl->functionDatabase)
        {
            LogWarning("AutoScanFunctionsFromDatabase: no FunctionDatabase wired");
            return {};
        }

        std::vector<std::string> names;
        names.reserve(2048);
        auto all = m_impl->functionDatabase->GetAllFunctions();
        for (const auto& [addr, info] : all)
        {
            if (!info.name.empty())
                names.push_back(info.name);
        }

        return AutoScanFunctionsByNames(names, progress);
    }

} // namespace SapphireHook