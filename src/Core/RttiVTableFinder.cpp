#include "RttiVTableFinder.h"
#include <cstdint>
#include <vector>
#include <string>
#include <string_view>
#include <algorithm>
#include <cstring>

namespace rtti {

    struct Sections {
        uint8_t* base{};
        uint8_t* textBegin{};
        size_t   textSize{};
        uint8_t* rdataBegin{};
        size_t   rdataSize{};
        size_t   ptrSize{};
    };

    static bool getSectionRange(HMODULE mod, const char* name, uint8_t*& begin, size_t& size) {
        auto base = reinterpret_cast<uint8_t*>(mod);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        auto sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
            if (std::memcmp(sec->Name, name, std::min<size_t>(std::strlen(name), 8)) == 0) {
                begin = base + sec->VirtualAddress;
                size = sec->Misc.VirtualSize;
                return true;
            }
        }
        return false;
    }

    static bool getSections(HMODULE mod, Sections& out) {
        out.base = reinterpret_cast<uint8_t*>(mod);
    #ifdef _WIN64
        out.ptrSize = 8;
    #else
        out.ptrSize = 4;
    #endif
        if (!getSectionRange(mod, ".text", out.textBegin, out.textSize)) return false;
        if (!getSectionRange(mod, ".rdata", out.rdataBegin, out.rdataSize)) return false;
        return true;
    }

    static bool inText(const Sections& s, const void* p) {
        auto b = reinterpret_cast<uintptr_t>(s.textBegin);
        auto e = b + s.textSize;
        auto v = reinterpret_cast<uintptr_t>(p);
        return v >= b && v < e;
    }
    static bool inRdata(const Sections& s, const void* p) {
        auto b = reinterpret_cast<uintptr_t>(s.rdataBegin);
        auto e = b + s.rdataSize;
        auto v = reinterpret_cast<uintptr_t>(p);
        return v >= b && v < e;
    }

    static std::string makeMsvcRttiName(std::string_view fqName, bool isClass) {
        std::vector<std::string_view> parts;
        size_t start = 0;
        while (start <= fqName.size()) {
            auto pos = fqName.find("::", start);
            if (pos == std::string_view::npos) {
                parts.emplace_back(fqName.substr(start));
                break;
            }
            parts.emplace_back(fqName.substr(start, pos - start));
            start = pos + 2;
        }
        std::string out;
        out += ".?A";
        out += (isClass ? 'V' : 'U');
        for (size_t i = 0; i < parts.size(); ++i) {
            auto& seg = parts[parts.size() - 1 - i];
            out.append(seg.data(), seg.size());
            out.push_back('@');
        }
        out.push_back('@');
        return out;
    }

    static uint8_t* findInRdata(const Sections& s, std::string_view needle) {
        auto* begin = s.rdataBegin;
        auto* end = s.rdataBegin + s.rdataSize;
        auto* cur = begin;
        if (needle.empty()) return nullptr;
        while (cur + needle.size() <= end) {
            if (std::memcmp(cur, needle.data(), needle.size()) == 0) {
                return cur;
            }
            ++cur;
        }
        return nullptr;
    }

    static uint8_t* calcTypeDescriptorFromName(const Sections& s, uint8_t* nameAddr) {
        if (!nameAddr) return nullptr;
        return nameAddr - static_cast<ptrdiff_t>(s.ptrSize * 2);
    }

    static std::vector<VTableInfo> findVTablesForType(const Sections& s, uint8_t* typeDesc) {
        std::vector<VTableInfo> out;
        if (!typeDesc) return out;

        auto* rdBegin = s.rdataBegin;
        auto* rdEnd = s.rdataBegin + s.rdataSize;
        for (uint8_t* p = rdBegin; p + s.ptrSize <= rdEnd; p += s.ptrSize) {
            uintptr_t val = 0;
            std::memcpy(&val, p, s.ptrSize);
            if (val != reinterpret_cast<uintptr_t>(typeDesc)) continue;

            uint8_t* col = p - 12;
            uint32_t signature = 0, offset = 0, cdOffset = 0;
            if (col < rdBegin || col + 12 > rdEnd) continue;
            std::memcpy(&signature, col + 0, 4);
            std::memcpy(&offset,    col + 4, 4);
            std::memcpy(&cdOffset,  col + 8, 4);
            if (signature != 0 && signature != 1) continue;

            for (uint8_t* q = rdBegin; q + s.ptrSize <= rdEnd; q += s.ptrSize) {
                uintptr_t qval = 0;
                std::memcpy(&qval, q, s.ptrSize);
                if (qval != reinterpret_cast<uintptr_t>(col)) continue;

                uint8_t* vft = q + s.ptrSize;
                uintptr_t f0 = 0;
                if (vft + s.ptrSize > rdEnd) continue;
                std::memcpy(&f0, vft, s.ptrSize);
                if (!inText(s, reinterpret_cast<void*>(f0))) continue;

                size_t count = 0;
                for (uint8_t* ent = vft; ent + s.ptrSize <= rdEnd; ent += s.ptrSize) {
                    uintptr_t f = 0;
                    std::memcpy(&f, ent, s.ptrSize);
                    if (inRdata(s, reinterpret_cast<void*>(f))) break;
                    if (!inText(s, reinterpret_cast<void*>(f))) break;
                    ++count;
                }

                auto already = std::find_if(out.begin(), out.end(), [&](const VTableInfo& i) { return i.vtable == reinterpret_cast<uintptr_t>(vft); });
                if (already == out.end()) {
                    out.push_back({ reinterpret_cast<uintptr_t>(vft), reinterpret_cast<uintptr_t>(col), count });
                }
            }
        }

        std::sort(out.begin(), out.end(), [](auto& a, auto& b) { return a.vtable < b.vtable; });
        out.erase(std::unique(out.begin(), out.end(), [](auto& a, auto& b) { return a.vtable == b.vtable; }), out.end());
        return out;
    }

    std::vector<VTableInfo> FindVTablesForType(HMODULE mod, std::string_view fqName) {
        Sections s{};
        if (!getSections(mod, s)) return {};
        for (bool isClass : { true, false }) {
            auto msvcName = makeMsvcRttiName(fqName, isClass);
            if (auto* nameAddr = findInRdata(s, msvcName)) {
                auto* typeDesc = calcTypeDescriptorFromName(s, nameAddr);
                auto vts = findVTablesForType(s, typeDesc);
                if (!vts.empty()) return vts;
            }
        }
        return {};
    }

} // namespace rtti