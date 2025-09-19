#include "NetworkMonitor.h"
#include <cstring>
#include "../vendor/imgui/imgui.h"
#include "../vendor/imgui/imgui_internal.h"
#include <sstream>
#include <cstdio>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <algorithm>
#include "OpcodeNames.h"
#include <vector>
#include <filesystem>
#include <fstream>
#include <chrono>
#include "../../vendor/miniz/miniz.h"
#include "../../vendor/ImGuiFD/ImGuiFD.h"

SafeHookLogger& SafeHookLogger::Instance() {
    static SafeHookLogger inst{};
    return inst;
}

// Track resolved connection type per connection_id (from SESSIONINIT packets)
namespace { static std::unordered_map<uint64_t, uint16_t> g_connTypeByConnId; }

// Correlate ActionRequest -> ActionResult by RequestId
namespace { struct ActionReqRec { uint64_t connId = 0; std::chrono::system_clock::time_point ts{}; uint8_t actionKind = 0; uint32_t actionKey = 0; uint64_t target = 0; uint16_t dir = 0; uint16_t dirTarget = 0;}; }
namespace { static std::unordered_map<uint32_t, ActionReqRec> g_actionReqById; }

// Config: inflate compressed segment area
namespace { static bool g_cfgInflateSegments = true; }

// Expose selection for external panes
namespace { static HookPacket g_lastSelected{}; static bool g_hasSelection = false; }

// NEW: Expose segment hover state for hex highlighting
namespace { 
    static int g_hoveredSegmentIndex = -1;
    static uint32_t g_hoveredSegmentOffset = 0;
    static uint32_t g_hoveredSegmentSize = 0;
    static bool g_hasHoveredSegment = false;
}

SafeHookLogger::SafeHookLogger() {
    for (size_t i = 0; i < SLOT_COUNT; ++i)
        slots_[i].state.store(uint8_t(SlotState::EMPTY));
}

SafeHookLogger::~SafeHookLogger() = default;

bool SafeHookLogger::TryEnqueueFromHook(const void* data, size_t len,
    bool outgoing, uint64_t conn_id) noexcept {
    if (!data || len == 0) return false;
    size_t tocopy = (len > SLOT_PAYLOAD_CAP) ? SLOT_PAYLOAD_CAP : len;

    size_t start = producer_fetch_.fetch_add(1, std::memory_order_relaxed) % SLOT_COUNT;
    for (size_t probe = 0; probe < SLOT_PROBES; ++probe) {
        size_t idx = (start + probe) % SLOT_COUNT;
        uint8_t expected = uint8_t(SlotState::EMPTY);
        if (slots_[idx].state.compare_exchange_strong(expected, uint8_t(SlotState::WRITING),
            std::memory_order_acquire,
            std::memory_order_relaxed)) {
            auto& slot = slots_[idx];
            slot.packet.outgoing = outgoing;
            slot.packet.connection_id = conn_id;
            slot.packet.ts = std::chrono::system_clock::now();
            slot.packet.len = (uint32_t)tocopy;
            std::memcpy(slot.packet.buf.data(), data, tocopy);
            slot.state.store(uint8_t(SlotState::READY), std::memory_order_release);
            return true;
        }
    }
    return false; // no free slot found
}

void SafeHookLogger::DrainToVector(std::vector<HookPacket>& out) {
    out.clear();
    out.reserve(256);
    for (size_t i = 0; i < SLOT_COUNT && out.size() < UI_BATCH_CAP; ++i) {
        uint8_t expected = uint8_t(SlotState::READY);
        if (slots_[i].state.compare_exchange_strong(expected, uint8_t(SlotState::READING),
            std::memory_order_acquire,
            std::memory_order_relaxed)) {
            out.push_back(slots_[i].packet);
            slots_[i].state.store(uint8_t(SlotState::EMPTY), std::memory_order_release);
        }
    }
}

void SafeHookLogger::DumpHexAscii(const HookPacket& hp) {
    const uint8_t* d = hp.buf.data();
    for (size_t off = 0; off < hp.len; off += 16) {
        size_t len = (hp.len - off < 16) ? hp.len - off : 16;
        char line[256];
        char* p = line;
        p += std::sprintf(p, "%04zx: ", off);
        for (size_t j = 0; j < 16; ++j) {
            if (j < len) p += std::sprintf(p, "%02x ", d[off + j]);
            else p += std::sprintf(p, "   ");
        }
        *p++ = ' ';
        for (size_t j = 0; j < len; ++j) {
            unsigned char c = d[off + j];
            *p++ = (c >= 32 && c < 127) ? (char)c : '.';
        }
        *p = 0;
        ImGui::TextUnformatted(line);
    }
}

void SafeHookLogger::DumpHexAsciiColored(const HookPacket& hp, const std::vector<unsigned int>& colors)
{
    if (colors.size() < hp.len) { DumpHexAscii(hp); return; }

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 origin = ImGui::GetCursorScreenPos();
    const ImGuiStyle& style = ImGui::GetStyle();

    const int bytesPerLine = 16;
    const float lineH = ImGui::GetTextLineHeight();
    const float charW = ImGui::CalcTextSize("A").x;
    const float hexCellW = ImGui::CalcTextSize("00 ").x; // rough cell width
    const float hexStride = hexCellW * 1.5f;              // spacing factor matching print layout

    // Persistent selection state (per-session)
    static int s_selStart = -1, s_selEnd = -1;
    static bool s_dragging = false;

    ImVec2 cursor = origin;

    // Pre-calc total lines to advance layout at the end
    const int totalLines = (int)((hp.len + bytesPerLine - 1) / bytesPerLine);

    // Mouse pos for hover/selection
    const ImVec2 mouse = ImGui::GetIO().MousePos;

    // Capture input with overlay to avoid window drag interfering
    const float offWidth = ImGui::CalcTextSize("0000:").x + style.ItemSpacing.x * 2.0f + 8.0f;
    const float hexWidth = bytesPerLine * hexStride;
    const float asciiWidth = bytesPerLine * charW;
    const float totalWidth = offWidth + hexWidth + style.ItemSpacing.x * 2.0f + asciiWidth;
    const ImVec2 regionSize(totalWidth, totalLines * lineH);
    ImGui::PushID("hex_viewer_overlay");
    ImGui::InvisibleButton("##hex_overlay", regionSize, ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight);
    ImVec2 overlayMin = ImGui::GetItemRectMin();
    ImGui::PopID();

    for (size_t off = 0; off < hp.len; off += bytesPerLine) {
        const float y = cursor.y;
        // Offsets
        char offbuf[16]; std::snprintf(offbuf, sizeof(offbuf), "%04zx:", off);
        ImVec2 offPos = ImVec2(cursor.x, y);
        dl->AddText(offPos, ImGui::GetColorU32(ImGuiCol_Text), offbuf);

        // Column anchors
        const float hexX = cursor.x + ImGui::CalcTextSize("0000:").x + style.ItemSpacing.x * 2.0f + 8.0f;
        const float asciiX = hexX + bytesPerLine * hexStride + style.ItemSpacing.x * 2.0f;

        // Determine hovered byte on this line (check both hex and ascii rects)
        int hoveredIdx = -1;
        for (int j = 0; j < bytesPerLine; ++j) {
            size_t i = off + j; if (i >= hp.len) break;
            ImRect hexR(ImVec2(hexX + j * hexStride, y), ImVec2(hexX + (j + 1) * hexStride, y + lineH));
            ImRect ascR(ImVec2(asciiX + j * charW, y), ImVec2(asciiX + (j + 1) * charW, y + lineH));
            if (hexR.Contains(mouse) || ascR.Contains(mouse)) { hoveredIdx = (int)i; break; }
        }

        // Update selection state from mouse
        if (hoveredIdx >= 0) {
            if (ImGui::IsMouseClicked(0)) { s_selStart = s_selEnd = hoveredIdx; s_dragging = true; }
        }
        if (s_dragging) {
            if (ImGui::IsMouseDown(0)) { if (hoveredIdx >= 0) s_selEnd = hoveredIdx; }
            else s_dragging = false;
        }
        if (ImGui::IsMouseClicked(1)) { s_selStart = s_selEnd = -1; s_dragging = false; }

        const int selMin = (s_selStart >= 0 && s_selEnd >= 0) ? std::min(s_selStart, s_selEnd) : -1;
        const int selMax = (s_selStart >= 0 && s_selEnd >= 0) ? std::max(s_selStart, s_selEnd) : -1;

        // Draw hex + ascii with highlights
        for (int j = 0; j < bytesPerLine; ++j) {
            size_t i = off + j;
            const ImU32 txtCol = (i < hp.len) ? colors[i] : ImGui::GetColorU32(ImGuiCol_Text);
            ImVec2 hpPos = ImVec2(hexX + j * hexStride, y);
            ImVec2 ascPos = ImVec2(asciiX + j * charW, y);
            ImRect hexR(hpPos, ImVec2(hpPos.x + hexStride, y + lineH));
            ImRect ascR(ascPos, ImVec2(ascPos.x + charW, y + lineH));

            // Backgrounds: selection then hover then segment highlight
            if ((int)i >= selMin && (int)i <= selMax && selMin != -1) {
                const ImU32 selCol = IM_COL32(255, 80, 80, 120);
                dl->AddRectFilled(hexR.Min, hexR.Max, selCol, 2.0f);
                dl->AddRectFilled(ascR.Min, ascR.Max, selCol, 2.0f);
            } else if ((int)i == hoveredIdx) {
                const ImU32 hovCol = IM_COL32(80, 160, 255, 90);
                dl->AddRectFilled(hexR.Min, hexR.Max, hovCol, 2.0f);
                dl->AddRectFilled(ascR.Min, ascR.Max, hovCol, 2.0f);
            } else if (g_hasHoveredSegment && 
                       i >= (uint32_t(0x28) + g_hoveredSegmentOffset) && 
                       i < (uint32_t(0x28) + g_hoveredSegmentOffset + g_hoveredSegmentSize)) {
                // Segment hover highlighting (light yellow)
                const ImU32 segCol = IM_COL32(255, 255, 120, 80);
                dl->AddRectFilled(hexR.Min, hexR.Max, segCol, 2.0f);
                dl->AddRectFilled(ascR.Min, ascR.Max, segCol, 2.0f);
            }

            // Hex text
            char b[4] = { 0 };
            if (i < hp.len) std::snprintf(b, sizeof(b), "%02x", hp.buf[i]); else { b[0] = ' '; b[1] = ' '; }
            dl->AddText(hpPos, txtCol, b);

            // ASCII text
            char c = (i < hp.len) ? (char)hp.buf[i] : ' ';
            if ((unsigned char)c < 32 || (unsigned char)c >= 127) c = '.';
            char s[2] = { c, 0 };
            dl->AddText(ascPos, txtCol, s);
        }

        cursor.y += lineH;
    }

    // reserve space and instructions
    ImGui::Dummy(ImVec2(0, totalLines * lineH));
    ImGui::TextDisabled("Hex selection: Left-drag to select bytes. Right-click to clear selection.");
}

bool SafeHookLogger::TryGetSelectedPacket(HookPacket& out)
{
    if (!g_hasSelection) return false;
    out = g_lastSelected;
    return true;
}

// === Decoding helpers using documented offsets ===
namespace {
    inline bool read16(const uint8_t* b, size_t len, size_t off, uint16_t& out) {
        if (!b || off + 2 > len) return false; out = (uint16_t)(b[off] | (b[off+1] << 8)); return true;
    }
    inline bool read32(const uint8_t* b, size_t len, size_t off, uint32_t& out) {
        if (!b || off + 4 > len) return false; out = (uint32_t)(b[off] | (b[off+1] << 8) | (b[off+2] << 16) | (b[off+3] << 24)); return true;
    }
    inline bool read64(const uint8_t* b, size_t len, size_t off, uint64_t& out) {
        if (!b || off + 8 > len) return false; out = 0; for (int i=0;i<8;i++) out |= (uint64_t)b[off+i] << (8*i); return true;
    }

    template<typename T>
    inline T loadLE(const uint8_t* b) {
        T v{}; std::memcpy(&v, b, sizeof(T)); return v;
    }

    struct ParsedPacket {
        // Packet header
        bool hdr_ok = false;
        uint64_t magic0=0, magic1=0, timestamp=0; // unix ms
        uint32_t size=0; uint16_t connType=0, segCount=0; uint8_t unknown20=0, isCompressed=0; uint32_t unknown24=0;
        // Segment header (first)
        bool seg_ok = false; uint32_t segSize=0, src=0, tgt=0; uint16_t segType=0, segPad=0;
        // IPC header (if segType==3)
        bool ipc_ok = false; uint16_t ipcReserved=0, opcode=0, ipcPad=0, serverId=0; uint32_t ipcTimestamp=0, ipcPad1=0;
    };

    struct SegmentInfo {
        uint32_t offset;   // absolute offset in packet buffer or decompressed view
        uint32_t size;
        uint32_t source;
        uint32_t target;
        uint16_t type;
        bool hasIpc;
        uint16_t opcode;
        uint16_t serverId;
        uint32_t ipcTimestamp;
    };

    static const char* SegTypeName(uint16_t t) {
        switch (t) {
            case 1: return "SESSIONINIT";
            case 3: return "IPC";
            case 7: return "KEEPALIVE";
            case 9: return "ENCRYPTIONINIT";
            default: return "?";
        }
    }

    struct SegmentView { const uint8_t* data=nullptr; size_t len=0; bool compressed=false; bool inflated=false; std::vector<uint8_t> storage; };

    // Build a view over the segment area (post header): either raw or inflated.
    static SegmentView GetSegmentView(const HookPacket& hp)
    {
        SegmentView v{};
        if (hp.len < 0x28) return v; // invalid
        const uint8_t* p = hp.buf.data(); const size_t L = hp.len;
        v.data = p + 0x28; v.len = L - 0x28; v.compressed = false; v.inflated = false;
        if (L >= 0x22) {
            uint16_t tmp = 0; std::memcpy(&tmp, p + 0x20, sizeof(tmp));
            v.compressed = (((tmp >> 8) & 0xFF) != 0);
        }
        if (!v.compressed || !g_cfgInflateSegments) return v;
        // Determine expected decompressed size from packet header
        uint32_t packetSize = 0; std::memcpy(&packetSize, p + 0x18, 4);
        size_t outLen = (packetSize > 0x28) ? (packetSize - 0x28) : 0;
        if (outLen == 0 || outLen > (64u<<20)) return v; // guard
        v.storage.resize(outLen);
        // Try raw DEFLATE first (no zlib header)
        size_t res = tinfl_decompress_mem_to_mem(v.storage.data(), outLen, v.data, v.len, 0);
        if (res == TINFL_DECOMPRESS_MEM_TO_MEM_FAILED || res != outLen) {
            // Try zlib header parsing as fallback
            res = tinfl_decompress_mem_to_mem(v.storage.data(), outLen, v.data, v.len, TINFL_FLAG_PARSE_ZLIB_HEADER);
            if (res == TINFL_DECOMPRESS_MEM_TO_MEM_FAILED || res != outLen) {
                // leave raw view if inflation failed
                v.storage.clear();
                return v;
            }
        }
        v.data = v.storage.data(); v.len = outLen; v.inflated = true; return v;
    }

    // Scan all segments in a given buffer containing concatenated segments.
    static void ParseAllSegmentsBuffer(const uint8_t* data, size_t len, std::vector<SegmentInfo>& outSegs)
    {
        outSegs.clear(); if (!data || len < 0x10) return;
        size_t pos = 0;
        while (true) {
            if (pos + 0x10 > len) break;
            uint32_t segSize = 0, src=0, tgt=0; uint16_t type=0, pad=0;
            std::memcpy(&segSize, data + pos + 0x00, 4);
            std::memcpy(&src,     data + pos + 0x04, 4);
            std::memcpy(&tgt,     data + pos + 0x08, 4);
            std::memcpy(&type,    data + pos + 0x0C, 2);
            std::memcpy(&pad,     data + pos + 0x0E, 2);
            if (segSize < 0x10 || pos + segSize > len) break;
            SegmentInfo si{}; si.offset = (uint32_t)pos; si.size = segSize; si.source = src; si.target = tgt; si.type = type; si.hasIpc = false; si.opcode=0; si.serverId=0; si.ipcTimestamp=0;
            if (type == 3 && segSize >= 0x20) {
                uint16_t opcode=0, serverId=0; uint32_t ts=0;
                std::memcpy(&opcode,   data + pos + 0x12, 2);
                std::memcpy(&serverId, data + pos + 0x16, 2);
                std::memcpy(&ts,       data + pos + 0x18, 4);
                si.hasIpc = true; si.opcode = opcode; si.serverId = serverId; si.ipcTimestamp = ts;
            }
            outSegs.push_back(si);
            pos += segSize;
        }
    }

    static ParsedPacket ParsePacket(const HookPacket& hp) {
        ParsedPacket P{};
        const uint8_t* p = hp.buf.data();
        const size_t L = hp.len;
        // Packet header at 0x00.. - use logical && instead of bitwise &
        P.hdr_ok = read64(p, L, 0x00, P.magic0) && read64(p, L, 0x08, P.magic1) && read64(p, L, 0x10, P.timestamp) && read32(p, L, 0x18, P.size) && read16(p, L, 0x1C, P.connType) && read16(p, L, 0x1E, P.segCount);
        if (L >= 0x22) {
            uint16_t tmp = 0; // Initialize to 0 to avoid uninitialized memory warning
            P.hdr_ok = P.hdr_ok && read16(p, L, 0x20, tmp);
            P.unknown20 = (uint8_t)(tmp & 0xFF);
            P.isCompressed = (uint8_t)((tmp >> 8) & 0xFF);
        }
        if (L >= 0x28) { (void)read32(p, L, 0x24, P.unknown24); }
        // Segment header just after packet header (assume at 0x28) - only reliable for uncompressed
        if (L >= 0x38 && P.isCompressed == 0) {
            P.seg_ok = read32(p, L, 0x28, P.segSize) && read32(p, L, 0x2C, P.src) && read32(p, L, 0x30, P.tgt) && read16(p, L, 0x34, P.segType) && read16(p, L, 0x36, P.segPad);
        }
        // IPC header after segment header (0x28 + 0x10 == 0x38)
        if (P.seg_ok && P.segType == 3 && L >= 0x48) {
            P.ipc_ok = read16(p, L, 0x38, P.ipcReserved) && read16(p, L, 0x3A, P.opcode) && read16(p, L, 0x3C, P.ipcPad) && read16(p, L, 0x3E, P.serverId) && read32(p, L, 0x40, P.ipcTimestamp) && read32(p, L, 0x44, P.ipcPad1);
        }
        return P;
    }

    // Resolve connection type for a packet: prefer cached mapping learned from SESSIONINIT, fallback to header field
    uint16_t ResolveConnType(const HookPacket& hp, const ParsedPacket& P) {
        auto it = g_connTypeByConnId.find(hp.connection_id);
        uint16_t cached = (it != g_connTypeByConnId.end()) ? it->second : 0xFFFF;
        uint16_t header = P.connType;
        if (header != 0 && header != 0xFFFF) {
            if (P.segCount > 0) g_connTypeByConnId[hp.connection_id] = header;
            return header;
        }
        if (cached != 0xFFFF) return cached;
        return 0xFFFF; // unknown
    }

    struct DecodedHeader {
        bool valid = false; // true if opcode read from IPC header
        uint16_t opcode = 0;
        uint16_t segType = 0;
        uint16_t connType = 0xFFFF; // resolved connection type
    };

    DecodedHeader DecodeForList(const HookPacket& hp) {
        DecodedHeader d{}; auto P = ParsePacket(hp); d.segType = P.seg_ok ? P.segType : 0; d.connType = ResolveConnType(hp, P);
        if (!P.isCompressed && P.ipc_ok) { d.valid = true; d.opcode = P.opcode; return d; }
        // If compressed or no first IPC header, parse from view to find first IPC
        SegmentView v = GetSegmentView(hp);
        std::vector<SegmentInfo> segs; ParseAllSegmentsBuffer(v.data, v.len, segs);
        for (const auto& s : segs) { if (s.hasIpc) { d.valid = true; d.opcode = s.opcode; break; } }
        return d;
    }

    // New: decode known payloads from a specific payload pointer/length (per IPC segment)
    static void RenderPayload_KnownAt(uint16_t opcode, bool outgoing, const HookPacket& hp, const uint8_t* payload, size_t payloadLen)
    {
        if (!payload || payloadLen == 0) return;

        auto rowKV = [](const char* k, const std::string& v){
            ImGui::TableNextRow(); ImGui::TableNextColumn(); ImGui::TextUnformatted(k);
            ImGui::TableNextColumn(); ImGui::TextUnformatted(v.c_str());
        };

        const uint8_t* buf = payload; size_t L = payloadLen; size_t base = 0; (void)base;

        // Client: ActionRequest (0x0196)
        if (outgoing && opcode == 0x0196 && L >= 0x18) {
            uint8_t execProc = *(buf + 0x00);
            uint8_t actionKind = *(buf + 0x01);
            uint32_t actionKey = loadLE<uint32_t>(buf + 0x04);
            uint32_t requestId = loadLE<uint32_t>(buf + 0x08);
            uint16_t dir = loadLE<uint16_t>(buf + 0x0C);
            uint16_t dirTarget = loadLE<uint16_t>(buf + 0x0E);
            uint64_t target = loadLE<uint64_t>(buf + 0x10);
            uint32_t arg = (L >= 0x1C) ? loadLE<uint32_t>(buf + 0x18) : 0;
            rowKV("req.execProc", std::to_string(execProc));
            rowKV("req.actionKind", std::to_string(actionKind));
            rowKV("req.actionKey", std::to_string(actionKey));
            rowKV("req.requestId", std::to_string(requestId));
            rowKV("req.dir", std::to_string(dir));
            rowKV("req.dirTarget", std::to_string(dirTarget));
            {
                std::ostringstream os; os << "0x" << std::hex << target; rowKV("req.target", os.str());
            }
            if (L >= 0x1C) rowKV("req.arg", std::to_string(arg));
            // Store correlation
            ActionReqRec rec{ hp.connection_id, hp.ts, actionKind, actionKey, target, dir, dirTarget };
            g_actionReqById[requestId] = rec;
            return;
        }

        // Server: ActionResult (0x0147) and ActionResult1 (0x0146)
        if (!outgoing && (opcode == 0x0147 || opcode == 0x0146) && L >= 0x20) {
            uint64_t mainTarget = loadLE<uint64_t>(buf + 0x00);
            uint16_t action = loadLE<uint16_t>(buf + 0x08);
            uint8_t actionArg = *(buf + 0x0A);
            uint8_t actionKind = *(buf + 0x0B);
            uint32_t actionKey = loadLE<uint32_t>(buf + 0x0C);
            uint32_t requestId = loadLE<uint32_t>(buf + 0x10);
            uint32_t resultId = loadLE<uint32_t>(buf + 0x14);
            float lockTime = loadLE<float>(buf + 0x18);
            rowKV("res.mainTarget", std::to_string((uint32_t)(mainTarget & 0xFFFFFFFF)));
            rowKV("res.action", std::to_string(action));
            rowKV("res.actionArg", std::to_string(actionArg));
            rowKV("res.actionKind", std::to_string(actionKind));
            rowKV("res.actionKey", std::to_string(actionKey));
            rowKV("res.requestId", std::to_string(requestId));
            rowKV("res.resultId", std::to_string(resultId));
            rowKV("res.lockTime", std::to_string(lockTime));
            // Correlate
            auto it = g_actionReqById.find(requestId);
            if (it != g_actionReqById.end()) {
                auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(hp.ts - it->second.ts).count();
                rowKV("res.correlatesWith", std::string("ActionRequest ") + std::to_string(requestId) + " (" + std::to_string(dt) + " ms)" );
            }
            return;
        }

        // ChatHandler (client 0x0067)
        if (outgoing && opcode == 0x0067 && L >= 0x18) {
            uint32_t clientTime = loadLE<uint32_t>(buf + 0x00);
            uint32_t origin = loadLE<uint32_t>(buf + 0x04);
            float px = loadLE<float>(buf + 0x08);
            float py = loadLE<float>(buf + 0x0C);
            float pz = loadLE<float>(buf + 0x10);
            float dir = loadLE<float>(buf + 0x14);
            uint16_t chatType = (L >= 0x1A) ? loadLE<uint16_t>(buf + 0x18) : 0;
            const char* msg = (L > 0x1A) ? reinterpret_cast<const char*>(buf + 0x1A) : "";
            std::string smsg = msg; if (auto nz = smsg.find('\0'); nz != std::string::npos) smsg.resize(nz);
            rowKV("chat.clientTime", std::to_string(clientTime));
            { std::ostringstream os; os << "0x" << std::hex << origin; rowKV("chat.origin", os.str()); }
            { std::ostringstream os; os << px << ", " << py << ", " << pz; rowKV("chat.pos", os.str()); }
            rowKV("chat.dir", std::to_string(dir));
            { std::ostringstream os; os << "0x" << std::hex << chatType; rowKV("chat.type", os.str()); }
            rowKV("chat.message", smsg);
            return;
        }

        // Client: Command (0x0191)
        if (outgoing && opcode == 0x0191 && L >= 0x18) {
            uint32_t id   = loadLE<uint32_t>(buf + 0x00);
            uint32_t a0   = loadLE<uint32_t>(buf + 0x04);
            uint32_t a1   = loadLE<uint32_t>(buf + 0x08);
            uint32_t a2   = loadLE<uint32_t>(buf + 0x0C);
            uint32_t a3   = loadLE<uint32_t>(buf + 0x10);
            uint64_t tgt  = (L >= 0x20) ? loadLE<uint64_t>(buf + 0x10 + 4) : 0ULL;
            auto hex32 = [](uint32_t v){ std::ostringstream os; os << "0x" << std::hex << v << " (" << std::dec << v << ")"; return os.str(); };
            rowKV("cmd.Id", hex32(id)); rowKV("cmd.Arg0", hex32(a0)); rowKV("cmd.Arg1", hex32(a1)); rowKV("cmd.Arg2", hex32(a2)); rowKV("cmd.Arg3", hex32(a3));
            { std::ostringstream os; os << "0x" << std::hex << tgt; rowKV("cmd.Target", os.str()); }
            return;
        }

        // Server: ActorControl / Self / Target
        if (!outgoing && (opcode == 0x0142 || opcode == 0x0143 || opcode == 0x0144) && L >= 0x14) {
            uint16_t category = loadLE<uint16_t>(buf + 0x00);
            uint32_t p1 = loadLE<uint32_t>(buf + 0x04);
            uint32_t p2 = loadLE<uint32_t>(buf + 0x08);
            uint32_t p3 = loadLE<uint32_t>(buf + 0x0C);
            uint32_t p4 = loadLE<uint32_t>(buf + 0x10);
            rowKV("actctl.category", std::to_string(category));
            rowKV("actctl.param1", std::to_string(p1));
            rowKV("actctl.param2", std::to_string(p2));
            rowKV("actctl.param3", std::to_string(p3));
            rowKV("actctl.param4", std::to_string(p4));
            if (opcode == 0x0143 && L >= 0x1C) {
                uint32_t p5 = loadLE<uint32_t>(buf + 0x14);
                uint32_t p6 = loadLE<uint32_t>(buf + 0x18);
                rowKV("actctl.param5", std::to_string(p5));
                rowKV("actctl.param6", std::to_string(p6));
            }
            if (opcode == 0x0144 && L >= 0x20) {
                uint64_t tgt = loadLE<uint64_t>(buf + 0x18);
                { std::ostringstream os; os << "0x" << std::hex << tgt; rowKV("actctl.targetId", os.str()); }
            }
            return;
        }

        // Server: InitZone (0x019A)
        if (!outgoing && opcode == 0x019A && L >= 0x20) {
            uint16_t ZoneId = loadLE<uint16_t>(buf + 0x00);
            uint16_t TerritoryType = loadLE<uint16_t>(buf + 0x02);
            uint16_t TerritoryIndex = loadLE<uint16_t>(buf + 0x04);
            uint32_t LayerSetId = loadLE<uint32_t>(buf + 0x08);
            uint32_t LayoutId = loadLE<uint32_t>(buf + 0x0C);
            uint8_t WeatherId = *(buf + 0x10);
            uint8_t Flag = *(buf + 0x11);
            float px = loadLE<float>(buf + 0x18);
            float py = loadLE<float>(buf + 0x1C);
            float pz = loadLE<float>(buf + 0x20);
            rowKV("init.ZoneId", std::to_string(ZoneId));
            rowKV("init.TerritoryType", std::to_string(TerritoryType));
            rowKV("init.TerritoryIndex", std::to_string(TerritoryIndex));
            rowKV("init.LayerSetId", std::to_string(LayerSetId));
            rowKV("init.LayoutId", std::to_string(LayoutId));
            rowKV("init.WeatherId", std::to_string(WeatherId));
            rowKV("init.Flag", std::to_string(Flag));
            {
                std::ostringstream os; os << px << ", " << py << ", " << pz; rowKV("init.Pos", os.str());
            }
            return;
        }

        // Server: Name (0x01A7)
        if (!outgoing && opcode == 0x01A7 && L >= 0x28) {
            uint64_t contentId = loadLE<uint64_t>(buf + 0x00);
            const char* name = reinterpret_cast<const char*>(buf + 0x08);
            std::string nm = name; if (auto nz = nm.find('\0'); nz != std::string::npos) nm.resize(nz);
            { std::ostringstream os; os << "0x" << std::hex << contentId; rowKV("name.contentId", os.str()); }
            rowKV("name.name", nm);
            return;
        }

        // Server: ActorCast (0x0196)
        if (!outgoing && opcode == 0x0196 && L >= 0x20) {
            uint16_t action = loadLE<uint16_t>(buf + 0x00);
            uint8_t actionKind = *(buf + 0x02);
            uint32_t actionKey = loadLE<uint32_t>(buf + 0x04);
            float castTime = loadLE<float>(buf + 0x08);
            uint32_t target = loadLE<uint32_t>(buf + 0x0C);
            float dir = loadLE<float>(buf + 0x10);
            uint32_t ballistaId = loadLE<uint32_t>(buf + 0x14);
            uint16_t tx = 0, ty = 0, tz = 0;
            if (L >= 0x1A) tx = loadLE<uint16_t>(buf + 0x18);
            if (L >= 0x1C) ty = loadLE<uint16_t>(buf + 0x1A);
            if (L >= 0x1E) tz = loadLE<uint16_t>(buf + 0x1C);
            rowKV("cast.action", std::to_string(action));
            rowKV("cast.kind", std::to_string(actionKind));
            { std::ostringstream os; os << "0x" << std::hex << actionKey << " (" << std::dec << actionKey << ")"; rowKV("cast.key", os.str()); }
            rowKV("cast.time", std::to_string(castTime));
            { std::ostringstream os; os << "0x" << std::hex << target << " (" << std::dec << target << ")"; rowKV("cast.target", os.str()); }
            rowKV("cast.dir", std::to_string(dir));
            rowKV("cast.ballista", std::to_string(ballistaId));
            { char b[96]; std::snprintf(b,sizeof(b),"(%u,%u,%u)", tx,ty,tz); rowKV("cast.targetPos", b); }
            return;
        }

        // Server: Warp (0x0194)
        if (!outgoing && opcode == 0x0194 && L >= 0x10) {
            uint16_t dir = loadLE<uint16_t>(buf + 0x00);
            uint8_t type = *(buf + 0x02);
            uint8_t typeArg = *(buf + 0x03);
            uint32_t layerSet = loadLE<uint32_t>(buf + 0x04);
            float x = 0, y = 0, z = 0;
            if (L >= 0x10) { x = loadLE<float>(buf + 0x08); y = loadLE<float>(buf + 0x0C); z = loadLE<float>(buf + 0x10); }
            rowKV("warp.dir", std::to_string(dir)); rowKV("warp.type", std::to_string(type)); rowKV("warp.typeArg", std::to_string(typeArg));
            { std::ostringstream os; os << "0x" << std::hex << layerSet << " (" << std::dec << layerSet << ")"; rowKV("warp.layerSet", os.str()); }
            { char b[96]; std::snprintf(b,sizeof(b),"(%.3f,%.3f,%.3f)", x,y,z); rowKV("warp.pos", b); }
            return;
        }

        // Move / ActorMove: try float then byte-variant
        if ((outgoing && opcode == 0x019A) || (!outgoing && opcode == 0x0192)) {
            if (L >= 0x1C) {
                float dir = loadLE<float>(buf + 0x00), dirBeforeSlip = loadLE<float>(buf + 0x04);
                uint8_t flag = *(buf + 0x08), flag2 = *(buf + 0x09), flag_unshared = *(buf + 0x0A);
                float px = loadLE<float>(buf + 0x0C), py = loadLE<float>(buf + 0x10), pz = loadLE<float>(buf + 0x14);
                char b[256]; std::snprintf(b,sizeof(b),"dir=%.3f dirBeforeSlip=%.3f flag=%u flag2=%u flagU=%u", dir, dirBeforeSlip, flag, flag2, flag_unshared); rowKV("move.core", b);
                std::snprintf(b,sizeof(b),"(%.3f, %.3f, %.3f)", px, py, pz); rowKV("move.pos", b);
            } else if (L >= 0x20) {
                uint8_t dir = *(buf + 0x14), dirBeforeSlip = *(buf + 0x15), flag = *(buf + 0x16), flag2 = *(buf + 0x17), speed = *(buf + 0x18);
                uint16_t px = (uint16_t)(buf[0x1A] | (buf[0x1B] << 8));
                uint16_t py = (uint16_t)(buf[0x1C] | (buf[0x1D] << 8));
                uint16_t pz = (uint16_t)(buf[0x1E] | (buf[0x1F] << 8));
                char b[256]; std::snprintf(b,sizeof(b),"dir=%u dirBeforeSlip=%u flag=%u flag2=%u speed=%u", dir, dirBeforeSlip, flag, flag2, speed); rowKV("move.core", b);
                std::snprintf(b,sizeof(b),"(%u, %u, %u)", px, py, pz); rowKV("move.pos", b);
            }
            return;
        }
    }

    // Backward-compatible entry: find the appropriate payload slice when possible and call RenderPayload_KnownAt
    static void RenderPayload_Known(uint16_t opcode, bool outgoing, const HookPacket& hp)
    {
        auto view = GetSegmentView(hp);
        if (view.data) {
            std::vector<SegmentInfo> segs; ParseAllSegmentsBuffer(view.data, view.len, segs);
            for (const auto& s : segs) {
                if (s.hasIpc && s.opcode == opcode) {
                    const uint8_t* payload = view.data + s.offset + 0x20;
                    size_t payloadLen = (s.size > 0x20) ? (s.size - 0x20) : 0;
                    RenderPayload_KnownAt(opcode, outgoing, hp, payload, payloadLen);
                    return;
                }
            }
        }
        // Fallback to raw first IPC payload offset
        if (hp.len > 0x48) {
            const uint8_t* payload = hp.buf.data() + 0x48;
            size_t payloadLen = hp.len - 0x48;
            RenderPayload_KnownAt(opcode, outgoing, hp, payload, payloadLen);
        }
    }

    static void RenderPayload_Heuristics(const uint8_t* base, size_t len)
    {
        if (!base || len == 0) return;
        if (ImGui::CollapsingHeader("Payload preview (heuristic)", ImGuiTreeNodeFlags_DefaultOpen))
        {
            // u32 view
            if (ImGui::BeginTable("pv_u32", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
                ImGui::TableSetupColumn("off"); ImGui::TableSetupColumn("u32 (dec)"); ImGui::TableSetupColumn("u32 (hex)"); ImGui::TableSetupColumn("float");
                for (size_t off=0; off+4<=len; off+=4) {
                    uint32_t v = loadLE<uint32_t>(base+off);
                    float f; std::memcpy(&f, base+off, sizeof(float));
                    char b1[32], b2[32], b3[64];
                    std::snprintf(b1,sizeof(b1),"0x%04zx", off);
                    std::snprintf(b2,sizeof(b2),"%u", v);
                    std::snprintf(b3,sizeof(b3),"0x%08X  (%.4f)", v, f);
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(b1);
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(b2);
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(b3);
                    ImGui::TableNextColumn(); ImGui::Text("%.6f", f);
                }
                ImGui::EndTable();
            }

            // u16 view (compact)
            if (ImGui::CollapsingHeader("u16 view", ImGuiTreeNodeFlags_None)) {
                if (ImGui::BeginTable("pv_u16", 8, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
                    for (size_t off=0; off+2<=len; off+=16) {
                        ImGui::TableNextRow();
                        for (int i=0;i<8;i++) {
                            size_t o2 = off + i*2; ImGui::TableNextColumn();
                            if (o2+2<=len) {
                                uint16_t v = loadLE<uint16_t>(base+o2);
                                ImGui::Text("%04zx:%5u (0x%04X)", o2, v, v);
                            } else {
                                ImGui::TextUnformatted(" ");
                            }
                        }
                    }
                    ImGui::EndTable();
                }
            }
        }
    }
}

// Filter UI state and helpers remain the same
namespace {
    struct Filters {
        bool showSend = true;
        bool showRecv = true;
        bool onlyKnown = false;
        char opcodeList[128] = ""; // comma-separated
        char search[128] = "";
        std::string lastParsed;
        std::unordered_set<uint16_t> opcodes;
        void parseOpcodesIfChanged() {
            if (lastParsed == opcodeList) return;
            lastParsed = opcodeList;
            opcodes.clear();
            std::string s = lastParsed; std::string tok;
            auto push = [&](const std::string& t){
                if (t.empty()) return; char* end=nullptr; unsigned long v=0;
                if (t.rfind("0x",0)==0 || t.rfind("0X",0)==0) v = strtoul(t.c_str()+2,&end,16);
                else v = strtoul(t.c_str(),&end,10);
                if (end!=t.c_str()) opcodes.insert(static_cast<uint16_t>(v & 0xFFFF));
            };
            size_t start=0; while (start<=s.size()) { size_t comma=s.find(',',start); std::string t=s.substr(start, comma==std::string::npos? std::string::npos: comma-start); // trim
                t.erase(0, t.find_first_not_of(" \t")); if (!t.empty()) t.erase(t.find_last_not_of(" \t")+1);
                push(t); if (comma==std::string::npos) break; start=comma+1; }
        }
    };
    Filters& GetFilters(){ static Filters f; return f; }

    bool Matches(const HookPacket& hp, const DecodedHeader& dec, const Filters& f) {
        if (hp.outgoing && !f.showSend) return false;
        if (!hp.outgoing && !f.showRecv) return false;
        if (f.onlyKnown && !dec.valid) return false;
        if (!f.opcodes.empty()) {
            if (!dec.valid || f.opcodes.find(dec.opcode) == f.opcodes.end()) return false;
        }
        if (f.search[0] != '\0') {
            std::string q = f.search; std::transform(q.begin(), q.end(), q.begin(), ::tolower);
            const char* nm = dec.valid ? LookupOpcodeName(dec.opcode, hp.outgoing, dec.connType) : "";
            char hexbuf[16]; std::snprintf(hexbuf, sizeof(hexbuf), "%04x", (unsigned)(dec.opcode));
            std::string name = nm; std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            std::string hex = hexbuf;
            if (name.find(q) == std::string::npos && hex.find(q) == std::string::npos) return false;
        }
        return true;
    }
}

static void DrawFilters() {
    auto& f = GetFilters();
    f.parseOpcodesIfChanged();
    ImGui::Checkbox("Send", &f.showSend); ImGui::SameLine();
    ImGui::Checkbox("Recv", &f.showRecv); ImGui::SameLine();
    ImGui::Checkbox("Known only", &f.onlyKnown); ImGui::SameLine();
    ImGui::Checkbox("Inflate compressed", &g_cfgInflateSegments);
    ImGui::SetNextItemWidth(180);
    ImGui::InputTextWithHint("##opcodes", "Opcodes (e.g. 0x67,0x191)", f.opcodeList, sizeof(f.opcodeList));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(180);
    ImGui::InputTextWithHint("##search", "Search name/hex", f.search, sizeof(f.search));
}

static void DrawPacketHeaderTable(const ParsedPacket& P, uint16_t resolvedConn) {
    if (!P.hdr_ok) return;
    if (ImGui::BeginTable("pkt_hdr_main", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        auto row=[&](const char* k, const char* v){ ImGui::TableNextRow(); ImGui::TableNextColumn(); ImGui::TextUnformatted(k); ImGui::TableNextColumn(); ImGui::TextUnformatted(v); };
        char b[128];
        std::snprintf(b,sizeof(b),"0x%016llX 0x%016llX", (unsigned long long)P.magic0, (unsigned long long)P.magic1); row("magic[2]", b);
        std::snprintf(b,sizeof(b),"%llu", (unsigned long long)P.timestamp); row("timestamp(ms)", b);
        std::snprintf(b,sizeof(b),"%u", P.size); row("size", b);
        std::snprintf(b,sizeof(b),"%u", P.connType); row("connectionType (header)", b);
        std::snprintf(b,sizeof(b),"%u", P.segCount); row("segmentCount", b);
        std::snprintf(b,sizeof(b),"0x%02X", P.unknown20); row("unknown_20", b);
        std::snprintf(b,sizeof(b),"%u", (unsigned)P.isCompressed); row("isCompressed", b);
        std::snprintf(b,sizeof(b),"0x%08X", P.unknown24); row("unknown_24", b);
        if (resolvedConn != 0xFFFF) { std::snprintf(b,sizeof(b),"%u", resolvedConn); row("connectionType (resolved)", b); }
        ImGui::EndTable();
    }
}

static void DrawSegmentHeaderTable(const ParsedPacket& P) {
    if (!P.seg_ok) return;
    if (ImGui::BeginTable("pkt_hdr_seg", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        auto row=[&](const char* k, const char* v){ ImGui::TableNextRow(); ImGui::TableNextColumn(); ImGui::TextUnformatted(k); ImGui::TableNextColumn(); ImGui::TextUnformatted(v); };
        char b[128];
        std::snprintf(b,sizeof(b),"%u", P.segSize); row("size", b);
        std::snprintf(b,sizeof(b),"0x%08X (%u)", P.src, P.src); row("source_actor", b);
        std::snprintf(b,sizeof(b),"0x%08X (%u)", P.tgt, P.tgt); row("target_actor", b);
        std::snprintf(b,sizeof(b),"%u (%s)", P.segType, SegTypeName(P.segType)); row("type", b);
        std::snprintf(b,sizeof(b),"0x%04X", P.segPad); row("padding", b);
        ImGui::EndTable();
    }
}

// Show IPC headers for all IPC segments and render structured payloads + heuristics
static void DrawIPCHeaderTable(const ParsedPacket& /*P*/, bool outgoing, const HookPacket& hp, uint16_t resolvedConn) {
    // Use segment view to find all IPC segments
    SegmentView v = GetSegmentView(hp);
    std::vector<SegmentInfo> segs; ParseAllSegmentsBuffer(v.data, v.len, segs);

    int ipcIndex = 0;
    for (const auto& s : segs) if (s.hasIpc) {
        ImGui::SeparatorText("IPC segment");
        if (ImGui::BeginTable((std::string("pkt_hdr_ipc_") + std::to_string(ipcIndex)).c_str(), 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
            auto row=[&](const char* k, const char* v){ ImGui::TableNextRow(); ImGui::TableNextColumn(); ImGui::TextUnformatted(k); ImGui::TableNextColumn(); ImGui::TextUnformatted(v); };
            char b[256];
            const char* name = LookupOpcodeName(s.opcode, outgoing, resolvedConn);
            std::snprintf(b,sizeof(b),"0x%04X (%s)", s.opcode, name); row("type (opcode)", b);
            std::snprintf(b,sizeof(b),"%u", s.serverId); row("serverId", b);
            std::snprintf(b,sizeof(b),"%u", s.ipcTimestamp); row("timestamp", b);

            // Known payload renderer for this specific segment
            const uint8_t* payload = v.data + s.offset + 0x20;
            size_t payloadLen = (s.size > 0x20) ? (s.size - 0x20) : 0;
            RenderPayload_KnownAt(s.opcode, outgoing, hp, payload, payloadLen);
            ImGui::EndTable();
        }
        ++ipcIndex;
    }

    // Heuristic payload view (entire view buffer)
    if (v.data && v.len) {
        RenderPayload_Heuristics(v.data, v.len);
    }
}

static void DrawAllSegmentsTable(const HookPacket& hp, uint16_t resolvedConn)
{
    SegmentView v = GetSegmentView(hp);
    if (!v.data) return;
    
    std::vector<SegmentInfo> segs; ParseAllSegmentsBuffer(v.data, v.len, segs);
    
    // Reset hover state at start of frame
    g_hasHoveredSegment = false;
    
    if (ImGui::BeginTable("pkt_all_segments", 6, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupColumn("#");
        ImGui::TableSetupColumn("offset");
        ImGui::TableSetupColumn("size");
        ImGui::TableSetupColumn("type");
        ImGui::TableSetupColumn("src->tgt");
        ImGui::TableSetupColumn("opcode");
        ImGui::TableHeadersRow();
        
        for (size_t i=0;i<segs.size();++i) {
            const auto& s = segs[i];
            ImGui::TableNextRow();
            
            // Use an invisible selectable to detect row hover
            ImGui::TableNextColumn(); 
            ImGui::PushID((int)i);
            bool rowHovered = ImGui::Selectable("##row", false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowItemOverlap);
            if (ImGui::IsItemHovered()) {
                g_hasHoveredSegment = true;
                g_hoveredSegmentIndex = (int)i;
                g_hoveredSegmentOffset = s.offset;
                g_hoveredSegmentSize = s.size;
            }
            ImGui::PopID();
            ImGui::SameLine();
            
            // Draw actual content
            ImGui::Text("%zu", i);
            ImGui::TableNextColumn(); ImGui::Text("0x%04X", s.offset);
            ImGui::TableNextColumn(); ImGui::Text("%u", s.size);
            ImGui::TableNextColumn(); ImGui::Text("%u (%s)", s.type, SegTypeName(s.type));
            ImGui::TableNextColumn(); ImGui::Text("%u -> %u", s.source, s.target);
            ImGui::TableNextColumn();
            if (s.hasIpc) {
                const char* nm = LookupOpcodeName(s.opcode, false /*direction unknown for list*/, resolvedConn);
                ImGui::Text("0x%04X (%s)", s.opcode, nm);
            } else {
                ImGui::TextUnformatted("-");
            }
        }
        ImGui::EndTable();
    }
}

// Export helpers
namespace {
    static std::string Hex(const uint8_t* d, size_t n) {
        static const char* k = "0123456789ABCDEF"; std::string s; s.resize(n*2);
        for (size_t i=0;i<n;++i) { s[2*i] = k[(d[i]>>4)&0xF]; s[2*i+1] = k[d[i]&0xF]; }
        return s;
    }

    static void EnsureExportDir() {
        std::error_code ec; std::filesystem::create_directories("exports", ec);
    }

    static bool ExportToJsonAs(const HookPacket& hp, const std::string& filepath) {
        try {
            std::filesystem::path p(filepath);
            if (p.has_parent_path()) {
                std::error_code ec; std::filesystem::create_directories(p.parent_path(), ec);
            }
            std::ofstream f(p, std::ios::binary);
            if (!f) return false;
            ParsedPacket P = ParsePacket(hp);
            SegmentView v = GetSegmentView(hp);
            std::vector<SegmentInfo> segs; ParseAllSegmentsBuffer(v.data, v.len, segs);
            f << "{\n";
            f << "  \"outgoing\": " << (hp.outgoing?"true":"false") << ",\n";
            f << "  \"connectionId\": " << hp.connection_id << ",\n";
            f << "  \"header\": { \"size\": " << P.size << ", \"connType\": " << P.connType << ", \"segCount\": " << P.segCount << ", \"isCompressed\": " << (unsigned)P.isCompressed << " },\n";
            f << "  \"segments\": [\n";
            for (size_t i=0;i<segs.size();++i) {
                const auto& s = segs[i];
                f << "    { \"offset\": "<<s.offset<<", \"size\": "<<s.size<<", \"type\": "<<s.type;
                if (s.hasIpc) f << ", \"opcode\": "<< s.opcode;
                f << " }" << (i+1<segs.size() ? ",\n" : "\n");
            }
            f << "  ],\n";
            f << "  \"payloadHex\": \"" << Hex(hp.buf.data(), hp.len) << "\"\n";
            f << "}\n";
            return true;
        } catch (...) { return false; }
    }

    static bool ExportToPcapAs(const HookPacket& hp, const std::string& filepath) {
        try {
            std::filesystem::path p(filepath);
            if (p.has_parent_path()) {
                std::error_code ec; std::filesystem::create_directories(p.parent_path(), ec);
            }
            auto tp = std::chrono::time_point_cast<std::chrono::microseconds>(hp.ts);
            uint64_t micros = (uint64_t)tp.time_since_epoch().count();
            uint32_t ts_sec = (uint32_t)(micros / 1000000ULL);
            uint32_t ts_usec = (uint32_t)(micros % 1000000ULL);
            std::ofstream f(p, std::ios::binary);
            if (!f) return false;
            // PCAP Global Header
            struct GH { uint32_t magic; uint16_t vmaj, vmin; int32_t thiszone; uint32_t sigfigs; uint32_t snaplen; uint32_t network; } gh{0xA1B2C3D4,2,4,0,0,0x00040000,1}; // LINKTYPE_ETHERNET
            f.write((const char*)&gh, sizeof(gh));
            // Build Ethernet+IPv4+UDP around payload
            const std::vector<uint8_t> payload(hp.buf.begin(), hp.buf.begin()+hp.len);
            const uint16_t udp_payload_len = (uint16_t)payload.size();
            const uint16_t udp_len = 8 + udp_payload_len;
            const uint16_t ip_len = 20 + udp_len;
            std::vector<uint8_t> frame;
            frame.resize(14 + ip_len);
            // Ethernet
            uint8_t* eth = frame.data();
            uint8_t dst[6] = {0x02,0,0,0,0,0x02}; uint8_t src[6] = {0x02,0,0,0,0,0x01};
            if (!hp.outgoing) { std::swap_ranges(dst, dst+6, src); }
            memcpy(eth, dst, 6); memcpy(eth+6, src, 6); eth[12]=0x08; eth[13]=0x00; // IPv4
            // IPv4
            auto ip_checksum = [](const uint8_t* buf, size_t len){ uint32_t sum=0; for (size_t i=0;i+1<len;i+=2) sum += (buf[i]<<8) | buf[i+1]; if (len&1) sum += (buf[len-1]<<8); while (sum>>16) sum = (sum & 0xFFFF) + (sum>>16); return (uint16_t)(~sum); };
            uint8_t* ip = eth + 14; memset(ip,0,20);
            ip[0] = 0x45; // v4, ihl=5
            ip[2] = (uint8_t)(ip_len>>8); ip[3] = (uint8_t)ip_len;
            ip[6] = 0x40; // flags/frag
            ip[8] = 64;   // ttl
            ip[9] = 17;   // UDP
            uint8_t saddr[4] = {10,0,0,1}; uint8_t daddr[4] = {10,0,0,2}; if (!hp.outgoing) { std::swap_ranges(saddr, saddr+4, daddr); }
            memcpy(ip+12, saddr,4); memcpy(ip+16, daddr,4);
            uint16_t csum = ip_checksum(ip,20); ip[10] = (uint8_t)(csum>>8); ip[11]=(uint8_t)csum;
            // UDP
            uint8_t* udp = ip + 20; uint16_t sport = hp.outgoing ? 55001 : 55002; uint16_t dport = hp.outgoing ? 55002 : 55001;
            udp[0]=(uint8_t)(sport>>8); udp[1]=(uint8_t)sport; udp[2]=(uint8_t)(dport>>8); udp[3]=(uint8_t)dport;
            udp[4]=(uint8_t)(udp_len>>8); udp[5]=(uint8_t)udp_len; udp[6]=udp[7]=0; // checksum omitted
            memcpy(udp+8, payload.data(), payload.size());
            // PCAP Packet Header
            struct PH { uint32_t ts_sec, ts_usec, incl_len, orig_len; } ph{ts_sec, ts_usec, (uint32_t)frame.size(), (uint32_t)frame.size()};
            f.write((const char*)&ph, sizeof(ph));
            f.write((const char*)frame.data(), frame.size());
            return true;
        } catch (...) { return false; }
    }

    static bool ExportToJson(const HookPacket& hp) {
        EnsureExportDir();
        auto t = std::chrono::system_clock::to_time_t(hp.ts);
        char fname[256]; std::strftime(fname, sizeof(fname), "exports/packet_%Y%m%d_%H%M%S.json", std::localtime(&t));
        return ExportToJsonAs(hp, fname);
    }

    static bool ExportToPcap(const HookPacket& hp) {
        EnsureExportDir();
        auto t = std::chrono::system_clock::to_time_t(hp.ts);
        char fname[256]; std::strftime(fname, sizeof(fname), "exports/packet_%Y%m%d_%H%M%S.pcap", std::localtime(&t));
        return ExportToPcapAs(hp, fname);
    }
}

static void DrawPacketListAndDetails(const std::vector<HookPacket>& display) {
    DrawFilters();
    auto& f = GetFilters();
    f.parseOpcodesIfChanged();

    // Build filtered index map
    static std::vector<int> filtered; filtered.clear(); filtered.reserve(display.size());
    for (int i=0;i<(int)display.size();++i){ const HookPacket& hp=display[i]; auto dec=DecodeForList(hp); if (Matches(hp,dec,f)) filtered.push_back(i);}    

    ImGui::Text("Shown: %d / %zu", (int)filtered.size(), display.size());

    // Top: list with fixed height (room for scrolling)
    ImGui::BeginChild("pkt_list", ImVec2(0, 260), true);
    ImGuiListClipper clip; clip.Begin((int)filtered.size());
    static int selectedFiltered = -1;
    while (clip.Step()) {
        for (int ri = clip.DisplayStart; ri < clip.DisplayEnd; ++ri) {
            int i = filtered[ri];
            const HookPacket& hp = display[i];
            const auto d = DecodeForList(hp);
            const char* name = d.valid ? LookupOpcodeName(d.opcode, hp.outgoing, d.connType) : "?";
            // Compute number of segments using view
            SegmentView v = GetSegmentView(hp); std::vector<SegmentInfo> tmp; ParseAllSegmentsBuffer(v.data, v.len, tmp);
            char label[300];
            if (d.valid)
                std::snprintf(label, sizeof(label), "%s op=%04x %-20s conn=%llu len=%u %s%zu segs",
                    hp.outgoing ? "SEND" : "RECV",
                    (unsigned)d.opcode, name,
                    (unsigned long long)hp.connection_id, hp.len,
                    (v.inflated?"(inflated) ": (hp.len>=0x22 && (hp.buf[0x21]!=0)?"(compressed) ":"")), tmp.size());
            else
                std::snprintf(label, sizeof(label), "%s seg=%u(%s) conn=%llu len=%u %s%zu segs",
                    hp.outgoing ? "SEND" : "RECV", (unsigned)d.segType, SegTypeName(d.segType),
                    (unsigned long long)hp.connection_id, hp.len,
                    (v.inflated?"(inflated) ": (hp.len>=0x22 && (hp.buf[0x21]!=0)?"(compressed) ":"")), tmp.size());

            ImGui::PushID(i);
            if (ImGui::Selectable(label, selectedFiltered == ri)) {
                selectedFiltered = ri;
                g_lastSelected = hp; g_hasSelection = true; // remember selection for external pane
            }
            ImGui::PopID();
        }
    }
    ImGui::EndChild();

    // Persistent state for export dialogs
    static bool s_openJsonDialog = false;
    static bool s_openPcapDialog = false;
    static HookPacket s_pendingJson{};
    static HookPacket s_pendingPcap{};

    // Bottom: details view fills all remaining height
    ImGui::BeginChild("pkt_details", ImVec2(0, 0), true);
    if (selectedFiltered >= 0 && selectedFiltered < (int)filtered.size()) {
        int selIndex = filtered[selectedFiltered];
        const HookPacket& hp = display[selIndex];
        const ParsedPacket P = ParsePacket(hp);
        uint16_t resolvedConn = ResolveConnType(hp, P);
        ImGui::Text("Packet header");
        DrawPacketHeaderTable(P, resolvedConn);
        ImGui::Text("First segment header (raw-only)");
        DrawSegmentHeaderTable(P);
        ImGui::Text("All segments");
        DrawAllSegmentsTable(hp, resolvedConn);
        ImGui::Text("IPC segments");
        DrawIPCHeaderTable(P, hp.outgoing, hp, resolvedConn);
        ImGui::Separator();
        if (ImGui::Button("Export JSON")) { s_pendingJson = hp; s_openJsonDialog = true; ImGuiFD::OpenDialog("Export JSON", ImGuiFDMode_SaveFile, "exports", "{JSON Files:*.json}, {*.*}"); }
        ImGui::SameLine();
        if (ImGui::Button("Export PCAP")) { s_pendingPcap = hp; s_openPcapDialog = true; ImGuiFD::OpenDialog("Export PCAP", ImGuiFDMode_SaveFile, "exports", "{PCAP Files:*.pcap}, {*.*}"); }
        ImGui::Separator();
    } else {
        ImGui::TextDisabled("Select a packet to view headers and hex dump");
    }
    ImGui::EndChild();

    // Handle JSON save dialog lifecycle
    if (ImGuiFD::BeginDialog("Export JSON")) {
        if (ImGuiFD::ActionDone()) {
            if (ImGuiFD::SelectionMade()) {
                // Expect a single selection
                const char* selPath = ImGuiFD::GetSelectionPathString(0);
                std::string path = selPath ? std::string(selPath) : std::string();
                if (!path.empty()) {
                    // Ensure .json extension
                    if (path.size() < 5 || path.substr(path.size()-5) != ".json")
                        path += ".json";
                    (void)ExportToJsonAs(s_pendingJson, path);
                }
            }
            ImGuiFD::CloseCurrentDialog();
            s_openJsonDialog = false;
        }
        ImGuiFD::EndDialog();
    }

    // Handle PCAP save dialog lifecycle
    if (ImGuiFD::BeginDialog("Export PCAP")) {
        if (ImGuiFD::ActionDone()) {
            if (ImGuiFD::SelectionMade()) {
                const char* selPath = ImGuiFD::GetSelectionPathString(0);
                std::string path = selPath ? std::string(selPath) : std::string();
                if (!path.empty()) {
                    if (path.size() < 5 || path.substr(path.size()-5) != ".pcap")
                        path += ".pcap";
                    (void)ExportToPcapAs(s_pendingPcap, path);
                }
            }
            ImGuiFD::CloseCurrentDialog();
            s_openPcapDialog = false;
        }
        ImGuiFD::EndDialog();
    }
}

void SafeHookLogger::DrawImGuiEmbedded() {
    static std::vector<HookPacket> ui_batch;
    DrainToVector(ui_batch);

    static std::vector<HookPacket> display;
    display.reserve(display.size() + ui_batch.size());
    for (auto& p : ui_batch) display.push_back(std::move(p));
    if (display.size() > 100000)
        display.erase(display.begin(), display.begin() + (display.size() - 100000));

    DrawPacketListAndDetails(display);
}

void SafeHookLogger::DrawImGuiSimple() {
    ImGui::Begin("Network Monitor");
    DrawImGuiEmbedded();
    ImGui::End();
}

void SafeHookLogger::DrawImGuiSimple(bool* p_open) {
    if (ImGui::Begin("Network Monitor", p_open)) {
        DrawImGuiEmbedded();
    }
    ImGui::End();
}
