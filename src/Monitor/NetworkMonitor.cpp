#include "NetworkMonitor.h"
#include <cstring>
#include "../vendor/imgui/imgui.h"
#include <sstream>
#include <cstdio>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <algorithm>
#include "OpcodeNames.h"

SafeHookLogger& SafeHookLogger::Instance() {
    static SafeHookLogger inst{};
    return inst;
}

// Track resolved connection type per connection_id (from SESSIONINIT packets)
namespace { static std::unordered_map<uint64_t, uint16_t> g_connTypeByConnId; }

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

    static const char* SegTypeName(uint16_t t) {
        switch (t) {
            case 1: return "SESSIONINIT";
            case 3: return "IPC";
            case 7: return "KEEPALIVE";
            case 9: return "ENCRYPTIONINIT";
            default: return "?";
        }
    }

    ParsedPacket ParsePacket(const HookPacket& hp) {
        ParsedPacket P{};
        const uint8_t* p = hp.buf.data();
        const size_t L = hp.len;
        // Packet header at 0x00..
        uint16_t dummy16;
        P.hdr_ok = read64(p,L,0x00,P.magic0) & read64(p,L,0x08,P.magic1) & read64(p,L,0x10,P.timestamp) & read32(p,L,0x18,P.size) & read16(p,L,0x1C,P.connType) & read16(p,L,0x1E,P.segCount);
        if (L >= 0x22) { uint16_t tmp; P.hdr_ok &= (read16(p,L,0x20,tmp)); P.unknown20 = (uint8_t)(tmp & 0xFF); P.isCompressed = (uint8_t)((tmp>>8)&0xFF); }
        if (L >= 0x28) { (void)read32(p,L,0x24,P.unknown24); }
        // Segment header just after packet header (assume at 0x28)
        if (L >= 0x38) {
            P.seg_ok = read32(p,L,0x28,P.segSize) & read32(p,L,0x2C,P.src) & read32(p,L,0x30,P.tgt) & read16(p,L,0x34,P.segType) & read16(p,L,0x36,P.segPad);
        }
        // IPC header after segment header (0x28 + 0x10 == 0x38)
        if (P.seg_ok && P.segType == 3 && L >= 0x48) {
            P.ipc_ok = read16(p,L,0x38,P.ipcReserved) & read16(p,L,0x3A,P.opcode) & read16(p,L,0x3C,P.ipcPad) & read16(p,L,0x3E,P.serverId) & read32(p,L,0x40,P.ipcTimestamp) & read32(p,L,0x44,P.ipcPad1);
        }
        return P;
    }

    // Resolve connection type for a packet: prefer cached mapping learned from SESSIONINIT, fallback to header field
    uint16_t ResolveConnType(const HookPacket& hp, const ParsedPacket& P) {
        auto it = g_connTypeByConnId.find(hp.connection_id);
        uint16_t cached = (it != g_connTypeByConnId.end()) ? it->second : 0xFFFF;
        uint16_t header = P.connType;
        if (P.seg_ok && P.segType == 1 && header != 0) {
            // Learn mapping
            g_connTypeByConnId[hp.connection_id] = header;
            return header;
        }
        if (header != 0) return header; // non-zero header on this packet
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
        DecodedHeader d{}; auto P = ParsePacket(hp); d.segType = P.segType; d.connType = ResolveConnType(hp, P); if (P.ipc_ok) { d.valid = true; d.opcode = P.opcode; } return d;
    }

    struct MoveFields { bool ok=false; uint8_t dir=0, dirBeforeSlip=0, flag=0, flag2=0, speed=0; uint16_t pad=0; uint16_t pos[3]{}; };

    // Try to decode Client Move (0x019A) or Server ActorMove (0x0192) payload
    // Our headers are 0x38 bytes; payload starts at 0x48. Offsets below are relative to payload start.
    MoveFields TryDecodeMove(const HookPacket& hp) {
        MoveFields m{};
        if (hp.len < 0x48 + 0x20) return m; // require minimal bytes for known fields
        const uint8_t* p = hp.buf.data();
        size_t base = 0x48; // start of IPC payload
        m.ok = true;
        m.dir = p[base + 0x14];
        m.dirBeforeSlip = p[base + 0x15];
        m.flag = p[base + 0x16];
        m.flag2 = p[base + 0x17];
        m.speed = p[base + 0x18];
        // two bytes padding/alignment commonly present
        if (hp.len >= base + 0x1C) {
            m.pos[0] = (uint16_t)(p[base + 0x1A] | (p[base + 0x1B] << 8));
            if (hp.len >= base + 0x1E)
                m.pos[1] = (uint16_t)(p[base + 0x1C] | (p[base + 0x1D] << 8));
            if (hp.len >= base + 0x20)
                m.pos[2] = (uint16_t)(p[base + 0x1E] | (p[base + 0x1F] << 8));
        }
        return m;
    }

    // Known payload renderers (prints rows inside the details area)
    static void RenderPayload_Known(uint16_t opcode, bool outgoing, const HookPacket& hp)
    {
        const uint8_t* buf = hp.buf.data();
        const size_t L = hp.len;
        const size_t base = (L >= 0x48) ? 0x48 : 0; // IPC payload start
        if (base == 0 || L <= base) return;

        auto rowKV = [](const char* k, const std::string& v){
            ImGui::TableNextRow(); ImGui::TableNextColumn(); ImGui::TextUnformatted(k);
            ImGui::TableNextColumn(); ImGui::TextUnformatted(v.c_str());
        };

        // ChatHandler (client 0x0067)
        if (outgoing && opcode == 0x0067 && L >= base + 0x18) {
            uint32_t clientTime = loadLE<uint32_t>(buf + base + 0x00);
            uint32_t origin = loadLE<uint32_t>(buf + base + 0x04);
            float px = loadLE<float>(buf + base + 0x08);
            float py = loadLE<float>(buf + base + 0x0C);
            float pz = loadLE<float>(buf + base + 0x10);
            float dir = loadLE<float>(buf + base + 0x14);
            uint16_t chatType = (L >= base + 0x1A) ? loadLE<uint16_t>(buf + base + 0x18) : 0;
            const char* msg = (L > base + 0x1A) ? reinterpret_cast<const char*>(buf + base + 0x1A) : "";
            std::string smsg = msg;
            if (auto nz = smsg.find('\0'); nz != std::string::npos) smsg.resize(nz);
            rowKV("chat.clientTime", std::to_string(clientTime));
            {
                std::ostringstream os; os << "0x" << std::hex << origin; rowKV("chat.origin", os.str());
            }
            {
                std::ostringstream os; os << px << ", " << py << ", " << pz; rowKV("chat.pos", os.str());
            }
            rowKV("chat.dir", std::to_string(dir));
            {
                std::ostringstream os; os << "0x" << std::hex << chatType; rowKV("chat.type", os.str());
            }
            rowKV("chat.message", smsg);
            return;
        }

        // Command (client 0x0191)
        if (outgoing && opcode == 0x0191 && L >= base + 0x18) {
            uint32_t id   = loadLE<uint32_t>(buf + base + 0x00);
            uint32_t a0   = loadLE<uint32_t>(buf + base + 0x04);
            uint32_t a1   = loadLE<uint32_t>(buf + base + 0x08);
            uint32_t a2   = loadLE<uint32_t>(buf + base + 0x0C);
            uint32_t a3   = loadLE<uint32_t>(buf + base + 0x10);
            uint64_t tgt  = (L >= base + 0x20) ? loadLE<uint64_t>(buf + base + 0x10 + 4) : 0ULL;
            auto hex32 = [](uint32_t v){ std::ostringstream os; os << "0x" << std::hex << v << " (" << std::dec << v << ")"; return os.str(); };
            rowKV("cmd.Id", hex32(id));
            rowKV("cmd.Arg0", hex32(a0));
            rowKV("cmd.Arg1", hex32(a1));
            rowKV("cmd.Arg2", hex32(a2));
            rowKV("cmd.Arg3", hex32(a3));
            {
                std::ostringstream os; os << "0x" << std::hex << tgt; rowKV("cmd.Target", os.str());
            }
            return;
        }

        // GMCommand (client 0x0197)
        if (outgoing && opcode == 0x0197 && L >= base + 0x18) {
            uint32_t id   = loadLE<uint32_t>(buf + base + 0x00);
            uint32_t a0   = loadLE<uint32_t>(buf + base + 0x04);
            uint32_t a1   = loadLE<uint32_t>(buf + base + 0x08);
            uint32_t a2   = loadLE<uint32_t>(buf + base + 0x0C);
            uint32_t a3   = loadLE<uint32_t>(buf + base + 0x10);
            uint64_t tgt  = (L >= base + 0x20) ? loadLE<uint64_t>(buf + base + 0x18) : 0ULL;
            auto hex32 = [](uint32_t v){ std::ostringstream os; os << "0x" << std::hex << v << " (" << std::dec << v << ")"; return os.str(); };
            rowKV("gm.Id", hex32(id));
            rowKV("gm.Arg0", hex32(a0));
            rowKV("gm.Arg1", hex32(a1));
            rowKV("gm.Arg2", hex32(a2));
            rowKV("gm.Arg3", hex32(a3));
            {
                std::ostringstream os; os << "0x" << std::hex << tgt; rowKV("gm.Target", os.str());
            }
            return;
        }

        // Move / ActorMove common
        if ((outgoing && opcode == 0x019A) || (!outgoing && opcode == 0x0192)) {
            MoveFields mv = TryDecodeMove(hp);
            if (mv.ok) {
                char b[256];
                std::snprintf(b,sizeof(b),"dir=%u dirBeforeSlip=%u flag=%u flag2=%u speed=%u",
                              mv.dir, mv.dirBeforeSlip, mv.flag, mv.flag2, mv.speed);
                rowKV("move.core", b);
                std::snprintf(b,sizeof(b),"(%u, %u, %u)", mv.pos[0], mv.pos[1], mv.pos[2]);
                rowKV("move.pos", b);
            }
            // Attempt alternative float-based decode for client UpdatePosition (fallback)
            if (outgoing && opcode == 0x019A && L >= base + 0x1C) {
                float dir = loadLE<float>(buf + base + 0x00);
                float dirBeforeSlip = loadLE<float>(buf + base + 0x04);
                uint8_t flag = *(buf + base + 0x08);
                uint8_t flag2 = *(buf + base + 0x09);
                uint8_t flag_unshared = *(buf + base + 0x0A);
                float px = 0, py = 0, pz = 0;
                // Common::FFXIVARR_POSITION3 is usually 3 floats; if so, read them
                if (L >= base + 0x1C) {
                    px = loadLE<float>(buf + base + 0x0C);
                    py = loadLE<float>(buf + base + 0x10);
                    pz = loadLE<float>(buf + base + 0x14);
                }
                char b[256];
                std::snprintf(b,sizeof(b),"dir=%.3f dirBeforeSlip=%.3f flag=%u flag2=%u flagU=%u",
                              dir, dirBeforeSlip, flag, flag2, flag_unshared);
                rowKV("move.alt.core", b);
                std::snprintf(b,sizeof(b),"(%.3f, %.3f, %.3f)", px, py, pz);
                rowKV("move.alt.pos", b);
            }
            return;
        }

        // Server: ActorCast (0x0196)
        if (!outgoing && opcode == 0x0196 && L >= base + 0x20) {
            uint16_t action = loadLE<uint16_t>(buf + base + 0x00);
            uint8_t actionKind = *(buf + base + 0x02);
            uint32_t actionKey = loadLE<uint32_t>(buf + base + 0x04);
            float castTime = loadLE<float>(buf + base + 0x08);
            uint32_t target = loadLE<uint32_t>(buf + base + 0x0C);
            float dir = loadLE<float>(buf + base + 0x10);
            uint32_t ballistaId = loadLE<uint32_t>(buf + base + 0x14);
            uint16_t tx = 0, ty = 0, tz = 0;
            if (L >= base + 0x1A) tx = loadLE<uint16_t>(buf + base + 0x18);
            if (L >= base + 0x1C) ty = loadLE<uint16_t>(buf + base + 0x1A);
            if (L >= base + 0x1E) tz = loadLE<uint16_t>(buf + base + 0x1C);
            rowKV("cast.action", std::to_string(action));
            rowKV("cast.kind", std::to_string(actionKind));
            {
                std::ostringstream os; os << "0x" << std::hex << actionKey << " (" << std::dec << actionKey << ")"; rowKV("cast.key", os.str());
            }
            rowKV("cast.time", std::to_string(castTime));
            {
                std::ostringstream os; os << "0x" << std::hex << target << " (" << std::dec << target << ")"; rowKV("cast.target", os.str());
            }
            rowKV("cast.dir", std::to_string(dir));
            rowKV("cast.ballista", std::to_string(ballistaId));
            {
                char b[96]; std::snprintf(b,sizeof(b),"(%u,%u,%u)", tx,ty,tz); rowKV("cast.targetPos", b);
            }
            return;
        }

        // Server: Warp (0x0194)
        if (!outgoing && opcode == 0x0194 && L >= base + 0x10) {
            uint16_t dir = loadLE<uint16_t>(buf + base + 0x00);
            uint8_t type = *(buf + base + 0x02);
            uint8_t typeArg = *(buf + base + 0x03);
            uint32_t layerSet = loadLE<uint32_t>(buf + base + 0x04);
            float x = 0, y = 0, z = 0;
            if (L >= base + 0x10) { x = loadLE<float>(buf + base + 0x08); y = loadLE<float>(buf + base + 0x0C); z = loadLE<float>(buf + base + 0x10); }
            rowKV("warp.dir", std::to_string(dir));
            rowKV("warp.type", std::to_string(type));
            rowKV("warp.typeArg", std::to_string(typeArg));
            {
                std::ostringstream os; os << "0x" << std::hex << layerSet << " (" << std::dec << layerSet << ")"; rowKV("warp.layerSet", os.str());
            }
            {
                char b[96]; std::snprintf(b,sizeof(b),"(%.3f,%.3f,%.3f)", x,y,z); rowKV("warp.pos", b);
            }
            return;
        }

        // Server: Chat (0x0067 on zone, 0x0065 on chat connection)
        // Note: Only show this when we are sure it's a chat connection (resolved connType == 2)
        // The generic renderer will handle others.
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
    ImGui::Checkbox("Known only", &f.onlyKnown);
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

static void DrawIPCHeaderTable(const ParsedPacket& P, bool outgoing, const HookPacket& hp, uint16_t resolvedConn) {
    if (!P.ipc_ok) return;
    if (ImGui::BeginTable("pkt_hdr_ipc", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        auto row=[&](const char* k, const char* v){ ImGui::TableNextRow(); ImGui::TableNextColumn(); ImGui::TextUnformatted(k); ImGui::TableNextColumn(); ImGui::TextUnformatted(v); };
        char b[256];
        std::snprintf(b,sizeof(b),"0x%04X", P.ipcReserved); row("reserved", b);
        const char* name = LookupOpcodeName(P.opcode, outgoing, resolvedConn);
        std::snprintf(b,sizeof(b),"0x%04X (%s)", P.opcode, name); row("type (opcode)", b);
        std::snprintf(b,sizeof(b),"0x%04X", P.ipcPad); row("padding", b);
        std::snprintf(b,sizeof(b),"%u", P.serverId); row("serverId", b);
        std::snprintf(b,sizeof(b),"%u", P.ipcTimestamp); row("timestamp", b);
        std::snprintf(b,sizeof(b),"0x%08X", P.ipcPad1); row("padding1", b);

        // Known payloads (structured)
        RenderPayload_Known(P.opcode, outgoing, hp);
        ImGui::EndTable();
    }

    // Human-readable payload preview (heuristic views)
    if (hp.len > 0x48) {
        const uint8_t* payload = hp.buf.data() + 0x48;
        const size_t payloadLen = hp.len - 0x48;
        RenderPayload_Heuristics(payload, payloadLen);
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
            char label[240];
            if (d.valid)
                std::snprintf(label, sizeof(label), "%s op=%04x %-16s conn=%llu len=%u",
                    hp.outgoing ? "SEND" : "RECV",
                    (unsigned)d.opcode, name,
                    (unsigned long long)hp.connection_id, hp.len);
            else
                std::snprintf(label, sizeof(label), "%s seg=%u(%s) conn=%llu len=%u",
                    hp.outgoing ? "SEND" : "RECV", (unsigned)d.segType, SegTypeName(d.segType),
                    (unsigned long long)hp.connection_id, hp.len);

            ImGui::PushID(i);
            if (ImGui::Selectable(label, selectedFiltered == ri))
                selectedFiltered = ri;
            ImGui::PopID();
        }
    }
    ImGui::EndChild();

    // Bottom: details view fills all remaining height
    ImGui::BeginChild("pkt_details", ImVec2(0, 0), true);
    if (selectedFiltered >= 0 && selectedFiltered < (int)filtered.size()) {
        int selIndex = filtered[selectedFiltered];
        const HookPacket& hp = display[selIndex];
        const ParsedPacket P = ParsePacket(hp);
        uint16_t resolvedConn = ResolveConnType(hp, P);
        ImGui::Text("Packet header");
        DrawPacketHeaderTable(P, resolvedConn);
        ImGui::Text("Segment header");
        DrawSegmentHeaderTable(P);
        ImGui::Text("IPC header");
        DrawIPCHeaderTable(P, hp.outgoing, hp, resolvedConn);
        ImGui::Separator();
        // Hex fills the remaining space inside details
        ImGui::BeginChild("hex", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
        SafeHookLogger::DumpHexAscii(hp);
        ImGui::EndChild();
    } else {
        ImGui::TextDisabled("Select a packet to view headers and hex dump");
    }
    ImGui::EndChild();
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
