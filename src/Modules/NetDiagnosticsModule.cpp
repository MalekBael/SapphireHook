#include "NetDiagnosticsModule.h"
#include "../Core/PacketInjector.h"
#include "../vendor/imgui/imgui.h"
#include "../Monitor/NetworkMonitor.h" // for embedded packet view and hex access

#if __has_include("../../vendor/implot/implot.h")
    #define SH_HAVE_IMPLOT 1
    #include "../../vendor/implot/implot.h"
#else
    #define SH_HAVE_IMPLOT 0
#endif

#include <vector>
#include <algorithm>
#include <cstring>

using namespace SapphireHook;

namespace {
    struct Sample {
        double t; // seconds since first sample
        double sends;
        double recvs;
        double kbpsOut;
        double kbpsIn;
        double e38, e54, e35, e57; // WSA deltas
    };

    struct Ring {
        std::vector<Sample> data;
        size_t head = 0;
        bool filled = false;
        void init(size_t cap) { data.resize(cap); head=0; filled=false; }
        void push(const Sample& s) {
            if (data.empty()) return;
            data[head] = s; head = (head+1)%data.size(); if (head==0) filled=true;
        }
        size_t size() const { return filled ? data.size() : head; }
        template<typename F> void for_each(F&& fn) const {
            const size_t n = size();
            for (size_t i=0;i<n;i++) {
                const size_t idx = filled ? (head + i) % data.size() : i;
                fn(data[idx]);
            }
        }
    };

    Ring g_ring;
    bool g_init = false;
    SapphireHook::PacketInjector::MetricsSnapshot g_prev{};
    double g_t0 = 0.0;

    void sample_once() {
        using MS = SapphireHook::PacketInjector::MetricsSnapshot;
        const MS cur = SapphireHook::PacketInjector::GetMetricsSnapshot();
        if (g_prev.t_ms == 0) { g_prev = cur; g_t0 = cur.t_ms/1000.0; return; }

        const double dt = (cur.t_ms - g_prev.t_ms) / 1000.0;
        if (dt <= 0.0) return;

        Sample s{};
        s.t = cur.t_ms/1000.0 - g_t0;
        s.sends = (cur.sendOk - g_prev.sendOk) / dt;
        s.recvs = (cur.recvOk - g_prev.recvOk) / dt;
        s.kbpsOut = ((cur.bytesSent - g_prev.bytesSent) / 1024.0) / dt;
        s.kbpsIn  = ((cur.bytesRecv - g_prev.bytesRecv) / 1024.0) / dt;
        s.e38 = double(cur.wsa10038 - g_prev.wsa10038);
        s.e54 = double(cur.wsa10054 - g_prev.wsa10054);
        s.e35 = double(cur.wsa10035 - g_prev.wsa10035);
        s.e57 = double(cur.wsa10057 - g_prev.wsa10057);

        g_ring.push(s);
        g_prev = cur;
    }

    // UI toggle for auto-highlighted hex ranges
    bool g_enableHexRegions = false;

    static inline uint16_t ReadU16LE(const uint8_t* p) { uint16_t v; std::memcpy(&v, p, 2); return v; }
    static inline uint32_t ReadU32LE(const uint8_t* p) { uint32_t v; std::memcpy(&v, p, 4); return v; }

    // Compute per-byte colors for interesting regions directly from the raw packet
    void BuildAutoHighlightColors(const HookPacket& hp, std::vector<unsigned int>& out)
    {
        const ImU32 def = ImGui::GetColorU32(ImGuiCol_Text);
        out.assign(hp.len, def);
        const uint8_t* b = hp.buf.data();
        const size_t L = hp.len;
        if (L < 0x28) return; // not enough bytes

        auto set = [&](size_t off, size_t count, ImU32 col){ size_t e = std::min(off+count, (size_t)L); for (size_t i=off; i<e; ++i) out[i] = col; };

        const ImU32 colHeader = IM_COL32(130, 180, 250, 255);     // packet header
        const ImU32 colSegHdr = IM_COL32(200, 180, 255, 255);     // segment header
        const ImU32 colIpcHdr = IM_COL32(255, 200, 150, 255);     // IPC header
        const ImU32 colCompressed = IM_COL32(255, 150, 150, 255); // compressed blob

        // Packet header
        set(0x00, 0x28, colHeader);

        // isCompressed flag (at 0x20 upper byte)
        bool isCompressed = false;
        if (L >= 0x22) { uint16_t tmp = ReadU16LE(b + 0x20); isCompressed = ((tmp >> 8) & 0xFF) != 0; }

        if (isCompressed) {
            // Highlight the entire compressed segment area
            set(0x28, L - 0x28, colCompressed);
            return;
        }

        // Walk raw segments at 0x28.. (uncompressed case)
        size_t pos = 0x28;
        while (pos + 0x10 <= L) {
            uint32_t segSize = ReadU32LE(b + pos + 0x00);
            if (segSize < 0x10 || pos + segSize > L) break; // sanity
            uint16_t segType = ReadU16LE(b + pos + 0x0C);
            // segment header (0x10)
            set(pos, 0x10, colSegHdr);
            if (segType == 3 && segSize >= 0x20) {
                // IPC header (next 0x10)
                set(pos + 0x10, 0x10, colIpcHdr);
            }
            pos += segSize;
        }
    }

    // Estimate required width for the highlighted hex viewer (offset + hex + ascii)
    float EstimateHexViewerWidth()
    {
        const ImGuiStyle& style = ImGui::GetStyle();
        const float charW = ImGui::CalcTextSize("A").x;
        const float hexCellW = ImGui::CalcTextSize("00 ").x;
        const float offW = ImGui::CalcTextSize("0000:").x;
        const float hexStride = hexCellW * 1.5f;
        const float hexW = 16.0f * hexStride;
        const float asciiW = 16.0f * charW;
        const float padding = 8.0f + style.ItemSpacing.x * 4.0f + 24.0f; // small margins
        return offW + hexW + asciiW + padding;
    }
}

void NetDiagnosticsModule::RenderMenu() {
    // No duplicate entry in Features. Toggled from Tools only.
}

void NetDiagnosticsModule::RenderWindow() {
    if (!m_windowOpen) return;
    if (!g_init) { g_ring.init(300); g_init = true; }
    sample_once();

    // Initial size hint (first use)
    ImGui::SetNextWindowSize(ImVec2(1260, 700), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Network Monitor", &m_windowOpen)) {
        // If auto-highlighting is enabled, ensure the right pane is wide enough; expand window if needed
        const float leftFrac = g_enableHexRegions ? 0.45f : 0.50f; // give a bit more room to the right when enabled
        const float totalAvailBefore = ImGui::GetContentRegionAvail().x;
        const float rightTargetBefore = totalAvailBefore * (1.0f - leftFrac) - ImGui::GetStyle().ItemSpacing.x;
        if (g_enableHexRegions) {
            float need = EstimateHexViewerWidth();
            if (need > rightTargetBefore) {
                ImVec2 cur = ImGui::GetWindowSize();
                float delta = need - rightTargetBefore + 8.0f;
                float maxW = ImGui::GetMainViewport()->WorkSize.x;
                float desired = cur.x + delta;
                if (desired > cur.x && desired < maxW - 8.0f) {
                    ImGui::SetWindowSize(ImVec2(desired, cur.y));
                }
            }
        }

        // Left: packet view
        const float leftWidth = ImGui::GetContentRegionAvail().x * leftFrac;
        ImGui::BeginChild("left", ImVec2(leftWidth, 0), true);
        SafeHookLogger::Instance().DrawImGuiEmbedded();
        ImGui::EndChild();
        ImGui::SameLine();

        // Right: diagnostics + hex
        ImGui::BeginChild("right", ImVec2(0, 0), true);
#if SH_HAVE_IMPLOT
        if (ImPlot::BeginPlot("Packets/sec", ImVec2(-1, 180))) {
            std::vector<double> x, a, b; x.reserve(g_ring.size()); a.reserve(g_ring.size()); b.reserve(g_ring.size());
            g_ring.for_each([&](const Sample& s){ x.push_back(s.t); a.push_back(s.sends); b.push_back(s.recvs); });
            ImPlot::SetupAxes("t (s)","count/s", ImPlotAxisFlags_AutoFit, ImPlotAxisFlags_AutoFit);
            if (!x.empty()) {
                ImPlot::PlotLine("send/sec", x.data(), a.data(), (int)x.size());
                ImPlot::PlotLine("recv/sec", x.data(), b.data(), (int)x.size());
            }
            ImPlot::EndPlot();
        }

        if (ImPlot::BeginPlot("Throughput (KB/s)", ImVec2(-1, 180))) {
            std::vector<double> x, o, i; x.reserve(g_ring.size()); o.reserve(g_ring.size()); i.reserve(g_ring.size());
            g_ring.for_each([&](const Sample& s){ x.push_back(s.t); o.push_back(s.kbpsOut); i.push_back(s.kbpsIn); });
            ImPlot::SetupAxes("t (s)","KB/s", ImPlotAxisFlags_AutoFit, ImPlotAxisFlags_AutoFit);
            if (!x.empty()) {
                ImPlot::PlotLine("out", x.data(), o.data(), (int)x.size());
                ImPlot::PlotLine("in",  x.data(), i.data(), (int)x.size());
            }
            ImPlot::EndPlot();
        }

        if (ImPlot::BeginPlot("WSA errors (delta per tick)", ImVec2(-1, 160))) {
            std::vector<double> x, e38, e54, e35, e57;
            x.reserve(g_ring.size()); e38.reserve(g_ring.size()); e54.reserve(g_ring.size()); e35.reserve(g_ring.size()); e57.reserve(g_ring.size());
            g_ring.for_each([&](const Sample& s){
                x.push_back(s.t); e38.push_back(s.e38); e54.push_back(s.e54); e35.push_back(s.e35); e57.push_back(s.e57);
            });
            ImPlot::SetupAxes("t (s)","count", ImPlotAxisFlags_AutoFit, ImPlotAxisFlags_AutoFit);
            if (!x.empty()) {
                ImPlot::PlotStems("10038 ENOTSOCK", x.data(), e38.data(), (int)x.size());
                ImPlot::PlotStems("10054 CONNRESET", x.data(), e54.data(), (int)x.size());
                ImPlot::PlotStems("10035 WOULDBLOCK", x.data(), e35.data(), (int)x.size());
                ImPlot::PlotStems("10057 NOTCONN", x.data(), e57.data(), (int)x.size());
            }
            ImPlot::EndPlot();
        }

        // Classic hex on the right (same content as the old in-place view)
        if (ImGui::CollapsingHeader("Selected packet hex", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::Checkbox("Auto highlight packet regions", &g_enableHexRegions);
            HookPacket hp{};
            if (SafeHookLogger::TryGetSelectedPacket(hp)) {
                ImGui::BeginChild("right_hex", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
                if (g_enableHexRegions) {
                    std::vector<unsigned int> colors;
                    BuildAutoHighlightColors(hp, colors);
                    SafeHookLogger::DumpHexAsciiColored(hp, colors);
                } else {
                    SafeHookLogger::DumpHexAscii(hp);
                }
                ImGui::EndChild();
            } else {
                ImGui::TextDisabled("No packet selected on the left pane");
            }
        }
#else
        ImGui::TextWrapped("ImPlot not found. Add vendor/implot to enable diagnostics graphs.");
#endif
        ImGui::EndChild();
    }
    ImGui::End();
}
