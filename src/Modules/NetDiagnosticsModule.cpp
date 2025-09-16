#include "NetDiagnosticsModule.h"
#include "../Core/PacketInjector.h"
#include "../vendor/imgui/imgui.h"

#if __has_include("../vendor/implot/implot.h")
    #define SH_HAVE_IMPLOT 1
    #include "../vendor/implot/implot.h"
#else
    #define SH_HAVE_IMPLOT 0
#endif

#include <vector>
#include <algorithm>

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
}

void NetDiagnosticsModule::RenderMenu() {
    // Intentionally no-op to avoid duplicate entry; this module is toggled from the Tools menu.
}

void NetDiagnosticsModule::RenderWindow() {
    if (!m_windowOpen) return;
    if (!g_init) { g_ring.init(300); g_init = true; }
    sample_once();

    if (ImGui::Begin("Net Diagnostics", &m_windowOpen)) {
#if SH_HAVE_IMPLOT
        if (ImPlot::BeginPlot("Packets/sec", ImVec2(-1, 160))) {
            std::vector<double> x, a, b; x.reserve(g_ring.size()); a.reserve(g_ring.size()); b.reserve(g_ring.size());
            g_ring.for_each([&](const Sample& s){ x.push_back(s.t); a.push_back(s.sends); b.push_back(s.recvs); });
            ImPlot::SetupAxes("t (s)","count/s", ImPlotAxisFlags_AutoFit, ImPlotAxisFlags_AutoFit);
            if (!x.empty()) {
                ImPlot::PlotLine("send/sec", x.data(), a.data(), (int)x.size());
                ImPlot::PlotLine("recv/sec", x.data(), b.data(), (int)x.size());
            }
            ImPlot::EndPlot();
        }

        if (ImPlot::BeginPlot("Throughput (KB/s)", ImVec2(-1, 160))) {
            std::vector<double> x, o, i; x.reserve(g_ring.size()); o.reserve(g_ring.size()); i.reserve(g_ring.size());
            g_ring.for_each([&](const Sample& s){ x.push_back(s.t); o.push_back(s.kbpsOut); i.push_back(s.kbpsIn); });
            ImPlot::SetupAxes("t (s)","KB/s", ImPlotAxisFlags_AutoFit, ImPlotAxisFlags_AutoFit);
            if (!x.empty()) {
                ImPlot::PlotLine("out", x.data(), o.data(), (int)x.size());
                ImPlot::PlotLine("in",  x.data(), i.data(), (int)x.size());
            }
            ImPlot::EndPlot();
        }

        if (ImPlot::BeginPlot("WSA errors (delta per tick)", ImVec2(-1, 120))) {
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
#else
        ImGui::TextWrapped("ImPlot not found. To enable Net Diagnostics graphs, add vendor/implot (implot.h/.cpp + implot_items.cpp) to the project.");
#endif
    }
    ImGui::End();
}
