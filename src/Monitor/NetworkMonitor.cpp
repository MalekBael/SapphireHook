#include "NetworkMonitor.h"
#include <cstring>
#include "../vendor/imgui/imgui.h"
#include <sstream>
#include <cstdio>

SafeHookLogger& SafeHookLogger::Instance() {
    static SafeHookLogger inst{};
    return inst;
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

static void DrawMonitorWindowContents(const std::vector<HookPacket>& display) {
    ImGui::Text("Buffered: %zu", display.size());
    ImGui::BeginChild("pkt_list", ImVec2(0, 300), true);
    ImGuiListClipper clip;
    clip.Begin((int)display.size());
    static int selected = -1;
    while (clip.Step()) {
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
            const HookPacket& hp = display[i];
            char label[128];
            std::snprintf(label, sizeof(label), "%s conn=%llu len=%u",
                hp.outgoing ? "SEND" : "RECV",
                (unsigned long long)hp.connection_id,
                hp.len);
            if (ImGui::Selectable(label, selected == i))
                selected = i;
        }
    }
    ImGui::EndChild();

    if (selected >= 0 && selected < (int)display.size()) {
        const HookPacket& hp = display[selected];
        ImGui::Separator();
        ImGui::Text("conn=%llu outgoing=%d len=%u",
            (unsigned long long)hp.connection_id,
            hp.outgoing ? 1 : 0, hp.len);
        ImGui::BeginChild("hex", ImVec2(0, 200), true, ImGuiWindowFlags_HorizontalScrollbar);
        SafeHookLogger::DumpHexAscii(hp);
        ImGui::EndChild();
    }
}

void SafeHookLogger::DrawImGuiSimple() {
    static std::vector<HookPacket> ui_batch;
    DrainToVector(ui_batch);

    static std::vector<HookPacket> display;
    display.reserve(display.size() + ui_batch.size());
    for (auto& p : ui_batch) display.push_back(std::move(p));
    if (display.size() > 100000)
        display.erase(display.begin(), display.begin() + (display.size() - 100000));

    ImGui::Begin("Network Monitor");
    DrawMonitorWindowContents(display);
    ImGui::End();
}

void SafeHookLogger::DrawImGuiSimple(bool* p_open) {
    static std::vector<HookPacket> ui_batch;
    DrainToVector(ui_batch);

    static std::vector<HookPacket> display;
    display.reserve(display.size() + ui_batch.size());
    for (auto& p : ui_batch) display.push_back(std::move(p));
    if (display.size() > 100000)
        display.erase(display.begin(), display.begin() + (display.size() - 100000));

    if (ImGui::Begin("Network Monitor", p_open)) {
        DrawMonitorWindowContents(display);
    }
    ImGui::End();
}
