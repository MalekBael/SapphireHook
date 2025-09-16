#pragma once
#include <cstdint>
#include <vector>

namespace SapphireHook {

    class PacketInjector {
    public:
        // Install WSASend hook. Safe to call multiple times.
        static bool Initialize();

        // Try to send a raw FFXIVARR packet buffer on the best socket (zone/chat inferred from buffer).
        static bool Send(const uint8_t* data, size_t len);

        // Optional explicit paths
        static bool SendZone(const uint8_t* data, size_t len);
        static bool SendChat(const uint8_t* data, size_t len);

        // Make these public so the detour function can access them
        static bool ClassifyPacket(const uint8_t* data, size_t len, bool& isChat);
        static std::uintptr_t s_zoneSocket;
        static std::uintptr_t s_chatSocket;

    private:
        static bool s_installed;
        static bool InstallWSASendHook();
    };

    // NEW: expose learned local actor id for UI/modules
    uint32_t GetLearnedLocalActorId();

} // namespace SapphireHook