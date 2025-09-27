#pragma once
#include <cstdint>
#include <vector>

namespace SapphireHook {

    enum class PacketLogMode : int { Off = 0, Summary = 1, Verbose = 2 };

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

        // Diagnostics metrics snapshot (for ImPlot graphs / UI)
        struct MetricsSnapshot {
            std::uint64_t t_ms;      // GetTickCount64()
            std::uint64_t sendOk;
            std::uint64_t sendFail;
            std::uint64_t bytesSent;
            std::uint64_t recvOk;
            std::uint64_t bytesRecv;
            std::uint64_t wsa10038;  // WSAENOTSOCK
            std::uint64_t wsa10054;  // WSAECONNRESET
            std::uint64_t wsa10035;  // WSAEWOULDBLOCK
            std::uint64_t wsa10057;  // WSAENOTCONN
        };

        static MetricsSnapshot GetMetricsSnapshot();

    private:
        static bool s_installed;
        static bool InstallWSASendHook();
    };

    // NEW: expose learned local actor id for UI/modules
    uint32_t GetLearnedLocalActorId();

    // Runtime control of packet logging verbosity
    void SetPacketLogMode(PacketLogMode mode);
    PacketLogMode GetPacketLogMode();
    bool PacketLogAtLeast(PacketLogMode level);

    // Persistence (INI: sapphirehook_settings.ini)
    bool LoadPacketLogModeFromConfig();  // returns true if key found (creates file if missing)
    bool SavePacketLogModeToConfig();    // returns true on successful write

} // namespace SapphireHook