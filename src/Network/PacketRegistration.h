#pragma once
namespace PacketDecoding {
    void RegisterZonePackets();
    void RegisterChatPackets();
    void RegisterLobbyPackets();
    void RegisterGenericPackets();
    void RegisterInitPackets();

    inline void RegisterAllPackets() {
        static bool done = false;
        if (!done) {
            RegisterZonePackets();
            RegisterChatPackets();
            RegisterLobbyPackets();
            RegisterGenericPackets();
            RegisterInitPackets();
            done = true;
        }
    }
}