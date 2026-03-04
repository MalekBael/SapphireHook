#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>
#include <atomic>
#include <mutex>

namespace SapphireHook {

    struct NetworkConnectionOffsets {
        static constexpr size_t Socket         = 0x08;     
        static constexpr size_t PacketCounter  = 0x98;     
        static constexpr size_t BytesReceived  = 0xA0;      
        static constexpr size_t BufferSize     = 0x100;      
        static constexpr size_t RecvBuffer     = 0x130;      
        static constexpr size_t QueueBase      = 0x168;     
        static constexpr size_t QueueCapacity  = 0x178;    
        static constexpr size_t QueueWritePos  = 0x180;     
        static constexpr size_t QueueCount     = 0x188;      
        static constexpr size_t ConnectionState = 0xF8;     
    };

    using RawPacketCallback = std::function<bool(void* connectionObj, std::span<const uint8_t> buffer)>;

    using IPCPacketCallback = std::function<bool(uint16_t opcode, uint32_t actorId, std::span<const uint8_t> payload)>;

    struct NetworkSignatures {
        static constexpr const char* RecvWrapper = "48 83 EC 28 48 8B 49 08 45 33 C9";
        
        static constexpr const char* SendWrapper = "48 83 EC 28 48 8B 49 08 45 33 C9 45 8B D0";
        
        static constexpr const char* SocketReceiveHandler = "48 89 74 24 10 57 48 83 EC 20 44 8B 81 00 01 00 00";
        
        static constexpr const char* PacketQueueHandler = "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 48 83 B9 88 01 00 00 40";
        
        static constexpr const char* IPCDispatcher = "48 89 5C 24 08 57 48 83 EC 60 8B FA 41 0F B7 50 02";
        
        static constexpr const char* ConnectionStateMachine = "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 8B 81 F8 00 00 00";
    };

    class NetworkHooks {
    public:
        static NetworkHooks& GetInstance();
        
        bool Initialize();
        
        void Shutdown();
        
        bool IsHooked() const { return m_hooked.load(); }
        
        void SetRawRecvCallback(RawPacketCallback callback);
        
        void SetRawSendCallback(RawPacketCallback callback);
        
        void SetIPCCallback(IPCPacketCallback callback);
        
        void* GetConnectionObject() const { return m_connectionObj; }
        
        uintptr_t GetSocket() const;
        
        uint64_t GetBytesReceived() const;
        
        const uint8_t* GetRecvBuffer() const;
        
        uint32_t GetBufferSize() const;
        
        uint32_t GetConnectionState() const;
        
        struct Stats {
            std::atomic<uint64_t> packetsReceived{0};
            std::atomic<uint64_t> packetsSent{0};
            std::atomic<uint64_t> ipcPacketsProcessed{0};
            std::atomic<uint64_t> bytesReceived{0};
            std::atomic<uint64_t> bytesSent{0};
        };
        
        const Stats& GetStats() const { return m_stats; }
        void ResetStats();
        
        struct HookAddresses {
            uintptr_t recvWrapper = 0;
            uintptr_t sendWrapper = 0;
            uintptr_t socketHandler = 0;
            uintptr_t ipcDispatcher = 0;
            uintptr_t packetQueue = 0;
        };
        
        const HookAddresses& GetHookAddresses() const { return m_addresses; }

    private:
        NetworkHooks() = default;
        ~NetworkHooks();
        NetworkHooks(const NetworkHooks&) = delete;
        NetworkHooks& operator=(const NetworkHooks&) = delete;
        
        bool FindNetworkFunctions();
        
        bool InstallRecvHook();
        bool InstallSendHook();
        bool InstallSocketHandlerHook();
        bool InstallIPCDispatcherHook();
        
        static int __fastcall DetourRecvWrapper(void* netObj, char* buffer, int length);
        static int __fastcall DetourSendWrapper(void* netObj, char* buffer, int length);
        static int __fastcall DetourSocketReceiveHandler(void* connectionObj);
        static void __fastcall DetourIPCDispatcher(void* thisPtr, uint32_t actorId, void* packetData);
        
        using RecvWrapper_t = int(__fastcall*)(void*, char*, int);
        using SendWrapper_t = int(__fastcall*)(void*, char*, int);
        using SocketReceiveHandler_t = int(__fastcall*)(void*);
        using IPCDispatcher_t = void(__fastcall*)(void*, uint32_t, void*);
        
        static inline RecvWrapper_t s_origRecvWrapper = nullptr;
        static inline SendWrapper_t s_origSendWrapper = nullptr;
        static inline SocketReceiveHandler_t s_origSocketHandler = nullptr;
        static inline IPCDispatcher_t s_origIPCDispatcher = nullptr;
        
        std::atomic<bool> m_hooked{false};
        std::atomic<bool> m_initialized{false};
        void* m_connectionObj = nullptr;
        HookAddresses m_addresses{};
        Stats m_stats{};
        
        std::mutex m_callbackMutex;
        RawPacketCallback m_recvCallback;
        RawPacketCallback m_sendCallback;
        IPCPacketCallback m_ipcCallback;
    };

}   
