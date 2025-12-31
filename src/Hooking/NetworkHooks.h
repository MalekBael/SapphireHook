#pragma once
/**
 * @file NetworkHooks.h
 * @brief High-level network hooks for FFXIV packet capture
 * 
 * These hooks work at the game's internal network layer rather than raw WS2_32,
 * providing access to structured packet data and connection state.
 * 
 * Discovered via radare2 analysis of FFXIV 3.35 binary.
 */

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

    // =========================================================================
    // Network Object Layout (from radare2 analysis)
    // =========================================================================
    
    /**
     * @brief Inferred layout of FFXIV's internal network connection object
     * These offsets were discovered via radare2 analysis of 3.35 binary
     */
    struct NetworkConnectionOffsets {
        static constexpr size_t Socket         = 0x08;   // SOCKET handle
        static constexpr size_t PacketCounter  = 0x98;   // Incrementing counter
        static constexpr size_t BytesReceived  = 0xA0;   // Total bytes received
        static constexpr size_t BufferSize     = 0x100;  // Size of receive buffer
        static constexpr size_t RecvBuffer     = 0x130;  // Pointer to receive buffer
        static constexpr size_t QueueBase      = 0x168;  // Packet queue base
        static constexpr size_t QueueCapacity  = 0x178;  // Queue capacity
        static constexpr size_t QueueWritePos  = 0x180;  // Queue write position
        static constexpr size_t QueueCount     = 0x188;  // Number of queued packets
        static constexpr size_t ConnectionState = 0xF8;  // State machine state
    };

    // =========================================================================
    // Hook Callbacks
    // =========================================================================
    
    /**
     * @brief Callback for receiving raw packet data
     * @param connectionObj Pointer to the network connection object
     * @param buffer Packet data buffer
     * @param size Size of packet data
     * @return true to allow packet through, false to drop
     */
    using RawPacketCallback = std::function<bool(void* connectionObj, std::span<const uint8_t> buffer)>;

    /**
     * @brief Callback for IPC packets (after header parsing)
     * @param opcode IPC opcode
     * @param actorId Source/target actor ID
     * @param payload Packet payload after IPC header
     * @return true to allow packet through, false to drop
     */
    using IPCPacketCallback = std::function<bool(uint16_t opcode, uint32_t actorId, std::span<const uint8_t> payload)>;

    // =========================================================================
    // Network Hook Signatures
    // =========================================================================
    
    /**
     * @brief Signature patterns for network functions (3.35)
     */
    struct NetworkSignatures {
        // Game's internal recv wrapper
        static constexpr const char* RecvWrapper = "48 83 EC 28 48 8B 49 08 45 33 C9";
        
        // Game's internal send wrapper
        static constexpr const char* SendWrapper = "48 83 EC 28 48 8B 49 08 45 33 C9 45 8B D0";
        
        // Socket receive handler (State 4 - active connection)
        static constexpr const char* SocketReceiveHandler = "48 89 74 24 10 57 48 83 EC 20 44 8B 81 00 01 00 00";
        
        // Packet queue handler
        static constexpr const char* PacketQueueHandler = "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 48 83 B9 88 01 00 00 40";
        
        // IPC dispatch function (main opcode switch)
        static constexpr const char* IPCDispatcher = "48 89 5C 24 08 57 48 83 EC 60 8B FA 41 0F B7 50 02";
        
        // Connection state machine
        static constexpr const char* ConnectionStateMachine = "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 8B 81 F8 00 00 00";
    };

    // =========================================================================
    // NetworkHooks Class
    // =========================================================================
    
    /**
     * @brief High-level network hooks for FFXIV
     * 
     * Hooks the game's internal network layer instead of raw WS2_32 functions,
     * providing structured access to packet data and connection state.
     */
    class NetworkHooks {
    public:
        // Singleton access
        static NetworkHooks& GetInstance();
        
        /**
         * @brief Initialize network hooks using signature scanning
         * @return true if hooks were successfully installed
         */
        bool Initialize();
        
        /**
         * @brief Shutdown and remove all hooks
         */
        void Shutdown();
        
        /**
         * @brief Check if hooks are active
         */
        bool IsHooked() const { return m_hooked.load(); }
        
        // ===== Callback Registration =====
        
        /**
         * @brief Register callback for raw received packets
         * Called from the socket receive handler (0x140dec130)
         */
        void SetRawRecvCallback(RawPacketCallback callback);
        
        /**
         * @brief Register callback for raw sent packets
         */
        void SetRawSendCallback(RawPacketCallback callback);
        
        /**
         * @brief Register callback for IPC packets (after dispatch)
         * Called from the IPC dispatcher (0x140DD9430)
         */
        void SetIPCCallback(IPCPacketCallback callback);
        
        // ===== Connection State Access =====
        
        /**
         * @brief Get the current connection object pointer
         * @return Pointer to the active NetworkConnection, or nullptr
         */
        void* GetConnectionObject() const { return m_connectionObj; }
        
        /**
         * @brief Get the socket handle from the connection object
         */
        uintptr_t GetSocket() const;
        
        /**
         * @brief Get total bytes received from connection object
         */
        uint64_t GetBytesReceived() const;
        
        /**
         * @brief Get current receive buffer pointer
         */
        const uint8_t* GetRecvBuffer() const;
        
        /**
         * @brief Get receive buffer size
         */
        uint32_t GetBufferSize() const;
        
        /**
         * @brief Get connection state (2=setup, 3=handshake, 4=active, 5=other)
         */
        uint32_t GetConnectionState() const;
        
        // ===== Statistics =====
        
        struct Stats {
            std::atomic<uint64_t> packetsReceived{0};
            std::atomic<uint64_t> packetsSent{0};
            std::atomic<uint64_t> ipcPacketsProcessed{0};
            std::atomic<uint64_t> bytesReceived{0};
            std::atomic<uint64_t> bytesSent{0};
        };
        
        const Stats& GetStats() const { return m_stats; }
        void ResetStats();
        
        // ===== Hook Addresses (for debugging) =====
        
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
        
        // Signature scanning
        bool FindNetworkFunctions();
        
        // Hook installation
        bool InstallRecvHook();
        bool InstallSendHook();
        bool InstallSocketHandlerHook();
        bool InstallIPCDispatcherHook();
        
        // Detour functions (must be static for MinHook)
        static int __fastcall DetourRecvWrapper(void* netObj, char* buffer, int length);
        static int __fastcall DetourSendWrapper(void* netObj, char* buffer, int length);
        static int __fastcall DetourSocketReceiveHandler(void* connectionObj);
        static void __fastcall DetourIPCDispatcher(void* thisPtr, uint32_t actorId, void* packetData);
        
        // Original function pointers
        using RecvWrapper_t = int(__fastcall*)(void*, char*, int);
        using SendWrapper_t = int(__fastcall*)(void*, char*, int);
        using SocketReceiveHandler_t = int(__fastcall*)(void*);
        using IPCDispatcher_t = void(__fastcall*)(void*, uint32_t, void*);
        
        static inline RecvWrapper_t s_origRecvWrapper = nullptr;
        static inline SendWrapper_t s_origSendWrapper = nullptr;
        static inline SocketReceiveHandler_t s_origSocketHandler = nullptr;
        static inline IPCDispatcher_t s_origIPCDispatcher = nullptr;
        
        // State
        std::atomic<bool> m_hooked{false};
        std::atomic<bool> m_initialized{false};
        void* m_connectionObj = nullptr;
        HookAddresses m_addresses{};
        Stats m_stats{};
        
        // Callbacks
        std::mutex m_callbackMutex;
        RawPacketCallback m_recvCallback;
        RawPacketCallback m_sendCallback;
        IPCPacketCallback m_ipcCallback;
    };

} // namespace SapphireHook
