#pragma once
#include "DebugVisualTypes.h"
#include <thread>
#include <atomic>
#include <functional>
#include <memory>
#include <string>

namespace SapphireHook::DebugVisuals {

    // ============================================
    // Callback for received debug commands
    // ============================================
    using DebugVisualCallback = std::function<void(const DebugVisualPacketHeader&, const void* data)>;
    using DebugCommandCallback = std::function<void(const DebugCommandPacket&)>;

    // ============================================
    // UDP Server for receiving debug visuals
    // ============================================
    class DebugVisualServer {
    public:
        static DebugVisualServer& GetInstance();

        // Server lifecycle
        bool Start(uint16_t port = DEBUG_VISUAL_PORT);
        void Stop();
        bool IsRunning() const { return m_running; }

        // Callbacks
        void SetVisualCallback(DebugVisualCallback callback) { m_visualCallback = std::move(callback); }
        void SetCommandCallback(DebugCommandCallback callback) { m_commandCallback = std::move(callback); }

        // Statistics
        uint64_t GetPacketsReceived() const { return m_packetsReceived; }
        uint64_t GetBytesReceived() const { return m_bytesReceived; }
        uint64_t GetErrorCount() const { return m_errorCount; }

        // Configuration
        uint16_t GetPort() const { return m_port; }
        void SetMaxPacketSize(size_t size) { m_maxPacketSize = size; }

    private:
        DebugVisualServer() = default;
        ~DebugVisualServer();
        DebugVisualServer(const DebugVisualServer&) = delete;
        DebugVisualServer& operator=(const DebugVisualServer&) = delete;

        void ServerThread();
        void ProcessPacket(const uint8_t* data, size_t size);

        // Socket
        uintptr_t m_socket = ~0ULL;  // INVALID_SOCKET
        uint16_t m_port = DEBUG_VISUAL_PORT;

        // Thread management
        std::unique_ptr<std::thread> m_thread;
        std::atomic<bool> m_running{ false };
        std::atomic<bool> m_shouldStop{ false };

        // Callbacks
        DebugVisualCallback m_visualCallback;
        DebugCommandCallback m_commandCallback;

        // Statistics
        std::atomic<uint64_t> m_packetsReceived{ 0 };
        std::atomic<uint64_t> m_bytesReceived{ 0 };
        std::atomic<uint64_t> m_errorCount{ 0 };

        // Configuration
        size_t m_maxPacketSize = 65536;
    };

} // namespace SapphireHook::DebugVisuals
