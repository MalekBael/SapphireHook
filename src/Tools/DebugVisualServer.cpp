// WinSock2 must be included BEFORE Windows.h to avoid redefinition errors
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include "DebugVisualServer.h"
#include "DebugRenderer.h"
#include "../Logger/Logger.h"

#include <vector>
#include <cstring>
#include <format>

#pragma comment(lib, "ws2_32.lib")

namespace SapphireHook::DebugVisuals {

    // Forward declarations for packet handlers
    static void HandleVisualPrimitive(const DebugVisualPacketHeader& header, const void* data);
    static void HandleCommand(const DebugCommandPacket& cmd);

    DebugVisualServer& DebugVisualServer::GetInstance() {
        static DebugVisualServer instance;
        return instance;
    }

    DebugVisualServer::~DebugVisualServer() {
        Stop();
    }

    bool DebugVisualServer::Start(uint16_t port) {
        if (m_running) {
            LogWarning("DebugVisualServer: Already running");
            return true;
        }

        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            LogError("DebugVisualServer: WSAStartup failed");
            return false;
        }

        // Create UDP socket
        m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (m_socket == INVALID_SOCKET) {
            LogError("DebugVisualServer: Failed to create socket, error: " + std::to_string(WSAGetLastError()));
            WSACleanup();
            return false;
        }

        // Set socket options
        int reuseAddr = 1;
        setsockopt(static_cast<SOCKET>(m_socket), SOL_SOCKET, SO_REUSEADDR, 
                   reinterpret_cast<const char*>(&reuseAddr), sizeof(reuseAddr));

        // Set receive timeout (1 second) to allow graceful shutdown
        DWORD timeout = 1000;
        setsockopt(static_cast<SOCKET>(m_socket), SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&timeout), sizeof(timeout));

        // Bind to port
        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;  // Listen on all interfaces
        serverAddr.sin_port = htons(port);

        if (bind(static_cast<SOCKET>(m_socket), reinterpret_cast<sockaddr*>(&serverAddr), 
                 sizeof(serverAddr)) == SOCKET_ERROR) {
            LogError("DebugVisualServer: Failed to bind to port " + std::to_string(port) + 
                     ", error: " + std::to_string(WSAGetLastError()));
            closesocket(static_cast<SOCKET>(m_socket));
            m_socket = INVALID_SOCKET;
            WSACleanup();
            return false;
        }

        m_port = port;
        m_shouldStop = false;
        m_running = true;

        // Start server thread
        m_thread = std::make_unique<std::thread>(&DebugVisualServer::ServerThread, this);

        LogInfo("DebugVisualServer: Started on port " + std::to_string(port));
        return true;
    }

    void DebugVisualServer::Stop() {
        if (!m_running) {
            return;
        }

        m_shouldStop = true;

        // Close socket to unblock recvfrom
        if (m_socket != INVALID_SOCKET) {
            closesocket(static_cast<SOCKET>(m_socket));
            m_socket = INVALID_SOCKET;
        }

        // Wait for thread to finish
        if (m_thread && m_thread->joinable()) {
            m_thread->join();
        }
        m_thread.reset();

        WSACleanup();
        m_running = false;

        LogInfo("DebugVisualServer: Stopped");
    }

    void DebugVisualServer::ServerThread() {
        std::vector<uint8_t> buffer(m_maxPacketSize);
        sockaddr_in clientAddr{};
        int clientAddrLen = sizeof(clientAddr);

        while (!m_shouldStop) {
            int bytesReceived = recvfrom(static_cast<SOCKET>(m_socket), 
                                         reinterpret_cast<char*>(buffer.data()),
                                         static_cast<int>(buffer.size()), 0,
                                         reinterpret_cast<sockaddr*>(&clientAddr),
                                         &clientAddrLen);

            if (bytesReceived == SOCKET_ERROR) {
                int error = WSAGetLastError();
                if (error == WSAETIMEDOUT) {
                    // Timeout - check if we should stop
                    continue;
                }
                if (error == WSAEINTR || error == WSAENOTSOCK) {
                    // Socket closed, we're shutting down
                    break;
                }
                m_errorCount++;
                LogWarning("DebugVisualServer: recvfrom error: " + std::to_string(error));
                continue;
            }

            if (bytesReceived > 0) {
                m_packetsReceived++;
                m_bytesReceived += bytesReceived;
                ProcessPacket(buffer.data(), bytesReceived);
            }
        }
    }

    void DebugVisualServer::ProcessPacket(const uint8_t* data, size_t size) {
        if (size < 4) {
            m_errorCount++;
            return;
        }

        uint32_t magic = *reinterpret_cast<const uint32_t*>(data);

        if (magic == DEBUG_VISUAL_MAGIC) {
            // Visual primitive packet
            if (size < sizeof(DebugVisualPacketHeader)) {
                m_errorCount++;
                LogWarning("DebugVisualServer: Visual packet too small");
                return;
            }

            const auto* header = reinterpret_cast<const DebugVisualPacketHeader*>(data);
            
            if (header->version != PROTOCOL_VERSION) {
                m_errorCount++;
                LogWarning("DebugVisualServer: Unsupported protocol version: " + 
                           std::to_string(header->version));
                return;
            }

            if (size < sizeof(DebugVisualPacketHeader) + header->dataSize) {
                m_errorCount++;
                LogWarning("DebugVisualServer: Visual packet data truncated");
                return;
            }

            // Process the visual primitive
            const void* primitiveData = data + sizeof(DebugVisualPacketHeader);
            
            if (m_visualCallback) {
                m_visualCallback(*header, primitiveData);
            } else {
                // Default handling - add to renderer directly
                HandleVisualPrimitive(*header, primitiveData);
            }
        }
        else if (magic == DEBUG_COMMAND_MAGIC) {
            // Command packet
            if (size < sizeof(DebugCommandPacket)) {
                m_errorCount++;
                LogWarning("DebugVisualServer: Command packet too small");
                return;
            }

            const auto* cmd = reinterpret_cast<const DebugCommandPacket*>(data);
            
            if (m_commandCallback) {
                m_commandCallback(*cmd);
            } else {
                // Default handling
                HandleCommand(*cmd);
            }
        }
        else {
            m_errorCount++;
            LogWarning("DebugVisualServer: Unknown packet magic: 0x" + 
                       std::format("{:08X}", magic));
        }
    }

    // ============================================
    // Default packet handlers implementation
    // ============================================
    static void HandleVisualPrimitive(const DebugVisualPacketHeader& header, const void* data) {
        auto& renderer = DebugRenderer::GetInstance();
        if (!renderer.IsInitialized()) {
            return;
        }

        auto primitiveType = static_cast<PrimitiveType>(header.primitiveType);
        float lifetime = header.lifetime > 0 ? header.lifetime : 999999.0f;

        switch (primitiveType) {
            case PrimitiveType::Line: {
                if (header.dataSize >= sizeof(DebugLine)) {
                    const auto* line = static_cast<const DebugLine*>(data);
                    renderer.AddLine(header.id, *line, lifetime);
                }
                break;
            }
            case PrimitiveType::Sphere: {
                if (header.dataSize >= sizeof(DebugSphere)) {
                    const auto* sphere = static_cast<const DebugSphere*>(data);
                    renderer.AddSphere(header.id, *sphere, lifetime);
                }
                break;
            }
            case PrimitiveType::Circle: {
                if (header.dataSize >= sizeof(DebugCircle)) {
                    const auto* circle = static_cast<const DebugCircle*>(data);
                    renderer.AddCircle(header.id, *circle, lifetime);
                }
                break;
            }
            case PrimitiveType::Path: {
                // Path needs special handling due to variable size
                // Format: [point_count: uint32][color: Color][thickness: float][closed: bool][points: Vec3[]]
                if (header.dataSize >= sizeof(uint32_t)) {
                    const uint8_t* pathData = static_cast<const uint8_t*>(data);
                    uint32_t pointCount = *reinterpret_cast<const uint32_t*>(pathData);
                    
                    size_t expectedSize = sizeof(uint32_t) + sizeof(Color) + sizeof(float) + 
                                         sizeof(bool) + pointCount * sizeof(Vec3);
                    
                    if (header.dataSize >= expectedSize && pointCount > 0 && pointCount < 10000) {
                        pathData += sizeof(uint32_t);
                        Color color = *reinterpret_cast<const Color*>(pathData);
                        pathData += sizeof(Color);
                        float thickness = *reinterpret_cast<const float*>(pathData);
                        pathData += sizeof(float);
                        bool closed = *reinterpret_cast<const bool*>(pathData);
                        pathData += sizeof(bool);
                        
                        const Vec3* points = reinterpret_cast<const Vec3*>(pathData);
                        
                        DebugPath path;
                        path.points.assign(points, points + pointCount);
                        path.color = color;
                        path.thickness = thickness;
                        path.closed = closed;
                        
                        renderer.AddPath(header.id, path, lifetime);
                    }
                }
                break;
            }
            default:
                LogWarning("DebugVisualServer: Unsupported primitive type: " + 
                           std::to_string(header.primitiveType));
                break;
        }
    }

    static void HandleCommand(const DebugCommandPacket& cmd) {
        auto& renderer = DebugRenderer::GetInstance();
        if (!renderer.IsInitialized()) {
            return;
        }

        auto command = static_cast<DebugCommand>(cmd.command);

        switch (command) {
            case DebugCommand::Remove:
                renderer.RemovePrimitive(cmd.id);
                break;
            case DebugCommand::Clear:
                renderer.ClearAllPrimitives();
                break;
            case DebugCommand::ClearType:
                renderer.ClearPrimitivesOfType(static_cast<PrimitiveType>(cmd.primitiveType));
                break;
            default:
                break;
        }
    }

} // namespace SapphireHook::DebugVisuals
