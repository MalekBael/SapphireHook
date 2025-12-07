#pragma once
/*
 * DebugVisualClient.h - Sample code for Sapphire server to send debug visuals
 * 
 * This file provides the protocol structures and a simple UDP client for sending
 * debug visualization commands to SapphireHook's DebugVisualServer.
 * 
 * Usage in Sapphire:
 *   #include "DebugVisualClient.h"
 *   
 *   // Initialize once
 *   DebugVisualClient client("127.0.0.1", 17899);
 *   
 *   // Draw a line from player to target
 *   client.DrawLine(1, playerPos, targetPos, Color::Red(), 5.0f);
 *   
 *   // Draw a circle around an NPC
 *   client.DrawCircle(2, npcPos, 3.0f, Color::Yellow(), 5.0f);
 *   
 *   // Clear all visuals
 *   client.ClearAll();
 */

#include <cstdint>
#include <string>
#include <vector>
#include <cstring>

#ifdef _WIN32
    #include <WinSock2.h>
    #include <WS2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define closesocket close
#endif

namespace SapphireDebug {

    // ============================================
    // Types - must match SapphireHook definitions
    // ============================================

    struct Color {
        float r, g, b, a;

        static constexpr Color Red()     { return { 1.0f, 0.0f, 0.0f, 1.0f }; }
        static constexpr Color Green()   { return { 0.0f, 1.0f, 0.0f, 1.0f }; }
        static constexpr Color Blue()    { return { 0.0f, 0.0f, 1.0f, 1.0f }; }
        static constexpr Color Yellow()  { return { 1.0f, 1.0f, 0.0f, 1.0f }; }
        static constexpr Color Cyan()    { return { 0.0f, 1.0f, 1.0f, 1.0f }; }
        static constexpr Color Magenta() { return { 1.0f, 0.0f, 1.0f, 1.0f }; }
        static constexpr Color White()   { return { 1.0f, 1.0f, 1.0f, 1.0f }; }
        static constexpr Color Orange()  { return { 1.0f, 0.5f, 0.0f, 1.0f }; }
    };

    struct Vec3 {
        float x, y, z;
    };

    enum class PrimitiveType : uint8_t {
        Line = 0,
        Sphere = 1,
        Box = 2,
        Circle = 3,
        Cylinder = 4,
        Cone = 5,
        Arrow = 6,
        Text3D = 7,
        Path = 8,
        Ring = 9,
    };

    enum class DebugCommand : uint8_t {
        Add = 0,
        Update = 1,
        Remove = 2,
        Clear = 3,
        ClearType = 4,
    };

    #pragma pack(push, 1)
    struct DebugVisualPacketHeader {
        uint32_t magic;        // 'DBGV' = 0x56474244
        uint8_t version;       // Protocol version = 1
        uint8_t primitiveType; // PrimitiveType enum
        uint16_t dataSize;     // Size of primitive data following header
        uint32_t id;           // Primitive ID (for updates/removal)
        float lifetime;        // Seconds to display (0 = permanent)
    };

    struct DebugCommandPacket {
        uint32_t magic;        // 'DBGC' = 0x43474244
        uint8_t command;       // DebugCommand enum
        uint8_t primitiveType; // For ClearType command
        uint16_t reserved;
        uint32_t id;           // For Remove command
    };

    struct DebugLine {
        Vec3 start;
        Vec3 end;
        Color color;
        float thickness;
    };

    struct DebugSphere {
        Vec3 center;
        float radius;
        Color color;
        bool filled;
        int segments;
    };

    struct DebugCircle {
        Vec3 center;
        float radius;
        Color color;
        int segments;
        bool filled;
        float yRotation;
    };
    #pragma pack(pop)

    constexpr uint32_t DEBUG_VISUAL_MAGIC = 0x56474244;  // 'DBGV'
    constexpr uint32_t DEBUG_COMMAND_MAGIC = 0x43474244; // 'DBGC'
    constexpr uint16_t DEBUG_VISUAL_PORT = 17899;
    constexpr uint8_t PROTOCOL_VERSION = 1;

    // ============================================
    // Client class
    // ============================================
    class DebugVisualClient {
    public:
        DebugVisualClient(const std::string& host = "127.0.0.1", uint16_t port = DEBUG_VISUAL_PORT)
            : m_host(host), m_port(port) {
#ifdef _WIN32
            WSADATA wsaData;
            WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
            m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            
            if (m_socket != INVALID_SOCKET) {
                m_serverAddr.sin_family = AF_INET;
                m_serverAddr.sin_port = htons(port);
                inet_pton(AF_INET, host.c_str(), &m_serverAddr.sin_addr);
            }
        }

        ~DebugVisualClient() {
            if (m_socket != INVALID_SOCKET) {
                closesocket(m_socket);
            }
#ifdef _WIN32
            WSACleanup();
#endif
        }

        bool IsConnected() const { return m_socket != INVALID_SOCKET; }

        // ============================================
        // Drawing methods
        // ============================================

        /// Draw a line between two points
        void DrawLine(uint32_t id, const Vec3& start, const Vec3& end, 
                      const Color& color = Color::White(), float lifetime = 5.0f,
                      float thickness = 2.0f) {
            DebugLine line;
            line.start = start;
            line.end = end;
            line.color = color;
            line.thickness = thickness;
            
            SendPrimitive(id, PrimitiveType::Line, &line, sizeof(line), lifetime);
        }

        /// Draw a sphere (wireframe)
        void DrawSphere(uint32_t id, const Vec3& center, float radius,
                        const Color& color = Color::White(), float lifetime = 5.0f,
                        bool filled = false, int segments = 16) {
            DebugSphere sphere;
            sphere.center = center;
            sphere.radius = radius;
            sphere.color = color;
            sphere.filled = filled;
            sphere.segments = segments;
            
            SendPrimitive(id, PrimitiveType::Sphere, &sphere, sizeof(sphere), lifetime);
        }

        /// Draw a circle on the ground (Y-up)
        void DrawCircle(uint32_t id, const Vec3& center, float radius,
                        const Color& color = Color::White(), float lifetime = 5.0f,
                        bool filled = false, int segments = 32) {
            DebugCircle circle;
            circle.center = center;
            circle.radius = radius;
            circle.color = color;
            circle.segments = segments;
            circle.filled = filled;
            circle.yRotation = 0;
            
            SendPrimitive(id, PrimitiveType::Circle, &circle, sizeof(circle), lifetime);
        }

        /// Draw a path (connected line segments)
        void DrawPath(uint32_t id, const std::vector<Vec3>& points,
                      const Color& color = Color::White(), float lifetime = 5.0f,
                      float thickness = 2.0f, bool closed = false) {
            if (points.empty()) return;

            // Build path packet: [count: u32][color][thickness][closed][points...]
            std::vector<uint8_t> buffer;
            buffer.resize(sizeof(uint32_t) + sizeof(Color) + sizeof(float) + 
                         sizeof(bool) + points.size() * sizeof(Vec3));

            uint8_t* ptr = buffer.data();
            uint32_t count = static_cast<uint32_t>(points.size());
            memcpy(ptr, &count, sizeof(count)); ptr += sizeof(count);
            memcpy(ptr, &color, sizeof(color)); ptr += sizeof(color);
            memcpy(ptr, &thickness, sizeof(thickness)); ptr += sizeof(thickness);
            memcpy(ptr, &closed, sizeof(closed)); ptr += sizeof(closed);
            memcpy(ptr, points.data(), points.size() * sizeof(Vec3));

            SendPrimitive(id, PrimitiveType::Path, buffer.data(), 
                         static_cast<uint16_t>(buffer.size()), lifetime);
        }

        // ============================================
        // Control methods
        // ============================================

        /// Remove a specific primitive by ID
        void Remove(uint32_t id) {
            SendCommand(DebugCommand::Remove, PrimitiveType::Line, id);
        }

        /// Clear all debug primitives
        void ClearAll() {
            SendCommand(DebugCommand::Clear, PrimitiveType::Line, 0);
        }

        /// Clear all primitives of a specific type
        void ClearType(PrimitiveType type) {
            SendCommand(DebugCommand::ClearType, type, 0);
        }

    private:
        void SendPrimitive(uint32_t id, PrimitiveType type, 
                           const void* data, uint16_t dataSize, float lifetime) {
            if (m_socket == INVALID_SOCKET) return;

            std::vector<uint8_t> packet(sizeof(DebugVisualPacketHeader) + dataSize);
            
            auto* header = reinterpret_cast<DebugVisualPacketHeader*>(packet.data());
            header->magic = DEBUG_VISUAL_MAGIC;
            header->version = PROTOCOL_VERSION;
            header->primitiveType = static_cast<uint8_t>(type);
            header->dataSize = dataSize;
            header->id = id;
            header->lifetime = lifetime;

            memcpy(packet.data() + sizeof(DebugVisualPacketHeader), data, dataSize);

            sendto(m_socket, reinterpret_cast<const char*>(packet.data()),
                   static_cast<int>(packet.size()), 0,
                   reinterpret_cast<const sockaddr*>(&m_serverAddr),
                   sizeof(m_serverAddr));
        }

        void SendCommand(DebugCommand cmd, PrimitiveType type, uint32_t id) {
            if (m_socket == INVALID_SOCKET) return;

            DebugCommandPacket packet;
            packet.magic = DEBUG_COMMAND_MAGIC;
            packet.command = static_cast<uint8_t>(cmd);
            packet.primitiveType = static_cast<uint8_t>(type);
            packet.reserved = 0;
            packet.id = id;

            sendto(m_socket, reinterpret_cast<const char*>(&packet),
                   sizeof(packet), 0,
                   reinterpret_cast<const sockaddr*>(&m_serverAddr),
                   sizeof(m_serverAddr));
        }

        SOCKET m_socket = INVALID_SOCKET;
        sockaddr_in m_serverAddr{};
        std::string m_host;
        uint16_t m_port;
    };

} // namespace SapphireDebug

/*
 * Example usage in Sapphire server code:
 * 
 * // In some manager class:
 * SapphireDebug::DebugVisualClient g_debugClient;
 * 
 * // When player casts an AoE:
 * void onAoECast(Player* player, uint32_t actionId, Position target, float radius) {
 *     static uint32_t aoeId = 10000;
 *     
 *     SapphireDebug::Vec3 center = { target.x, target.y, target.z };
 *     
 *     // Draw the AoE indicator
 *     g_debugClient.DrawCircle(aoeId++, center, radius, 
 *                               SapphireDebug::Color::Red(), 
 *                               3.0f,   // lifetime in seconds
 *                               true);  // filled
 * }
 * 
 * // Draw NPC patrol path:
 * void showPatrolPath(BNpc* npc, const std::vector<Position>& waypoints) {
 *     std::vector<SapphireDebug::Vec3> points;
 *     for (const auto& wp : waypoints) {
 *         points.push_back({ wp.x, wp.y, wp.z });
 *     }
 *     
 *     g_debugClient.DrawPath(npc->getId(), points,
 *                             SapphireDebug::Color::Cyan(),
 *                             10.0f,   // lifetime
 *                             3.0f,    // thickness
 *                             true);   // closed loop
 * }
 * 
 * // Draw line from player to target:
 * void showTargetLine(Player* player, Actor* target) {
 *     auto pPos = player->getPos();
 *     auto tPos = target->getPos();
 *     
 *     g_debugClient.DrawLine(player->getId() * 1000 + 1,
 *                             { pPos.x, pPos.y + 1.0f, pPos.z },
 *                             { tPos.x, tPos.y + 1.0f, tPos.z },
 *                             SapphireDebug::Color::Green(),
 *                             0.5f);  // short lifetime, updates frequently
 * }
 */
