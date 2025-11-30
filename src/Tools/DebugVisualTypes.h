#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <DirectXMath.h>

namespace SapphireHook::DebugVisuals {

    // ============================================
    // Color representation for debug primitives
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
        static constexpr Color Pink()    { return { 1.0f, 0.4f, 0.7f, 1.0f }; }

        uint32_t ToABGR() const {
            return (static_cast<uint32_t>(a * 255) << 24) |
                   (static_cast<uint32_t>(b * 255) << 16) |
                   (static_cast<uint32_t>(g * 255) << 8) |
                   static_cast<uint32_t>(r * 255);
        }

        static Color FromABGR(uint32_t abgr) {
            return {
                (abgr & 0xFF) / 255.0f,
                ((abgr >> 8) & 0xFF) / 255.0f,
                ((abgr >> 16) & 0xFF) / 255.0f,
                ((abgr >> 24) & 0xFF) / 255.0f
            };
        }
    };

    // ============================================
    // 3D Vector for world positions
    // ============================================
    struct Vec3 {
        float x, y, z;

        Vec3() : x(0), y(0), z(0) {}
        Vec3(float x_, float y_, float z_) : x(x_), y(y_), z(z_) {}

        Vec3 operator+(const Vec3& other) const { return { x + other.x, y + other.y, z + other.z }; }
        Vec3 operator-(const Vec3& other) const { return { x - other.x, y - other.y, z - other.z }; }
        Vec3 operator*(float s) const { return { x * s, y * s, z * s }; }

        DirectX::XMVECTOR ToXMVector() const {
            return DirectX::XMVectorSet(x, y, z, 1.0f);
        }

        static Vec3 FromXMVector(DirectX::XMVECTOR v) {
            return { DirectX::XMVectorGetX(v), DirectX::XMVectorGetY(v), DirectX::XMVectorGetZ(v) };
        }
    };

    // ============================================
    // Debug Primitive Types
    // ============================================
    enum class PrimitiveType : uint8_t {
        Line = 0,
        Sphere = 1,
        Box = 2,
        Circle = 3,       // Flat circle on ground
        Cylinder = 4,
        Cone = 5,
        Arrow = 6,        // Line with arrowhead
        Text3D = 7,       // Text floating in world
        Path = 8,         // Connected line segments
        Ring = 9,         // Vertical ring (like AoE indicator)
    };

    // ============================================
    // Debug Primitive Structures
    // ============================================

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
        int segments;  // Resolution of sphere wireframe
    };

    struct DebugBox {
        Vec3 center;
        Vec3 halfExtents;  // Half-size in each dimension
        Vec3 rotation;     // Euler angles in radians
        Color color;
        bool filled;
    };

    struct DebugCircle {
        Vec3 center;
        float radius;
        Color color;
        int segments;
        bool filled;
        float yRotation;  // Rotation around Y axis (for tilted circles)
    };

    struct DebugCylinder {
        Vec3 base;
        float radius;
        float height;
        Color color;
        int segments;
        bool filled;
    };

    struct DebugCone {
        Vec3 apex;
        Vec3 direction;
        float radius;     // Base radius
        float height;
        Color color;
        int segments;
        bool filled;
    };

    struct DebugArrow {
        Vec3 start;
        Vec3 end;
        Color color;
        float thickness;
        float headSize;   // Size of arrowhead
    };

    struct DebugText3D {
        Vec3 position;
        std::string text;
        Color color;
        float scale;
        bool billboard;   // Always face camera
    };

    struct DebugPath {
        std::vector<Vec3> points;
        Color color;
        float thickness;
        bool closed;      // Connect last point to first
    };

    struct DebugRing {
        Vec3 center;
        float innerRadius;
        float outerRadius;
        float height;
        Color color;
        int segments;
    };

    // ============================================
    // Timed Debug Primitive (with lifetime)
    // ============================================
    template<typename T>
    struct TimedPrimitive {
        T primitive;
        std::chrono::steady_clock::time_point expireTime;
        uint32_t id;  // Optional ID for updates/removal

        bool IsExpired() const {
            return std::chrono::steady_clock::now() >= expireTime;
        }
    };

    // ============================================
    // Network Protocol Definitions
    // ============================================

    // Protocol header for debug visual packets from Sapphire
    #pragma pack(push, 1)
    struct DebugVisualPacketHeader {
        uint32_t magic;        // 'DBGV' = 0x56474244
        uint8_t version;       // Protocol version
        uint8_t primitiveType; // PrimitiveType enum
        uint16_t dataSize;     // Size of primitive data following header
        uint32_t id;           // Primitive ID (for updates/removal)
        float lifetime;        // Seconds to display (0 = until manually removed)
    };

    // Commands that can be sent
    enum class DebugCommand : uint8_t {
        Add = 0,        // Add new primitive
        Update = 1,     // Update existing primitive by ID
        Remove = 2,     // Remove primitive by ID
        Clear = 3,      // Clear all primitives
        ClearType = 4,  // Clear all primitives of a type
    };

    struct DebugCommandPacket {
        uint32_t magic;        // 'DBGC' = 0x43474244
        uint8_t command;       // DebugCommand enum
        uint8_t primitiveType; // For ClearType command
        uint16_t reserved;
        uint32_t id;           // For Remove/Update commands
    };
    #pragma pack(pop)

    constexpr uint32_t DEBUG_VISUAL_MAGIC = 0x56474244;  // 'DBGV'
    constexpr uint32_t DEBUG_COMMAND_MAGIC = 0x43474244; // 'DBGC'
    constexpr uint16_t DEBUG_VISUAL_PORT = 17899;        // UDP port for debug visuals
    constexpr uint8_t PROTOCOL_VERSION = 1;

} // namespace SapphireHook::DebugVisuals
