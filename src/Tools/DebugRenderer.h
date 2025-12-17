#pragma once
#include "DebugVisualTypes.h"
#include <d3d11.h>
#include <DirectXMath.h>
#include <vector>
#include <memory>
#include <mutex>
#include <optional>

struct ID3D11Device;
struct ID3D11DeviceContext;
struct ID3D11Buffer;
struct ID3D11InputLayout;
struct ID3D11VertexShader;
struct ID3D11PixelShader;
struct ID3D11RasterizerState;
struct ID3D11DepthStencilState;
struct ID3D11BlendState;

namespace SapphireHook::DebugVisuals {

    // ============================================
    // Vertex format for debug primitives
    // ============================================
    struct DebugVertex {
        DirectX::XMFLOAT3 position;
        DirectX::XMFLOAT4 color;
    };

    // ============================================
    // Constant buffer for shader parameters
    // ============================================
    struct alignas(16) DebugConstantBuffer {
        DirectX::XMMATRIX viewProjection;
        DirectX::XMFLOAT4 screenSize;  // xy = screen size, zw = 1/screenSize
    };

    // ============================================
    // Camera data extracted from game
    // ============================================
    struct CameraData {
        DirectX::XMMATRIX view;
        DirectX::XMMATRIX projection;
        DirectX::XMFLOAT3 position;
        float fov;
        float nearPlane;
        float farPlane;
    };

    // ============================================
    // Main Debug Renderer class
    // ============================================
    class DebugRenderer {
    public:
        static DebugRenderer& GetInstance();

        // Initialization
        bool Initialize(ID3D11Device* device, ID3D11DeviceContext* context);
        void Shutdown();
        bool IsInitialized() const { return m_initialized; }

        // Frame lifecycle
        void BeginFrame();
        void EndFrame();

        // Camera setup - must be called each frame with current camera state
        void SetViewProjection(const DirectX::XMMATRIX& view, const DirectX::XMMATRIX& projection);
        
        // Set pre-computed ViewProjection directly (preferred - avoids frame timing issues)
        void SetViewProjectionDirect(const DirectX::XMMATRIX& viewProjection);
        
        void SetScreenSize(float width, float height);
        float GetScreenWidth() const { return m_screenWidth; }
        float GetScreenHeight() const { return m_screenHeight; }

        // Manual camera matrix setup (for when we can extract from game)
        void SetCameraFromGame(const CameraData& camera);

        // Immediate-mode rendering (drawn this frame only)
        void DrawLine(const Vec3& start, const Vec3& end, const Color& color, float thickness = 2.0f);
        void DrawThickLine(const Vec3& start, const Vec3& end, const Color& color, float worldThickness);  // Uses quads for actual thick lines
        void DrawSphere(const Vec3& center, float radius, const Color& color, bool filled = false, int segments = 16);
        void DrawBox(const Vec3& center, const Vec3& halfExtents, const Color& color, bool filled = false);
        void DrawCircle(const Vec3& center, float radius, const Color& color, int segments = 32, bool filled = false);
        void DrawCylinder(const Vec3& base, float radius, float height, const Color& color, int segments = 16, bool filled = false);
        void DrawCone(const Vec3& apex, const Vec3& direction, float radius, float height, const Color& color, int segments = 16);
        void DrawArrow(const Vec3& start, const Vec3& end, const Color& color, float thickness = 2.0f, float headSize = 0.5f);
        void DrawPath(const std::vector<Vec3>& points, const Color& color, float thickness = 2.0f, bool closed = false);
        void DrawRing(const Vec3& center, float innerRadius, float outerRadius, float height, const Color& color, int segments = 32);

        // Text rendering (uses ImGui's draw list for simplicity)
        void DrawText3D(const Vec3& position, const std::string& text, const Color& color, float scale = 1.0f);

        // Persistent primitives with lifetime
        void AddLine(uint32_t id, const DebugLine& line, float lifetime);
        void AddSphere(uint32_t id, const DebugSphere& sphere, float lifetime);
        void AddCircle(uint32_t id, const DebugCircle& circle, float lifetime);
        void AddPath(uint32_t id, const DebugPath& path, float lifetime);
        
        void RemovePrimitive(uint32_t id);
        void ClearAllPrimitives();
        void ClearPrimitivesOfType(PrimitiveType type);

        // World-to-screen projection
        std::optional<DirectX::XMFLOAT2> WorldToScreen(const Vec3& worldPos) const;
        
        // Frustum culling - returns true if point is potentially visible
        bool IsPointInFrustum(const Vec3& worldPos) const;
        bool IsPointInFrustum(float x, float y, float z) const;
        bool IsSphereInFrustum(const Vec3& center, float radius) const;

        // Configuration
        void SetEnabled(bool enabled) { m_enabled = enabled; }
        bool IsEnabled() const { return m_enabled; }
        void SetFrustumCullingEnabled(bool enabled) { m_frustumCullingEnabled = enabled; }
        bool IsFrustumCullingEnabled() const { return m_frustumCullingEnabled; }
        void SetDepthTestEnabled(bool enabled) { m_depthTestEnabled = enabled; }
        bool IsDepthTestEnabled() const { return m_depthTestEnabled; }

        // Statistics
        size_t GetPrimitiveCount() const;

    private:
        DebugRenderer() = default;
        ~DebugRenderer() = default;
        DebugRenderer(const DebugRenderer&) = delete;
        DebugRenderer& operator=(const DebugRenderer&) = delete;

        // DirectX resources
        bool CreateShaders();
        bool CreateBuffers();
        bool CreateStates();
        void ReleaseResources();

        // Geometry generation helpers
        void GenerateSphereVertices(std::vector<DebugVertex>& vertices, const Vec3& center, 
                                     float radius, const Color& color, int segments);
        void GenerateCircleVertices(std::vector<DebugVertex>& vertices, const Vec3& center,
                                     float radius, const Color& color, int segments);
        void GenerateCylinderVertices(std::vector<DebugVertex>& vertices, const Vec3& base,
                                       float radius, float height, const Color& color, int segments);
        void GenerateConeVertices(std::vector<DebugVertex>& vertices, const Vec3& apex,
                                   const Vec3& direction, float radius, float height,
                                   const Color& color, int segments);

        // Rendering internals
        void FlushLines();
        void FlushTriangles();
        void UpdateConstantBuffer();

        // Cleanup expired primitives
        void CleanupExpiredPrimitives();

        // DirectX state
        ID3D11Device* m_device = nullptr;
        ID3D11DeviceContext* m_context = nullptr;
        ID3D11Buffer* m_vertexBuffer = nullptr;
        ID3D11Buffer* m_constantBuffer = nullptr;
        ID3D11InputLayout* m_inputLayout = nullptr;
        ID3D11VertexShader* m_vertexShader = nullptr;
        ID3D11PixelShader* m_pixelShader = nullptr;
        ID3D11RasterizerState* m_rasterizerState = nullptr;
        ID3D11RasterizerState* m_rasterizerStateNoCull = nullptr;
        ID3D11DepthStencilState* m_depthStencilState = nullptr;
        ID3D11DepthStencilState* m_depthStencilStateNoDepth = nullptr;
        ID3D11BlendState* m_blendState = nullptr;

        // Batch buffers
        std::vector<DebugVertex> m_lineVertices;
        std::vector<DebugVertex> m_triangleVertices;
        static constexpr size_t MAX_VERTICES = 65536;

        // Camera/projection state
        DirectX::XMMATRIX m_view = DirectX::XMMatrixIdentity();
        DirectX::XMMATRIX m_projection = DirectX::XMMatrixIdentity();
        DirectX::XMMATRIX m_viewProjection = DirectX::XMMatrixIdentity();
        float m_screenWidth = 1920.0f;
        float m_screenHeight = 1080.0f;

        // Persistent primitives
        std::vector<TimedPrimitive<DebugLine>> m_persistentLines;
        std::vector<TimedPrimitive<DebugSphere>> m_persistentSpheres;
        std::vector<TimedPrimitive<DebugCircle>> m_persistentCircles;
        std::vector<TimedPrimitive<DebugPath>> m_persistentPaths;
        mutable std::mutex m_primitiveMutex;

        // State
        bool m_initialized = false;
        bool m_enabled = true;
        bool m_frustumCullingEnabled = true;  // Enable frustum culling by default
        bool m_depthTestEnabled = false;  // Usually we want debug visuals on top
        bool m_inFrame = false;
        
        // Cached frustum planes (updated each frame from view-projection)
        DirectX::XMFLOAT4 m_frustumPlanes[6];  // Left, Right, Bottom, Top, Near, Far
        void UpdateFrustumPlanes();
    };

} // namespace SapphireHook::DebugVisuals
