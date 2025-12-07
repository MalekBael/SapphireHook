#pragma once

#include <d3d11.h>
#include <DirectXMath.h>
#include <mutex>
#include <atomic>
#include <vector>
#include <array>

namespace SapphireHook::DebugVisuals {

    // Info about a captured matrix candidate
    struct MatrixCandidate {
        DirectX::XMMATRIX matrix;
        DirectX::XMFLOAT3 extractedCameraPos;
        float score;
        uint32_t bufferSize;
        uint32_t offsetInBuffer;
        uint64_t frameCapured;
        bool looksLikeView;
        bool looksLikeProjection;
        bool looksLikeViewProj;
        bool cameraPositionMatches;
    };

    // Captures the View-Projection matrix from D3D11 constant buffer updates
    // This is game-version independent - works by intercepting D3D11 calls
    class D3D11MatrixCapture {
    public:
        static D3D11MatrixCapture& GetInstance();

        // Initialize hooks on the device context
        bool Initialize(ID3D11DeviceContext* context);
        void Shutdown();

        // Get the captured matrices
        bool HasValidMatrices() const { return m_hasValidMatrices.load(); }
        DirectX::XMMATRIX GetViewMatrix() const;
        DirectX::XMMATRIX GetProjectionMatrix() const;
        DirectX::XMMATRIX GetViewProjectionMatrix() const;
        DirectX::XMFLOAT3 GetCameraPosition() const;

        // Called from our hook to analyze constant buffer data
        void OnUpdateSubresource(ID3D11Resource* dstResource, UINT dstSubresource, 
                                 const D3D11_BOX* dstBox, const void* srcData,
                                 UINT srcRowPitch, UINT srcDepthPitch);
        void OnMap(ID3D11Resource* resource, UINT subresource, D3D11_MAP mapType,
                   UINT mapFlags, D3D11_MAPPED_SUBRESOURCE* mappedResource);
        void OnUnmap(ID3D11Resource* resource, UINT subresource);
        
        // NEW: Called from VSSetConstantBuffers hook to read buffer contents
        void OnVSSetConstantBuffers(UINT startSlot, UINT numBuffers, ID3D11Buffer* const* buffers,
                                    ID3D11DeviceContext* context);

        // Frame management
        void OnNewFrame() { m_currentFrame++; }
        uint64_t GetCurrentFrame() const { return m_currentFrame; }

        // Settings
        void SetCaptureEnabled(bool enabled) { m_captureEnabled = enabled; }
        bool IsCaptureEnabled() const { return m_captureEnabled; }
        void SetVerboseLogging(bool enabled) { m_verboseLogging = enabled; }
        bool IsVerboseLogging() const { return m_verboseLogging; }
        
        // Set known camera position for validation
        void SetKnownCameraPosition(const DirectX::XMFLOAT3& pos);
        
        // Debug info
        uint32_t GetCapturedBufferCount() const { return m_capturedBufferCount; }
        uint32_t GetValidMatrixCount() const { return m_validMatrixCount; }
        uint32_t GetVSSetCallCount() const { return m_vsSetCallCount; }
        
        // Get recent matrix candidates for debugging UI
        std::vector<MatrixCandidate> GetRecentCandidates() const;
        void ClearCandidates();

    private:
        D3D11MatrixCapture() = default;
        ~D3D11MatrixCapture() = default;

        D3D11MatrixCapture(const D3D11MatrixCapture&) = delete;
        D3D11MatrixCapture& operator=(const D3D11MatrixCapture&) = delete;

        // Try to identify if a buffer contains a ViewProjection matrix
        bool AnalyzeBufferForViewProjection(const void* data, size_t dataSize);
        
        // Validate that a matrix looks like a valid ViewProjection
        bool IsValidViewProjectionMatrix(const DirectX::XMMATRIX& matrix);
        
        // Extract camera position from view matrix
        DirectX::XMFLOAT3 ExtractCameraPosition(const DirectX::XMMATRIX& viewMatrix);
        
        // Score a matrix based on how likely it is to be view/projection/viewproj
        MatrixCandidate ScoreMatrix(const DirectX::XMMATRIX& matrix, uint32_t bufferSize, uint32_t offset);
        
        // Read buffer contents via staging buffer
        bool ReadBufferContents(ID3D11Buffer* buffer, ID3D11DeviceContext* context, 
                                std::vector<uint8_t>& outData);

        mutable std::mutex m_mutex;
        std::atomic<bool> m_initialized{ false };
        std::atomic<bool> m_captureEnabled{ true };
        std::atomic<bool> m_hasValidMatrices{ false };
        std::atomic<bool> m_verboseLogging{ false };

        ID3D11DeviceContext* m_context = nullptr;
        ID3D11Device* m_device = nullptr;

        // Captured matrices
        DirectX::XMMATRIX m_viewMatrix = DirectX::XMMatrixIdentity();
        DirectX::XMMATRIX m_projMatrix = DirectX::XMMatrixIdentity();
        DirectX::XMMATRIX m_viewProjMatrix = DirectX::XMMatrixIdentity();
        DirectX::XMFLOAT3 m_cameraPosition = { 0.0f, 0.0f, 0.0f };

        // Frame counter to avoid processing same frame multiple times
        std::atomic<uint64_t> m_lastCaptureFrame{ 0 };
        std::atomic<uint64_t> m_currentFrame{ 0 };
        
        // Debug counters
        std::atomic<uint32_t> m_capturedBufferCount{ 0 };
        std::atomic<uint32_t> m_validMatrixCount{ 0 };
        std::atomic<uint32_t> m_vsSetCallCount{ 0 };
        
        // Track mapped buffers for Map/Unmap pairs
        struct MappedBuffer {
            ID3D11Resource* resource = nullptr;
            void* data = nullptr;
            size_t size = 0;
        };
        MappedBuffer m_currentMappedBuffer;
        
        // Known camera position for validation (from GameCameraExtractor)
        DirectX::XMFLOAT3 m_knownCameraPosition = { 0.0f, 0.0f, 0.0f };
        std::atomic<bool> m_hasKnownCameraPosition{ false };
        
        // Recent matrix candidates for debugging
        static constexpr size_t MAX_CANDIDATES = 16;
        std::vector<MatrixCandidate> m_recentCandidates;
        
        // Staging buffer for reading GPU buffers
        ID3D11Buffer* m_stagingBuffer = nullptr;
        size_t m_stagingBufferSize = 0;
    };

} // namespace SapphireHook::DebugVisuals
