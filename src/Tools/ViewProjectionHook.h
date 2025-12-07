#pragma once

#include <DirectXMath.h>
#include <atomic>
#include <mutex>
#include <cstdint>

namespace SapphireHook::DebugVisuals {

    // ============================================
    // ViewProjectionHook - Captures ViewProjection matrix by hooking
    // the game's WorldToScreen function (sub_7FF69A5616A0)
    // 
    // This is much more reliable than reading from memory offsets
    // because we capture the matrix as it's actually used.
    // ============================================
    class ViewProjectionHook {
    public:
        static ViewProjectionHook& GetInstance();

        // Prevent copying
        ViewProjectionHook(const ViewProjectionHook&) = delete;
        ViewProjectionHook& operator=(const ViewProjectionHook&) = delete;

        // Initialize - scans for WorldToScreen function and installs hook
        bool Initialize();
        void Shutdown();

        // Get the captured ViewProjection matrix
        bool GetViewProjectionMatrix(DirectX::XMMATRIX& outMatrix) const;
        
        // Get the last captured camera position (extracted from matrix)
        bool GetCameraPosition(DirectX::XMFLOAT3& outPos) const;
        
        // Check if we have valid matrices
        bool HasValidMatrix() const { return m_hasValidMatrix.load(); }
        
        // Get capture statistics
        uint64_t GetCaptureCount() const { return m_captureCount.load(); }
        uint64_t GetFrameOfLastCapture() const { return m_lastCaptureFrame.load(); }
        
        // Increment frame counter (call once per frame from main render loop)
        void OnNewFrame() { m_currentFrame.fetch_add(1); }
        
        // Get hook status
        bool IsHooked() const { return m_isHooked.load(); }
        uintptr_t GetHookedAddress() const { return m_hookedAddress; }

        // Called from the hook to capture matrix data
        static void CaptureMatrixFromArgs(const float* matrixPtr);

    private:
        ViewProjectionHook() = default;
        ~ViewProjectionHook() = default;

        // Signature patterns for WorldToScreen function
        // Based on IDA analysis: sub_7FF69A5616A0 (score 13/17)
        bool ScanForWorldToScreen();
        
        // Validate that the found address looks like W2S
        bool ValidateWorldToScreenFunction(uintptr_t address);
        
        // Install the hooks
        bool InstallHook(uintptr_t address);
        bool InstallSecondHook(uintptr_t address);  // For alternate W2S function

        // State
        std::atomic<bool> m_initialized{ false };
        std::atomic<bool> m_isHooked{ false };
        std::atomic<bool> m_hasValidMatrix{ false };
        
        uintptr_t m_hookedAddress = 0;
        void* m_originalFunction = nullptr;
        
        // Captured matrix data (protected by mutex)
        mutable std::mutex m_mutex;
        DirectX::XMMATRIX m_viewProjMatrix = DirectX::XMMatrixIdentity();
        DirectX::XMFLOAT3 m_cameraPosition = { 0, 0, 0 };
        
        // Statistics
        std::atomic<uint64_t> m_captureCount{ 0 };
        std::atomic<uint64_t> m_lastCaptureFrame{ 0 };
        std::atomic<uint64_t> m_currentFrame{ 0 };
    };

} // namespace SapphireHook::DebugVisuals
