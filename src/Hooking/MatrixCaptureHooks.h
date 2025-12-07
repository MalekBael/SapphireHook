#pragma once

#include <DirectXMath.h>
#include <cstdint>
#include <mutex>
#include <atomic>
#include <array>

namespace SapphireHook::MatrixHooks {

    // ============================================
    // Matrix Write Function Hooks
    // ============================================
    // These hooks capture View, Projection, and ViewProjection matrices
    // as they are computed by the game's camera system.
    //
    // From IDA analysis (December 2025):
    // - 0x140358640: Writes View Matrix to [rcx+0x40] (50 writes)
    // - 0x140352930: Writes Projection Matrix to [rcx+0x80] (50 writes)
    // - 0x140351D30: Writes ViewProjection Matrix to [rcx+0xC0] (26 writes)
    // ============================================

    // RVAs for the matrix write functions (add to module base)
    namespace MatrixFunctionRVAs {
        constexpr uintptr_t ViewMatrixWriter = 0x358640;       // sub_140358640
        constexpr uintptr_t ProjectionMatrixWriter = 0x352930; // sub_140352930
        constexpr uintptr_t ViewProjMatrixWriter = 0x351D30;   // sub_140351D30
    }

    // Matrix offsets within the camera object (from IDA analysis Dec 2025)
    // ViewMatrixWriter writes to: 0xA0-0xF0, 0x100-0x130, 0x140-0x170 via rax/rcx
    // ProjectionMatrixWriter writes to: 0x10-0x30 (r14), 0x140-0x170 (rbx)
    // The traditional 0x40/0x80/0xC0 offsets may be populated by different code paths
    namespace MatrixOffsets {
        // Traditional offsets (may still work depending on camera object type)
        constexpr size_t ViewMatrix = 0x40;        // 4x4 matrix (64 bytes)
        constexpr size_t ProjectionMatrix = 0x80;  // 4x4 matrix (64 bytes)
        constexpr size_t ViewProjMatrix = 0xC0;    // 4x4 matrix (64 bytes)
        
        // Offsets seen in ViewMatrixWriter (via rax register)
        constexpr size_t Matrix_0xA0 = 0xA0;       // First matrix block
        constexpr size_t Matrix_0xC0 = 0xC0;       // Second matrix block (overlaps ViewProj)
        constexpr size_t Matrix_0x100 = 0x100;     // Third matrix block (via rcx)
        constexpr size_t Matrix_0x140 = 0x140;     // Fourth matrix block
        
        // Offsets seen in ProjectionMatrixWriter (via r14 register)
        constexpr size_t Matrix_0x10 = 0x10;       // Render::Camera.ViewMatrix (FFXIVClientStructs)
        
        // Position - still at 0x100 but may be overwritten by matrices
        constexpr size_t Position = 0x100;         // float3 camera position
        constexpr size_t Position_Alt = 0xE0;      // Alternative position
    }

    // Captured matrix data
    struct CapturedMatrices {
        DirectX::XMMATRIX viewMatrix;
        DirectX::XMMATRIX projectionMatrix;
        DirectX::XMMATRIX viewProjMatrix;
        DirectX::XMFLOAT3 cameraPosition;
        
        uintptr_t cameraObjectPtr;      // The camera object that holds these matrices
        uint64_t frameNumber;           // Frame when captured
        uint64_t captureTimestamp;      // High-resolution timestamp
        
        bool viewValid;
        bool projectionValid;
        bool viewProjValid;
        bool positionValid;
        
        // Which hook captured each matrix
        bool viewFromHook;
        bool projFromHook;
        bool viewProjFromHook;
    };

    // ============================================
    // MatrixCaptureHooks - captures camera matrices from game functions
    // ============================================
    class MatrixCaptureHooks {
    public:
        // Singleton access
        static MatrixCaptureHooks& GetInstance();

        // Prevent copying
        MatrixCaptureHooks(const MatrixCaptureHooks&) = delete;
        MatrixCaptureHooks& operator=(const MatrixCaptureHooks&) = delete;

        // Initialize and install all hooks
        bool Initialize();
        
        // Shutdown and remove all hooks
        void Shutdown();

        // Check if hooks are installed
        bool IsInitialized() const { return m_initialized.load(); }

        // Get the latest captured matrices (thread-safe)
        CapturedMatrices GetCapturedMatrices() const;
        
        // Get individual matrices (thread-safe, returns identity if not captured)
        DirectX::XMMATRIX GetViewMatrix() const;
        DirectX::XMMATRIX GetProjectionMatrix() const;
        DirectX::XMMATRIX GetViewProjMatrix() const;
        DirectX::XMFLOAT3 GetCameraPosition() const;

        // Check if we have valid matrices
        bool HasValidViewMatrix() const;
        bool HasValidProjectionMatrix() const;
        bool HasValidViewProjMatrix() const;
        bool HasAnyValidMatrix() const;

        // Get capture statistics
        uint64_t GetViewCaptureCount() const { return m_viewCaptureCount.load(); }
        uint64_t GetProjCaptureCount() const { return m_projCaptureCount.load(); }
        uint64_t GetViewProjCaptureCount() const { return m_viewProjCaptureCount.load(); }
        
        // Get the camera object pointer (for debugging)
        uintptr_t GetCameraObjectPtr() const { return m_capturedMatrices.cameraObjectPtr; }

        // Enable/disable verbose logging
        void SetVerboseLogging(bool enabled) { m_verboseLogging = enabled; }
        bool IsVerboseLogging() const { return m_verboseLogging; }

        // Frame tracking
        void OnNewFrame() { m_currentFrame++; }

    private:
        MatrixCaptureHooks() = default;
        ~MatrixCaptureHooks() = default;

        // Hook installation helpers
        bool InstallViewMatrixHook();
        bool InstallProjectionMatrixHook();
        bool InstallViewProjMatrixHook();

        // Matrix validation
        static bool IsValidMatrix(const DirectX::XMMATRIX& matrix);
        static bool IsValidFloat3(const DirectX::XMFLOAT3& vec);

        // Safe memory reading
        bool SafeReadMatrix(uintptr_t address, DirectX::XMMATRIX& outMatrix) const;
        bool SafeReadFloat3(uintptr_t address, DirectX::XMFLOAT3& outVec) const;

        // Called by hook functions to store captured data
        void OnViewMatrixWritten(void* destBuffer, void* srcCamera);
        void OnProjectionMatrixWritten(void* cameraObject);
        void OnViewProjMatrixWritten(void* cameraObject);

        // Friend declarations for hook functions (exact IDA-analyzed signatures)
        // ViewMatrixWriter: __int64 __fastcall(__int64, __int64)
        friend __int64 __fastcall HookedViewMatrixWriter(__int64 thisPtr, __int64 param2);
        // ProjectionMatrixWriter: __int64 __fastcall(_DWORD*) - only 1 param!
        friend __int64 __fastcall HookedProjectionMatrixWriter(__int32* thisPtr);
        // ViewProjMatrixWriter: char __fastcall(...) - 8 params!
        friend char __fastcall HookedViewProjMatrixWriter(__int64, char, __int64, bool*, unsigned int*, void*, __int32*, __int32*);

        // State
        std::atomic<bool> m_initialized{ false };
        mutable std::mutex m_mutex;

        // Captured data
        CapturedMatrices m_capturedMatrices{};
        
        // Capture statistics
        std::atomic<uint64_t> m_viewCaptureCount{ 0 };
        std::atomic<uint64_t> m_projCaptureCount{ 0 };
        std::atomic<uint64_t> m_viewProjCaptureCount{ 0 };
        
        // Frame tracking
        std::atomic<uint64_t> m_currentFrame{ 0 };
        
        // Verbose logging
        bool m_verboseLogging = false;

        // Original function pointers (for calling originals)
        void* m_originalViewMatrixWriter = nullptr;
        void* m_originalProjectionMatrixWriter = nullptr;
        void* m_originalViewProjMatrixWriter = nullptr;

        // Hook addresses
        uintptr_t m_viewMatrixWriterAddr = 0;
        uintptr_t m_projMatrixWriterAddr = 0;
        uintptr_t m_viewProjMatrixWriterAddr = 0;
    };

} // namespace SapphireHook::MatrixHooks
