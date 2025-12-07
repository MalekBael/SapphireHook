#pragma once

#include <DirectXMath.h>
#include <optional>
#include <cstdint>
#include <mutex>
#include <atomic>
#include <string>
#include <vector>

namespace SapphireHook::DebugVisuals {

    // ============================================
    // Game camera structure (reverse-engineered offsets)
    // VERIFIED via IDA Pro 9.1 analysis (December 2025)
    // ============================================
    
    // ===== GLOBAL POINTER RVAs (from December 2025 IDA analysis) =====
    // These are relative virtual addresses to add to the module base
    namespace GlobalRVAs {
        // From ida_trace_viewmatrix_results.txt:
        // g_RenderManager: pattern at 0x140015362, global at 0x1415E9E78
        // g_CameraManager: pattern at 0x1402EC98A, global at 0x1415F6CB8
        constexpr uintptr_t RenderManager = 0x15E9E78;    // g_RenderManager global pointer
        constexpr uintptr_t CameraManager = 0x15F6CB8;    // g_CameraManager global pointer
        
        // Matrix Writer Functions (from ida_camera_matrices_deep_results.txt):
        // These functions write matrices to camera objects at offsets 0x40/0x80/0xC0
        constexpr uintptr_t ViewMatrixWriter = 0x358640;       // Writes 50x to offset 0x40 (View)
        constexpr uintptr_t ProjectionMatrixWriter = 0x352930; // Writes 50x to offset 0x80 (Projection)
        constexpr uintptr_t ViewProjMatrixWriter = 0x351D30;   // Writes 26x to offset 0xC0 (ViewProjection)
    }
    
    // Client::Graphics::Scene::Camera offsets from IDA decompilation analysis
    // Verified from:
    //   - sub_7FF69A82F6D0 (CalculateViewMatrix)
    //   - sub_7FF69A56D750 (Projection function, 10KB, 54 DIVSS, 309 MULSS)
    //   - sub_7FF69B45BF30 (Matrix copy function - confirms View at 0x40, 0x50, 0x60)
    //   - sub_7FF69A790940 (Writes View+Proj, 2152 bytes)
    //   - sub_7FF69A79F400 (Writes View+Proj, 483 bytes)
    //
    // g_CameraManager: 0x7FF69BA46CB8 (244 references)
    // g_RenderManager: 0x7FF69BA39E78 (276 references)
    //
    namespace CameraOffsets {
        // ===== VIEW MATRIX - VERIFIED via matrix copy function =====
        // sub_7FF69B45BF30 copies from [rdi+0x40/0x50/0x60] to [rbx+0x40/0x50/0x60]
        // sub_7FF69A790940 writes View at [r12+0x10] thru [r12+0x70] (relative to output buffer)
        // sub_7FF69A79F400 writes View at [rsi+0x10] thru [rsi+0x70]
        constexpr size_t ViewMatrix = 0x40;          // 4x4 matrix (64 bytes: 0x40-0x7F)
        constexpr size_t ViewMatrixRow0 = 0x40;      // Right vector (16 bytes)
        constexpr size_t ViewMatrixRow1 = 0x50;      // Up vector (16 bytes)
        constexpr size_t ViewMatrixRow2 = 0x60;      // Forward vector (16 bytes)
        constexpr size_t ViewMatrixRow3 = 0x70;      // Translation row (16 bytes)
        
        // ===== PROJECTION MATRIX - from IDA analysis =====
        // sub_7FF69A790940 writes Proj at [r12+0x80] thru [r12+0xC0]
        // sub_7FF69A79F400 writes Proj at [rsi+0x80] thru [rsi+0xC0]
        // Projection function output is at [rbx+0x400]+0x10 thru +0x50
        constexpr size_t ProjectionMatrix = 0x80;    // 4x4 matrix (64 bytes: 0x80-0xBF)
        constexpr size_t ProjMatrixRow0 = 0x80;      // [1/aspect*cot(fov/2), 0, 0, 0]
        constexpr size_t ProjMatrixRow1 = 0x90;      // [0, cot(fov/2), 0, 0]
        constexpr size_t ProjMatrixRow2 = 0xA0;      // [0, 0, f/(f-n), 1]
        constexpr size_t ProjMatrixRow3 = 0xB0;      // [0, 0, -n*f/(f-n), 0]
        
        // ===== VIEW-PROJECTION MATRIX - combined for rendering =====
        // sub_7FF69A790940 writes ViewProj at [r12+0xC0] thru [r12+0x160]
        constexpr size_t ViewProjection = 0xC0;      // Combined VP matrix (64 bytes: 0xC0-0xFF)
        constexpr size_t ViewProjRow0 = 0xC0;
        constexpr size_t ViewProjRow1 = 0xD0;
        constexpr size_t ViewProjRow2 = 0xE0;
        constexpr size_t ViewProjRow3 = 0xF0;
        
        // ===== POSITION - VERIFIED via memory dumps in 3.35 =====
        // 0x100 = PLAYER world position (changes when player walks)
        // Camera position is computed from: player pos + distance + angles
        constexpr size_t Position = 0x100;           // float[3] - player world position (VERIFIED in 3.35)
        constexpr size_t Position_Alt = 0xE0;        // float[3] - alternate/look-at position offset
        constexpr size_t PositionW = 0xEC;           // float - usually 1.0 (W component after xyz)
        constexpr size_t LookAtTarget = 0xE0;        // float[3] - same as Position (player pos)
        constexpr size_t Distance = 0xD8;            // Distance/zoom from player to camera
        
        // ===== ROTATION ANGLES - VERIFIED via runtime probing in 3.35 =====
        // Console log shows valid angles found at 0x1A0/0x1A4: pitch=0.690, yaw=0.780
        // The 0x70/0x74/0x78 offsets overlap with ViewMatrixRow3 and are likely wrong for 3.35
        constexpr size_t Pitch = 0x1A0;              // Rotation X (VERIFIED: valid angles in 3.35)
        constexpr size_t Yaw = 0x1A4;                // Rotation Y (VERIFIED: valid angles in 3.35)
        constexpr size_t Roll = 0x1A8;               // Rotation Z (unverified)
        // Legacy offsets (may be for different camera type or version)
        constexpr size_t Pitch_Legacy = 0x70;
        constexpr size_t Yaw_Legacy = 0x74;
        constexpr size_t Roll_Legacy = 0x78;
        
        // ===== Alternative matrix locations to probe =====
        constexpr size_t ViewMatrix_Alt1 = 0x00;     // Sometimes at start
        constexpr size_t ViewMatrix_Alt2 = 0x10;     // Matches [r12+0x10] pattern
        constexpr size_t ViewMatrix_Alt3 = 0x140;    // After position data
        constexpr size_t ProjMatrix_Alt1 = 0x90;     // One row after 0x80
        constexpr size_t ProjMatrix_Alt2 = 0xA0;     // Two rows after 0x80
        constexpr size_t ProjMatrix_Alt3 = 0x180;    // Further out
        
        // ===== FFXIVClientStructs-based offsets (modern client 7.x, may apply to 3.35) =====
        // Client::Graphics::Scene::Camera (size 0x100):
        //   - 0x80 = LookAtVector (Vector3)
        //   - 0xA0 = ViewMatrix (Matrix4x4) -- IMPORTANT: different from our 0x40!
        //   - 0xE0 = RenderCamera* (pointer to Render::Camera)
        constexpr size_t SceneCameraViewMatrix = 0xA0;   // Scene::Camera.ViewMatrix
        constexpr size_t RenderCameraPtr = 0xE0;         // Scene::Camera.RenderCamera pointer
        constexpr size_t SceneCameraLookAt = 0x80;       // Scene::Camera.LookAtVector
        
        // Client::Graphics::Render::Camera (size 0x290):
        //   - 0x10 = ViewMatrix (Matrix4x4)
        //   - 0x50 = ProjectionMatrix2
        //   - 0x90 = Origin (Vector3)
        //   - 0x1A0 = ProjectionMatrix (Matrix4x4)
        constexpr size_t RenderCameraViewMatrix = 0x10;  // Render::Camera.ViewMatrix
        constexpr size_t RenderCameraProjMatrix = 0x1A0; // Render::Camera.ProjectionMatrix
        constexpr size_t RenderCameraOrigin = 0x90;      // Render::Camera.Origin
        
        // ===== Camera config offsets - VERIFIED via memory dumps in 3.35 =====
        constexpr size_t LookAt = 0xD8;              // float[3] - direction vector
        constexpr size_t FovY = 0x114;               // float - FOV in DEGREES (e.g., 45.0), NOT radians!
        constexpr size_t NearClip = 0x118;           // float  
        constexpr size_t FarClip = 0x11C;            // float
        constexpr size_t AspectRatio = 0x120;        // float (usually 16/9)
    }

    // Camera manager structure offsets
    // VERIFIED via IDA analysis: g_CameraManager at 0x7FF69BA46CB8 (244 references)
    namespace CameraManagerOffsets {
        // From IDA analysis of g_CameraManager:
        // Offset 0x20 accessed 62 times - camera list/array
        // Offset 0x40 accessed 19 times - active camera pointer
        // Offset 0x158 accessed 21 times - camera index
        constexpr size_t CameraList = 0x20;          // Camera array/list (most accessed)
        constexpr size_t ActiveCamera = 0x40;        // Active camera pointer
        constexpr size_t RenderCamera = 0x40;        // Alias for ActiveCamera (legacy name)
        constexpr size_t Camera1 = 0x48;             // Secondary camera (ptr 1)
        constexpr size_t Camera2 = 0x50;             // Tertiary camera (ptr 2)
        constexpr size_t CameraIndex = 0x158;        // Camera index/count (21 accesses)
        
        // Alternative: via RenderManager (0x7FF69BA39E78, 276 references)
        // Offset 0xAD28 accessed 10 times - camera array in RenderManager
        constexpr size_t RenderManagerCameraArray = 0xAD28;
    }
    
    // ===================================================================================
    // RenderManager Camera Data Offsets (from decompiled sub_1403779D0)
    // ===================================================================================
    // Path: qword_1415E9E78 (g_RenderManager) -> +0xAD28 -> CameraData pointer
    // This is where sub_1403779D0 reads View/Projection matrices before uploading to shaders
    // ===================================================================================
    namespace RenderCameraOffsets {
        // From decompiled code (sub_1403779D0, lines 640950-641500):
        //   v20 = *(_QWORD *)(qword_1415E9E78 + 44328);  // CameraData at offset 0xAD28
        //   sub_14017C1F0(v155, (float *)(v20 + 16), (float *)(v20 + 80)); // view * proj
        constexpr size_t CameraDataOffset = 0xAD28;      // 44328 decimal - offset from RenderManager to CameraData ptr
        
        // Within CameraData structure:
        constexpr size_t ViewMatrix = 0x10;              // +16: View matrix (4x4, 64 bytes)
        constexpr size_t ProjectionMatrix = 0x50;        // +80: Projection matrix (4x4, 64 bytes)
        constexpr size_t CameraPosition = 0x90;          // +144: Camera position (v5[36,37,38] in decompile = floats at +144)
        
        // From additional decompiled analysis:
        // v5 = *(float **)(qword_1415E9E78 + 44328);
        // v3 = v5[36]; // offset 144 = 36*4 = X position
        // v4 = v5[37]; // offset 148 = Y position  
        // v5 = v5[38]; // offset 152 = Z position
    }
    
    // ===================================================================================
    // Global RVAs for signature scanning
    // ===================================================================================
    namespace GlobalAddresses {
        // From decompiled code analysis (3.35):
        // These are absolute addresses in the 3.35 binary, need to convert to RVAs
        constexpr uintptr_t RenderManager_Abs = 0x1415E9E78;  // qword_1415E9E78 from decomp
        constexpr uintptr_t DeviceContext_Abs = 0x1415E92E0;  // qword_1415E92E0
        constexpr uintptr_t TlsIndex_Abs = 0x14193AE14;       // TlsIndex for shader state
        
        // Handle IDs for shader constants (from decomp):
        constexpr uintptr_t WorldViewMatrix_Handle = 0x1415B4BFC;   // dword_1415B4BFC
        constexpr uintptr_t WorldViewProjMatrix_Handle = 0x1415B4C00; // dword_1415B4C00
        constexpr uintptr_t GeometryParam_Handle = 0x1415B4C04;     // dword_1415B4C04
    }
    
    // ============================================
    // GameCamera structure (final layout from IDA)
    // This matches what the game writes at Camera + offset
    // ============================================
    #pragma pack(push, 1)
    struct GameCameraLayout {
        uint8_t unknown_0x00[0x40];               // 0x00 - vtable, unknown data
        
        // View Matrix (verified via sub_7FF69B45BF30)
        DirectX::XMFLOAT4 viewRow0;               // 0x40 - Right vector
        DirectX::XMFLOAT4 viewRow1;               // 0x50 - Up vector  
        DirectX::XMFLOAT4 viewRow2;               // 0x60 - Forward vector
        DirectX::XMFLOAT4 viewRow3;               // 0x70 - Translation/angles
        
        // Projection Matrix (at 0x80, verify in-game)
        DirectX::XMFLOAT4 projRow0;               // 0x80 - [1/aspect*cot(fov/2), 0, 0, 0]
        DirectX::XMFLOAT4 projRow1;               // 0x90 - [0, cot(fov/2), 0, 0]
        DirectX::XMFLOAT4 projRow2;               // 0xA0 - [0, 0, f/(f-n), 1]
        DirectX::XMFLOAT4 projRow3;               // 0xB0 - [0, 0, -n*f/(f-n), 0]
        
        // ViewProjection combined (pre-computed)
        DirectX::XMFLOAT4 viewProjRow0;           // 0xC0
        DirectX::XMFLOAT4 viewProjRow1;           // 0xD0
        DirectX::XMFLOAT4 viewProjRow2;           // 0xE0
        DirectX::XMFLOAT4 viewProjRow3;           // 0xF0
        
        // Position data (verified via memory dumps)
        DirectX::XMFLOAT3 cameraPosition;         // 0x100
        float padding_10C;                        // 0x10C - usually 1.0 or 0.0
        
        // Camera parameters (0x110+)
        float unknown_110;                        // 0x110
        float fovY;                               // 0x114 - field of view (radians)
        float nearClip;                           // 0x118 - near clipping plane
        float farClip;                            // 0x11C - far clipping plane
        float aspectRatio;                        // 0x120 - width/height ratio
    };
    
    // Camera Manager structure
    struct CameraManagerLayout {
        uint8_t unknown_0x00[0x20];               // 0x00
        void* cameraList;                         // 0x20 - Camera array (62 accesses)
        uint8_t unknown_0x28[0x18];               // 0x28
        void* activeCamera;                       // 0x40 - Active camera (19 accesses)
        void* camera1;                            // 0x48 - Secondary camera
        void* camera2;                            // 0x50 - Tertiary camera
        uint8_t unknown_0x58[0x100];              // 0x58
        int32_t cameraIndex;                      // 0x158 - Current camera index
    };
    #pragma pack(pop)
    
    // Result of probing for a matrix at a specific offset
    struct MatrixProbeResult {
        DirectX::XMMATRIX matrix;
        size_t offset;
        float score;
        bool looksLikeView;
        bool looksLikeProjection;
        bool isIdentity;
        bool isValid;
        DirectX::XMFLOAT3 extractedCameraPos;
    };

    // ============================================
    // Extracted camera data
    // ============================================
    struct ExtractedCamera {
        DirectX::XMMATRIX view;
        DirectX::XMMATRIX projection;
        DirectX::XMFLOAT3 position;
        DirectX::XMFLOAT3 lookAt;
        float fovY;
        float nearClip;
        float farClip;
        float aspectRatio;

        bool valid = false;
    };

    // ============================================
    // Camera extraction status
    // ============================================
    enum class CameraExtractionStatus {
        NotInitialized,
        ScanningSignatures,
        SignaturesFound,
        SignaturesNotFound,
        Extracting,
        ExtractionFailed,
        Ready
    };

    inline const char* ToString(CameraExtractionStatus status) {
        switch (status) {
            case CameraExtractionStatus::NotInitialized:      return "Not Initialized";
            case CameraExtractionStatus::ScanningSignatures:  return "Scanning Signatures...";
            case CameraExtractionStatus::SignaturesFound:     return "Signatures Found";
            case CameraExtractionStatus::SignaturesNotFound:  return "Signatures Not Found";
            case CameraExtractionStatus::Extracting:          return "Extracting...";
            case CameraExtractionStatus::ExtractionFailed:    return "Extraction Failed";
            case CameraExtractionStatus::Ready:               return "Ready";
            default:                                          return "Unknown";
        }
    }

    // ============================================
    // GameCameraExtractor - extracts camera matrices from game memory
    // ============================================
    class GameCameraExtractor {
    public:
        // Singleton access
        static GameCameraExtractor& GetInstance();

        // Prevent copying
        GameCameraExtractor(const GameCameraExtractor&) = delete;
        GameCameraExtractor& operator=(const GameCameraExtractor&) = delete;

        // Initialization - scans for camera signatures
        bool Initialize();
        void Shutdown();

        // Get current camera data (call each frame)
        std::optional<ExtractedCamera> ExtractCamera();

        // Get cached camera without re-reading memory
        const ExtractedCamera& GetCachedCamera() const { return m_cachedCamera; }

        // Update cached camera (call once per frame)
        bool Update();

        // Status and diagnostics
        CameraExtractionStatus GetStatus() const { return m_status.load(); }
        bool IsReady() const { return m_status.load() == CameraExtractionStatus::Ready; }
        bool IsInitialized() const { return m_initialized.load(); }

        // Get raw addresses for debugging
        uintptr_t GetCameraManagerAddress() const { return m_cameraManagerPtr; }
        uintptr_t GetActiveCameraAddress() const { return m_activeCameraPtr; }
        uintptr_t GetRenderManagerAddress() const { return m_renderManagerPtr; }
        uintptr_t GetSceneCameraManagerAddress() const { return m_sceneCameraManagerPtr; }
        uintptr_t GetGraphicsCameraAddress() const { return m_graphicsCameraPtr; }
        
        // Get player position (lookAt target from game camera at 0xE0)
        // This is the position that changes when the player walks
        DirectX::XMFLOAT3 GetPlayerPosition() const;
        
        // Get player position LIVE - reads directly from camera memory every call
        // Use this for UI that needs real-time updates without depending on Update()
        DirectX::XMFLOAT3 GetPlayerPositionLive() const;
        
        // Get which signature/method was used to find camera
        std::string GetFoundSignatureName() const;

        // Manual offset adjustment (for version differences)
        void SetViewMatrixOffset(size_t offset) { m_viewMatrixOffset = offset; }
        void SetProjectionMatrixOffset(size_t offset) { m_projMatrixOffset = offset; }
        void SetPositionOffset(size_t offset) { m_positionOffset = offset; }

        // Force re-scan of signatures
        void RescanSignatures();

        // Debug: dump camera memory to find correct offsets
        void DumpCameraMemory();
        
        // Debug: compare with previous dump to find changing values
        void CompareCameraMemory();
        
        // Debug: compare matrices between ActiveCamera (0x20) and RenderCamera (0x40)
        void CompareActiveCameraVsRenderCamera();

        // Debug: dump RenderManager object (0x0-0x400) to find render camera matrices
        void DumpRenderManagerMemory();
        
        // Debug: dump matrices at IDA-verified offsets (0x40, 0x80, 0xC0)
        // This is the key verification function per the implementation checklist
        void DumpVerifiedMatrices();
        
        // Probe multiple matrix offsets and return best candidates
        std::vector<MatrixProbeResult> ProbeMatrixOffsets();
        
        // Get the best view and projection matrices from probing
        bool GetBestMatrices(DirectX::XMMATRIX& outView, DirectX::XMMATRIX& outProj);
        
        // Get the pre-computed ViewProjection matrix directly from game memory at 0xC0
        // This is the preferred method as it's perfectly synchronized - no frame timing issues
        bool GetViewProjectionMatrix(DirectX::XMMATRIX& outViewProj);
        
        // ===================================================================================
        // NEW: Get matrices via RenderManager path (from decompiled sub_1403779D0)
        // ===================================================================================
        // This is the actual path the game uses to compute shader matrices:
        //   1. Read qword_1415E9E78 (g_RenderManager) 
        //   2. Dereference at offset 0xAD28 to get CameraData pointer
        //   3. Read View matrix at CameraData+16, Projection at CameraData+80
        // This should give us the EXACT matrices used for rendering.
        // ===================================================================================
        bool GetRenderManagerMatrices(DirectX::XMMATRIX& outView, DirectX::XMMATRIX& outProj);
        bool GetRenderManagerViewProjection(DirectX::XMMATRIX& outViewProj);
        DirectX::XMFLOAT3 GetRenderManagerCameraPosition();
        
        // Debug: Dump RenderManager camera data structure
        void DumpRenderManagerCameraData();
        
        // Enable/disable verbose matrix logging
        void SetVerboseLogging(bool enabled) { m_verboseLogging = enabled; }
        bool IsVerboseLogging() const { return m_verboseLogging; }

    private:
        GameCameraExtractor() = default;
        ~GameCameraExtractor() = default;

        // Signature scanning - multi-strategy approach
        bool ScanForCameraManager();
        bool TryCachedSignatures();
        bool ScanAllSignaturePatterns();
        bool TryStringXrefFallback();
        bool ScanForActiveCamera();
        bool ScanForRenderManager();  // Also scan for g_RenderManager
        bool ScanForSceneCameraManager();  // Scan for Client::Graphics::Scene::CameraManager singleton
        bool ScanForGraphicsCamera();      // Find Client::Graphics::Scene::Camera with valid matrices
        
        // String xref analysis helper
        uintptr_t AnalyzeFunctionForCameraAccess(uintptr_t functionAddress);
        
        // Validation
        bool ValidateCameraManagerPtr(uintptr_t ptr);
        
        // Helper to resolve RIP-relative addresses (for mov rax, [rip+offset] style instructions)
        static uintptr_t ResolveRipRelative(uintptr_t instructionAddress, int ripOffset, size_t instructionLength);

        // Safe memory reading
        template<typename T>
        bool SafeRead(uintptr_t address, T& outValue) const;
        
        bool SafeReadMatrix(uintptr_t address, DirectX::XMMATRIX& outMatrix) const;
        bool SafeReadFloat3(uintptr_t address, DirectX::XMFLOAT3& outVec) const;
        bool SafeReadFloat(uintptr_t address, float& outValue) const;

        // Internal helper: assumes mutex is already held
        void DumpRenderManagerMemoryLocked(uintptr_t renderManagerInstance);

        // State
        std::atomic<bool> m_initialized{ false };
        std::atomic<CameraExtractionStatus> m_status{ CameraExtractionStatus::NotInitialized };
        mutable std::mutex m_mutex;

        // Resolved addresses
        uintptr_t m_cameraManagerSignature = 0;  // Address of the signature instruction
        uintptr_t m_cameraManagerPtr = 0;        // Actual g_CameraManager pointer
        uintptr_t m_activeCameraPtr = 0;         // Active camera pointer (Game layer - has player position)
        uintptr_t m_renderManagerPtr = 0;        // g_RenderManager pointer (may hold matrices)
        uintptr_t m_sceneCameraManagerPtr = 0;   // Client::Graphics::Scene::CameraManager pointer
        uintptr_t m_graphicsCameraPtr = 0;       // Client::Graphics::Scene::Camera pointer (HAS MATRICES)
        
        // Cached player position for menu bar display
        DirectX::XMFLOAT3 m_cachedPlayerPosition = {0.0f, 0.0f, 0.0f};

        // Configurable offsets (can be adjusted if game version changes)
        size_t m_viewMatrixOffset = CameraOffsets::ViewMatrix;
        size_t m_projMatrixOffset = CameraOffsets::ProjectionMatrix;
        size_t m_positionOffset = CameraOffsets::Position;
        size_t m_fovOffset = CameraOffsets::FovY;
        size_t m_nearClipOffset = CameraOffsets::NearClip;
        size_t m_farClipOffset = CameraOffsets::FarClip;

        // Cached camera data
        ExtractedCamera m_cachedCamera;
        
        // Which signature/method found the camera
        std::string m_foundSignatureName;
        
        // Previous memory dump for comparison
        std::vector<float> m_previousDump;
        uintptr_t m_previousDumpCamera = 0;
        
        // Verbose logging mode - enabled by default for matrix probing debugging
        bool m_verboseLogging = true;

        // One-shot dump for RenderManager to avoid spamming logs each frame
        bool m_renderManagerDumped = false;
        
        // Best matrices from probing
        DirectX::XMMATRIX m_bestViewMatrix = DirectX::XMMatrixIdentity();
        DirectX::XMMATRIX m_bestProjMatrix = DirectX::XMMatrixIdentity();
        bool m_hasValidMatrices = false;
        size_t m_foundViewOffset = 0;
        size_t m_foundProjOffset = 0;
        
        // Score a matrix and determine its type
        MatrixProbeResult ScoreMatrixAtOffset(uintptr_t baseAddr, size_t offset, 
                                               const DirectX::XMFLOAT3& knownCameraPos);
    };

} // namespace SapphireHook::DebugVisuals
