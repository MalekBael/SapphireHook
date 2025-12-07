#include "MatrixCaptureHooks.h"
#include "../Logger/Logger.h"
#include "../Analysis/PatternScanner.h"
#include <MinHook.h>
#include <Windows.h>
#include <Psapi.h>
#include <format>
#include <chrono>

#pragma comment(lib, "psapi.lib")

namespace SapphireHook::MatrixHooks {

    // ============================================
    // Original function typedefs
    // ============================================
    // Exact signatures from IDA Pro analysis (December 2025):
    //
    // ViewMatrixWriter:       __int64 __fastcall(__int64, __int64)
    //                         rcx -> r12 (this), rdx -> r13 (param2)
    //
    // ProjectionMatrixWriter: __int64 __fastcall(_DWORD *)
    //                         rcx -> rsi (this) - ONLY 1 PARAM!
    //
    // ViewProjMatrixWriter:   char __fastcall(__int64, char, __int64, bool*, uint*, _QWORD*, _DWORD*, _DWORD*)
    //                         8 PARAMS! rcx=this, dl=char, r8=ptr, r9=bool*, stack=rest
    // ============================================
    
    // ViewMatrixWriter: 2 params (rcx, rdx)
    typedef __int64(__fastcall* ViewMatrixWriter_t)(__int64 thisPtr, __int64 param2);
    
    // ProjectionMatrixWriter: 1 param (rcx only)
    typedef __int64(__fastcall* ProjectionMatrixWriter_t)(__int32* thisPtr);
    
    // ViewProjMatrixWriter: 8 params - complex signature
    typedef char(__fastcall* ViewProjMatrixWriter_t)(
        __int64 thisPtr,      // rcx
        char param2,          // dl (second param as char/byte)
        __int64 param3,       // r8
        bool* param4,         // r9
        unsigned int* param5, // stack
        void* param6,         // stack
        __int32* param7,      // stack
        __int32* param8       // stack
    );

    // Original function pointers (static for hook callbacks)
    static ViewMatrixWriter_t s_originalViewMatrixWriter = nullptr;
    static ProjectionMatrixWriter_t s_originalProjectionMatrixWriter = nullptr;
    static ViewProjMatrixWriter_t s_originalViewProjMatrixWriter = nullptr;

    // ============================================
    // Hook callback functions
    // ============================================

    __int64 __fastcall HookedViewMatrixWriter(__int64 thisPtr, __int64 param2) {
        static std::atomic<uint64_t> callCount = 0;
        uint64_t count = ++callCount;
        
        // Log every 100th call to avoid spam
        if (count == 1 || count % 100 == 0) {
            LogInfo(std::format("MatrixCaptureHooks: ViewMatrixWriter called #{}, thisPtr=0x{:X}, param2=0x{:X}", 
                count, static_cast<uint64_t>(thisPtr), static_cast<uint64_t>(param2)));
        }
        
        __int64 result = 0;
        // Call the original function first to let it write the matrix
        if (s_originalViewMatrixWriter) {
            result = s_originalViewMatrixWriter(thisPtr, param2);
        }

        // Now capture the matrix that was just written - pass both pointers for analysis
        MatrixCaptureHooks::GetInstance().OnViewMatrixWritten(
            reinterpret_cast<void*>(thisPtr), 
            reinterpret_cast<void*>(param2));
        return result;
    }

    __int64 __fastcall HookedProjectionMatrixWriter(__int32* thisPtr) {
        static std::atomic<uint64_t> callCount = 0;
        uint64_t count = ++callCount;
        
        // Log every 100th call to avoid spam
        if (count == 1 || count % 100 == 0) {
            LogInfo(std::format("MatrixCaptureHooks: ProjectionMatrixWriter called #{}, thisPtr=0x{:X}", 
                count, reinterpret_cast<uintptr_t>(thisPtr)));
        }
        
        __int64 result = 0;
        // Call the original function first
        if (s_originalProjectionMatrixWriter) {
            result = s_originalProjectionMatrixWriter(thisPtr);
        }

        // Capture the projection matrix
        MatrixCaptureHooks::GetInstance().OnProjectionMatrixWritten(reinterpret_cast<void*>(thisPtr));
        return result;
    }

    char __fastcall HookedViewProjMatrixWriter(
        __int64 thisPtr,
        char param2,
        __int64 param3,
        bool* param4,
        unsigned int* param5,
        void* param6,
        __int32* param7,
        __int32* param8
    ) {
        // Note: Logging removed to prevent spam - this is called 60+ times per second
        
        char result = 0;
        // Call the original function first
        if (s_originalViewProjMatrixWriter) {
            result = s_originalViewProjMatrixWriter(thisPtr, param2, param3, param4, param5, param6, param7, param8);
        }

        // Capture the view-projection matrix
        MatrixCaptureHooks::GetInstance().OnViewProjMatrixWritten(reinterpret_cast<void*>(thisPtr));
        return result;
    }

    // ============================================
    // Singleton accessor
    // ============================================
    MatrixCaptureHooks& MatrixCaptureHooks::GetInstance() {
        static MatrixCaptureHooks instance;
        return instance;
    }

    // ============================================
    // Initialization
    // ============================================
    bool MatrixCaptureHooks::Initialize() {
        if (m_initialized.load()) {
            return true;
        }

        std::lock_guard<std::mutex> lock(m_mutex);

        LogInfo("MatrixCaptureHooks: Initializing matrix capture hooks...");

        // Get module base address
        HMODULE hModule = GetModuleHandleW(nullptr);
        if (!hModule) {
            LogError("MatrixCaptureHooks: Failed to get module handle");
            return false;
        }

        MODULEINFO moduleInfo{};
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) {
            LogError("MatrixCaptureHooks: Failed to get module information");
            return false;
        }

        uintptr_t moduleBase = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
        LogInfo(std::format("MatrixCaptureHooks: Module base: 0x{:X}", moduleBase));

        // Calculate absolute addresses from RVAs
        m_viewMatrixWriterAddr = moduleBase + MatrixFunctionRVAs::ViewMatrixWriter;
        m_projMatrixWriterAddr = moduleBase + MatrixFunctionRVAs::ProjectionMatrixWriter;
        m_viewProjMatrixWriterAddr = moduleBase + MatrixFunctionRVAs::ViewProjMatrixWriter;

        LogInfo(std::format("MatrixCaptureHooks: ViewMatrixWriter at 0x{:X}", m_viewMatrixWriterAddr));
        LogInfo(std::format("MatrixCaptureHooks: ProjectionMatrixWriter at 0x{:X}", m_projMatrixWriterAddr));
        LogInfo(std::format("MatrixCaptureHooks: ViewProjMatrixWriter at 0x{:X}", m_viewProjMatrixWriterAddr));

        // Install hooks
        bool allSuccess = true;
        
        if (!InstallViewMatrixHook()) {
            LogWarning("MatrixCaptureHooks: Failed to install ViewMatrixWriter hook");
            allSuccess = false;
        }

        if (!InstallProjectionMatrixHook()) {
            LogWarning("MatrixCaptureHooks: Failed to install ProjectionMatrixWriter hook");
            allSuccess = false;
        }

        if (!InstallViewProjMatrixHook()) {
            LogWarning("MatrixCaptureHooks: Failed to install ViewProjMatrixWriter hook");
            allSuccess = false;
        }

        if (allSuccess) {
            LogInfo("MatrixCaptureHooks: All three matrix hooks installed successfully!");
        } else {
            LogWarning("MatrixCaptureHooks: Some hooks failed to install, partial functionality available");
        }

        m_initialized.store(true);
        return true;
    }

    void MatrixCaptureHooks::Shutdown() {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (!m_initialized.load()) {
            return;
        }

        LogInfo("MatrixCaptureHooks: Shutting down...");

        // Disable and remove hooks
        if (m_viewMatrixWriterAddr != 0) {
            MH_DisableHook(reinterpret_cast<LPVOID>(m_viewMatrixWriterAddr));
            MH_RemoveHook(reinterpret_cast<LPVOID>(m_viewMatrixWriterAddr));
        }

        if (m_projMatrixWriterAddr != 0) {
            MH_DisableHook(reinterpret_cast<LPVOID>(m_projMatrixWriterAddr));
            MH_RemoveHook(reinterpret_cast<LPVOID>(m_projMatrixWriterAddr));
        }

        if (m_viewProjMatrixWriterAddr != 0) {
            MH_DisableHook(reinterpret_cast<LPVOID>(m_viewProjMatrixWriterAddr));
            MH_RemoveHook(reinterpret_cast<LPVOID>(m_viewProjMatrixWriterAddr));
        }

        // Reset state
        s_originalViewMatrixWriter = nullptr;
        s_originalProjectionMatrixWriter = nullptr;
        s_originalViewProjMatrixWriter = nullptr;

        m_viewMatrixWriterAddr = 0;
        m_projMatrixWriterAddr = 0;
        m_viewProjMatrixWriterAddr = 0;

        m_initialized.store(false);

        LogInfo("MatrixCaptureHooks: Shutdown complete");
    }

    // ============================================
    // Hook installation
    // ============================================
    bool MatrixCaptureHooks::InstallViewMatrixHook() {
        if (m_viewMatrixWriterAddr == 0) {
            return false;
        }

        MH_STATUS status = MH_CreateHook(
            reinterpret_cast<LPVOID>(m_viewMatrixWriterAddr),
            reinterpret_cast<LPVOID>(&HookedViewMatrixWriter),
            reinterpret_cast<LPVOID*>(&s_originalViewMatrixWriter)
        );

        if (status != MH_OK) {
            LogError(std::format("MatrixCaptureHooks: MH_CreateHook failed for ViewMatrixWriter: {}", 
                MH_StatusToString(status)));
            return false;
        }

        status = MH_EnableHook(reinterpret_cast<LPVOID>(m_viewMatrixWriterAddr));
        if (status != MH_OK) {
            LogError(std::format("MatrixCaptureHooks: MH_EnableHook failed for ViewMatrixWriter: {}", 
                MH_StatusToString(status)));
            return false;
        }

        m_originalViewMatrixWriter = s_originalViewMatrixWriter;
        LogInfo("MatrixCaptureHooks: ViewMatrixWriter hook installed");
        return true;
    }

    bool MatrixCaptureHooks::InstallProjectionMatrixHook() {
        if (m_projMatrixWriterAddr == 0) {
            return false;
        }

        MH_STATUS status = MH_CreateHook(
            reinterpret_cast<LPVOID>(m_projMatrixWriterAddr),
            reinterpret_cast<LPVOID>(&HookedProjectionMatrixWriter),
            reinterpret_cast<LPVOID*>(&s_originalProjectionMatrixWriter)
        );

        if (status != MH_OK) {
            LogError(std::format("MatrixCaptureHooks: MH_CreateHook failed for ProjectionMatrixWriter: {}", 
                MH_StatusToString(status)));
            return false;
        }

        status = MH_EnableHook(reinterpret_cast<LPVOID>(m_projMatrixWriterAddr));
        if (status != MH_OK) {
            LogError(std::format("MatrixCaptureHooks: MH_EnableHook failed for ProjectionMatrixWriter: {}", 
                MH_StatusToString(status)));
            return false;
        }

        m_originalProjectionMatrixWriter = s_originalProjectionMatrixWriter;
        LogInfo("MatrixCaptureHooks: ProjectionMatrixWriter hook installed");
        return true;
    }

    bool MatrixCaptureHooks::InstallViewProjMatrixHook() {
        if (m_viewProjMatrixWriterAddr == 0) {
            return false;
        }

        MH_STATUS status = MH_CreateHook(
            reinterpret_cast<LPVOID>(m_viewProjMatrixWriterAddr),
            reinterpret_cast<LPVOID>(&HookedViewProjMatrixWriter),
            reinterpret_cast<LPVOID*>(&s_originalViewProjMatrixWriter)
        );

        if (status != MH_OK) {
            LogError(std::format("MatrixCaptureHooks: MH_CreateHook failed for ViewProjMatrixWriter: {}", 
                MH_StatusToString(status)));
            return false;
        }

        status = MH_EnableHook(reinterpret_cast<LPVOID>(m_viewProjMatrixWriterAddr));
        if (status != MH_OK) {
            LogError(std::format("MatrixCaptureHooks: MH_EnableHook failed for ViewProjMatrixWriter: {}", 
                MH_StatusToString(status)));
            return false;
        }

        m_originalViewProjMatrixWriter = s_originalViewProjMatrixWriter;
        LogInfo("MatrixCaptureHooks: ViewProjMatrixWriter hook installed");
        return true;
    }

    // ============================================
    // Matrix capture callbacks
    // ============================================
    void MatrixCaptureHooks::OnViewMatrixWritten(void* destBuffer, void* srcCamera) {
        if (!destBuffer) return;

        uintptr_t destAddr = reinterpret_cast<uintptr_t>(destBuffer);
        uintptr_t srcAddr = srcCamera ? reinterpret_cast<uintptr_t>(srcCamera) : 0;
        
        // Debug: dump both buffers on first call
        static bool dumpedOnce = false;
        if (!dumpedOnce && srcCamera) {
            dumpedOnce = true;
            LogInfo("MatrixCaptureHooks: === ViewMatrixWriter DUMP (AFTER function wrote) ===");
            LogInfo(std::format("  destBuffer (thisPtr) = 0x{:X}", destAddr));
            LogInfo(std::format("  srcCamera (param2)   = 0x{:X}", srcAddr));
            
            // Dump destination buffer (where matrix was written TO)
            LogInfo("  --- Destination Buffer (thisPtr) ---");
            for (size_t offset = 0; offset < 0x100; offset += 0x40) {
                DirectX::XMMATRIX mat;
                if (SafeReadMatrix(destAddr + offset, mat)) {
                    DirectX::XMFLOAT4X4 m;
                    DirectX::XMStoreFloat4x4(&m, mat);
                    LogInfo(std::format("    +0x{:03X}: [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", offset, m._11, m._12, m._13, m._14));
                    LogInfo(std::format("            [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m._21, m._22, m._23, m._24));
                    LogInfo(std::format("            [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m._31, m._32, m._33, m._34));
                    LogInfo(std::format("            [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m._41, m._42, m._43, m._44));
                }
            }
            
            // Dump source camera (where matrix was read FROM)
            if (srcAddr) {
                LogInfo("  --- Source Camera (param2) ---");
                for (size_t offset = 0; offset < 0x200; offset += 0x40) {
                    DirectX::XMMATRIX mat;
                    if (SafeReadMatrix(srcAddr + offset, mat)) {
                        DirectX::XMFLOAT4X4 m;
                        DirectX::XMStoreFloat4x4(&m, mat);
                        LogInfo(std::format("    +0x{:03X}: [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", offset, m._11, m._12, m._13, m._14));
                        LogInfo(std::format("            [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m._21, m._22, m._23, m._24));
                        LogInfo(std::format("            [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m._31, m._32, m._33, m._34));
                        LogInfo(std::format("            [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m._41, m._42, m._43, m._44));
                    }
                }
            }
            LogInfo("MatrixCaptureHooks: === End ViewMatrixWriter DUMP ===");
        }
        
        // Try to find valid View matrix in destination buffer (where function wrote)
        static constexpr size_t kViewOffsets[] = { 0x00, 0x40, 0x80, 0xC0 };
        
        for (size_t offset : kViewOffsets) {
            DirectX::XMMATRIX viewMatrix;
            if (SafeReadMatrix(destAddr + offset, viewMatrix)) {
                if (IsValidMatrix(viewMatrix)) {
                    DirectX::XMFLOAT4X4 m;
                    DirectX::XMStoreFloat4x4(&m, viewMatrix);
                    
                    // View matrix: orthonormal basis in upper-left 3x3
                    float len0 = std::sqrt(m._11*m._11 + m._12*m._12 + m._13*m._13);
                    float len1 = std::sqrt(m._21*m._21 + m._22*m._22 + m._23*m._23);
                    float len2 = std::sqrt(m._31*m._31 + m._32*m._32 + m._33*m._33);
                    
                    bool looksLikeView = (std::abs(len0 - 1.0f) < 0.1f) && 
                                         (std::abs(len1 - 1.0f) < 0.1f) && 
                                         (std::abs(len2 - 1.0f) < 0.1f);
                    
                    if (looksLikeView) {
                        std::lock_guard<std::mutex> lock(m_mutex);
                        m_capturedMatrices.viewMatrix = viewMatrix;
                        m_capturedMatrices.cameraObjectPtr = srcAddr ? srcAddr : destAddr;
                        m_capturedMatrices.viewValid = true;
                        m_capturedMatrices.viewFromHook = true;
                        m_capturedMatrices.frameNumber = m_currentFrame.load();
                        m_capturedMatrices.captureTimestamp = 
                            std::chrono::high_resolution_clock::now().time_since_epoch().count();
                        
                        m_viewCaptureCount++;

                        if (m_verboseLogging && (m_viewCaptureCount % 60 == 1)) {
                            LogInfo(std::format("MatrixCaptureHooks: View Matrix captured at dest+0x{:X}", offset));
                        }
                        return;
                    }
                }
            }
        }
    }

    void MatrixCaptureHooks::OnProjectionMatrixWritten(void* cameraObject) {
        if (!cameraObject) return;

        uintptr_t objAddr = reinterpret_cast<uintptr_t>(cameraObject);
        
        // Debug: dump raw data from this object on first call
        static bool dumpedOnce = false;
        if (!dumpedOnce) {
            dumpedOnce = true;
            LogInfo(std::format("MatrixCaptureHooks: DUMPING RAW DATA from ProjectionMatrixWriter thisPtr=0x{:X}", objAddr));
            
            // Dump first 512 bytes of the object
            for (size_t offset = 0; offset < 0x200; offset += 0x40) {
                DirectX::XMMATRIX mat;
                if (SafeReadMatrix(objAddr + offset, mat)) {
                    DirectX::XMFLOAT4X4 m;
                    DirectX::XMStoreFloat4x4(&m, mat);
                    LogInfo(std::format("  Offset 0x{:03X}: [{:.4f} {:.4f} {:.4f} {:.4f}]", offset, m._11, m._12, m._13, m._14));
                    LogInfo(std::format("                [{:.4f} {:.4f} {:.4f} {:.4f}]", m._21, m._22, m._23, m._24));
                    LogInfo(std::format("                [{:.4f} {:.4f} {:.4f} {:.4f}]", m._31, m._32, m._33, m._34));
                    LogInfo(std::format("                [{:.4f} {:.4f} {:.4f} {:.4f}]", m._41, m._42, m._43, m._44));
                }
            }
        }
        
        // IDA shows ProjectionMatrixWriter writes to: 0x10-0x30 (r14), 0x140-0x170 (rbx)
        // Try multiple offsets
        static constexpr size_t kProjOffsets[] = { 
            0x80,   // Traditional Projection offset
            0x140,  // From IDA analysis
            0x1A0,  // Render::Camera.ProjectionMatrix (FFXIVClientStructs)
            0x50,   // ProjectionMatrix2 (FFXIVClientStructs)
        };
        
        for (size_t offset : kProjOffsets) {
            DirectX::XMMATRIX projMatrix;
            if (SafeReadMatrix(objAddr + offset, projMatrix)) {
                if (IsValidMatrix(projMatrix)) {
                    DirectX::XMFLOAT4X4 m;
                    DirectX::XMStoreFloat4x4(&m, projMatrix);
                    
                    // Projection matrix typically has: m[0][0] != 0, m[1][1] != 0, m[2][3] ~= 1 or -1
                    // and m[3][3] ~= 0 for perspective projection
                    bool looksLikeProj = (std::abs(m._11) > 0.1f) && 
                                         (std::abs(m._22) > 0.1f) &&
                                         (std::abs(std::abs(m._34) - 1.0f) < 0.1f) &&
                                         (std::abs(m._44) < 0.1f);
                    
                    if (looksLikeProj) {
                        std::lock_guard<std::mutex> lock(m_mutex);
                        m_capturedMatrices.projectionMatrix = projMatrix;
                        m_capturedMatrices.cameraObjectPtr = objAddr;
                        m_capturedMatrices.projectionValid = true;
                        m_capturedMatrices.projFromHook = true;
                        m_capturedMatrices.frameNumber = m_currentFrame.load();
                        m_capturedMatrices.captureTimestamp = 
                            std::chrono::high_resolution_clock::now().time_since_epoch().count();
                        
                        m_projCaptureCount++;

                        if (m_verboseLogging && (m_projCaptureCount % 60 == 1)) {
                            LogInfo(std::format("MatrixCaptureHooks: Found Projection Matrix at 0x{:X}+0x{:X}", objAddr, offset));
                        }
                        return; // Found valid projection matrix
                    }
                }
            }
        }
    }

    void MatrixCaptureHooks::OnViewProjMatrixWritten(void* cameraObject) {
        if (!cameraObject) return;

        uintptr_t objAddr = reinterpret_cast<uintptr_t>(cameraObject);
        
        // ViewProj is typically at 0xC0 or computed from View * Proj
        static constexpr size_t kViewProjOffsets[] = { 
            0xC0,   // Traditional ViewProj offset
            0x100,  // Alternative
            0x140,  // Alternative (from IDA)
        };
        
        for (size_t offset : kViewProjOffsets) {
            DirectX::XMMATRIX viewProjMatrix;
            if (SafeReadMatrix(objAddr + offset, viewProjMatrix)) {
                if (IsValidMatrix(viewProjMatrix)) {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_capturedMatrices.viewProjMatrix = viewProjMatrix;
                    m_capturedMatrices.cameraObjectPtr = objAddr;
                    m_capturedMatrices.viewProjValid = true;
                    m_capturedMatrices.viewProjFromHook = true;
                    m_capturedMatrices.frameNumber = m_currentFrame.load();
                    m_capturedMatrices.captureTimestamp = 
                        std::chrono::high_resolution_clock::now().time_since_epoch().count();
                    
                    m_viewProjCaptureCount++;

                    if (m_verboseLogging && (m_viewProjCaptureCount % 60 == 1)) {
                        LogInfo(std::format("MatrixCaptureHooks: Found ViewProj Matrix at 0x{:X}+0x{:X}", objAddr, offset));
                    }
                    return; // Found valid matrix
                }
            }
        }
    }

    // ============================================
    // Matrix access (thread-safe)
    // ============================================
    CapturedMatrices MatrixCaptureHooks::GetCapturedMatrices() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_capturedMatrices;
    }

    DirectX::XMMATRIX MatrixCaptureHooks::GetViewMatrix() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_capturedMatrices.viewValid) {
            return m_capturedMatrices.viewMatrix;
        }
        return DirectX::XMMatrixIdentity();
    }

    DirectX::XMMATRIX MatrixCaptureHooks::GetProjectionMatrix() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_capturedMatrices.projectionValid) {
            return m_capturedMatrices.projectionMatrix;
        }
        return DirectX::XMMatrixIdentity();
    }

    DirectX::XMMATRIX MatrixCaptureHooks::GetViewProjMatrix() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_capturedMatrices.viewProjValid) {
            return m_capturedMatrices.viewProjMatrix;
        }
        return DirectX::XMMatrixIdentity();
    }

    DirectX::XMFLOAT3 MatrixCaptureHooks::GetCameraPosition() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_capturedMatrices.cameraPosition;
    }

    bool MatrixCaptureHooks::HasValidViewMatrix() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_capturedMatrices.viewValid;
    }

    bool MatrixCaptureHooks::HasValidProjectionMatrix() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_capturedMatrices.projectionValid;
    }

    bool MatrixCaptureHooks::HasValidViewProjMatrix() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_capturedMatrices.viewProjValid;
    }

    bool MatrixCaptureHooks::HasAnyValidMatrix() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_capturedMatrices.viewValid || 
               m_capturedMatrices.projectionValid || 
               m_capturedMatrices.viewProjValid;
    }

    // ============================================
    // Matrix validation
    // ============================================
    bool MatrixCaptureHooks::IsValidMatrix(const DirectX::XMMATRIX& matrix) {
        // Check for NaN or Infinity
        DirectX::XMFLOAT4X4 m;
        DirectX::XMStoreFloat4x4(&m, matrix);

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                float val = m.m[i][j];
                if (std::isnan(val) || std::isinf(val)) {
                    return false;
                }
                // Check for unreasonably large values (likely garbage)
                if (std::abs(val) > 1e10f) {
                    return false;
                }
            }
        }

        // Check that it's not all zeros
        float sum = 0.0f;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                sum += std::abs(m.m[i][j]);
            }
        }
        if (sum < 0.0001f) {
            return false;  // All zeros or near-zero
        }

        return true;
    }

    bool MatrixCaptureHooks::IsValidFloat3(const DirectX::XMFLOAT3& vec) {
        if (std::isnan(vec.x) || std::isnan(vec.y) || std::isnan(vec.z)) {
            return false;
        }
        if (std::isinf(vec.x) || std::isinf(vec.y) || std::isinf(vec.z)) {
            return false;
        }
        // Check for unreasonably large values
        if (std::abs(vec.x) > 1e6f || std::abs(vec.y) > 1e6f || std::abs(vec.z) > 1e6f) {
            return false;
        }
        return true;
    }

    // ============================================
    // Safe memory reading
    // ============================================
    bool MatrixCaptureHooks::SafeReadMatrix(uintptr_t address, DirectX::XMMATRIX& outMatrix) const {
        __try {
            const float* data = reinterpret_cast<const float*>(address);
            outMatrix = DirectX::XMMATRIX(
                data[0], data[1], data[2], data[3],
                data[4], data[5], data[6], data[7],
                data[8], data[9], data[10], data[11],
                data[12], data[13], data[14], data[15]
            );
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    bool MatrixCaptureHooks::SafeReadFloat3(uintptr_t address, DirectX::XMFLOAT3& outVec) const {
        __try {
            const float* data = reinterpret_cast<const float*>(address);
            outVec.x = data[0];
            outVec.y = data[1];
            outVec.z = data[2];
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

} // namespace SapphireHook::MatrixHooks
