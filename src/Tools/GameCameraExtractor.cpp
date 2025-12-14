// Ensure WinSock2 is included before Windows.h
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <Psapi.h>
#pragma comment(lib, "psapi.lib")

#include "GameCameraExtractor.h"
#include "../Analysis/PatternScanner.h"
#include "../Hooking/MatrixCaptureHooks.h"  // Matrix capture hooks for real-time matrix capture
// Note: SignatureScanner.h has no implementation - using PatternScanner directly
#// CHANGE NOTE (2025-12-15): Prefer our SafeMemory validation helpers over `IsBadReadPtr`.
#// `IsBadReadPtr` is deprecated/unreliable; `IsValidMemoryAddress` gives us a VirtualQuery-based check.
#include "../Core/SafeMemory.h"
#include "../Logger/Logger.h"

#include <cstring>
#include <format>
#include <array>
#include <cmath>
#include <vector>
#include <limits>

namespace SapphireHook::DebugVisuals {

    // ============================================
    // Signature definitions with metadata
    // ============================================
    struct SignatureInfo {
        const char* pattern;
        const char* name;
        int ripOffset;          // Offset to RIP-relative displacement within pattern
        int instructionLength;  // Total instruction length for RIP calculation
    };

    // ============================================
    // VERIFIED SIGNATURES from IDA Pro 9.1 analysis (December 2025)
    // These were confirmed working for FFXIV 3.35
    // ============================================
    static constexpr std::array<SignatureInfo, 8> CAMERA_SIGNATURES = {{
        // ===== PRIMARY - VERIFIED WORKING =====
        // g_CameraManager - VERIFIED at 0x7FF69BA46CB8 (from ida_camera_struct_layout.py)
        // Found at 0x7FF69A5DBB3F: mov r9, cs:qword_7FF69BA46CB8
        {"4C 8B 0D ?? ?? ?? ?? 48 69 C0 E8 03 00 00", "g_CameraManager_Verified", 3, 7},
        
        // g_RenderManager - VERIFIED at 0x7FF69BA39E78 (from ida_camera_struct_layout.py)
        // Found at 0x7FF69A465362: mov rcx, cs:qword_7FF69BA39E78
        {"48 8B 0D ?? ?? ?? ?? 48 85 C9 74 05 E8", "g_RenderManager_Verified", 3, 7},
        
        // ===== SECONDARY - from alternative pattern search =====
        // CameraManager with offset check (from ida_analyze_camera_matrix.py)
        {"48 8B 05 ?? ?? ?? ?? 83 78", "g_CameraManager_Alt", 3, 7},
        
        // Singleton with vtable access pattern
        {"48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 41", "CameraManager_Singleton", 3, 7},
        
        // ===== LEGACY - kept for compatibility =====
        // g_CameraManager - original from data-sig-old.json (may not work in 3.35)
        {"48 8B 05 ?? ?? ?? ?? 83 78 50 00 75 22", "g_CameraManager_Legacy", 3, 7},
        
        // g_ControlSystem_CameraManager - original from data-sig-old.json
        {"48 8D 0D ?? ?? ?? ?? F3 0F 10 4B ??", "g_ControlSystem_CameraManager", 3, 7},
        
        // PrepareRenderCamera pattern
        {"40 53 48 83 EC 20 48 8B 05 ?? ?? ?? ?? 48 8B D9 48 8B 40 58", "PrepareRenderCamera", 9, 7},
        
        // Camera update loop pattern
        {"48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 48 ?? E8", "CameraUpdateLoop", 3, 7},
    }};

    // Camera-related strings to search for if signatures fail
    static constexpr std::array<const char*, 8> CAMERA_XREF_STRINGS = {{
        "CameraManager",
        "Camera",
        "g_Camera",
        "RenderCamera",
        "ViewMatrix",
        "ProjectionMatrix",
        "Client::Graphics::Scene::Camera",
        "PrepareRenderCamera",
    }};

    // ============================================
    // Singleton accessor
    // ============================================
    GameCameraExtractor& GameCameraExtractor::GetInstance() {
        static GameCameraExtractor instance;
        return instance;
    }

    // ============================================
    // Initialization
    // ============================================
    bool GameCameraExtractor::Initialize() {
        if (m_initialized.load()) {
            return true;
        }

        std::lock_guard<std::mutex> lock(m_mutex);
        
        m_status.store(CameraExtractionStatus::ScanningSignatures);
        LogInfo("GameCameraExtractor: Scanning for camera signatures...");

        // Try SignatureScanner first (has caching)
        if (TryCachedSignatures()) {
            m_status.store(CameraExtractionStatus::SignaturesFound);
            LogInfo(std::format("GameCameraExtractor: Camera manager found via cached signature at 0x{:X}", m_cameraManagerPtr));
            
            // Also try to find RenderManager (may hold ViewProjection matrices)
            ScanForRenderManager();
            ScanForSceneCameraManager();

            // One-shot dump of RenderManager object for live layout discovery
            if (!m_renderManagerDumped && m_renderManagerPtr != 0) {
                uintptr_t renderManagerInstance = 0;
                if (SafeRead(m_renderManagerPtr, renderManagerInstance) && renderManagerInstance != 0) {
                    DumpRenderManagerMemoryLocked(renderManagerInstance);
                    m_renderManagerDumped = true;
                }
            }
            
            // Initialize MatrixCaptureHooks for real-time matrix capture
            if (MatrixHooks::MatrixCaptureHooks::GetInstance().Initialize()) {
                LogInfo("GameCameraExtractor: MatrixCaptureHooks initialized successfully");
            } else {
                LogWarning("GameCameraExtractor: MatrixCaptureHooks initialization failed, using fallback methods");
            }
            
            m_initialized.store(true);
            return true;
        }

        // Try all known signature patterns
        if (ScanAllSignaturePatterns()) {
            m_status.store(CameraExtractionStatus::SignaturesFound);
            LogInfo(std::format("GameCameraExtractor: Camera manager found via pattern scan at 0x{:X}", m_cameraManagerPtr));
            
            // Also try to find RenderManager
            ScanForRenderManager();
            ScanForSceneCameraManager();
            
            // Initialize MatrixCaptureHooks for real-time matrix capture
            if (MatrixHooks::MatrixCaptureHooks::GetInstance().Initialize()) {
                LogInfo("GameCameraExtractor: MatrixCaptureHooks initialized successfully");
            }
            
            m_initialized.store(true);
            return true;
        }

        // Fallback: Try string xref analysis
        if (TryStringXrefFallback()) {
            m_status.store(CameraExtractionStatus::SignaturesFound);
            LogInfo(std::format("GameCameraExtractor: Camera manager found via string xref at 0x{:X}", m_cameraManagerPtr));
            
            // Also try to find RenderManager
            ScanForRenderManager();
            ScanForSceneCameraManager();
            
            m_initialized.store(true);
            return true;
        }

        m_status.store(CameraExtractionStatus::SignaturesNotFound);
        LogWarning("GameCameraExtractor: Could not find camera manager via any method");
        LogWarning("GameCameraExtractor: Debug visuals will use fallback camera mode");
        
        m_initialized.store(true);
        return true; // Still return true - we can work in manual mode
    }

    void GameCameraExtractor::Shutdown() {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Shutdown MatrixCaptureHooks first
        MatrixHooks::MatrixCaptureHooks::GetInstance().Shutdown();
        
        m_initialized.store(false);
        m_status.store(CameraExtractionStatus::NotInitialized);
        m_cameraManagerSignature = 0;
        m_cameraManagerPtr = 0;
        m_activeCameraPtr = 0;
        m_renderManagerPtr = 0;
        m_sceneCameraManagerPtr = 0;
        m_graphicsCameraPtr = 0;
        m_cachedPlayerPosition = {0.0f, 0.0f, 0.0f};
        m_cachedCamera = ExtractedCamera{};
        m_foundSignatureName.clear();
        m_renderManagerDumped = false;

        LogInfo("GameCameraExtractor: Shutdown complete");
    }
    
    // ============================================
    // Scan for RenderManager (may hold ViewProjection matrix)
    // ============================================
    bool GameCameraExtractor::ScanForRenderManager() {
        // Get module base for direct RVA access
        HMODULE hModule = GetModuleHandleW(nullptr);
        uintptr_t moduleBase = reinterpret_cast<uintptr_t>(hModule);
        
        // ===== APPROACH 1: Use verified RVA from decompiled analysis (December 2025) =====
        // From decomp.c: qword_1415E9E78 = Graphics/Render Context
        // RVA = 0x1415E9E78 - 0x140000000 = 0x15E9E78
        constexpr uintptr_t VERIFIED_RENDER_MANAGER_RVA = 0x15E9E78;  // qword_1415E9E78
        
        uintptr_t directAddr = moduleBase + VERIFIED_RENDER_MANAGER_RVA;
        uintptr_t directInstance = 0;
        if (SafeRead(directAddr, directInstance) && directInstance != 0) {
            // Validate it looks like a valid pointer (heap address)
            if (directInstance > 0x10000 && directInstance < 0x7FFFFFFFFFFF) {
                m_renderManagerPtr = directAddr;
                LogInfo(std::format("GameCameraExtractor: g_RenderManager via direct RVA 0x{:X} -> 0x{:X} (instance: 0x{:X})", 
                    VERIFIED_RENDER_MANAGER_RVA, directAddr, directInstance));
                return true;
            }
        }
        
        // ===== APPROACH 2: Signature scan as fallback =====
        // g_RenderManager signature: 48 8B 0D ?? ?? ?? ?? 48 85 C9 74 05 E8
        constexpr const char* RENDER_MANAGER_PATTERN = "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 05 E8";
        
        auto result = PatternScanner::ScanMainModule(RENDER_MANAGER_PATTERN);
        if (result) {
            uintptr_t scanResult = ResolveRipRelative(result->address, 3, 7);
            
            if (scanResult != 0 && scanResult > 0x10000) {
                // Basic validation - try to read from it
                uintptr_t testRead = 0;
                if (SafeRead(scanResult, testRead) && testRead != 0) {
                    m_renderManagerPtr = scanResult;
                    LogInfo(std::format("GameCameraExtractor: g_RenderManager found via pattern at 0x{:X} (instance: 0x{:X})", 
                        scanResult, testRead));
                    return true;
                } else {
                    LogDebug(std::format("GameCameraExtractor: Pattern found RenderManager at 0x{:X} but instance is 0x{:X} (NULL or unreadable)", 
                        scanResult, testRead));
                }
            }
        }
        
        LogDebug("GameCameraExtractor: Could not find g_RenderManager via direct RVA or pattern scan");
        m_renderManagerPtr = 0;
        return false;
    }

    bool GameCameraExtractor::ScanForSceneCameraManager() {
        // Client::Graphics::Scene::CameraManager singleton 
        // Common patterns for singleton access:
        // Pattern 1: mov rcx, [rip+offset] for singleton Instance
        // Pattern 2: Pattern similar to other graphics singletons
        
        // Try multiple patterns
        constexpr const char* SCENE_CAMERA_PATTERNS[] = {
            "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? E8 ?? ?? ?? ?? 48 8B C8",  // mov rcx, [singleton]; test rcx; jz; call
            "48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D8",                   // mov rcx, [singleton]; call method
            "48 8B 05 ?? ?? ?? ?? 48 8B 48 ?? 48 85 C9",                      // mov rax, [singleton]; mov rcx, [rax+off]
        };
        
        for (const char* pattern : SCENE_CAMERA_PATTERNS) {
            auto result = PatternScanner::ScanMainModule(pattern);
            if (result) {
                // Check if it's mov rcx or mov rax
                int ripOffset = 3;  // Standard RIP offset for mov reg, [rip+disp32]
                int instructionLength = 7;
                
                uintptr_t singletonPtr = ResolveRipRelative(result->address, ripOffset, instructionLength);
                
                if (singletonPtr != 0 && singletonPtr > 0x10000) {
                    // Read the instance pointer
                    uintptr_t instance = 0;
                    if (SafeRead(singletonPtr, instance) && instance != 0 && instance > 0x10000) {
                        // Basic validation - try to read vtable
                        uintptr_t vtable = 0;
                        if (SafeRead(instance, vtable) && vtable != 0) {
                            m_sceneCameraManagerPtr = instance;
                            LogInfo(std::format("GameCameraExtractor: Scene::CameraManager found at 0x{:X} (vtable: 0x{:X})", 
                                instance, vtable));
                            return true;
                        }
                    }
                }
            }
        }
        
        LogDebug("GameCameraExtractor: Could not find Client::Graphics::Scene::CameraManager");
        m_sceneCameraManagerPtr = 0;
        return false;
    }
    
    // ============================================
    // Find Client::Graphics::Scene::Camera with valid matrices
    // Based on IDA analysis of 3.35: View Matrix at +0x40, Projection at +0x80
    // The Graphics camera is different from the Game camera (which only has position/angles)
    // ============================================
    bool GameCameraExtractor::ScanForGraphicsCamera() {
        // The Game layer camera (from CameraManager) only has position/angles.
        // We need to find the Graphics layer camera which has the actual View/Projection matrices.
        
        // Strategy 1: Look for RenderCamera* at offset 0xE0 in the Game camera
        // FFXIVClientStructs shows Scene::Camera has RenderCamera* at offset 0xE0
        if (m_activeCameraPtr != 0) {
            uintptr_t renderCameraPtr = 0;
            if (SafeRead(m_activeCameraPtr + CameraOffsets::RenderCameraPtr, renderCameraPtr)) {
                // Validate it looks like a pointer (not float data)
                if (renderCameraPtr > 0x10000 && renderCameraPtr < 0x7FFFFFFFFFFF && (renderCameraPtr & 0x7) == 0) {
                    // Validate it has matrix-like data at +0x40
                    float testMatrix[4] = {};
                    bool hasViewMatrix = true;
                    for (int i = 0; i < 4 && hasViewMatrix; ++i) {
                        if (!SafeRead(renderCameraPtr + 0x40 + i * sizeof(float), testMatrix[i])) {
                            hasViewMatrix = false;
                        }
                    }
                    
                    if (hasViewMatrix) {
                        // Check if values look like matrix data (not garbage)
                        bool looksValid = !std::isnan(testMatrix[0]) && 
                                         std::abs(testMatrix[0]) < 10.0f &&  // View matrix values typically < 1
                                         (std::abs(testMatrix[0]) > 0.001f || std::abs(testMatrix[1]) > 0.001f);
                        
                        if (looksValid) {
                            m_graphicsCameraPtr = renderCameraPtr;
                            LogInfo(std::format("GameCameraExtractor: Graphics camera found via RenderCamera ptr at 0x{:X}", 
                                renderCameraPtr));
                            return true;
                        }
                    }
                }
            }
        }
        
        // Strategy 2: Search through CameraManager for a camera object with valid matrices
        if (m_cameraManagerPtr != 0) {
            uintptr_t cameraManagerInstance = 0;
            if (!SafeRead(m_cameraManagerPtr, cameraManagerInstance) || cameraManagerInstance == 0) {
                return false;
            }
            
            // Try different offsets in CameraManager that might point to Graphics camera
            static constexpr size_t kGraphicsCameraOffsets[] = { 0x40, 0x48, 0x50, 0x58, 0x60, 0x30, 0x38 };
            
            for (size_t offset : kGraphicsCameraOffsets) {
                uintptr_t candidatePtr = 0;
                if (!SafeRead(cameraManagerInstance + offset, candidatePtr)) continue;
                if (candidatePtr == 0 || candidatePtr < 0x10000 || (candidatePtr & 0x7) != 0) continue;
                if (candidatePtr == m_activeCameraPtr) continue;  // Skip the Game camera we already have
                
                // Check if this camera has valid View matrix at +0x40
                float viewRow0[4] = {};
                bool hasViewMatrix = true;
                for (int i = 0; i < 4 && hasViewMatrix; ++i) {
                    if (!SafeRead(candidatePtr + 0x40 + i * sizeof(float), viewRow0[i])) {
                        hasViewMatrix = false;
                    }
                }
                
                if (!hasViewMatrix) continue;
                
                // Validate view matrix: should have orthonormal 3x3 (determinant ~= 1)
                // and values should be in reasonable range (-1 to 1 for rotation, larger for translation)
                bool isOrthonormal = !std::isnan(viewRow0[0]) && std::abs(viewRow0[0]) <= 1.5f;
                
                // Check projection matrix at +0x80
                float projRow0[4] = {};
                bool hasProjMatrix = true;
                for (int i = 0; i < 4 && hasProjMatrix; ++i) {
                    if (!SafeRead(candidatePtr + 0x80 + i * sizeof(float), projRow0[i])) {
                        hasProjMatrix = false;
                    }
                }
                
                // Projection matrix should have specific pattern: _11 > 0, _12 = 0, _13 = 0, _14 = 0
                bool isPerspectiveProj = hasProjMatrix && !std::isnan(projRow0[0]) && 
                                         projRow0[0] > 0.1f && projRow0[0] < 10.0f &&  // Focal length
                                         std::abs(projRow0[1]) < 0.01f && std::abs(projRow0[2]) < 0.01f;
                
                if (isOrthonormal && isPerspectiveProj) {
                    m_graphicsCameraPtr = candidatePtr;
                    LogInfo(std::format("GameCameraExtractor: Graphics camera found at CameraManager+0x{:X} -> 0x{:X}", 
                        offset, candidatePtr));
                    return true;
                }
            }
        }
        
        // Strategy 3: The Game camera itself might have the matrices at +0x40/+0x80
        // (This is the case if Game and Graphics cameras are the same object in 3.35)
        if (m_activeCameraPtr != 0) {
            float viewTest[4] = {}, projTest[4] = {};
            bool hasView = true, hasProj = true;
            
            for (int i = 0; i < 4; ++i) {
                if (!SafeRead(m_activeCameraPtr + 0x40 + i * sizeof(float), viewTest[i])) hasView = false;
                if (!SafeRead(m_activeCameraPtr + 0x80 + i * sizeof(float), projTest[i])) hasProj = false;
            }
            
            // Check if the matrices look valid (not garbage values we've been seeing)
            bool viewValid = hasView && !std::isnan(viewTest[0]) && std::abs(viewTest[0]) < 100.0f &&
                            (std::abs(viewTest[0]) > 0.001f || std::abs(viewTest[1]) > 0.001f);
            bool projValid = hasProj && !std::isnan(projTest[0]) && projTest[0] > 0.1f && projTest[0] < 10.0f;
            
            if (viewValid && projValid) {
                m_graphicsCameraPtr = m_activeCameraPtr;
                LogInfo(std::format("GameCameraExtractor: Using Game camera 0x{:X} as Graphics camera (has valid matrices at +0x40/+0x80)", 
                    m_activeCameraPtr));
                return true;
            }
        }
        
        // Only log this warning once to avoid spam (D3D11MatrixCapture is used as fallback)
        static bool s_loggedGraphicsCameraNotFound = false;
        if (!s_loggedGraphicsCameraNotFound) {
            LogDebug("GameCameraExtractor: Could not find Graphics layer camera with valid matrices - using D3D11 captured matrices as fallback");
            s_loggedGraphicsCameraNotFound = true;
        }
        m_graphicsCameraPtr = 0;
        return false;
    }

    // ============================================
    // Try cached signatures via PatternScanner
    // Note: Using PatternScanner directly since SignatureScanner has no implementation
    // ============================================
    bool GameCameraExtractor::TryCachedSignatures() {
        // Use PatternScanner::ScanMainModule for pattern scanning
        // This doesn't have persistent caching like SignatureScanner was meant to,
        // but it's the functional implementation we have
        for (const auto& sig : CAMERA_SIGNATURES) {
            auto result = PatternScanner::ScanMainModule(sig.pattern);
            if (result) {
                m_cameraManagerSignature = result->address;
                m_cameraManagerPtr = ResolveRipRelative(result->address, sig.ripOffset, sig.instructionLength);
                
                if (m_cameraManagerPtr != 0 && ValidateCameraManagerPtr(m_cameraManagerPtr)) {
                    m_foundSignatureName = sig.name;
                    LogInfo(std::format("GameCameraExtractor: '{}' found via PatternScanner at 0x{:X}", 
                            sig.name, m_cameraManagerSignature));
                    return true;
                }
            }
        }
        return false;
    }

    // ============================================
    // Direct pattern scanning with all signatures
    // ============================================
    bool GameCameraExtractor::ScanAllSignaturePatterns() {
        HMODULE mainModule = GetModuleHandleA("ffxiv_dx11.exe");
        if (!mainModule) {
            mainModule = GetModuleHandleA(nullptr);
        }
        if (!mainModule) {
            LogError("GameCameraExtractor: Could not get main module handle");
            return false;
        }

        for (const auto& sig : CAMERA_SIGNATURES) {
            auto result = PatternScanner::ScanMainModule(sig.pattern);
            if (result) {
                m_cameraManagerSignature = result->address;
                m_cameraManagerPtr = ResolveRipRelative(result->address, sig.ripOffset, sig.instructionLength);
                
                if (m_cameraManagerPtr != 0 && ValidateCameraManagerPtr(m_cameraManagerPtr)) {
                    m_foundSignatureName = sig.name;
                    LogInfo(std::format("GameCameraExtractor: '{}' found via PatternScanner at 0x{:X}", 
                            sig.name, m_cameraManagerSignature));
                    return true;
                } else {
                    LogDebug(std::format("GameCameraExtractor: '{}' pattern matched but validation failed", sig.name));
                }
            }
        }
        
        LogDebug("GameCameraExtractor: No signature patterns matched");
        return false;
    }

    // ============================================
    // String xref fallback - find camera via string references
    // ============================================
    bool GameCameraExtractor::TryStringXrefFallback() {
        LogInfo("GameCameraExtractor: Attempting string xref fallback...");

        HMODULE mainModule = GetModuleHandleA("ffxiv_dx11.exe");
        if (!mainModule) {
            mainModule = GetModuleHandleA(nullptr);
        }
        if (!mainModule) {
            return false;
        }

        for (const auto* searchString : CAMERA_XREF_STRINGS) {
            auto functions = PatternScanner::FindFunctionsReferencingString(mainModule, searchString);
            
            if (!functions.empty()) {
                LogDebug(std::format("GameCameraExtractor: Found {} functions referencing '{}'", 
                        functions.size(), searchString));
                
                // Analyze each function to find camera manager access
                for (uintptr_t funcAddr : functions) {
                    auto cameraPtr = AnalyzeFunctionForCameraAccess(funcAddr);
                    if (cameraPtr != 0 && ValidateCameraManagerPtr(cameraPtr)) {
                        m_cameraManagerPtr = cameraPtr;
                        m_foundSignatureName = std::string("StringXref:") + searchString;
                        LogInfo(std::format("GameCameraExtractor: Found camera manager via string '{}' at function 0x{:X}", 
                                searchString, funcAddr));
                        return true;
                    }
                }
            }
        }

        LogDebug("GameCameraExtractor: String xref fallback did not find camera manager");
        return false;
    }

    // ============================================
    // Analyze a function for camera manager access patterns
    // ============================================
    uintptr_t GameCameraExtractor::AnalyzeFunctionForCameraAccess(uintptr_t functionAddress) {
        HMODULE mainModule = GetModuleHandleA(nullptr);
        if (!mainModule) return 0;

        auto textSection = PatternScanner::GetPESection(mainModule, ".text");
        if (!textSection) return 0;

        // Scan first 0x200 bytes of the function for RIP-relative accesses
        const size_t maxScan = 0x200;
        const auto* code = reinterpret_cast<const std::byte*>(functionAddress);
        
        // Make sure we're within .text section
        if (functionAddress < reinterpret_cast<uintptr_t>(textSection.baseAddress) ||
            functionAddress >= reinterpret_cast<uintptr_t>(textSection.baseAddress) + textSection.size) {
            return 0;
        }

        size_t maxBytes = std::min(maxScan, 
            static_cast<size_t>(reinterpret_cast<uintptr_t>(textSection.baseAddress) + textSection.size - functionAddress));

        for (size_t i = 0; i + 7 <= maxBytes; ++i) {
            uintptr_t target = 0;
            size_t instrLen = 0;

            if (PatternScanner::ParseRipRelativeInstruction(code + i, target, instrLen)) {
                // Check if target looks like a valid global pointer
                if (target > reinterpret_cast<uintptr_t>(mainModule) && 
                    target < reinterpret_cast<uintptr_t>(mainModule) + 0x10000000) {
                    
                    // Try to read the pointer and validate it looks like camera data
                    uintptr_t potentialCameraManager = 0;
                    if (SafeRead(target, potentialCameraManager) && potentialCameraManager != 0) {
                        // Basic validation: check if the pointer chain looks valid
                        uintptr_t activeCamera = 0;
                        if (SafeRead(potentialCameraManager + CameraManagerOffsets::ActiveCamera, activeCamera)) {
                            if (activeCamera != 0) {
                                // Found a valid pointer chain - this might be the camera manager
                                return target;
                            }
                        }
                    }
                }
                i += instrLen - 1; // -1 because loop will ++i
            }
        }

        return 0;
    }

    // ============================================
    // Validate that a pointer looks like camera manager
    // ============================================
    bool GameCameraExtractor::ValidateCameraManagerPtr(uintptr_t ptr) {
        if (ptr == 0) return false;

        // Try to read the camera manager instance
        uintptr_t cameraManagerInstance = 0;
        if (!SafeRead(ptr, cameraManagerInstance)) {
            return false;
        }

        // Instance might be null if game hasn't initialized camera yet
        // That's OK - we'll try again later
        if (cameraManagerInstance == 0) {
            LogDebug("GameCameraExtractor: Camera manager instance is null (game may not be fully loaded)");
            return true; // Accept it - the pointer itself is valid
        }

        // Try to read active camera pointer
        uintptr_t activeCamera = 0;
        if (!SafeRead(cameraManagerInstance + CameraManagerOffsets::ActiveCamera, activeCamera)) {
            return false;
        }

        // Active camera can be null if in loading screen etc
        return true;
    }

    // ============================================
    // Legacy ScanForCameraManager for compatibility
    // ============================================
    bool GameCameraExtractor::ScanForCameraManager() {
        // Now just calls the new methods
        if (TryCachedSignatures()) return true;
        if (ScanAllSignaturePatterns()) return true;
        if (TryStringXrefFallback()) return true;
        return false;
    }

    bool GameCameraExtractor::ScanForActiveCamera() {
        if (m_cameraManagerPtr == 0) {
            return false;
        }

        // Read the camera manager instance pointer
        uintptr_t cameraManagerInstance = 0;
        if (!SafeRead(m_cameraManagerPtr, cameraManagerInstance) || cameraManagerInstance == 0) {
            return false;
        }

        // Helper to validate position (reasonable range, not garbage)
        auto IsValidPos = [](float x, float y, float z) {
            if (std::isnan(x) || std::isnan(y) || std::isnan(z)) return false;
            if (std::abs(x) > 50000.0f || std::abs(y) > 50000.0f || std::abs(z) > 50000.0f) return false;
            return (std::abs(x) > 0.1f || std::abs(y) > 0.1f || std::abs(z) > 0.1f);
        };

        // Always re-read camera pointer each frame - the game may swap cameras
        // or the pointer at CameraManager+0x20 may change
        uintptr_t cameraPtr = 0;
        if (!SafeRead(cameraManagerInstance + 0x20, cameraPtr) || cameraPtr == 0) {
            m_activeCameraPtr = 0;
            return false;
        }

        // Validate it's a heap pointer, not code
        uintptr_t moduleBase = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
        if (cameraPtr >= moduleBase && cameraPtr < moduleBase + 0x10000000) {
            m_activeCameraPtr = 0;
            return false;  // This is a code address, not valid camera
        }

        // Validate position at 0x100 (verified offset for 3.35 - player world position)
        float pos[3] = {};
        if (!SafeRead(cameraPtr + CameraOffsets::Position, pos[0]) ||
            !SafeRead(cameraPtr + CameraOffsets::Position + 4, pos[1]) ||
            !SafeRead(cameraPtr + CameraOffsets::Position + 8, pos[2])) {
            m_activeCameraPtr = 0;
            return false;
        }

        if (!IsValidPos(pos[0], pos[1], pos[2])) {
            m_activeCameraPtr = 0;
            return false;
        }

        // Log only when camera pointer changes
        if (m_activeCameraPtr != cameraPtr) {
            LogInfo(std::format("[CameraExtractor] Camera at 0x{:X}, player pos = ({:.1f}, {:.1f}, {:.1f})",
                cameraPtr, pos[0], pos[1], pos[2]));
        }
        
        m_activeCameraPtr = cameraPtr;
        return true;
    }

    // ============================================
    // RIP-relative address resolution
    // ============================================
    uintptr_t GameCameraExtractor::ResolveRipRelative(uintptr_t instructionAddress, int ripOffset, size_t instructionLength) {
        // For instructions like: 48 8B 05 XX XX XX XX (mov rax, [rip+XXXX])
        // ripOffset is where the 4-byte displacement starts within the instruction
        // The final address is: instruction_address + instruction_length + signed_offset
        
        // CHANGE NOTE (2025-12-15): Avoid `IsBadReadPtr` and avoid unaligned `*reinterpret_cast<int32_t*>` reads.
        // We validate the address, then memcpy into a local int32_t (alignment-safe).
        int32_t offset = 0;
        const uintptr_t dispAddr = instructionAddress + static_cast<uintptr_t>(ripOffset);
        if (!SapphireHook::IsValidMemoryAddress(dispAddr, sizeof(int32_t))) {
            return 0;
        }
        __try {
            std::memcpy(&offset, reinterpret_cast<const void*>(dispAddr), sizeof(offset));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }

        return instructionAddress + instructionLength + offset;
    }

    // ============================================
    // Safe memory reading
    // ============================================
    template<typename T>
    bool GameCameraExtractor::SafeRead(uintptr_t address, T& outValue) const {
        if (address == 0) {
            return false;
        }

        // CHANGE NOTE (2025-12-15): Use VirtualQuery-backed validation instead of `IsBadReadPtr`.
        // We still keep SEH as a last-resort guard because game memory can change concurrently.
        __try {
            if (!SapphireHook::IsValidMemoryAddress(address, sizeof(T))) {
                return false;
            }
            std::memcpy(&outValue, reinterpret_cast<const void*>(address), sizeof(T));
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    bool GameCameraExtractor::SafeReadMatrix(uintptr_t address, DirectX::XMMATRIX& outMatrix) const {
        if (address == 0) {
            return false;
        }

        std::array<float, 16> m{};
        if (!SafeRead(address, m)) return false;
        outMatrix = DirectX::XMMATRIX(
            m[0], m[1], m[2], m[3],
            m[4], m[5], m[6], m[7],
            m[8], m[9], m[10], m[11],
            m[12], m[13], m[14], m[15]);
        return true;
    }

    bool GameCameraExtractor::SafeReadFloat3(uintptr_t address, DirectX::XMFLOAT3& outVec) const {
        if (address == 0) {
            return false;
        }
        std::array<float, 3> v{};
        if (!SafeRead(address, v)) return false;
        outVec = DirectX::XMFLOAT3(v[0], v[1], v[2]);
        return true;
    }

    bool GameCameraExtractor::SafeReadFloat(uintptr_t address, float& outValue) const {
        return SafeRead(address, outValue);
    }

    // ============================================
    // Camera extraction
    // ============================================
    std::optional<ExtractedCamera> GameCameraExtractor::ExtractCamera() {
        if (!m_initialized.load()) {
            return std::nullopt;
        }

        std::lock_guard<std::mutex> lock(m_mutex);

        // Update active camera pointer (Game layer - has player position)
        if (!ScanForActiveCamera()) {
            m_status.store(CameraExtractionStatus::ExtractionFailed);
            return std::nullopt;
        }
        
        // Try to find Graphics layer camera (has matrices at +0x40, +0x80)
        // This is separate from the Game camera which only has position/angles
        if (m_graphicsCameraPtr == 0) {
            ScanForGraphicsCamera();
        }

        m_status.store(CameraExtractionStatus::Extracting);

        ExtractedCamera camera;

        // =================================================================
        // UPDATED INTERPRETATION (December 2025, based on IDA analysis):
        // Game Camera (m_activeCameraPtr):
        //   - 0x100 = PLAYER world position (changes when player walks)
        //   - 0xD8 = Camera distance from player  
        //   - 0x70/0x74 = Pitch/Yaw angles
        // Graphics Camera (m_graphicsCameraPtr):
        //   - 0x40 = View Matrix (4x4, verified via IDA CalculateViewMatrix)
        //   - 0x80 = Projection Matrix (4x4, verified via IDA)
        //   - 0xC0 = ViewProjection Matrix (pre-computed)
        // =================================================================
        
        // Read PLAYER position from Game camera offset 0xE0
        // In 3.35, this is the player/look-at target position
        DirectX::XMFLOAT3 playerPos = {0, 0, 0};
        if (!SafeReadFloat3(m_activeCameraPtr + CameraOffsets::Position, playerPos)) {
            playerPos = DirectX::XMFLOAT3(0, 0, 0);
        }
        
        // Validate player position isn't garbage
        if (std::isnan(playerPos.x) || std::abs(playerPos.x) > 50000.0f) {
            playerPos = DirectX::XMFLOAT3(0, 0, 0);
        }
        
        // Cache player position for menu bar display
        m_cachedPlayerPosition = playerPos;
        
        // Store player position as lookAt (camera looks at player)
        camera.lookAt = playerPos;
        
        // Read camera distance and angles to compute camera eye position
        float distance = 0.0f;
        float pitch = 0.0f;  // Vertical angle (up/down)
        float yaw = 0.0f;    // Horizontal angle (left/right)
        
        SafeReadFloat(m_activeCameraPtr + CameraOffsets::Distance, distance);
        
        // Try to find valid rotation angles by probing multiple offsets
        // The angles should be in radians, typically between -PI and PI
        // Prioritize 0x1A0/0x1A4 which is VERIFIED to work in 3.35
        static constexpr size_t kAngleOffsets[] = { 
            0x1A0, 0x1A4,  // VERIFIED working in 3.35
            0x130, 0x134,  // After position data
            0x140, 0x144,  // Further out
            0x150, 0x154,  // Even further
            0x160, 0x164,  // More offsets
            0x110, 0x114,  // Near position
            0x1B0, 0x1B4,  // Even more
            0x70, 0x74,    // Legacy (probably wrong for 3.35)
        };
        
        bool foundValidAngles = false;
        for (size_t i = 0; i < sizeof(kAngleOffsets)/sizeof(kAngleOffsets[0]); i += 2) {
            float testPitch = 0.0f, testYaw = 0.0f;
            if (!SafeReadFloat(m_activeCameraPtr + kAngleOffsets[i], testPitch)) continue;
            if (!SafeReadFloat(m_activeCameraPtr + kAngleOffsets[i+1], testYaw)) continue;
            
            // Valid angles should be in reasonable range (radians)
            bool pitchValid = !std::isnan(testPitch) && std::abs(testPitch) < 2.0f;
            bool yawValid = !std::isnan(testYaw) && std::abs(testYaw) < 10.0f;
            
            if (pitchValid && yawValid) {
                pitch = testPitch;
                yaw = testYaw;
                foundValidAngles = true;
                
                static size_t s_lastAngleOffset = 0;
                if (s_lastAngleOffset != kAngleOffsets[i]) {
                    LogInfo(std::format("[CameraExtractor] Found valid angles at offsets 0x{:X}/0x{:X}: pitch={:.3f}, yaw={:.3f}",
                        kAngleOffsets[i], kAngleOffsets[i+1], pitch, yaw));
                    s_lastAngleOffset = kAngleOffsets[i];
                }
                break;
            }
        }
        
        if (!foundValidAngles) {
            // Fallback: assume camera looking forward (along -Z axis)
            pitch = 0.0f;
            yaw = 0.0f;
        }
        
        // Clamp distance to reasonable values
        if (std::isnan(distance) || distance < 1.0f || distance > 100.0f) {
            distance = 10.0f;  // Default camera distance
        }
        
        // Compute camera eye position orbiting around player
        // Camera is at: player + spherical offset based on distance and angles
        // In FFXIV: Y is up, camera orbits in XZ plane with pitch for elevation
        float cosPitch = std::cos(pitch);
        float sinPitch = std::sin(pitch);
        float cosYaw = std::cos(yaw);
        float sinYaw = std::sin(yaw);
        
        // Camera offset from player (spherical coordinates)
        float offsetX = distance * cosPitch * sinYaw;
        float offsetY = distance * sinPitch;  // Elevation
        float offsetZ = distance * cosPitch * cosYaw;
        
        camera.position.x = playerPos.x + offsetX;
        camera.position.y = playerPos.y + offsetY;
        camera.position.z = playerPos.z + offsetZ;
        
        // Log once for debugging - dump multiple float values to find angles
        static bool s_loggedCameraCompute = false;
        if (!s_loggedCameraCompute) {
            LogInfo(std::format("[CameraExtractor] Computed camera position:"));
            LogInfo(std::format("  Player (0xE0): ({:.1f}, {:.1f}, {:.1f})", playerPos.x, playerPos.y, playerPos.z));
            LogInfo(std::format("  Distance (0xD8): {:.2f}, Pitch: {:.3f}, Yaw: {:.3f}", distance, pitch, yaw));
            LogInfo(std::format("  Camera Eye: ({:.1f}, {:.1f}, {:.1f})", camera.position.x, camera.position.y, camera.position.z));
            
            // Dump floats at various offsets to find real rotation data
            LogInfo("[CameraExtractor] Scanning for angle/rotation data:");
            for (size_t off = 0x100; off <= 0x200; off += 4) {
                float val = 0.0f;
                if (SafeReadFloat(m_activeCameraPtr + off, val)) {
                    // Only log if value looks like it could be an angle or useful float
                    if (!std::isnan(val) && std::abs(val) < 1000.0f && val != 0.0f) {
                        LogInfo(std::format("  0x{:03X}: {:.4f}", off, val));
                    }
                }
            }
            
            s_loggedCameraCompute = true;
        }

        // Read FOV, near/far clip (use defaults if failed)
        if (!SafeReadFloat(m_activeCameraPtr + CameraOffsets::FovY, camera.fovY)) {
            camera.fovY = DirectX::XM_PIDIV4;  // Default 45 degrees in radians
        }
        
        // FOV sanity check and degrees-to-radians conversion
        // In 3.35, FOV at 0x114 is stored in DEGREES (e.g., 45.0), not radians
        // Radians would be < 3.14, degrees would be > 10 typically
        if (!std::isnan(camera.fovY) && camera.fovY > 0.0f) {
            if (camera.fovY > 10.0f && camera.fovY < 180.0f) {
                // Looks like degrees - convert to radians
                static bool s_loggedFovConversion = false;
                if (!s_loggedFovConversion) {
                    LogInfo(std::format("[CameraExtractor] FOV appears to be in degrees ({:.1f}), converting to radians", camera.fovY));
                    s_loggedFovConversion = true;
                }
                camera.fovY = DirectX::XMConvertToRadians(camera.fovY);
            } else if (camera.fovY > DirectX::XM_PI) {
                // Invalid radians value, use default
                camera.fovY = DirectX::XM_PIDIV4;
            }
        } else {
            camera.fovY = DirectX::XM_PIDIV4;  // Default 45 degrees
        }
        
        if (!SafeReadFloat(m_activeCameraPtr + CameraOffsets::NearClip, camera.nearClip)) {
            camera.nearClip = 0.1f;
        }
        if (!SafeReadFloat(m_activeCameraPtr + CameraOffsets::FarClip, camera.farClip)) {
            camera.farClip = 10000.0f;
        }
        
        // Validate near/far clip planes - XMMatrixPerspectiveFovLH asserts NearZ > 0 && FarZ > 0
        if (std::isnan(camera.nearClip) || camera.nearClip <= 0.0f || camera.nearClip > 100.0f) {
            camera.nearClip = 0.1f;
        }
        if (std::isnan(camera.farClip) || camera.farClip <= 0.0f || camera.farClip < camera.nearClip) {
            camera.farClip = 10000.0f;
        }
        // Ensure far > near
        if (camera.farClip <= camera.nearClip) {
            camera.nearClip = 0.1f;
            camera.farClip = 10000.0f;
        }
        
        camera.aspectRatio = 16.0f / 9.0f;

        // ===================================================================
        // Read matrices from Graphics camera (preferred) or Game camera (fallback)
        // Based on IDA analysis: View at +0x40, Projection at +0x80
        // ===================================================================
        uintptr_t matrixSource = (m_graphicsCameraPtr != 0) ? m_graphicsCameraPtr : m_activeCameraPtr;
        
        bool hasViewMatrix = SafeReadMatrix(matrixSource + CameraOffsets::ViewMatrix, camera.view);
        bool hasProjMatrix = SafeReadMatrix(matrixSource + CameraOffsets::ProjectionMatrix, camera.projection);
        
        // Log matrix values once for debugging
        static bool loggedMatrixOnce = false;
        if (!loggedMatrixOnce && (hasViewMatrix || hasProjMatrix)) {
            DirectX::XMFLOAT4X4 viewFloat, projFloat;
            DirectX::XMStoreFloat4x4(&viewFloat, camera.view);
            DirectX::XMStoreFloat4x4(&projFloat, camera.projection);
            
            const char* sourceType = (m_graphicsCameraPtr != 0) ? "Graphics" : "Game";
            LogInfo(std::format("GameCameraExtractor: Reading matrices from {} camera at 0x{:X}:", 
                sourceType, matrixSource));
            
            LogInfo(std::format("  View Matrix (0x40): [{:.4f} {:.4f} {:.4f} {:.4f}]", 
                viewFloat._11, viewFloat._12, viewFloat._13, viewFloat._14));
            LogInfo(std::format("                      [{:.4f} {:.4f} {:.4f} {:.4f}]", 
                viewFloat._21, viewFloat._22, viewFloat._23, viewFloat._24));
            LogInfo(std::format("                      [{:.4f} {:.4f} {:.4f} {:.4f}]", 
                viewFloat._31, viewFloat._32, viewFloat._33, viewFloat._34));
            LogInfo(std::format("                      [{:.4f} {:.4f} {:.4f} {:.4f}]", 
                viewFloat._41, viewFloat._42, viewFloat._43, viewFloat._44));
            
            LogInfo(std::format("  Proj Matrix (0x80): [{:.4f} {:.4f} {:.4f} {:.4f}]", 
                projFloat._11, projFloat._12, projFloat._13, projFloat._14));
            LogInfo(std::format("                      [{:.4f} {:.4f} {:.4f} {:.4f}]", 
                projFloat._21, projFloat._22, projFloat._23, projFloat._24));
            LogInfo(std::format("                      [{:.4f} {:.4f} {:.4f} {:.4f}]", 
                projFloat._31, projFloat._32, projFloat._33, projFloat._34));
            LogInfo(std::format("                      [{:.4f} {:.4f} {:.4f} {:.4f}]", 
                projFloat._41, projFloat._42, projFloat._43, projFloat._44));
            
            loggedMatrixOnce = true;
        }
        
        // Validate matrices aren't garbage
        if (hasViewMatrix) {
            DirectX::XMFLOAT4X4 viewFloat;
            DirectX::XMStoreFloat4x4(&viewFloat, camera.view);
            if (std::isnan(viewFloat._11) || std::abs(viewFloat._11) > 1000.0f) {
                hasViewMatrix = false;
            }
        }
        
        if (hasProjMatrix) {
            DirectX::XMFLOAT4X4 projFloat;
            DirectX::XMStoreFloat4x4(&projFloat, camera.projection);
            if (std::isnan(projFloat._11) || projFloat._11 == 0.0f) {
                hasProjMatrix = false;
            }
        }

        // If we have valid position but not matrices, BUILD them from camera parameters
        bool hasValidPosition = !std::isnan(camera.position.x) && 
                                (std::abs(camera.position.x) > 0.1f || 
                                 std::abs(camera.position.y) > 0.1f || 
                                 std::abs(camera.position.z) > 0.1f);

        if (hasValidPosition) {
            // Build matrices from parameters if pre-computed ones are garbage
            if (!hasViewMatrix) {
                // Build view matrix: camera looks at player (lookAt)
                DirectX::XMVECTOR eye = DirectX::XMVectorSet(camera.position.x, camera.position.y, camera.position.z, 1.0f);
                DirectX::XMVECTOR target = DirectX::XMVectorSet(camera.lookAt.x, camera.lookAt.y, camera.lookAt.z, 1.0f);
                DirectX::XMVECTOR up = DirectX::XMVectorSet(0.0f, 1.0f, 0.0f, 0.0f);
                camera.view = DirectX::XMMatrixLookAtLH(eye, target, up);
                
                static bool s_loggedViewBuild = false;
                if (!s_loggedViewBuild) {
                    LogInfo(std::format("[CameraExtractor] Built View matrix: eye=({:.1f},{:.1f},{:.1f}) -> target=({:.1f},{:.1f},{:.1f})",
                        camera.position.x, camera.position.y, camera.position.z,
                        camera.lookAt.x, camera.lookAt.y, camera.lookAt.z));
                    s_loggedViewBuild = true;
                }
            }
            
            if (!hasProjMatrix) {
                // Build projection matrix from FOV, aspect ratio, near/far clips
                // Safety check: XMMatrixPerspectiveFovLH asserts NearZ > 0 && FarZ > 0
                float safeNear = (camera.nearClip > 0.0f) ? camera.nearClip : 0.1f;
                float safeFar = (camera.farClip > safeNear) ? camera.farClip : 10000.0f;
                float safeFov = (camera.fovY > 0.0f && camera.fovY < DirectX::XM_PI) ? camera.fovY : DirectX::XM_PIDIV4;
                float safeAspect = (camera.aspectRatio > 0.0f) ? camera.aspectRatio : (16.0f / 9.0f);
                
                camera.projection = DirectX::XMMatrixPerspectiveFovLH(
                    safeFov,
                    safeAspect,
                    safeNear,
                    safeFar
                );
                
                static bool s_loggedProjBuild = false;
                if (!s_loggedProjBuild) {
                    LogInfo(std::format("[CameraExtractor] Built Proj matrix: fov={:.2f}rad ({:.1f}deg), aspect={:.2f}, near={:.2f}, far={:.1f}",
                        safeFov, DirectX::XMConvertToDegrees(safeFov),
                        safeAspect, safeNear, safeFar));
                    s_loggedProjBuild = true;
                }
            }

            // Promote constructed matrices to best-known so downstream code skips probing garbage
            m_bestViewMatrix = camera.view;
            m_bestProjMatrix = camera.projection;
            m_hasValidMatrices = true;
            m_foundViewOffset = 0;  // denote constructed
            m_foundProjOffset = 0;

            camera.valid = true;
            m_status.store(CameraExtractionStatus::Ready);
            return camera;
        }

        m_status.store(CameraExtractionStatus::ExtractionFailed);
        return std::nullopt;
    }

    bool GameCameraExtractor::Update() {
        auto camera = ExtractCamera();
        if (camera) {
            m_cachedCamera = *camera;
            return true;
        }
        m_cachedCamera.valid = false;
        return false;
    }

    // ============================================
    // Force re-scan
    // ============================================
    void GameCameraExtractor::RescanSignatures() {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        m_cameraManagerSignature = 0;
        m_cameraManagerPtr = 0;
        m_activeCameraPtr = 0;
        m_cachedCamera = ExtractedCamera{};
        m_foundSignatureName.clear();

        m_status.store(CameraExtractionStatus::ScanningSignatures);
        
        // Note: PatternScanner doesn't have a persistent cache to clear,
        // so we just re-scan directly
        
        if (ScanForCameraManager()) {
            m_status.store(CameraExtractionStatus::SignaturesFound);
            LogInfo(std::format("GameCameraExtractor: Re-scan successful, camera manager at 0x{:X} (via {})", 
                    m_cameraManagerPtr, m_foundSignatureName));
        } else {
            m_status.store(CameraExtractionStatus::SignaturesNotFound);
            LogWarning("GameCameraExtractor: Re-scan failed, no signatures found");
        }
    }

    // ============================================
    // Get diagnostic info
    // ============================================
    std::string GameCameraExtractor::GetFoundSignatureName() const {
        return m_foundSignatureName;
    }

    // ============================================
    // Debug: Dump camera memory to find correct offsets
    // ============================================
    void GameCameraExtractor::DumpCameraMemory() {
        if (!m_initialized.load()) {
            LogWarning("GameCameraExtractor::DumpCameraMemory: Not initialized");
            return;
        }

        std::lock_guard<std::mutex> lock(m_mutex);

        LogInfo("=== Camera Memory Dump ===");
        LogInfo(std::format("Camera Manager Ptr: 0x{:X}", m_cameraManagerPtr));

        // Read camera manager instance
        uintptr_t cameraManagerInstance = 0;
        if (!SafeRead(m_cameraManagerPtr, cameraManagerInstance)) {
            LogError("Failed to read camera manager instance");
            return;
        }
        LogInfo(std::format("Camera Manager Instance: 0x{:X}", cameraManagerInstance));

        // Try different offsets for camera pointers
        LogInfo("--- Probing camera manager for pointers ---");
        std::vector<std::pair<size_t, uintptr_t>> validCameraPtrs;
        for (size_t offset = 0x00; offset <= 0x80; offset += 0x8) {
            uintptr_t potentialCamera = 0;
            if (SafeRead(cameraManagerInstance + offset, potentialCamera)) {
                // Check if it looks like a valid heap pointer (not float data)
                // Valid pointers are typically > 0x10000 and < 0x800000000000
                bool looksLikePointer = (potentialCamera > 0x10000) && 
                                        (potentialCamera < 0x800000000000ULL) &&
                                        ((potentialCamera & 0x7) == 0);  // Aligned
                if (looksLikePointer) {
                    LogInfo(std::format("  Offset 0x{:02X}: 0x{:X} (valid pointer)", offset, potentialCamera));
                    validCameraPtrs.push_back({offset, potentialCamera});
                } else if (potentialCamera != 0) {
                    LogInfo(std::format("  Offset 0x{:02X}: 0x{:X} (data/not pointer)", offset, potentialCamera));
                }
            }
        }

        // Probe each valid camera pointer for matrices
        for (const auto& [offset, cameraPtr] : validCameraPtrs) {
            LogInfo(std::format("--- Probing Camera at 0x{:02X} (0x{:X}) for matrices ---", offset, cameraPtr));
            
            for (size_t matOffset = 0; matOffset <= 0x200; matOffset += 0x10) {
                float matrix[16] = {};
                bool readable = true;
                
                for (int i = 0; i < 16; ++i) {
                    if (!SafeRead(cameraPtr + matOffset + i * sizeof(float), matrix[i])) {
                        readable = false;
                        break;
                    }
                }
                
                if (readable) {
                    bool hasReasonableValues = true;
                    bool hasNearOne = false;
                    int zeroCount = 0;
                    
                    for (int i = 0; i < 16; ++i) {
                        if (std::isnan(matrix[i]) || std::isinf(matrix[i])) {
                            hasReasonableValues = false;
                            break;
                        }
                        if (std::abs(matrix[i]) > 10000.0f) {
                            hasReasonableValues = false;
                            break;
                        }
                        if (std::abs(matrix[i] - 1.0f) < 0.01f || std::abs(matrix[i] + 1.0f) < 0.01f) {
                            hasNearOne = true;
                        }
                        if (std::abs(matrix[i]) < 0.0001f) {
                            zeroCount++;
                        }
                    }
                    
                    if (hasReasonableValues && hasNearOne && zeroCount >= 4) {
                        LogInfo(std::format("  Offset 0x{:03X}: POTENTIAL MATRIX", matOffset));
                        LogInfo(std::format("    [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                                matrix[0], matrix[1], matrix[2], matrix[3]));
                        LogInfo(std::format("    [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                                matrix[4], matrix[5], matrix[6], matrix[7]));
                        LogInfo(std::format("    [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                                matrix[8], matrix[9], matrix[10], matrix[11]));
                        LogInfo(std::format("    [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                                matrix[12], matrix[13], matrix[14], matrix[15]));
                    }
                }
            }
            
            // Also probe for position (float3) - scan wide range
            LogInfo(std::format("  --- Position candidates (0x00 to 0x200) ---"));
            for (size_t posOffset = 0; posOffset <= 0x200; posOffset += 0x4) {
                float pos[3] = {};
                bool readable = true;
                for (int i = 0; i < 3; ++i) {
                    if (!SafeRead(cameraPtr + posOffset + i * sizeof(float), pos[i])) {
                        readable = false;
                        break;
                    }
                }
                
                if (readable) {
                    bool valid = !std::isnan(pos[0]) && !std::isnan(pos[1]) && !std::isnan(pos[2]);
                    valid = valid && std::abs(pos[0]) < 10000.0f && std::abs(pos[1]) < 10000.0f && std::abs(pos[2]) < 10000.0f;
                    valid = valid && (std::abs(pos[0]) > 0.1f || std::abs(pos[1]) > 0.1f || std::abs(pos[2]) > 0.1f);
                    
                    // Highlight offsets that look like world coordinates (large values in reasonable range)
                    bool looksLikeWorldCoord = valid && 
                        (std::abs(pos[0]) > 10.0f || std::abs(pos[2]) > 10.0f) &&  // X or Z > 10
                        std::abs(pos[1]) < 500.0f;  // Y (height) reasonable
                    
                    if (valid) {
                        const char* marker = looksLikeWorldCoord ? " <-- WORLD COORD?" : "";
                        LogInfo(std::format("    Offset 0x{:03X}: ({:9.2f}, {:9.2f}, {:9.2f}){}",
                                posOffset, pos[0], pos[1], pos[2], marker));
                    }
                }
            }
        }

        LogInfo("=== End Camera Memory Dump ===");
        LogInfo("TIP: Run this twice while moving camera to see which values change!");
    }

    // ============================================
    // Debug: Dump RenderManager memory (0x0-0x400)
    // Logs pointer-like fields and matrix-like blocks once per run
    // ============================================
    void GameCameraExtractor::DumpRenderManagerMemory() {
        if (!m_initialized.load()) {
            LogWarning("GameCameraExtractor::DumpRenderManagerMemory: Not initialized");
            return;
        }

        std::lock_guard<std::mutex> lock(m_mutex);

        if (m_renderManagerPtr == 0) {
            LogWarning("GameCameraExtractor::DumpRenderManagerMemory: g_RenderManager not resolved");
            return;
        }

        uintptr_t renderManagerInstance = 0;
        if (!SafeRead(m_renderManagerPtr, renderManagerInstance) || renderManagerInstance == 0) {
            LogError("GameCameraExtractor::DumpRenderManagerMemory: Failed to read RenderManager instance");
            return;
        }

        DumpRenderManagerMemoryLocked(renderManagerInstance);
    }

    void GameCameraExtractor::DumpRenderManagerMemoryLocked(uintptr_t renderManagerInstance) {
        LogInfo("=== RenderManager Memory Dump ===");
        LogInfo(std::format("g_RenderManager global: 0x{:X} -> instance 0x{:X}", m_renderManagerPtr, renderManagerInstance));

        LogInfo("--- Pointer-like fields (0x00-0x120) ---");
        for (size_t offset = 0; offset <= 0x120; offset += 0x8) {
            uintptr_t ptr = 0;
            if (!SafeRead(renderManagerInstance + offset, ptr)) {
                continue;
            }

            bool looksPointer = (ptr > 0x10000) && (ptr < 0x7FFFFFFFFFFFULL) && ((ptr & 0x7) == 0);
            if (looksPointer) {
                LogInfo(std::format("  +0x{:03X}: 0x{:X}", offset, ptr));
            }
        }

        LogInfo("--- Matrix-like blocks (0x00-0x400) ---");
        int loggedMatrices = 0;
        for (size_t offset = 0; offset <= 0x400 - 0x40; offset += 0x10) {
            float m[16] = {};
            bool readable = true;
            for (int i = 0; i < 16; ++i) {
                if (!SafeRead(renderManagerInstance + offset + i * sizeof(float), m[i])) {
                    readable = false;
                    break;
                }
            }
            if (!readable) {
                continue;
            }

            bool hasNaN = false;
            bool allZero = true;
            bool hasUnitish = false;
            bool hasHuge = false;
            for (float v : m) {
                if (std::isnan(v) || std::isinf(v)) {
                    hasNaN = true;
                    break;
                }
                if (std::abs(v) > 10000.0f) {
                    hasHuge = true;
                }
                if (std::abs(v) > 0.0001f) {
                    allZero = false;
                }
                if (std::abs(std::abs(v) - 1.0f) < 0.2f) {
                    hasUnitish = true;
                }
            }

            if (hasNaN || hasHuge || allZero || !hasUnitish) {
                continue;
            }

            float det3x3 = m[0] * (m[5] * m[10] - m[6] * m[9])
                         - m[1] * (m[4] * m[10] - m[6] * m[8])
                         + m[2] * (m[4] * m[9] - m[5] * m[8]);
            bool isOrthonormal = std::abs(std::abs(det3x3) - 1.0f) < 0.2f;
            bool isProjish = std::abs(m[11]) > 0.5f && std::abs(m[11]) < 5.0f && std::abs(m[15]) < 0.05f;

            const char* kind = isOrthonormal ? "VIEW-ish" : (isProjish ? "PROJ-ish" : "MATRIX");

            LogInfo(std::format("  +0x{:03X} ({})", offset, kind));
            LogInfo(std::format("    [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", m[0], m[1], m[2], m[3]));
            LogInfo(std::format("    [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", m[4], m[5], m[6], m[7]));
            LogInfo(std::format("    [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", m[8], m[9], m[10], m[11]));
            LogInfo(std::format("    [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", m[12], m[13], m[14], m[15]));

            if (++loggedMatrices >= 24) {
                LogInfo("  ...truncated matrix log (limit 24 blocks)...");
                break;
            }
        }

        LogInfo("=== End RenderManager Memory Dump ===");
    }

    // ============================================
    // Debug: Compare camera memory to find what changes
    // ============================================
    void GameCameraExtractor::CompareCameraMemory() {
        if (!m_initialized.load()) {
            LogWarning("GameCameraExtractor::CompareCameraMemory: Not initialized");
            return;
        }

        std::lock_guard<std::mutex> lock(m_mutex);

        // Read camera manager instance
        uintptr_t cameraManagerInstance = 0;
        if (!SafeRead(m_cameraManagerPtr, cameraManagerInstance)) {
            LogError("Failed to read camera manager instance");
            return;
        }

        // Get first valid camera pointer (at offset 0x20)
        uintptr_t cameraPtr = 0;
        if (!SafeRead(cameraManagerInstance + 0x20, cameraPtr)) {
            LogError("Failed to read camera pointer");
            return;
        }

        if (cameraPtr == 0 || cameraPtr < 0x10000) {
            LogError("Invalid camera pointer");
            return;
        }

        // Read current memory (0x300 bytes = 192 floats)
        constexpr size_t DUMP_SIZE = 0x300;
        constexpr size_t NUM_FLOATS = DUMP_SIZE / sizeof(float);
        std::vector<float> currentDump(NUM_FLOATS);
        
        for (size_t i = 0; i < NUM_FLOATS; ++i) {
            if (!SafeRead(cameraPtr + i * sizeof(float), currentDump[i])) {
                currentDump[i] = std::numeric_limits<float>::quiet_NaN();
            }
        }

        // If we have a previous dump from the same camera, compare
        if (m_previousDumpCamera == cameraPtr && m_previousDump.size() == NUM_FLOATS) {
            LogInfo("=== Camera Memory CHANGES (moved since last dump) ===");
            LogInfo(std::format("Camera at: 0x{:X}", cameraPtr));
            
            int changeCount = 0;
            for (size_t i = 0; i < NUM_FLOATS; ++i) {
                float prev = m_previousDump[i];
                float curr = currentDump[i];
                
                // Skip NaN values
                if (std::isnan(prev) || std::isnan(curr)) continue;
                
                // Check if changed significantly
                float diff = std::abs(curr - prev);
                if (diff > 0.001f) {
                    size_t offset = i * sizeof(float);
                    
                    // Flag if this looks like a world coordinate change
                    bool looksLikePosition = std::abs(curr) > 10.0f && std::abs(curr) < 10000.0f;
                    const char* marker = looksLikePosition ? " <-- POSITION?" : "";
                    
                    LogInfo(std::format("  Offset 0x{:03X}: {:12.4f} -> {:12.4f} (delta: {:+.4f}){}",
                            offset, prev, curr, curr - prev, marker));
                    changeCount++;
                }
            }
            
            if (changeCount == 0) {
                LogInfo("  No changes detected! Try moving the camera further.");
            } else {
                LogInfo(std::format("  Total changes: {}", changeCount));
            }
            
            // Also show float3 candidates that changed together (likely position/lookAt)
            LogInfo("--- Checking for float3 groups that changed together ---");
            for (size_t i = 0; i + 2 < NUM_FLOATS; ++i) {
                float px = m_previousDump[i], cx = currentDump[i];
                float py = m_previousDump[i+1], cy = currentDump[i+1];
                float pz = m_previousDump[i+2], cz = currentDump[i+2];
                
                if (std::isnan(px) || std::isnan(cx)) continue;
                
                float dx = std::abs(cx - px);
                float dy = std::abs(cy - py);
                float dz = std::abs(cz - pz);
                
                // All three changed?
                if (dx > 0.01f && dz > 0.01f) {  // X and Z both changed (horizontal movement)
                    size_t offset = i * sizeof(float);
                    LogInfo(std::format("  Offset 0x{:03X}: float3 changed! ({:.2f},{:.2f},{:.2f}) -> ({:.2f},{:.2f},{:.2f})",
                            offset, px, py, pz, cx, cy, cz));
                }
            }
            
            LogInfo("=== End Changes ===");
        } else {
            LogInfo("=== Camera Memory Snapshot Saved ===");
            LogInfo(std::format("Camera at: 0x{:X}", cameraPtr));
            LogInfo("Move the camera and run Compare again to see what changed!");
        }

        // Save for next comparison
        m_previousDump = std::move(currentDump);
        m_previousDumpCamera = cameraPtr;
    }

    // ============================================
    // Debug: Compare matrices from ActiveCamera vs RenderCamera
    // This helps verify which camera object has the final rendered matrices
    // ============================================
    void GameCameraExtractor::CompareActiveCameraVsRenderCamera() {
        if (!m_initialized.load()) {
            LogWarning("GameCameraExtractor::CompareActiveCameraVsRenderCamera: Not initialized");
            return;
        }

        std::lock_guard<std::mutex> lock(m_mutex);

        LogInfo("=== ActiveCamera vs RenderCamera Matrix Comparison ===");
        LogInfo(std::format("Camera Manager Ptr: 0x{:X}", m_cameraManagerPtr));

        // Read camera manager instance
        uintptr_t cameraManagerInstance = 0;
        if (!SafeRead(m_cameraManagerPtr, cameraManagerInstance)) {
            LogError("Failed to read camera manager instance");
            return;
        }
        LogInfo(std::format("Camera Manager Instance: 0x{:X}", cameraManagerInstance));

        // Read both camera pointers
        uintptr_t activeCamera = 0, renderCamera = 0;
        SafeRead(cameraManagerInstance + CameraManagerOffsets::ActiveCamera, activeCamera);  // 0x20
        SafeRead(cameraManagerInstance + CameraManagerOffsets::RenderCamera, renderCamera);  // 0x40

        LogInfo(std::format("ActiveCamera (0x20): 0x{:X}", activeCamera));
        LogInfo(std::format("RenderCamera (0x40): 0x{:X}", renderCamera));

        // Lambda to log matrix info for a camera
        auto LogCameraMatrices = [this](const char* name, uintptr_t camPtr) {
            if (camPtr == 0) {
                LogInfo(std::format("  {} is NULL", name));
                return;
            }

            LogInfo(std::format("--- {} (0x{:X}) ---", name, camPtr));

            // Read position first
            DirectX::XMFLOAT3 pos{};
            if (SafeReadFloat3(camPtr + CameraOffsets::Position, pos)) {
                LogInfo(std::format("  Position (0x100): ({:.2f}, {:.2f}, {:.2f})", pos.x, pos.y, pos.z));
            } else {
                LogInfo("  Position (0x100): FAILED TO READ");
            }

            // Read View matrix at 0x40
            DirectX::XMMATRIX viewMat;
            DirectX::XMFLOAT4X4 viewFloat;
            if (SafeReadMatrix(camPtr + CameraOffsets::ViewMatrix, viewMat)) {
                DirectX::XMStoreFloat4x4(&viewFloat, viewMat);
                
                // Check if it looks valid
                bool hasNaN = std::isnan(viewFloat._11);
                bool isIdentityLike = std::abs(viewFloat._11 - 1.0f) < 0.01f && 
                                      std::abs(viewFloat._22 - 1.0f) < 0.01f &&
                                      std::abs(viewFloat._33 - 1.0f) < 0.01f;
                bool isZero = std::abs(viewFloat._11) < 0.0001f && std::abs(viewFloat._22) < 0.0001f;
                bool hasWorldPos = std::abs(viewFloat._41) > 10.0f || std::abs(viewFloat._43) > 10.0f;
                
                const char* verdict = "UNKNOWN";
                if (hasNaN) verdict = "GARBAGE (NaN)";
                else if (isZero) verdict = "GARBAGE (all zeros)";
                else if (isIdentityLike && !hasWorldPos) verdict = "IDENTITY (not set)";
                else if (hasWorldPos) verdict = "LOOKS VALID (has world coords)";
                else verdict = "LOOKS LIKE ROTATION ONLY";

                LogInfo(std::format("  View Matrix (0x40): {}", verdict));
                LogInfo(std::format("    Row0: [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                    viewFloat._11, viewFloat._12, viewFloat._13, viewFloat._14));
                LogInfo(std::format("    Row1: [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                    viewFloat._21, viewFloat._22, viewFloat._23, viewFloat._24));
                LogInfo(std::format("    Row2: [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                    viewFloat._31, viewFloat._32, viewFloat._33, viewFloat._34));
                LogInfo(std::format("    Row3: [{:8.4f} {:8.4f} {:8.4f} {:8.4f}] (Translation)", 
                    viewFloat._41, viewFloat._42, viewFloat._43, viewFloat._44));
            } else {
                LogInfo("  View Matrix (0x40): FAILED TO READ");
            }

            // Read Projection matrix at 0x80
            DirectX::XMMATRIX projMat;
            DirectX::XMFLOAT4X4 projFloat;
            if (SafeReadMatrix(camPtr + CameraOffsets::ProjectionMatrix, projMat)) {
                DirectX::XMStoreFloat4x4(&projFloat, projMat);
                
                // Projection matrix characteristics:
                // - _11 is (cot(fov/2) / aspect) or similar, typically 0.5-3.0
                // - _22 is cot(fov/2), typically 0.5-3.0
                // - _33 is far/(far-near), typically 0.9-1.0 for large far plane
                // - _43 is -near*far/(far-near) or -near, typically negative
                // - _34 is 1.0 for perspective (to store Z in W for perspective divide)
                bool hasNaN = std::isnan(projFloat._11);
                bool looksLikePerspective = !hasNaN &&
                    std::abs(projFloat._11) > 0.1f && std::abs(projFloat._11) < 10.0f &&
                    std::abs(projFloat._22) > 0.1f && std::abs(projFloat._22) < 10.0f &&
                    (std::abs(projFloat._34 - 1.0f) < 0.01f || std::abs(projFloat._34 + 1.0f) < 0.01f);  // ±1 for perspective
                bool isZero = std::abs(projFloat._11) < 0.0001f && std::abs(projFloat._22) < 0.0001f;

                const char* verdict = "UNKNOWN";
                if (hasNaN) verdict = "GARBAGE (NaN)";
                else if (isZero) verdict = "GARBAGE (all zeros)";
                else if (looksLikePerspective) verdict = "LOOKS LIKE PERSPECTIVE PROJECTION";
                else verdict = "NOT PERSPECTIVE";

                LogInfo(std::format("  Proj Matrix (0x80): {}", verdict));
                LogInfo(std::format("    Row0: [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                    projFloat._11, projFloat._12, projFloat._13, projFloat._14));
                LogInfo(std::format("    Row1: [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                    projFloat._21, projFloat._22, projFloat._23, projFloat._24));
                LogInfo(std::format("    Row2: [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                    projFloat._31, projFloat._32, projFloat._33, projFloat._34));
                LogInfo(std::format("    Row3: [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                    projFloat._41, projFloat._42, projFloat._43, projFloat._44));
            } else {
                LogInfo("  Proj Matrix (0x80): FAILED TO READ");
            }

            // Also check 0xC0 for possible ViewProjection combined matrix
            DirectX::XMMATRIX vpMat;
            DirectX::XMFLOAT4X4 vpFloat;
            if (SafeReadMatrix(camPtr + CameraOffsets::ViewProjection, vpMat)) {
                DirectX::XMStoreFloat4x4(&vpFloat, vpMat);
                
                bool hasNaN = std::isnan(vpFloat._11);
                bool isZero = std::abs(vpFloat._11) < 0.0001f && std::abs(vpFloat._22) < 0.0001f;
                
                if (!hasNaN && !isZero) {
                    LogInfo("  VP Matrix (0xC0): HAS DATA");
                    LogInfo(std::format("    Row0: [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                        vpFloat._11, vpFloat._12, vpFloat._13, vpFloat._14));
                    LogInfo(std::format("    Row3: [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                        vpFloat._41, vpFloat._42, vpFloat._43, vpFloat._44));
                } else {
                    LogInfo(std::format("  VP Matrix (0xC0): {} ", hasNaN ? "NaN" : "ZEROS"));
                }
            }
        };

        LogCameraMatrices("ActiveCamera", activeCamera);
        LogCameraMatrices("RenderCamera", renderCamera);

        // Also check Camera1 and Camera2 if they're different
        uintptr_t camera1 = 0, camera2 = 0;
        SafeRead(cameraManagerInstance + CameraManagerOffsets::Camera1, camera1);  // 0x48
        SafeRead(cameraManagerInstance + CameraManagerOffsets::Camera2, camera2);  // 0x50
        
        if (camera1 != 0 && camera1 != activeCamera && camera1 != renderCamera) {
            LogCameraMatrices("Camera1 (0x48)", camera1);
        }
        if (camera2 != 0 && camera2 != activeCamera && camera2 != renderCamera && camera2 != camera1) {
            LogCameraMatrices("Camera2 (0x50)", camera2);
        }

        LogInfo("=== End Comparison ===");
        LogInfo("VERDICT: Use the camera with 'LOOKS VALID' or 'PERSPECTIVE PROJECTION' matrices");
    }

    // ============================================
    // Debug: Dump matrices at IDA-verified offsets
    // This is the key verification function per the implementation checklist:
    // - ViewMatrix at 0x40 (verified via sub_7FF69B45BF30)
    // - ProjMatrix at 0x80 (from IDA analysis)
    // - ViewProj at 0xC0 (from IDA analysis)
    // ============================================
    void GameCameraExtractor::DumpVerifiedMatrices() {
        if (!m_initialized.load()) {
            LogWarning("GameCameraExtractor::DumpVerifiedMatrices: Not initialized");
            return;
        }

        std::lock_guard<std::mutex> lock(m_mutex);

        LogInfo("======================================================================");
        LogInfo("  IDA-VERIFIED MATRIX DUMP (December 2025)");
        LogInfo("======================================================================");
        LogInfo(std::format("Camera Manager Global: 0x{:X}", m_cameraManagerPtr));
        LogInfo(std::format("Found via: {}", m_foundSignatureName));

        // Read camera manager instance
        uintptr_t cameraManagerInstance = 0;
        if (!SafeRead(m_cameraManagerPtr, cameraManagerInstance)) {
            LogError("Failed to read camera manager instance");
            return;
        }
        LogInfo(std::format("Camera Manager Instance: 0x{:X}", cameraManagerInstance));

        // Try both camera offsets - 0x20 (CameraList) has the real camera based on memory dump
        uintptr_t camera20 = 0, camera40 = 0;
        SafeRead(cameraManagerInstance + 0x20, camera20);
        SafeRead(cameraManagerInstance + CameraManagerOffsets::ActiveCamera, camera40);
        
        LogInfo(std::format("Camera at 0x20: 0x{:X}", camera20));
        LogInfo(std::format("Camera at 0x40: 0x{:X}", camera40));
        
        // Use camera at 0x20 - it has valid world coordinates based on dump
        uintptr_t activeCamera = camera20;
        if (activeCamera == 0 || activeCamera < 0x10000) {
            activeCamera = camera40;  // Fallback to 0x40
        }
        
        LogInfo(std::format("Using Camera: 0x{:X}", activeCamera));

        if (activeCamera == 0) {
            LogError("No valid camera found");
            return;
        }

        // Read position at 0x100 (verified)
        DirectX::XMFLOAT3 cameraPos{};
        if (SafeReadFloat3(activeCamera + CameraOffsets::Position, cameraPos)) {
            LogInfo(std::format("Position (0x100): ({:.2f}, {:.2f}, {:.2f})", 
                cameraPos.x, cameraPos.y, cameraPos.z));
        } else {
            LogWarning("Failed to read position at 0x100");
        }

        // Lambda to dump a matrix with validation
        auto DumpMatrix = [this](uintptr_t baseAddr, size_t offset, const char* name) {
            DirectX::XMMATRIX mat;
            if (!SafeReadMatrix(baseAddr + offset, mat)) {
                LogInfo(std::format("  {} (0x{:02X}): FAILED TO READ", name, offset));
                return;
            }

            DirectX::XMFLOAT4X4 m;
            DirectX::XMStoreFloat4x4(&m, mat);

            // Validate matrix
            bool hasNaN = false;
            bool allZero = true;
            bool hasLargeValue = false;
            for (int r = 0; r < 4; ++r) {
                for (int c = 0; c < 4; ++c) {
                    float v = (&m._11)[r * 4 + c];
                    if (std::isnan(v) || std::isinf(v)) hasNaN = true;
                    if (std::abs(v) > 0.0001f) allZero = false;
                    if (std::abs(v) > 10000.0f) hasLargeValue = true;
                }
            }

            // Determine matrix type
            std::string verdict = "UNKNOWN";
            if (hasNaN) {
                verdict = "GARBAGE (NaN/Inf)";
            } else if (allZero) {
                verdict = "ZEROS (not set)";
            } else if (hasLargeValue) {
                verdict = "SUSPECT (large values)";
            } else {
                // Check if it looks like a view matrix (orthonormal 3x3 + translation)
                float det3x3 = m._11 * (m._22 * m._33 - m._23 * m._32)
                             - m._12 * (m._21 * m._33 - m._23 * m._31)
                             + m._13 * (m._21 * m._32 - m._22 * m._31);
                bool isOrthonormal = std::abs(std::abs(det3x3) - 1.0f) < 0.1f;
                
                // Check for projection matrix pattern
                bool hasZeroPattern = std::abs(m._12) < 0.01f && std::abs(m._13) < 0.01f && 
                                      std::abs(m._21) < 0.01f && std::abs(m._23) < 0.01f;
                bool hasPerspective = (std::abs(m._34 - 1.0f) < 0.01f || std::abs(m._34 + 1.0f) < 0.01f);
                
                if (isOrthonormal && std::abs(m._44 - 1.0f) < 0.01f) {
                    verdict = "VIEW MATRIX (orthonormal + w=1)";
                } else if (hasZeroPattern && hasPerspective && std::abs(m._44) < 0.01f) {
                    verdict = "PROJECTION MATRIX (perspective)";
                } else if (std::abs(m._44) > 0.001f) {
                    verdict = "VIEWPROJECTION or OTHER";
                } else {
                    verdict = "DATA (unknown type)";
                }
            }

            LogInfo(std::format("  {} (0x{:02X}): {}", name, offset, verdict));
            LogInfo(std::format("    [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m._11, m._12, m._13, m._14));
            LogInfo(std::format("    [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m._21, m._22, m._23, m._24));
            LogInfo(std::format("    [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m._31, m._32, m._33, m._34));
            LogInfo(std::format("    [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m._41, m._42, m._43, m._44));
        };

        LogInfo("----------------------------------------------------------------------");
        LogInfo("VERIFIED OFFSETS FROM IDA ANALYSIS:");
        LogInfo("----------------------------------------------------------------------");
        
        DumpMatrix(activeCamera, CameraOffsets::ViewMatrix, "ViewMatrix");        // 0x40
        DumpMatrix(activeCamera, CameraOffsets::ProjectionMatrix, "ProjMatrix");  // 0x80
        DumpMatrix(activeCamera, CameraOffsets::ViewProjection, "ViewProj");      // 0xC0

        LogInfo("----------------------------------------------------------------------");
        LogInfo("FALLBACK OFFSETS (if above don't work):");
        LogInfo("----------------------------------------------------------------------");
        
        DumpMatrix(activeCamera, CameraOffsets::ProjMatrix_Alt1, "ProjAlt1");     // 0x90
        DumpMatrix(activeCamera, CameraOffsets::ProjMatrix_Alt2, "ProjAlt2");     // 0xA0
        DumpMatrix(activeCamera, CameraOffsets::ViewMatrix_Alt2, "ViewAlt2");     // 0x10

        LogInfo("----------------------------------------------------------------------");
        LogInfo("RENDER CAMERA (via 0xE0 pointer) - FFXIVClientStructs approach:");
        LogInfo("----------------------------------------------------------------------");
        
        // Check if 0xE0 is a pointer to Render::Camera structure
        uintptr_t renderCameraPtr = 0;
        if (SafeRead(activeCamera + CameraOffsets::RenderCameraPtr, renderCameraPtr)) {
            LogInfo(std::format("Value at 0xE0: 0x{:X}", renderCameraPtr));
            
            // Check if it looks like a valid pointer (not float data)
            bool looksLikePointer = (renderCameraPtr > 0x10000) && 
                                    (renderCameraPtr < 0x800000000000ULL) &&
                                    ((renderCameraPtr & 0x7) == 0);  // 8-byte aligned
            
            if (looksLikePointer) {
                LogInfo(std::format("  --> Following pointer to Render::Camera at 0x{:X}", renderCameraPtr));
                
                // FFXIVClientStructs Render::Camera offsets:
                //   0x10 = ViewMatrix (4x4)
                //   0x1A0 = ProjectionMatrix (4x4)
                DumpMatrix(renderCameraPtr, 0x10, "RenderCam.View");
                DumpMatrix(renderCameraPtr, 0x50, "RenderCam.Proj2");
                DumpMatrix(renderCameraPtr, 0x1A0, "RenderCam.Proj");
                
                // Also try some other offsets that might have matrices
                DumpMatrix(renderCameraPtr, 0x00, "RenderCam.+0x00");
                DumpMatrix(renderCameraPtr, 0x40, "RenderCam.+0x40");
                DumpMatrix(renderCameraPtr, 0x80, "RenderCam.+0x80");
                DumpMatrix(renderCameraPtr, 0xC0, "RenderCam.+0xC0");
                DumpMatrix(renderCameraPtr, 0x100, "RenderCam.+0x100");
                DumpMatrix(renderCameraPtr, 0x140, "RenderCam.+0x140");
            } else {
                // Not a pointer - might be float data (part of ViewProjection matrix row 2)
                float floatVal = 0;
                SafeRead(activeCamera + CameraOffsets::RenderCameraPtr, floatVal);
                LogInfo(std::format("  --> NOT a pointer, value as float: {:.6f}", floatVal));
            }
        } else {
            LogInfo("  --> Failed to read value at 0xE0");
        }

        LogInfo("----------------------------------------------------------------------");
        LogInfo("VALIDATION CHECKS:");
        LogInfo("----------------------------------------------------------------------");
        
        // Read FOV, near/far to validate projection matrix
        float fov = 0, nearClip = 0, farClip = 0;
        SafeReadFloat(activeCamera + CameraOffsets::FovY, fov);
        SafeReadFloat(activeCamera + CameraOffsets::NearClip, nearClip);
        SafeReadFloat(activeCamera + CameraOffsets::FarClip, farClip);
        
        LogInfo(std::format("  FovY (0x114): {:.4f} rad ({:.1f} deg)", fov, fov * 180.0f / 3.14159f));
        LogInfo(std::format("  NearClip (0x118): {:.4f}", nearClip));
        LogInfo(std::format("  FarClip (0x11C): {:.4f}", farClip));
        
        // Expected projection matrix values based on FOV
        if (fov > 0.1f && fov < 3.14159f) {
            float cotHalfFov = 1.0f / std::tan(fov * 0.5f);
            LogInfo(std::format("  Expected Proj[1][1] (cot(fov/2)): ~{:.4f}", cotHalfFov));
        }

        LogInfo("======================================================================");
        LogInfo("NEXT STEPS:");
        LogInfo("  1. If ViewMatrix shows VIEW MATRIX - offset 0x40 is correct");
        LogInfo("  2. If ProjMatrix shows PROJECTION MATRIX - offset 0x80 is correct");  
        LogInfo("  3. If ViewProj shows data - offset 0xC0 has pre-computed VP");
        LogInfo("  4. Move camera and run again to verify matrices change");
        LogInfo("======================================================================");
        
        // RAW DUMP: Show ALL 16-float blocks from 0x00 to 0x200 without filtering
        LogInfo("");
        LogInfo("======================================================================");
        LogInfo("RAW MATRIX DUMP (every 0x40 bytes, no filtering):");
        LogInfo("======================================================================");
        
        for (size_t offset = 0; offset <= 0x1C0; offset += 0x40) {
            float m[16] = {};
            bool readable = true;
            for (int i = 0; i < 16; ++i) {
                if (!SafeRead(activeCamera + offset + i * sizeof(float), m[i])) {
                    readable = false;
                    break;
                }
            }
            
            if (readable) {
                LogInfo(std::format("Offset 0x{:03X}:", offset));
                LogInfo(std::format("  Row0: [{:12.4f} {:12.4f} {:12.4f} {:12.4f}]", m[0], m[1], m[2], m[3]));
                LogInfo(std::format("  Row1: [{:12.4f} {:12.4f} {:12.4f} {:12.4f}]", m[4], m[5], m[6], m[7]));
                LogInfo(std::format("  Row2: [{:12.4f} {:12.4f} {:12.4f} {:12.4f}]", m[8], m[9], m[10], m[11]));
                LogInfo(std::format("  Row3: [{:12.4f} {:12.4f} {:12.4f} {:12.4f}]", m[12], m[13], m[14], m[15]));
            } else {
                LogInfo(std::format("Offset 0x{:03X}: FAILED TO READ", offset));
            }
        }
        LogInfo("======================================================================");
        
        // Also probe camera at 0x40 (different structure)
        if (camera40 != 0 && camera40 > 0x10000) {
            LogInfo("");
            LogInfo("======================================================================");
            LogInfo(std::format("CAMERA AT 0x40 (0x{:X}) - RAW DUMP:", camera40));
            LogInfo("======================================================================");
            
            for (size_t offset = 0; offset <= 0x1C0; offset += 0x40) {
                float m[16] = {};
                bool readable = true;
                for (int i = 0; i < 16; ++i) {
                    if (!SafeRead(camera40 + offset + i * sizeof(float), m[i])) {
                        readable = false;
                        break;
                    }
                }
                
                if (readable) {
                    // Check if this looks like a valid matrix (has values between -100 and 100, some near 1.0)
                    bool hasReasonable = true;
                    bool hasNearOne = false;
                    for (int i = 0; i < 16; ++i) {
                        if (std::abs(m[i]) > 10000.0f) hasReasonable = false;
                        if (std::abs(m[i] - 1.0f) < 0.1f || std::abs(m[i] + 1.0f) < 0.1f) hasNearOne = true;
                    }
                    
                    std::string tag = (hasReasonable && hasNearOne) ? " <-- POTENTIAL MATRIX" : "";
                    LogInfo(std::format("Offset 0x{:03X}:{}", offset, tag));
                    LogInfo(std::format("  Row0: [{:12.4f} {:12.4f} {:12.4f} {:12.4f}]", m[0], m[1], m[2], m[3]));
                    LogInfo(std::format("  Row1: [{:12.4f} {:12.4f} {:12.4f} {:12.4f}]", m[4], m[5], m[6], m[7]));
                    LogInfo(std::format("  Row2: [{:12.4f} {:12.4f} {:12.4f} {:12.4f}]", m[8], m[9], m[10], m[11]));
                    LogInfo(std::format("  Row3: [{:12.4f} {:12.4f} {:12.4f} {:12.4f}]", m[12], m[13], m[14], m[15]));
                }
            }
            LogInfo("======================================================================");
        }
        
        // NEW: Search for rotation/angle data by looking at single float offsets
        LogInfo("");
        LogInfo("======================================================================");
        LogInfo("SEARCHING FOR ROTATION/ANGLE DATA (single floats):");
        LogInfo("======================================================================");
        
        // From IDA: CalculateViewMatrix reads angles from [rcx+0x70], [rcx+0x74], [rcx+0x78]
        // But dump showed 0x70 is part of garbage matrix. Search wider range.
        
        // Look for angles (values between -2π and 2π) or small values (-10 to 10)
        LogInfo(std::format("Camera at 0x20 (0x{:X}):", activeCamera));
        for (size_t offset = 0; offset <= 0x200; offset += 0x4) {
            float val = 0;
            if (SafeRead(activeCamera + offset, val)) {
                // Skip NaN, Inf, very large values, zeros
                if (std::isnan(val) || std::isinf(val)) continue;
                if (std::abs(val) > 1000.0f) continue;
                if (std::abs(val) < 0.0001f) continue;
                
                // Flag potential angles (π, π/2, small values)
                bool isPi = std::abs(std::abs(val) - 3.14159f) < 0.01f;
                bool isPiHalf = std::abs(std::abs(val) - 1.5708f) < 0.01f;
                bool isSmallAngle = std::abs(val) < 6.3f && std::abs(val) > 0.01f;  // < 2π
                bool isWorldCoord = std::abs(val) > 10.0f && std::abs(val) < 1000.0f;
                
                std::string tag = "";
                if (isPi) tag = " <-- PI (180 deg)";
                else if (isPiHalf) tag = " <-- PI/2 (90 deg)";
                else if (isSmallAngle && !isWorldCoord) tag = " <-- ANGLE?";
                else if (isWorldCoord) tag = " <-- WORLD COORD?";
                
                if (!tag.empty() || (std::abs(val) > 0.1f && std::abs(val) < 50.0f)) {
                    LogInfo(std::format("  0x{:03X}: {:12.6f}{}", offset, val, tag));
                }
            }
        }
        
        // Same for camera at 0x40
        if (camera40 != 0 && camera40 > 0x10000) {
            LogInfo(std::format("Camera at 0x40 (0x{:X}):", camera40));
            for (size_t offset = 0; offset <= 0x100; offset += 0x4) {
                float val = 0;
                if (SafeRead(camera40 + offset, val)) {
                    if (std::isnan(val) || std::isinf(val)) continue;
                    if (std::abs(val) > 1000.0f) continue;
                    if (std::abs(val) < 0.0001f) continue;
                    
                    bool isPi = std::abs(std::abs(val) - 3.14159f) < 0.01f;
                    bool isPiHalf = std::abs(std::abs(val) - 1.5708f) < 0.01f;
                    bool isSmallAngle = std::abs(val) < 6.3f && std::abs(val) > 0.01f;
                    bool isZoomDist = std::abs(val) >= 1.0f && std::abs(val) <= 50.0f;
                    
                    std::string tag = "";
                    if (isPi) tag = " <-- PI";
                    else if (isPiHalf) tag = " <-- PI/2 (FOV?)";
                    else if (isSmallAngle) tag = " <-- ANGLE?";
                    else if (isZoomDist) tag = " <-- ZOOM/DIST?";
                    
                    if (!tag.empty()) {
                        LogInfo(std::format("  0x{:03X}: {:12.6f}{}", offset, val, tag));
                    }
                }
            }
        }
        
        // NEW: Comprehensive matrix scan - check ALL 16-byte aligned offsets
        LogInfo("======================================================================");
        LogInfo("COMPREHENSIVE MATRIX SCAN (all 16-byte aligned offsets 0x00-0x300):");
        LogInfo("======================================================================");
        
        int validMatrixCount = 0;
        for (size_t offset = 0; offset <= 0x300; offset += 0x10) {
            float m[16] = {};
            bool readable = true;
            for (int i = 0; i < 16; ++i) {
                if (!SafeRead(activeCamera + offset + i * sizeof(float), m[i])) {
                    readable = false;
                    break;
                }
            }
            
            if (!readable) continue;
            
            // Check for valid matrix characteristics:
            // 1. No NaN/Inf
            // 2. Not all zeros
            // 3. Has at least one value near 1.0 or -1.0
            // 4. All values within reasonable range (-100 to 100 for most, translation can be larger)
            
            bool hasNaN = false;
            bool allZero = true;
            bool hasUnitValue = false;
            bool hasLargeValue = false;
            float sumAbs = 0;
            
            for (int i = 0; i < 16; ++i) {
                if (std::isnan(m[i]) || std::isinf(m[i])) hasNaN = true;
                if (std::abs(m[i]) > 0.0001f) allZero = false;
                if (std::abs(std::abs(m[i]) - 1.0f) < 0.1f) hasUnitValue = true;
                if (std::abs(m[i]) > 1000.0f) hasLargeValue = true;
                sumAbs += std::abs(m[i]);
            }
            
            // Skip garbage data
            if (hasNaN || allZero || !hasUnitValue) continue;
            if (hasLargeValue && sumAbs > 50000.0f) continue;  // Probably not a matrix
            
            // Count zeros in upper-left 3x3 (projection matrices have specific patterns)
            int upperLeftZeros = 0;
            if (std::abs(m[1]) < 0.01f) upperLeftZeros++;  // m[0][1]
            if (std::abs(m[2]) < 0.01f) upperLeftZeros++;  // m[0][2]
            if (std::abs(m[4]) < 0.01f) upperLeftZeros++;  // m[1][0]
            if (std::abs(m[6]) < 0.01f) upperLeftZeros++;  // m[1][2]
            if (std::abs(m[8]) < 0.01f) upperLeftZeros++;  // m[2][0]
            if (std::abs(m[9]) < 0.01f) upperLeftZeros++;  // m[2][1]
            
            // Check for view matrix: orthonormal upper 3x3
            float det3x3 = m[0] * (m[5] * m[10] - m[6] * m[9])
                         - m[1] * (m[4] * m[10] - m[6] * m[8])
                         + m[2] * (m[4] * m[9] - m[5] * m[8]);
            bool isOrthonormal = std::abs(std::abs(det3x3) - 1.0f) < 0.1f;
            
            // Check for projection matrix: specific pattern of zeros and _34 = +/-1
            bool isProjPattern = upperLeftZeros >= 4 && (std::abs(m[11] - 1.0f) < 0.1f || std::abs(m[11] + 1.0f) < 0.1f);
            
            std::string matrixType = "UNKNOWN";
            if (isOrthonormal && std::abs(m[15] - 1.0f) < 0.1f) {
                matrixType = "** VIEW MATRIX **";
            } else if (isProjPattern && std::abs(m[15]) < 0.1f) {
                matrixType = "** PROJECTION MATRIX **";
            } else if (isOrthonormal) {
                matrixType = "Rotation-like";
            } else if (upperLeftZeros >= 3) {
                matrixType = "Sparse (proj-like)";
            }
            
            validMatrixCount++;
            LogInfo(std::format("Offset 0x{:03X}: {}", offset, matrixType));
            LogInfo(std::format("  [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m[0], m[1], m[2], m[3]));
            LogInfo(std::format("  [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m[4], m[5], m[6], m[7]));
            LogInfo(std::format("  [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m[8], m[9], m[10], m[11]));
            LogInfo(std::format("  [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m[12], m[13], m[14], m[15]));
            LogInfo(std::format("  det3x3={:.4f}, orthonormal={}, zeros={}", det3x3, isOrthonormal, upperLeftZeros));
        }
        
        LogInfo(std::format("Found {} potential matrices in camera structure", validMatrixCount));
        LogInfo("======================================================================");
        
        // NEW: Scan RenderManager for matrices (Graphics layer)
        if (m_renderManagerPtr != 0) {
            LogInfo("");
            LogInfo("======================================================================");
            LogInfo(std::format("RENDER MANAGER (0x{:X}) - MATRIX SCAN:", m_renderManagerPtr));
            LogInfo("======================================================================");
            
            int renderMatrixCount = 0;
            for (size_t offset = 0; offset <= 0x400; offset += 0x10) {
                float m[16] = {};
                bool readable = true;
                for (int i = 0; i < 16; ++i) {
                    if (!SafeRead(m_renderManagerPtr + offset + i * sizeof(float), m[i])) {
                        readable = false;
                        break;
                    }
                }
                
                if (!readable) continue;
                
                // Check for valid matrix
                bool hasNaN = false;
                bool allZero = true;
                bool hasUnitValue = false;
                bool hasLargeValue = false;
                
                for (int i = 0; i < 16; ++i) {
                    if (std::isnan(m[i]) || std::isinf(m[i])) hasNaN = true;
                    if (std::abs(m[i]) > 0.0001f) allZero = false;
                    if (std::abs(std::abs(m[i]) - 1.0f) < 0.1f) hasUnitValue = true;
                    if (std::abs(m[i]) > 10000.0f) hasLargeValue = true;
                }
                
                if (hasNaN || allZero || !hasUnitValue || hasLargeValue) continue;
                
                // Check for view/projection characteristics
                float det3x3 = m[0] * (m[5] * m[10] - m[6] * m[9])
                             - m[1] * (m[4] * m[10] - m[6] * m[8])
                             + m[2] * (m[4] * m[9] - m[5] * m[8]);
                bool isOrthonormal = std::abs(std::abs(det3x3) - 1.0f) < 0.1f;
                bool isProjPattern = (std::abs(m[11] - 1.0f) < 0.1f || std::abs(m[11] + 1.0f) < 0.1f) && std::abs(m[15]) < 0.1f;
                
                std::string matrixType = "";
                if (isOrthonormal && std::abs(m[15] - 1.0f) < 0.1f) {
                    matrixType = " ** VIEW MATRIX **";
                } else if (isProjPattern) {
                    matrixType = " ** PROJECTION MATRIX **";
                }
                
                renderMatrixCount++;
                LogInfo(std::format("Offset 0x{:03X}:{}", offset, matrixType));
                LogInfo(std::format("  [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m[0], m[1], m[2], m[3]));
                LogInfo(std::format("  [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m[4], m[5], m[6], m[7]));
                LogInfo(std::format("  [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m[8], m[9], m[10], m[11]));
                LogInfo(std::format("  [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m[12], m[13], m[14], m[15]));
            }
            
            LogInfo(std::format("Found {} potential matrices in RenderManager", renderMatrixCount));
            LogInfo("======================================================================");
        } else {
            LogInfo("");
            LogInfo("RenderManager not found - skipping Graphics layer matrix scan");
        }
        
        // NEW: Scan SceneCameraManager for camera pointers and matrices
        if (m_sceneCameraManagerPtr != 0) {
            LogInfo("");
            LogInfo("======================================================================");
            LogInfo(std::format("SCENE CAMERA MANAGER (0x{:X}) - POINTER & MATRIX SCAN:", m_sceneCameraManagerPtr));
            LogInfo("======================================================================");
            
            // First, dump pointers at various offsets to find camera objects
            LogInfo("Looking for camera pointers in SceneCameraManager:");
            uintptr_t firstValidSceneCamera = 0;    // Will do a raw dump of the first one
            uintptr_t cameraAt0x30 = 0;             // Specifically track 0x30 (known active camera offset)
            uintptr_t firstHeapCamera = 0;          // First heap object as fallback
            
            for (size_t offset = 0; offset <= 0x100; offset += 0x8) {
                uintptr_t ptr = 0;
                if (SafeRead(m_sceneCameraManagerPtr + offset, ptr) && ptr > 0x10000 && ptr < 0x7FFFFFFFFFFF) {
                    // Try to read vtable to see if this is a valid object
                    uintptr_t vtable = 0;
                    if (SafeRead(ptr, vtable) && vtable > 0x10000) {
                        LogInfo(std::format("  0x{:02X}: ptr=0x{:X}, vtable=0x{:X}", offset, ptr, vtable));
                        
                        // Store camera candidates - prefer heap objects (< 0x7FF0...) over module addresses
                        // Module addresses (0x7FF6...) are likely vtables/statics, not actual camera instances
                        bool isHeapObject = (ptr < 0x7FF000000000ULL);
                        
                        if (offset == 0x30 && isHeapObject) {
                            cameraAt0x30 = ptr;  // 0x30 is likely the active scene camera
                        } else if (firstHeapCamera == 0 && isHeapObject) {
                            firstHeapCamera = ptr;  // First heap object as fallback
                        }
                        
                        // Try to find matrices in this object
                        int foundMatrices = 0;
                        for (size_t matOffset = 0; matOffset <= 0x200; matOffset += 0x10) {
                            float m[16] = {};
                            bool readable = true;
                            for (int i = 0; i < 16; ++i) {
                                if (!SafeRead(ptr + matOffset + i * sizeof(float), m[i])) {
                                    readable = false;
                                    break;
                                }
                            }
                            
                            if (!readable) continue;
                            
                            // Quick validation
                            bool hasNaN = false;
                            bool allZero = true;
                            bool hasUnitValue = false;
                            bool hasLargeValue = false;
                            
                            for (int i = 0; i < 16; ++i) {
                                if (std::isnan(m[i]) || std::isinf(m[i])) hasNaN = true;
                                if (std::abs(m[i]) > 0.0001f) allZero = false;
                                if (std::abs(std::abs(m[i]) - 1.0f) < 0.1f) hasUnitValue = true;
                                if (std::abs(m[i]) > 10000.0f) hasLargeValue = true;
                            }
                            
                            if (hasNaN || allZero || !hasUnitValue || hasLargeValue) continue;
                            
                            // Found a potential matrix!
                            float det3x3 = m[0] * (m[5] * m[10] - m[6] * m[9])
                                         - m[1] * (m[4] * m[10] - m[6] * m[8])
                                         + m[2] * (m[4] * m[9] - m[5] * m[8]);
                            bool isOrthonormal = std::abs(std::abs(det3x3) - 1.0f) < 0.1f;
                            bool isProjPattern = (std::abs(m[11] - 1.0f) < 0.1f || std::abs(m[11] + 1.0f) < 0.1f) && std::abs(m[15]) < 0.1f;
                            
                            std::string matrixType = "";
                            if (isOrthonormal && std::abs(m[15] - 1.0f) < 0.1f) {
                                matrixType = " ** VIEW MATRIX **";
                            } else if (isProjPattern) {
                                matrixType = " ** PROJECTION MATRIX **";
                            }
                            
                            foundMatrices++;
                            LogInfo(std::format("    [ptr+0x{:03X}]{}", matOffset, matrixType));
                            LogInfo(std::format("      [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m[0], m[1], m[2], m[3]));
                            LogInfo(std::format("      [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m[4], m[5], m[6], m[7]));
                            LogInfo(std::format("      [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m[8], m[9], m[10], m[11]));
                            LogInfo(std::format("      [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", m[12], m[13], m[14], m[15]));
                        }
                        
                        if (foundMatrices > 0) {
                            LogInfo(std::format("    Found {} potential matrices in object at 0x{:X}", foundMatrices, ptr));
                        }
                    }
                }
            }
            
            // Select best camera: prefer 0x30 (known active camera offset), then first heap object
            firstValidSceneCamera = (cameraAt0x30 != 0) ? cameraAt0x30 : firstHeapCamera;
            if (cameraAt0x30 != 0) {
                LogInfo(std::format("\nSelected Scene Camera at 0x30: 0x{:X}", cameraAt0x30));
            } else if (firstHeapCamera != 0) {
                LogInfo(std::format("\nFallback: using first heap camera: 0x{:X}", firstHeapCamera));
            }
            
            // RAW DUMP of first valid Scene Camera object (no filtering)
            if (firstValidSceneCamera != 0) {
                LogInfo("");
                LogInfo("----------------------------------------------------------------------");
                LogInfo(std::format("RAW DUMP OF SCENE CAMERA OBJECT AT 0x{:X} (no filtering):", firstValidSceneCamera));
                LogInfo("----------------------------------------------------------------------");
                
                // FFXIVClientStructs Client::Graphics::Scene::Camera layout (approximate):
                //   0x00-0x50 = Object base / vtable / transform data
                //   0x50-0x90 = Unknown
                //   0x90-0xD0 = ViewMatrix (64 bytes)?
                //   0xD0-0x110 = ProjectionMatrix (64 bytes)?
                //   0x110-0x150 = ViewProjection (64 bytes)?
                // Also check Render::Camera at deeper offsets (0x1A0+ for matrices)
                
                // Dump 0x00 to 0x300 in 0x40 chunks to cover all possibilities
                for (size_t offset = 0x00; offset <= 0x2C0; offset += 0x40) {
                    float m[16] = {};
                    bool readable = true;
                    for (int i = 0; i < 16; ++i) {
                        if (!SafeRead(firstValidSceneCamera + offset + i * sizeof(float), m[i])) {
                            readable = false;
                            break;
                        }
                    }
                    
                    if (readable) {
                        // Check for reasonable values (not garbage)
                        bool hasNaN = false;
                        bool allZero = true;
                        bool hasLargeVal = false;
                        for (int i = 0; i < 16; ++i) {
                            if (std::isnan(m[i]) || std::isinf(m[i])) hasNaN = true;
                            if (std::abs(m[i]) > 0.0001f) allZero = false;
                            if (std::abs(m[i]) > 100000.0f) hasLargeVal = true;
                        }
                        
                        std::string status = "";
                        if (hasNaN) status = " [GARBAGE - NaN/Inf]";
                        else if (allZero) status = " [ZEROS]";
                        else if (hasLargeVal) status = " [LARGE VALUES]";
                        else {
                            // Check for view/proj patterns
                            float det = m[0]*(m[5]*m[10]-m[6]*m[9]) - m[1]*(m[4]*m[10]-m[6]*m[8]) + m[2]*(m[4]*m[9]-m[5]*m[8]);
                            bool ortho = std::abs(std::abs(det) - 1.0f) < 0.1f;
                            bool hasUnit = std::abs(m[15] - 1.0f) < 0.1f || std::abs(m[15] + 1.0f) < 0.1f;
                            bool projW = std::abs(m[15]) < 0.01f && (std::abs(m[11] - 1.0f) < 0.1f || std::abs(m[11] + 1.0f) < 0.1f);
                            
                            if (ortho && hasUnit) status = " ** LOOKS LIKE VIEW MATRIX **";
                            else if (projW) status = " ** LOOKS LIKE PROJECTION **";
                        }
                        
                        LogInfo(std::format("Offset 0x{:03X}:{}", offset, status));
                        LogInfo(std::format("  [{:12.6f} {:12.6f} {:12.6f} {:12.6f}]", m[0], m[1], m[2], m[3]));
                        LogInfo(std::format("  [{:12.6f} {:12.6f} {:12.6f} {:12.6f}]", m[4], m[5], m[6], m[7]));
                        LogInfo(std::format("  [{:12.6f} {:12.6f} {:12.6f} {:12.6f}]", m[8], m[9], m[10], m[11]));
                        LogInfo(std::format("  [{:12.6f} {:12.6f} {:12.6f} {:12.6f}]", m[12], m[13], m[14], m[15]));
                    }
                }
                LogInfo("----------------------------------------------------------------------");
            }
            
            LogInfo("======================================================================");
        } else {
            LogInfo("");
            LogInfo("SceneCameraManager not found - skipping pointer scan");
        }
    }

    // Explicit template instantiations for common types
    template bool GameCameraExtractor::SafeRead<uintptr_t>(uintptr_t, uintptr_t&) const;
    template bool GameCameraExtractor::SafeRead<uint32_t>(uintptr_t, uint32_t&) const;
    template bool GameCameraExtractor::SafeRead<float>(uintptr_t, float&) const;
    
    // ============================================
    // Get player position for menu bar display
    // ============================================
    DirectX::XMFLOAT3 GameCameraExtractor::GetPlayerPosition() const {
        return m_cachedPlayerPosition;
    }
    
    // ============================================
    // Get player position LIVE - re-reads entire pointer chain each call
    // This bypasses all caching to ensure we get the current position
    // ============================================
    DirectX::XMFLOAT3 GameCameraExtractor::GetPlayerPositionLive() const {
        // Re-read the entire pointer chain: CameraManagerPtr -> Instance -> Camera -> Position
        // This ensures we always get fresh data, even if m_activeCameraPtr is stale
        
        static int s_logCounter = 0;
        
        if (m_cameraManagerPtr == 0) {
            if (s_logCounter++ % 300 == 0) {
                LogDebug("[GetPlayerPositionLive] m_cameraManagerPtr is 0");
            }
            return DirectX::XMFLOAT3(0.0f, 0.0f, 0.0f);
        }
        
        // Step 1: Read camera manager instance from the global pointer
        uintptr_t cameraManagerInstance = 0;
        if (!SafeRead(m_cameraManagerPtr, cameraManagerInstance) || cameraManagerInstance == 0) {
            if (s_logCounter++ % 300 == 0) {
                LogDebug(std::format("[GetPlayerPositionLive] Failed to read cameraManagerInstance from 0x{:X}", m_cameraManagerPtr));
            }
            return DirectX::XMFLOAT3(0.0f, 0.0f, 0.0f);
        }
        
        // Step 2: Read active camera pointer from CameraManager+0x20
        uintptr_t cameraPtr = 0;
        if (!SafeRead(cameraManagerInstance + 0x20, cameraPtr) || cameraPtr == 0) {
            if (s_logCounter++ % 300 == 0) {
                LogDebug(std::format("[GetPlayerPositionLive] Failed to read cameraPtr from instance 0x{:X}+0x20", cameraManagerInstance));
            }
            return DirectX::XMFLOAT3(0.0f, 0.0f, 0.0f);
        }
        
        // Step 3: Read position from Camera+0xE0 (verified offset for 3.35)
        DirectX::XMFLOAT3 pos = {0.0f, 0.0f, 0.0f};
        if (!SafeReadFloat3(cameraPtr + CameraOffsets::Position, pos)) {
            if (s_logCounter++ % 300 == 0) {
                LogDebug(std::format("[GetPlayerPositionLive] Failed to read position from camera 0x{:X}+0xE0", cameraPtr));
            }
            return DirectX::XMFLOAT3(0.0f, 0.0f, 0.0f);
        }
        
        // Validate position isn't garbage
        if (std::isnan(pos.x) || std::abs(pos.x) > 50000.0f) {
            if (s_logCounter++ % 300 == 0) {
                LogDebug(std::format("[GetPlayerPositionLive] Invalid position: ({:.1f}, {:.1f}, {:.1f})", pos.x, pos.y, pos.z));
            }
            return DirectX::XMFLOAT3(0.0f, 0.0f, 0.0f);
        }
        
        // Log successful reads periodically
        if (s_logCounter++ % 300 == 0) {
            LogDebug(std::format("[GetPlayerPositionLive] SUCCESS: camera=0x{:X}, pos=({:.1f}, {:.1f}, {:.1f})", 
                cameraPtr, pos.x, pos.y, pos.z));
        }
        
        return pos;
    }

    // ============================================
    // Matrix Probing - Find best view/projection matrices
    // ============================================

    MatrixProbeResult GameCameraExtractor::ScoreMatrixAtOffset(uintptr_t basePtr, size_t offset, 
                                                                const DirectX::XMFLOAT3& knownCameraPos) {
        MatrixProbeResult result{};
        result.offset = offset;
        result.score = 0.0f;
        result.looksLikeView = false;
        result.looksLikeProjection = false;
        result.isIdentity = false;
        result.isValid = false;
        result.matrix = DirectX::XMMatrixIdentity();
        result.extractedCameraPos = DirectX::XMFLOAT3(0, 0, 0);

        // Read 16 floats at this offset
        float m[16] = {};
        bool readable = true;
        for (int i = 0; i < 16; ++i) {
            if (!SafeRead(basePtr + offset + i * sizeof(float), m[i])) {
                readable = false;
                break;
            }
        }

        if (!readable) {
            return result;
        }

        // Check for NaN/Inf
        for (int i = 0; i < 16; ++i) {
            if (std::isnan(m[i]) || std::isinf(m[i])) {
                return result;
            }
        }

        // Store the matrix
        DirectX::XMFLOAT4X4 matFloat(
            m[0], m[1], m[2], m[3],
            m[4], m[5], m[6], m[7],
            m[8], m[9], m[10], m[11],
            m[12], m[13], m[14], m[15]
        );
        result.matrix = DirectX::XMLoadFloat4x4(&matFloat);

        // Check if it's an identity matrix (useless)
        bool isIdentity = std::abs(m[0] - 1.0f) < 0.001f && 
                          std::abs(m[5] - 1.0f) < 0.001f && 
                          std::abs(m[10] - 1.0f) < 0.001f && 
                          std::abs(m[15] - 1.0f) < 0.001f &&
                          std::abs(m[1]) < 0.001f && std::abs(m[2]) < 0.001f && std::abs(m[3]) < 0.001f &&
                          std::abs(m[4]) < 0.001f && std::abs(m[6]) < 0.001f && std::abs(m[7]) < 0.001f &&
                          std::abs(m[8]) < 0.001f && std::abs(m[9]) < 0.001f && std::abs(m[11]) < 0.001f &&
                          std::abs(m[12]) < 0.001f && std::abs(m[13]) < 0.001f && std::abs(m[14]) < 0.001f;
        
        if (isIdentity) {
            result.isIdentity = true;
            return result;
        }

        // Check if it's all zeros (useless)
        float sumAbs = 0.0f;
        for (int i = 0; i < 16; ++i) sumAbs += std::abs(m[i]);
        if (sumAbs < 0.0001f) {
            return result;
        }

        float score = 1.0f;

        // === VIEW MATRIX CHARACTERISTICS ===
        // View matrix typically has:
        // - 3x3 rotation part with det = 1 (orthonormal)
        // - Last row is [0, 0, 0, 1]
        // - Last column (translation) has reasonable world coordinates

        // Check last row for [0, 0, 0, 1] (common for view matrices)
        bool lastRowValid = std::abs(m[12]) < 0.01f && 
                           std::abs(m[13]) < 0.01f && 
                           std::abs(m[14]) < 0.01f && 
                           std::abs(m[15] - 1.0f) < 0.01f;

        // Compute 3x3 determinant (should be near 1 for rotation matrix)
        float det3x3 = m[0] * (m[5] * m[10] - m[6] * m[9])
                     - m[1] * (m[4] * m[10] - m[6] * m[8])
                     + m[2] * (m[4] * m[9] - m[5] * m[8]);

        bool rotationLikelyOrthonormal = std::abs(std::abs(det3x3) - 1.0f) < 0.1f;

        // Check if translation (m[3], m[7], m[11]) looks like camera position
        // In row-major view matrix, translation is often in last column
        float transLen = std::sqrt(m[3]*m[3] + m[7]*m[7] + m[11]*m[11]);
        bool hasReasonableTranslation = transLen > 10.0f && transLen < 50000.0f;
        
        // Store extracted camera position from view matrix
        result.extractedCameraPos = DirectX::XMFLOAT3(m[3], m[7], m[11]);
        
        // Check if extracted position is close to known camera position
        float posDist = std::sqrt(
            (m[3] - knownCameraPos.x) * (m[3] - knownCameraPos.x) +
            (m[7] - knownCameraPos.y) * (m[7] - knownCameraPos.y) +
            (m[11] - knownCameraPos.z) * (m[11] - knownCameraPos.z)
        );
        bool positionMatches = posDist < 50.0f;  // Within 50 units

        if (lastRowValid && rotationLikelyOrthonormal) {
            result.looksLikeView = true;
            score += 5.0f;  // Strong view matrix candidate
            if (hasReasonableTranslation) score += 2.0f;
            if (positionMatches) score += 3.0f;  // Bonus for matching camera position
        }

        // === PROJECTION MATRIX CHARACTERISTICS ===
        // Perspective projection typically has:
        // - m[0] and m[5] are focal length related (positive, reasonable)
        // - m[10] contains depth range info
        // - m[11] = -1 (for RH) or 1 (for LH) 
        // - m[14] = near/far plane factor
        // - m[15] = 0 (perspective divide)
        // - Many zeros: m[1], m[2], m[3], m[4], m[6], m[7], m[8], m[9], m[12], m[13]

        bool hasProjectionZeros = std::abs(m[1]) < 0.001f && std::abs(m[2]) < 0.001f && std::abs(m[3]) < 0.001f &&
                                  std::abs(m[4]) < 0.001f && std::abs(m[6]) < 0.001f && std::abs(m[7]) < 0.001f &&
                                  std::abs(m[8]) < 0.001f && std::abs(m[9]) < 0.001f && 
                                  std::abs(m[12]) < 0.001f && std::abs(m[13]) < 0.001f;
        
        bool hasProjectionDiagonal = m[0] > 0.1f && m[0] < 10.0f &&   // Focal length X
                                     m[5] > 0.1f && m[5] < 10.0f;    // Focal length Y
        
        bool hasProjectionLastColumn = (std::abs(m[11] - 1.0f) < 0.01f || std::abs(m[11] + 1.0f) < 0.01f) &&
                                       std::abs(m[15]) < 0.01f;  // Perspective divide indicator

        if (hasProjectionZeros && hasProjectionDiagonal && hasProjectionLastColumn) {
            result.looksLikeProjection = true;
            score += 5.0f;  // Strong projection matrix candidate
        }

        // Penalize matrices with very large values (garbage)
        for (int i = 0; i < 16; ++i) {
            if (std::abs(m[i]) > 10000.0f) {
                score -= 2.0f;
            }
        }

        result.score = std::max(0.0f, score);
        result.isValid = result.score > 0.0f;
        return result;
    }

    std::vector<MatrixProbeResult> GameCameraExtractor::ProbeMatrixOffsets() {
        std::vector<MatrixProbeResult> results;
        
        // One-shot guard for verbose logging to avoid spam
        static bool s_loggedProbeOnce = false;
        const bool shouldLog = m_verboseLogging && !s_loggedProbeOnce;
        
        if (!m_initialized.load() || m_activeCameraPtr == 0) {
            if (shouldLog) {
                LogDebug("GameCameraExtractor::ProbeMatrixOffsets: No active camera");
            }
            return results;
        }

        std::lock_guard<std::mutex> lock(m_mutex);

        // Get known camera position for comparison
        DirectX::XMFLOAT3 knownCameraPos(0, 0, 0);
        SafeReadFloat3(m_activeCameraPtr + CameraOffsets::Position, knownCameraPos);

        // ===== PHASE 1: Probe the current camera (Scene::Camera) =====
        // Offsets to probe based on both IDA analysis (3.35) and FFXIVClientStructs (7.x)
        static constexpr size_t kSceneCameraOffsets[] = {
            0x00,   // ViewMatrix_Alt1
            0x10,   // ViewMatrix_Alt2, also Render::Camera.ViewMatrix
            0x40,   // ViewMatrix (3.35 IDA)
            0x50,   // ProjectionMatrix2
            0x80,   // ProjectionMatrix (3.35 IDA), also Scene::Camera.LookAt
            0xA0,   // Scene::Camera.ViewMatrix (FFXIVClientStructs 7.x)
            0xC0,   // ViewProjection (3.35 IDA)
            0x140,  // ViewMatrix_Alt3
            0x180,  // ProjMatrix_Alt3
            0x1A0,  // Render::Camera.ProjectionMatrix
        };

        MatrixProbeResult bestView{};
        MatrixProbeResult bestProj{};
        
        if (shouldLog) {
            LogDebug("=== Probing Matrix Offsets (Scene Camera) ===");
            LogDebug(std::format("Scene Camera at: 0x{:X}", m_activeCameraPtr));
            LogDebug(std::format("Known camera position: ({:.2f}, {:.2f}, {:.2f})", 
                knownCameraPos.x, knownCameraPos.y, knownCameraPos.z));
        }

        for (size_t offset : kSceneCameraOffsets) {
            MatrixProbeResult result = ScoreMatrixAtOffset(m_activeCameraPtr, offset, knownCameraPos);
            results.push_back(result);

            if (shouldLog && result.score > 0.0f) {
                DirectX::XMFLOAT4X4 matFloat;
                DirectX::XMStoreFloat4x4(&matFloat, result.matrix);
                
                std::string type = "";
                if (result.looksLikeView) type += "[VIEW] ";
                if (result.looksLikeProjection) type += "[PROJ] ";
                
                LogDebug(std::format("  Offset 0x{:03X}: Score={:.1f} {}", offset, result.score, type));
                LogDebug(std::format("    [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                    matFloat._11, matFloat._12, matFloat._13, matFloat._14));
                LogDebug(std::format("    [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                    matFloat._21, matFloat._22, matFloat._23, matFloat._24));
                LogDebug(std::format("    [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                    matFloat._31, matFloat._32, matFloat._33, matFloat._34));
                LogDebug(std::format("    [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                    matFloat._41, matFloat._42, matFloat._43, matFloat._44));
            }

            if (result.looksLikeView && result.score > bestView.score) {
                bestView = result;
            }
            if (result.looksLikeProjection && result.score > bestProj.score) {
                bestProj = result;
            }
        }

        // ===== PHASE 2: Try to follow RenderCamera pointer at 0xE0 =====
        // FFXIVClientStructs shows Scene::Camera has RenderCamera* at offset 0xE0
        uintptr_t renderCameraPtr = 0;
        if (SafeRead(m_activeCameraPtr + CameraOffsets::RenderCameraPtr, renderCameraPtr)) {
            // Validate pointer - should be in valid memory range
            if (renderCameraPtr > 0x10000 && renderCameraPtr < 0x7FFFFFFFFFFF) {
                if (shouldLog) {
                    LogDebug(std::format("=== Probing RenderCamera at 0x{:X} (from Scene::Camera+0xE0) ===", 
                        renderCameraPtr));
                }
                
                // Offsets within Render::Camera structure
                static constexpr size_t kRenderCameraOffsets[] = {
                    0x10,   // Render::Camera.ViewMatrix
                    0x50,   // Render::Camera.ProjectionMatrix2
                    0x90,   // Render::Camera.Origin
                    0x1A0,  // Render::Camera.ProjectionMatrix
                };
                
                for (size_t offset : kRenderCameraOffsets) {
                    MatrixProbeResult result = ScoreMatrixAtOffset(renderCameraPtr, offset, knownCameraPos);
                    result.offset = 0xE0 * 0x1000 + offset;  // Encode as RenderCamera offset for debugging
                    results.push_back(result);
                    
                    if (shouldLog && result.score > 0.0f) {
                        DirectX::XMFLOAT4X4 matFloat;
                        DirectX::XMStoreFloat4x4(&matFloat, result.matrix);
                        
                        std::string type = "";
                        if (result.looksLikeView) type += "[VIEW] ";
                        if (result.looksLikeProjection) type += "[PROJ] ";
                        
                        LogDebug(std::format("  RenderCam+0x{:03X}: Score={:.1f} {}", offset, result.score, type));
                        LogDebug(std::format("    [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                            matFloat._11, matFloat._12, matFloat._13, matFloat._14));
                    }
                    
                    if (result.looksLikeView && result.score > bestView.score) {
                        bestView = result;
                    }
                    if (result.looksLikeProjection && result.score > bestProj.score) {
                        bestProj = result;
                    }
                }
            }
        }

        // Update best matrices if found
        if (bestView.score > 0.0f) {
            m_bestViewMatrix = bestView.matrix;
            m_foundViewOffset = bestView.offset;
            if (shouldLog) {
                LogDebug(std::format("Best VIEW matrix at offset 0x{:03X} (score: {:.1f})", 
                    bestView.offset, bestView.score));
            }
        }
        
        if (bestProj.score > 0.0f) {
            m_bestProjMatrix = bestProj.matrix;
            m_foundProjOffset = bestProj.offset;
            if (shouldLog) {
                LogDebug(std::format("Best PROJ matrix at offset 0x{:03X} (score: {:.1f})", 
                    bestProj.offset, bestProj.score));
            }
        }

        m_hasValidMatrices = (bestView.score > 0.0f && bestProj.score > 0.0f);
        
        if (shouldLog) {
            LogDebug(std::format("=== Probe complete. Valid matrices: {} ===", m_hasValidMatrices ? "YES" : "NO"));
            s_loggedProbeOnce = true;
        }
        
        return results;
    }

    bool GameCameraExtractor::GetBestMatrices(DirectX::XMMATRIX& outView, DirectX::XMMATRIX& outProj) {
        // If we already have valid matrices (constructed or captured), return them without probing
        if (m_hasValidMatrices) {
            outView = m_bestViewMatrix;
            outProj = m_bestProjMatrix;
            return true;
        }

        // Only probe once - after that use cached matrices
        static bool s_probed = false;
        if (!s_probed) {
            ProbeMatrixOffsets();
            s_probed = true;
        }
        
        if (!m_hasValidMatrices) {
            return false;
        }
        
        outView = m_bestViewMatrix;
        outProj = m_bestProjMatrix;
        return true;
    }

    bool GameCameraExtractor::GetViewProjectionMatrix(DirectX::XMMATRIX& outViewProj) {
        // ===================================================================================
        // STRATEGY 0 (NEW): Try RenderManager path first (from decompiled sub_1403779D0)
        // ===================================================================================
        // This is the ACTUAL path the game uses to compute shader matrices:
        //   qword_1415E9E78 (g_RenderManager) -> +0xAD28 -> CameraData
        //   CameraData+16 = View, CameraData+80 = Projection
        // This should be the most accurate as it's what the game itself reads.
        // ===================================================================================
        if (GetRenderManagerViewProjection(outViewProj)) {
            return true;
        }
        
        // STRATEGY 1: Try MatrixCaptureHooks (captures when matrices are written to GPU)
        auto& matrixHooks = MatrixHooks::MatrixCaptureHooks::GetInstance();
        if (matrixHooks.IsInitialized() && matrixHooks.HasValidViewProjMatrix()) {
            outViewProj = matrixHooks.GetViewProjMatrix();
            return true;
        }
        
        // Fallback: If we have View and Projection from hooks, compute ViewProj
        if (matrixHooks.IsInitialized() && matrixHooks.HasValidViewMatrix() && matrixHooks.HasValidProjectionMatrix()) {
            DirectX::XMMATRIX view = matrixHooks.GetViewMatrix();
            DirectX::XMMATRIX proj = matrixHooks.GetProjectionMatrix();
            outViewProj = DirectX::XMMatrixMultiply(view, proj);
            return true;
        }

        // STRATEGY 2: If we have a cached camera with constructed matrices, use it
        if (m_cachedCamera.valid) {
            outViewProj = DirectX::XMMatrixMultiply(m_cachedCamera.view, m_cachedCamera.projection);
            return true;
        }
        
        // Original fallback strategies below
        if (!m_initialized.load() || m_activeCameraPtr == 0) {
            return false;
        }

        std::lock_guard<std::mutex> lock(m_mutex);

        // Run probing to find best matrices - only once per session
        static bool s_probingAttempted = false;
        if (!m_hasValidMatrices && !s_probingAttempted) {
            s_probingAttempted = true;
            
            DirectX::XMFLOAT3 knownCameraPos(0, 0, 0);
            SafeReadFloat3(m_activeCameraPtr + CameraOffsets::Position, knownCameraPos);
            
            LogInfo(std::format("[CameraExtractor] Probing camera at 0x{:X}, player pos ({:.1f}, {:.1f}, {:.1f})",
                m_activeCameraPtr, knownCameraPos.x, knownCameraPos.y, knownCameraPos.z));
            
            // Probe FFXIVClientStructs Scene::Camera offsets
            static constexpr size_t kProbeOffsets[] = {
                0xA0,   // Scene::Camera.ViewMatrix (FFXIVClientStructs)
                0x40,   // ViewMatrix (old 3.35 guess)
            };
            
            for (size_t offset : kProbeOffsets) {
                MatrixProbeResult result = ScoreMatrixAtOffset(m_activeCameraPtr, offset, knownCameraPos);
                if (result.looksLikeView && result.score > 0.5f) {
                    m_bestViewMatrix = result.matrix;
                    m_foundViewOffset = offset;
                    
                    // Found view - now look for projection at common offsets relative to this
                    static constexpr size_t kProjOffsets[] = { 0x80, 0xC0, 0x1A0 };
                    for (size_t projOffset : kProjOffsets) {
                        MatrixProbeResult projResult = ScoreMatrixAtOffset(m_activeCameraPtr, projOffset, knownCameraPos);
                        if (projResult.looksLikeProjection && projResult.score > 0.5f) {
                            m_bestProjMatrix = projResult.matrix;
                            m_foundProjOffset = projOffset;
                            m_hasValidMatrices = true;
                            
                            LogInfo(std::format("[CameraExtractor] Probed: View@0x{:X} (score {:.1f}), Proj@0x{:X} (score {:.1f})",
                                offset, result.score, projOffset, projResult.score));
                            break;
                        }
                    }
                    if (m_hasValidMatrices) break;
                }
            }
            
            // Try following RenderCamera pointer at 0xE0 (FFXIVClientStructs pattern)
            if (!m_hasValidMatrices) {
                uintptr_t renderCameraPtr = 0;
                if (SafeRead(m_activeCameraPtr + CameraOffsets::RenderCameraPtr, renderCameraPtr) &&
                    renderCameraPtr > 0x10000 && renderCameraPtr < 0x7FFFFFFFFFFF) {
                    
                    LogInfo(std::format("[CameraExtractor] Following RenderCamera ptr at 0xE0 -> 0x{:X}", renderCameraPtr));
                    
                    // Render::Camera offsets from FFXIVClientStructs
                    MatrixProbeResult viewResult = ScoreMatrixAtOffset(renderCameraPtr, 0x10, knownCameraPos);
                    MatrixProbeResult projResult = ScoreMatrixAtOffset(renderCameraPtr, 0x1A0, knownCameraPos);
                    
                    if (viewResult.looksLikeView && viewResult.score > 0.3f) {
                        m_bestViewMatrix = viewResult.matrix;
                        m_foundViewOffset = 0xE0 * 0x1000 + 0x10;  // Encoded as RenderCamera offset
                        
                        if (projResult.looksLikeProjection && projResult.score > 0.3f) {
                            m_bestProjMatrix = projResult.matrix;
                            m_foundProjOffset = 0xE0 * 0x1000 + 0x1A0;
                            m_hasValidMatrices = true;
                            
                            LogInfo(std::format("[CameraExtractor] Using RenderCamera matrices: View@0x10 (score {:.1f}), Proj@0x1A0 (score {:.1f})",
                                viewResult.score, projResult.score));
                        }
                    }
                }
            }
        }

        // STRATEGY 0: Try RenderManager for current render camera matrices
        // RenderManager is the Graphics layer - it has the actual ViewProjection used for rendering
        if (m_renderManagerPtr != 0) {
            uintptr_t renderManagerInstance = 0;
            if (SafeRead(m_renderManagerPtr, renderManagerInstance) && 
                renderManagerInstance != 0 && renderManagerInstance > 0x10000) {
                
                // RenderManager structure (from FFXIVClientStructs research):
                // The render camera with matrices is typically at an offset within RenderManager
                // Common offsets to check: 0x40, 0x48, 0x50, 0x58 (camera pointers)
                // Or matrices might be directly at offsets like 0x40, 0x80, 0xC0
                
                static constexpr size_t kRenderCameraOffsets[] = { 0x40, 0x48, 0x50, 0x58, 0x60 };
                
                for (size_t ptrOffset : kRenderCameraOffsets) {
                    uintptr_t cameraPtr = 0;
                    if (!SafeRead(renderManagerInstance + ptrOffset, cameraPtr)) continue;
                    if (cameraPtr == 0 || cameraPtr < 0x10000 || cameraPtr > 0x7FFFFFFFFFFF) continue;
                    
                    // Try reading View matrix at offset 0x40 within this camera
                    DirectX::XMMATRIX testView;
                    if (!SafeReadMatrix(cameraPtr + 0x40, testView)) continue;
                    
                    DirectX::XMFLOAT4X4 viewFloat;
                    DirectX::XMStoreFloat4x4(&viewFloat, testView);
                    
                    // Validate: View matrix should have orthonormal 3x3 (det ~= 1) and last row [0,0,0,1]
                    float det3x3 = viewFloat._11 * (viewFloat._22 * viewFloat._33 - viewFloat._23 * viewFloat._32)
                                 - viewFloat._12 * (viewFloat._21 * viewFloat._33 - viewFloat._23 * viewFloat._31)
                                 + viewFloat._13 * (viewFloat._21 * viewFloat._32 - viewFloat._22 * viewFloat._31);
                    
                    bool isOrthonormal = std::abs(std::abs(det3x3) - 1.0f) < 0.1f;
                    bool lastRowValid = std::abs(viewFloat._41) < 0.01f && 
                                       std::abs(viewFloat._42) < 0.01f && 
                                       std::abs(viewFloat._43) < 0.01f &&
                                       std::abs(viewFloat._44 - 1.0f) < 0.01f;
                    
                    if (isOrthonormal && lastRowValid) {
                        // Found a valid view matrix! Try to get projection at 0x80
                        DirectX::XMMATRIX testProj;
                        if (SafeReadMatrix(cameraPtr + 0x80, testProj)) {
                            DirectX::XMFLOAT4X4 projFloat;
                            DirectX::XMStoreFloat4x4(&projFloat, testProj);
                            
                            // Validate projection matrix pattern
                            bool isProjValid = projFloat._11 > 0.1f && projFloat._11 < 10.0f &&
                                              std::abs(projFloat._12) < 0.01f;
                            
                            if (isProjValid) {
                                outViewProj = DirectX::XMMatrixMultiply(testView, testProj);
                                
                                static bool s_loggedRenderMgr = false;
                                if (!s_loggedRenderMgr) {
                                    LogInfo(std::format("[CameraExtractor] Using RenderManager camera at 0x{:X}+0x{:X} -> 0x{:X}",
                                        renderManagerInstance, ptrOffset, cameraPtr));
                                    LogInfo(std::format("  View det={:.3f}, Proj[0,0]={:.3f}", det3x3, projFloat._11));
                                    s_loggedRenderMgr = true;
                                }
                                return true;
                            }
                        }
                        
                        // No projection found, try ViewProjection at 0xC0
                        DirectX::XMMATRIX testVP;
                        if (SafeReadMatrix(cameraPtr + 0xC0, testVP)) {
                            DirectX::XMFLOAT4X4 vpFloat;
                            DirectX::XMStoreFloat4x4(&vpFloat, testVP);
                            
                            if (!std::isnan(vpFloat._11) && std::abs(vpFloat._11) < 100.0f) {
                                outViewProj = testVP;
                                
                                static bool s_loggedRenderMgrVP = false;
                                if (!s_loggedRenderMgrVP) {
                                    LogInfo(std::format("[CameraExtractor] Using RenderManager camera VP at 0x{:X}+0x{:X} -> 0x{:X}+0xC0",
                                        renderManagerInstance, ptrOffset, cameraPtr));
                                    s_loggedRenderMgrVP = true;
                                }
                                return true;
                            }
                        }
                    }
                }
            }
        }
        
        // STRATEGY 1: Use probed best matrices (View * Proj)
        // This is the FFXIVClientStructs approach: ViewMatrix * RenderCamera->ProjectionMatrix
        if (m_hasValidMatrices) {
            outViewProj = DirectX::XMMatrixMultiply(m_bestViewMatrix, m_bestProjMatrix);
            
            static bool s_loggedProbed = false;
            if (!s_loggedProbed) {
                DirectX::XMFLOAT4X4 vpFloat;
                DirectX::XMStoreFloat4x4(&vpFloat, outViewProj);
                LogInfo(std::format("[CameraExtractor] Using PROBED View*Proj matrices (View@0x{:X}, Proj@0x{:X}):",
                    m_foundViewOffset, m_foundProjOffset));
                LogInfo(std::format("  [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                    vpFloat._11, vpFloat._12, vpFloat._13, vpFloat._14));
                LogInfo(std::format("  [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                    vpFloat._21, vpFloat._22, vpFloat._23, vpFloat._24));
                LogInfo(std::format("  [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                    vpFloat._31, vpFloat._32, vpFloat._33, vpFloat._34));
                LogInfo(std::format("  [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                    vpFloat._41, vpFloat._42, vpFloat._43, vpFloat._44));
                s_loggedProbed = true;
            }
            return true;
        }

        // STRATEGY 2: Try pre-computed ViewProjection matrix directly from 0xC0
        DirectX::XMMATRIX viewProj;
        if (!SafeReadMatrix(m_activeCameraPtr + CameraOffsets::ViewProjection, viewProj)) {
            return false;
        }
        
        // Validate the matrix - check it's not identity or garbage
        DirectX::XMFLOAT4X4 vpFloat;
        DirectX::XMStoreFloat4x4(&vpFloat, viewProj);
        
        // Check for identity matrix (indicates uninitialized)
        bool isIdentity = (std::abs(vpFloat._11 - 1.0f) < 0.001f &&
                          std::abs(vpFloat._22 - 1.0f) < 0.001f &&
                          std::abs(vpFloat._33 - 1.0f) < 0.001f &&
                          std::abs(vpFloat._44 - 1.0f) < 0.001f &&
                          std::abs(vpFloat._12) < 0.001f &&
                          std::abs(vpFloat._21) < 0.001f);
        
        if (isIdentity) {
            return false;
        }
        
        // Check for NaN or extreme values
        if (std::isnan(vpFloat._11) || std::isinf(vpFloat._11) || 
            std::abs(vpFloat._11) > 1000.0f) {
            return false;
        }
        
        // Log once on first successful read
        static bool s_loggedViewProjOnce = false;
        if (!s_loggedViewProjOnce) {
            LogDebug(std::format("[CameraExtractor] Using pre-computed ViewProjection at 0x{:X}+0xC0:",
                m_activeCameraPtr));
            LogDebug(std::format("  [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                vpFloat._11, vpFloat._12, vpFloat._13, vpFloat._14));
            LogDebug(std::format("  [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                vpFloat._21, vpFloat._22, vpFloat._23, vpFloat._24));
            LogDebug(std::format("  [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                vpFloat._31, vpFloat._32, vpFloat._33, vpFloat._34));
            LogDebug(std::format("  [{:8.4f} {:8.4f} {:8.4f} {:8.4f}]", 
                vpFloat._41, vpFloat._42, vpFloat._43, vpFloat._44));
            s_loggedViewProjOnce = true;
        }
        
        outViewProj = viewProj;
        return true;
    }

    // ===================================================================================
    // NEW: RenderManager path (from decompiled sub_1403779D0)
    // ===================================================================================
    // This is the actual path the game uses in sub_1403779D0 to compute shader matrices:
    //   v20 = *(_QWORD *)(qword_1415E9E78 + 44328);  // CameraData at offset 0xAD28
    //   sub_14017C1F0(v155, (float *)(v20 + 16), (float *)(v20 + 80)); // view * proj
    //
    // The matrices at CameraData+16 and CameraData+80 are the EXACT ones used for rendering.
    // ===================================================================================
    
    bool GameCameraExtractor::GetRenderManagerMatrices(DirectX::XMMATRIX& outView, DirectX::XMMATRIX& outProj) {
        if (m_renderManagerPtr == 0) {
            return false;
        }
        
        // Step 1: Read g_RenderManager instance
        uintptr_t renderManagerInstance = 0;
        if (!SafeRead(m_renderManagerPtr, renderManagerInstance) || renderManagerInstance == 0) {
            return false;
        }
        
        // Step 2: Read CameraData pointer at offset 0xAD28 (44328 decimal)
        uintptr_t cameraData = 0;
        if (!SafeRead(renderManagerInstance + RenderCameraOffsets::CameraDataOffset, cameraData) || cameraData == 0) {
            static bool s_loggedOnce = false;
            if (!s_loggedOnce) {
                LogDebug(std::format("[RenderMgr] CameraData at 0x{:X}+0xAD28 is NULL or failed to read", 
                    renderManagerInstance));
                s_loggedOnce = true;
            }
            return false;
        }
        
        // Step 3: Read View matrix at CameraData+16 (0x10)
        if (!SafeReadMatrix(cameraData + RenderCameraOffsets::ViewMatrix, outView)) {
            return false;
        }
        
        // Step 4: Read Projection matrix at CameraData+80 (0x50)
        if (!SafeReadMatrix(cameraData + RenderCameraOffsets::ProjectionMatrix, outProj)) {
            return false;
        }
        
        // Validate matrices are not garbage
        DirectX::XMFLOAT4X4 viewFloat, projFloat;
        DirectX::XMStoreFloat4x4(&viewFloat, outView);
        DirectX::XMStoreFloat4x4(&projFloat, outProj);
        
        if (std::isnan(viewFloat._11) || std::isnan(projFloat._11)) {
            return false;
        }
        
        // Log once on first successful read
        static bool s_loggedRenderMgrMatrices = false;
        if (!s_loggedRenderMgrMatrices) {
            LogInfo("[RenderMgr] Successfully reading matrices via RenderManager path!");
            LogInfo(std::format("  RenderManager: 0x{:X} -> Instance: 0x{:X}", m_renderManagerPtr, renderManagerInstance));
            LogInfo(std::format("  CameraData (0xAD28): 0x{:X}", cameraData));
            LogInfo(std::format("  View (CameraData+0x10): [{:.4f} {:.4f} {:.4f} {:.4f}]...", 
                viewFloat._11, viewFloat._12, viewFloat._13, viewFloat._14));
            LogInfo(std::format("  Proj (CameraData+0x50): [{:.4f} {:.4f} {:.4f} {:.4f}]...", 
                projFloat._11, projFloat._12, projFloat._13, projFloat._14));
            s_loggedRenderMgrMatrices = true;
        }
        
        return true;
    }
    
    bool GameCameraExtractor::GetRenderManagerViewProjection(DirectX::XMMATRIX& outViewProj) {
        DirectX::XMMATRIX view, proj;
        if (!GetRenderManagerMatrices(view, proj)) {
            return false;
        }
        
        // Compute ViewProjection = View * Projection (same as sub_14017C1F0 does)
        outViewProj = DirectX::XMMatrixMultiply(view, proj);
        return true;
    }
    
    DirectX::XMFLOAT3 GameCameraExtractor::GetRenderManagerCameraPosition() {
        DirectX::XMFLOAT3 pos = {0, 0, 0};
        
        if (m_renderManagerPtr == 0) {
            return pos;
        }
        
        uintptr_t renderManagerInstance = 0;
        if (!SafeRead(m_renderManagerPtr, renderManagerInstance) || renderManagerInstance == 0) {
            return pos;
        }
        
        uintptr_t cameraData = 0;
        if (!SafeRead(renderManagerInstance + RenderCameraOffsets::CameraDataOffset, cameraData) || cameraData == 0) {
            return pos;
        }
        
        // Camera position is at floats [36], [37], [38] = offset 144 (0x90)
        SafeReadFloat3(cameraData + RenderCameraOffsets::CameraPosition, pos);
        return pos;
    }
    
    void GameCameraExtractor::DumpRenderManagerCameraData() {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        LogInfo("===================================================================================");
        LogInfo("RENDER MANAGER CAMERA DATA DUMP (from decompiled sub_1403779D0)");
        LogInfo("===================================================================================");
        
        if (m_renderManagerPtr == 0) {
            LogWarning("RenderManager not found - run Initialize() first or signature scan failed");
            return;
        }
        
        LogInfo(std::format("g_RenderManager global: 0x{:X}", m_renderManagerPtr));
        
        uintptr_t renderManagerInstance = 0;
        if (!SafeRead(m_renderManagerPtr, renderManagerInstance)) {
            LogError("Failed to read RenderManager instance");
            return;
        }
        LogInfo(std::format("RenderManager instance: 0x{:X}", renderManagerInstance));
        
        if (renderManagerInstance == 0) {
            LogWarning("RenderManager instance is NULL (game may not be fully loaded)");
            return;
        }
        
        // Read CameraData pointer at offset 0xAD28
        uintptr_t cameraData = 0;
        if (!SafeRead(renderManagerInstance + RenderCameraOffsets::CameraDataOffset, cameraData)) {
            LogError(std::format("Failed to read CameraData pointer at offset 0x{:X}", 
                RenderCameraOffsets::CameraDataOffset));
            return;
        }
        
        LogInfo(std::format("CameraData pointer (RenderManager+0xAD28): 0x{:X}", cameraData));
        
        if (cameraData == 0) {
            LogWarning("CameraData pointer is NULL");
            return;
        }
        
        // Dump the CameraData structure (first 0x100 bytes as floats)
        LogInfo("--- CameraData structure ---");
        
        // View Matrix at offset 0x10 (16 floats = 64 bytes)
        LogInfo("View Matrix (CameraData+0x10):");
        DirectX::XMMATRIX viewMat;
        if (SafeReadMatrix(cameraData + RenderCameraOffsets::ViewMatrix, viewMat)) {
            DirectX::XMFLOAT4X4 v;
            DirectX::XMStoreFloat4x4(&v, viewMat);
            LogInfo(std::format("  [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", v._11, v._12, v._13, v._14));
            LogInfo(std::format("  [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", v._21, v._22, v._23, v._24));
            LogInfo(std::format("  [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", v._31, v._32, v._33, v._34));
            LogInfo(std::format("  [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", v._41, v._42, v._43, v._44));
            
            // Validate view matrix
            float det3x3 = v._11 * (v._22 * v._33 - v._23 * v._32)
                         - v._12 * (v._21 * v._33 - v._23 * v._31)
                         + v._13 * (v._21 * v._32 - v._22 * v._31);
            LogInfo(std::format("  3x3 determinant: {:.4f} (should be ~1.0 for orthonormal)", det3x3));
        } else {
            LogError("  Failed to read View Matrix");
        }
        
        // Projection Matrix at offset 0x50 (16 floats = 64 bytes)
        LogInfo("Projection Matrix (CameraData+0x50):");
        DirectX::XMMATRIX projMat;
        if (SafeReadMatrix(cameraData + RenderCameraOffsets::ProjectionMatrix, projMat)) {
            DirectX::XMFLOAT4X4 p;
            DirectX::XMStoreFloat4x4(&p, projMat);
            LogInfo(std::format("  [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", p._11, p._12, p._13, p._14));
            LogInfo(std::format("  [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", p._21, p._22, p._23, p._24));
            LogInfo(std::format("  [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", p._31, p._32, p._33, p._34));
            LogInfo(std::format("  [{:10.4f} {:10.4f} {:10.4f} {:10.4f}]", p._41, p._42, p._43, p._44));
            
            // Validate projection matrix pattern
            bool isPerspective = (std::abs(p._34 - 1.0f) < 0.1f || std::abs(p._34 + 1.0f) < 0.1f) && 
                                 std::abs(p._44) < 0.1f;
            LogInfo(std::format("  Looks like perspective projection: {}", isPerspective ? "YES" : "NO"));
        } else {
            LogError("  Failed to read Projection Matrix");
        }
        
        // Camera Position at offset 0x90 (floats at index 36, 37, 38)
        LogInfo("Camera Position (CameraData+0x90):");
        DirectX::XMFLOAT3 camPos = {0, 0, 0};
        if (SafeReadFloat3(cameraData + RenderCameraOffsets::CameraPosition, camPos)) {
            LogInfo(std::format("  ({:.2f}, {:.2f}, {:.2f})", camPos.x, camPos.y, camPos.z));
        } else {
            LogError("  Failed to read camera position");
        }
        
        // Dump additional floats to understand the structure better
        LogInfo("--- Raw float dump (CameraData+0x00 to CameraData+0xC0) ---");
        for (size_t offset = 0; offset <= 0xC0; offset += 0x10) {
            float row[4] = {};
            bool ok = true;
            for (int i = 0; i < 4; ++i) {
                if (!SafeRead(cameraData + offset + i * sizeof(float), row[i])) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                LogInfo(std::format("  +0x{:02X}: {:10.4f} {:10.4f} {:10.4f} {:10.4f}", 
                    offset, row[0], row[1], row[2], row[3]));
            }
        }
        
        LogInfo("===================================================================================");
    }

} // namespace SapphireHook::DebugVisuals
