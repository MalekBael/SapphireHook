#include "D3D11MatrixCapture.h"
#include "../Logger/Logger.h"
#include <format>
#include <cmath>
#include <cstring>
#include <algorithm>

namespace SapphireHook::DebugVisuals {

    D3D11MatrixCapture& D3D11MatrixCapture::GetInstance() {
        static D3D11MatrixCapture instance;
        return instance;
    }

    bool D3D11MatrixCapture::Initialize(ID3D11DeviceContext* context) {
        if (m_initialized.load()) {
            return true;
        }

        if (!context) {
            LogError("D3D11MatrixCapture: Invalid device context");
            return false;
        }

        m_context = context;
        context->GetDevice(&m_device);
        
        if (!m_device) {
            LogError("D3D11MatrixCapture: Could not get device from context");
            return false;
        }

        m_initialized.store(true);
        
        LogInfo("D3D11MatrixCapture: Initialized - will capture ViewProjection from constant buffers");
        return true;
    }

    void D3D11MatrixCapture::Shutdown() {
        m_initialized.store(false);
        m_hasValidMatrices.store(false);
        
        if (m_stagingBuffer) {
            m_stagingBuffer->Release();
            m_stagingBuffer = nullptr;
        }
        m_stagingBufferSize = 0;
        
        if (m_device) {
            m_device->Release();
            m_device = nullptr;
        }
        
        m_context = nullptr;
        
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_recentCandidates.clear();
        }
        
        LogInfo("D3D11MatrixCapture: Shutdown");
    }

    DirectX::XMMATRIX D3D11MatrixCapture::GetViewMatrix() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_viewMatrix;
    }

    DirectX::XMMATRIX D3D11MatrixCapture::GetProjectionMatrix() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_projMatrix;
    }

    DirectX::XMMATRIX D3D11MatrixCapture::GetViewProjectionMatrix() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_viewProjMatrix;
    }

    DirectX::XMFLOAT3 D3D11MatrixCapture::GetCameraPosition() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_cameraPosition;
    }

    void D3D11MatrixCapture::SetKnownCameraPosition(const DirectX::XMFLOAT3& pos) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_knownCameraPosition = pos;
        m_hasKnownCameraPosition.store(std::abs(pos.x) > 0.1f || std::abs(pos.y) > 0.1f || std::abs(pos.z) > 0.1f);
    }
    
    std::vector<MatrixCandidate> D3D11MatrixCapture::GetRecentCandidates() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_recentCandidates;
    }
    
    void D3D11MatrixCapture::ClearCandidates() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_recentCandidates.clear();
    }
    
    bool D3D11MatrixCapture::ReadBufferContents(ID3D11Buffer* buffer, ID3D11DeviceContext* context,
                                                  std::vector<uint8_t>& outData) {
        if (!buffer || !context || !m_device) return false;
        
        D3D11_BUFFER_DESC desc;
        buffer->GetDesc(&desc);
        
        // Create or resize staging buffer as needed
        if (!m_stagingBuffer || m_stagingBufferSize < desc.ByteWidth) {
            if (m_stagingBuffer) {
                m_stagingBuffer->Release();
                m_stagingBuffer = nullptr;
            }
            
            D3D11_BUFFER_DESC stagingDesc = {};
            stagingDesc.ByteWidth = desc.ByteWidth;
            stagingDesc.Usage = D3D11_USAGE_STAGING;
            stagingDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
            stagingDesc.BindFlags = 0;
            
            HRESULT hr = m_device->CreateBuffer(&stagingDesc, nullptr, &m_stagingBuffer);
            if (FAILED(hr)) {
                return false;
            }
            m_stagingBufferSize = desc.ByteWidth;
        }
        
        // Copy to staging
        context->CopyResource(m_stagingBuffer, buffer);
        
        // Map and read
        D3D11_MAPPED_SUBRESOURCE mapped;
        HRESULT hr = context->Map(m_stagingBuffer, 0, D3D11_MAP_READ, 0, &mapped);
        if (FAILED(hr)) {
            return false;
        }
        
        outData.resize(desc.ByteWidth);
        std::memcpy(outData.data(), mapped.pData, desc.ByteWidth);
        
        context->Unmap(m_stagingBuffer, 0);
        return true;
    }

    void D3D11MatrixCapture::OnUpdateSubresource(ID3D11Resource* dstResource, UINT dstSubresource,
                                                  const D3D11_BOX* dstBox, const void* srcData,
                                                  UINT srcRowPitch, UINT srcDepthPitch) {
        if (!m_captureEnabled || !srcData || !dstResource) {
            return;
        }

        // Check if this is a buffer (constant buffers are D3D11_RESOURCE_DIMENSION_BUFFER)
        D3D11_RESOURCE_DIMENSION dim;
        dstResource->GetType(&dim);
        if (dim != D3D11_RESOURCE_DIMENSION_BUFFER) {
            return;
        }

        // Get buffer description to check size
        ID3D11Buffer* buffer = static_cast<ID3D11Buffer*>(dstResource);
        D3D11_BUFFER_DESC desc;
        buffer->GetDesc(&desc);

        // We're interested in constant buffers with matrix-sized data
        // Minimum 64 bytes (one 4x4 matrix), typical camera buffers are 128-512 bytes
        if (!(desc.BindFlags & D3D11_BIND_CONSTANT_BUFFER)) {
            return;
        }

        if (desc.ByteWidth < 64 || desc.ByteWidth > 1024) {
            return;  // Not a typical camera constant buffer size
        }

        m_capturedBufferCount++;

        // Analyze the buffer data for ViewProjection matrices
        if (AnalyzeBufferForViewProjection(srcData, desc.ByteWidth)) {
            m_hasValidMatrices.store(true);
            m_validMatrixCount++;
        }
    }

    void D3D11MatrixCapture::OnMap(ID3D11Resource* resource, UINT subresource, D3D11_MAP mapType,
                                    UINT mapFlags, D3D11_MAPPED_SUBRESOURCE* mappedResource) {
        if (!m_captureEnabled || !resource || !mappedResource) {
            return;
        }

        // Only interested in write maps
        if (mapType != D3D11_MAP_WRITE && mapType != D3D11_MAP_WRITE_DISCARD && mapType != D3D11_MAP_WRITE_NO_OVERWRITE) {
            return;
        }

        D3D11_RESOURCE_DIMENSION dim;
        resource->GetType(&dim);
        if (dim != D3D11_RESOURCE_DIMENSION_BUFFER) {
            return;
        }

        ID3D11Buffer* buffer = static_cast<ID3D11Buffer*>(resource);
        D3D11_BUFFER_DESC desc;
        buffer->GetDesc(&desc);

        if (!(desc.BindFlags & D3D11_BIND_CONSTANT_BUFFER)) {
            return;
        }

        if (desc.ByteWidth >= 64 && desc.ByteWidth <= 1024) {
            // Track this mapping so we can analyze on Unmap
            m_currentMappedBuffer.resource = resource;
            m_currentMappedBuffer.data = mappedResource->pData;
            m_currentMappedBuffer.size = desc.ByteWidth;
        }
    }

    void D3D11MatrixCapture::OnUnmap(ID3D11Resource* resource, UINT subresource) {
        if (!m_captureEnabled) {
            return;
        }

        // Check if this was a buffer we're tracking
        if (m_currentMappedBuffer.resource == resource && m_currentMappedBuffer.data != nullptr) {
            m_capturedBufferCount++;
            
            if (AnalyzeBufferForViewProjection(m_currentMappedBuffer.data, m_currentMappedBuffer.size)) {
                m_hasValidMatrices.store(true);
                m_validMatrixCount++;
            }

            m_currentMappedBuffer.resource = nullptr;
            m_currentMappedBuffer.data = nullptr;
            m_currentMappedBuffer.size = 0;
        }
    }

    void D3D11MatrixCapture::OnVSSetConstantBuffers(UINT startSlot, UINT numBuffers, 
                                                      ID3D11Buffer* const* buffers,
                                                      ID3D11DeviceContext* context) {
        if (!m_captureEnabled || !buffers || !context) {
            return;
        }
        
        m_vsSetCallCount++;
        
        // Slot 0 is commonly used for per-frame camera matrices
        // Check slots 0-2 for potential camera constant buffers
        for (UINT i = 0; i < numBuffers && (startSlot + i) <= 2; ++i) {
            ID3D11Buffer* buffer = buffers[i];
            if (!buffer) continue;
            
            D3D11_BUFFER_DESC desc;
            buffer->GetDesc(&desc);
            
            // Camera CBs are typically 64-512 bytes
            if (!(desc.BindFlags & D3D11_BIND_CONSTANT_BUFFER)) continue;
            if (desc.ByteWidth < 64 || desc.ByteWidth > 1024) continue;
            
            // Read buffer contents
            std::vector<uint8_t> bufferData;
            if (!ReadBufferContents(buffer, context, bufferData)) {
                continue;
            }
            
            m_capturedBufferCount++;
            
            // Analyze for matrices
            if (AnalyzeBufferForViewProjection(bufferData.data(), bufferData.size())) {
                m_hasValidMatrices.store(true);
                m_validMatrixCount++;
            }
        }
    }
    
    MatrixCandidate D3D11MatrixCapture::ScoreMatrix(const DirectX::XMMATRIX& matrix, 
                                                     uint32_t bufferSize, uint32_t offset) {
        MatrixCandidate candidate = {};
        candidate.matrix = matrix;
        candidate.bufferSize = bufferSize;
        candidate.offsetInBuffer = offset;
        candidate.frameCapured = m_currentFrame.load();
        
        DirectX::XMFLOAT4X4 m;
        DirectX::XMStoreFloat4x4(&m, matrix);
        
        // Check for NaN/Inf
        const float* ptr = &m._11;
        for (int i = 0; i < 16; ++i) {
            if (std::isnan(ptr[i]) || std::isinf(ptr[i])) {
                candidate.score = -100.0f;
                return candidate;
            }
        }
        
        // Skip identity
        bool isIdentity = (std::abs(m._11 - 1.0f) < 0.001f && 
                          std::abs(m._22 - 1.0f) < 0.001f && 
                          std::abs(m._33 - 1.0f) < 0.001f && 
                          std::abs(m._44 - 1.0f) < 0.001f &&
                          std::abs(m._41) < 0.001f && std::abs(m._42) < 0.001f && std::abs(m._43) < 0.001f);
        if (isIdentity) {
            candidate.score = -50.0f;
            return candidate;
        }
        
        float score = 0.0f;
        
        // Check for perspective projection characteristics
        // Perspective: _34 = +/-1, _44 ≈ 0, _14=_24=0
        bool looksLikeProjection = (std::abs(std::abs(m._34) - 1.0f) < 0.2f) &&
                                   std::abs(m._44) < 0.5f &&
                                   std::abs(m._14) < 0.01f && std::abs(m._24) < 0.01f &&
                                   std::abs(m._11) > 0.1f && std::abs(m._11) < 10.0f &&
                                   std::abs(m._22) > 0.1f && std::abs(m._22) < 10.0f;
        
        // Check for view matrix characteristics
        // View: orthonormal upper 3x3, _14=_24=_34≈0, _44≈1
        float det3x3 = m._11 * (m._22 * m._33 - m._23 * m._32) -
                       m._12 * (m._21 * m._33 - m._23 * m._31) +
                       m._13 * (m._21 * m._32 - m._22 * m._31);
        bool looksLikeView = std::abs(std::abs(det3x3) - 1.0f) < 0.2f &&
                             std::abs(m._14) < 0.01f && std::abs(m._24) < 0.01f && std::abs(m._34) < 0.01f &&
                             std::abs(m._44 - 1.0f) < 0.1f;
        
        // Check for ViewProj (combined characteristics)
        bool looksLikeViewProj = (std::abs(std::abs(m._34) - 1.0f) < 0.3f || std::abs(m._34) > 0.5f) &&
                                 std::abs(m._44) < 5.0f &&
                                 std::abs(m._11) > 0.001f && std::abs(m._22) > 0.001f;
        
        if (looksLikeProjection) {
            score += 5.0f;
            candidate.looksLikeProjection = true;
        }
        if (looksLikeView) {
            score += 4.0f;
            candidate.looksLikeView = true;
        }
        if (looksLikeViewProj && !looksLikeProjection && !looksLikeView) {
            score += 3.0f;
            candidate.looksLikeViewProj = true;
        }
        
        // Extract and validate camera position
        candidate.extractedCameraPos = ExtractCameraPosition(matrix);
        
        if (m_hasKnownCameraPosition.load()) {
            DirectX::XMFLOAT3 known = m_knownCameraPosition;
            float dx = candidate.extractedCameraPos.x - known.x;
            float dy = candidate.extractedCameraPos.y - known.y;
            float dz = candidate.extractedCameraPos.z - known.z;
            float dist = std::sqrt(dx*dx + dy*dy + dz*dz);
            
            if (dist < 5.0f) {
                score += 10.0f;  // Very close match
                candidate.cameraPositionMatches = true;
            } else if (dist < 20.0f) {
                score += 5.0f;   // Reasonable match
                candidate.cameraPositionMatches = true;
            } else if (dist < 50.0f) {
                score += 2.0f;   // Possible match
            }
        }
        
        candidate.score = score;
        return candidate;
    }

    bool D3D11MatrixCapture::AnalyzeBufferForViewProjection(const void* data, size_t dataSize) {
        // Common constant buffer layouts for camera data:
        // Layout 1: ViewProjection only (64 bytes)
        // Layout 2: View + Projection (128 bytes)  
        // Layout 3: World + View + Projection (192 bytes)
        // Layout 4: WorldViewProj at offset 0, View at 64, Proj at 128

        const float* floatData = static_cast<const float*>(data);
        size_t numFloats = dataSize / sizeof(float);

        if (numFloats < 16) {
            return false;
        }

        MatrixCandidate bestViewCandidate = {};
        MatrixCandidate bestProjCandidate = {};
        MatrixCandidate bestViewProjCandidate = {};
        bool foundView = false;
        bool foundProj = false;
        bool foundViewProj = false;

        // Scan all potential matrix positions (every 16 floats = 64 bytes)
        for (size_t offset = 0; offset + 16 <= numFloats; offset += 16) {
            DirectX::XMMATRIX testMatrix = DirectX::XMMATRIX(
                floatData[offset + 0], floatData[offset + 1], floatData[offset + 2], floatData[offset + 3],
                floatData[offset + 4], floatData[offset + 5], floatData[offset + 6], floatData[offset + 7],
                floatData[offset + 8], floatData[offset + 9], floatData[offset + 10], floatData[offset + 11],
                floatData[offset + 12], floatData[offset + 13], floatData[offset + 14], floatData[offset + 15]
            );

            MatrixCandidate candidate = ScoreMatrix(testMatrix, static_cast<uint32_t>(dataSize), 
                                                     static_cast<uint32_t>(offset * sizeof(float)));
            
            if (candidate.score <= 0) continue;
            
            // Store in recent candidates for debugging
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (m_recentCandidates.size() >= MAX_CANDIDATES) {
                    m_recentCandidates.erase(m_recentCandidates.begin());
                }
                m_recentCandidates.push_back(candidate);
            }

            // Track best candidates by type
            if (candidate.looksLikeProjection && (!foundProj || candidate.score > bestProjCandidate.score)) {
                bestProjCandidate = candidate;
                foundProj = true;
            }
            if (candidate.looksLikeView && (!foundView || candidate.score > bestViewCandidate.score)) {
                bestViewCandidate = candidate;
                foundView = true;
            }
            if (candidate.looksLikeViewProj && (!foundViewProj || candidate.score > bestViewProjCandidate.score)) {
                bestViewProjCandidate = candidate;
                foundViewProj = true;
            }
            
            // Log high-scoring candidates if verbose
            if (m_verboseLogging && candidate.score >= 5.0f) {
                DirectX::XMFLOAT4X4 mf;
                DirectX::XMStoreFloat4x4(&mf, candidate.matrix);
                LogInfo(std::format("D3D11MatrixCapture: High-score matrix at offset {} (score={:.1f}), "
                    "view={} proj={} vp={} camMatch={}, extractedPos=({:.1f},{:.1f},{:.1f})",
                    candidate.offsetInBuffer, candidate.score,
                    candidate.looksLikeView ? 1 : 0, candidate.looksLikeProjection ? 1 : 0,
                    candidate.looksLikeViewProj ? 1 : 0, candidate.cameraPositionMatches ? 1 : 0,
                    candidate.extractedCameraPos.x, candidate.extractedCameraPos.y, candidate.extractedCameraPos.z));
            }
        }

        // Store the best matrices we found
        if (foundViewProj || (foundView && foundProj) || 
            (foundView && bestViewCandidate.cameraPositionMatches) ||
            (foundProj && bestProjCandidate.score >= 5.0f)) {
            
            std::lock_guard<std::mutex> lock(m_mutex);
            
            if (foundView && bestViewCandidate.score >= 4.0f) {
                m_viewMatrix = bestViewCandidate.matrix;
                m_cameraPosition = bestViewCandidate.extractedCameraPos;
            }
            if (foundProj && bestProjCandidate.score >= 4.0f) {
                m_projMatrix = bestProjCandidate.matrix;
            }
            if (foundViewProj && bestViewProjCandidate.score >= 3.0f) {
                m_viewProjMatrix = bestViewProjCandidate.matrix;
                if (!foundView) {
                    m_viewMatrix = bestViewProjCandidate.matrix;
                    m_cameraPosition = bestViewProjCandidate.extractedCameraPos;
                }
            } else if (foundView && foundProj) {
                m_viewProjMatrix = DirectX::XMMatrixMultiply(m_viewMatrix, m_projMatrix);
            }

            m_lastCaptureFrame.store(m_currentFrame.load());
            
            static int logCount = 0;
            if (logCount < 3) {
                LogInfo(std::format("D3D11MatrixCapture: Captured matrices - View={:.1f} Proj={:.1f} VP={:.1f}, cam=({:.1f},{:.1f},{:.1f})",
                    foundView ? bestViewCandidate.score : 0.0f,
                    foundProj ? bestProjCandidate.score : 0.0f,
                    foundViewProj ? bestViewProjCandidate.score : 0.0f,
                    m_cameraPosition.x, m_cameraPosition.y, m_cameraPosition.z));
                logCount++;
            }
            
            return true;
        }

        return false;
    }

    DirectX::XMFLOAT3 D3D11MatrixCapture::ExtractCameraPosition(const DirectX::XMMATRIX& viewMatrix) {
        // The camera position in world space is -R^T * T where R is rotation and T is translation
        // For a view matrix V = [R | T], camera pos = -transpose(R) * T
        // Or equivalently, invert the view matrix and take the translation
        
        DirectX::XMVECTOR det;
        DirectX::XMMATRIX invView = DirectX::XMMatrixInverse(&det, viewMatrix);
        
        DirectX::XMFLOAT4X4 invViewFloat;
        DirectX::XMStoreFloat4x4(&invViewFloat, invView);
        
        return DirectX::XMFLOAT3(invViewFloat._41, invViewFloat._42, invViewFloat._43);
    }

    bool D3D11MatrixCapture::IsValidViewProjectionMatrix(const DirectX::XMMATRIX& matrix) {
        DirectX::XMFLOAT4X4 m;
        DirectX::XMStoreFloat4x4(&m, matrix);

        const float* data = &m._11;
        for (int i = 0; i < 16; ++i) {
            if (std::isnan(data[i]) || std::isinf(data[i])) {
                return false;
            }
        }

        // Check for identity (not useful)
        bool isIdentity = (std::abs(m._11 - 1.0f) < 0.001f && 
                          std::abs(m._22 - 1.0f) < 0.001f && 
                          std::abs(m._33 - 1.0f) < 0.001f && 
                          std::abs(m._44 - 1.0f) < 0.001f);
        if (isIdentity) return false;

        // Check for perspective characteristics
        bool looksLikePerspective = (std::abs(m._34 - 1.0f) < 0.1f || std::abs(m._34 + 1.0f) < 0.1f);
        bool hasReasonableScale = std::abs(m._11) > 0.01f && std::abs(m._11) < 100.0f &&
                                  std::abs(m._22) > 0.01f && std::abs(m._22) < 100.0f;

        return looksLikePerspective || hasReasonableScale;
    }

} // namespace SapphireHook::DebugVisuals
