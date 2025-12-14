#include "DebugRenderer.h"
#include "../Logger/Logger.h"
#include "../vendor/imgui/imgui.h"
#include <d3dcompiler.h>
#include <algorithm>
#include <cmath>

#pragma comment(lib, "d3dcompiler.lib")

namespace SapphireHook::DebugVisuals {

    // ============================================
    // HLSL Shaders (embedded as strings)
    // ============================================
    static const char* g_vertexShaderCode = R"(
        cbuffer ConstantBuffer : register(b0) {
            matrix viewProjection;
            float4 screenSize;
        };

        struct VS_INPUT {
            float3 position : POSITION;
            float4 color : COLOR;
        };

        struct PS_INPUT {
            float4 position : SV_POSITION;
            float4 color : COLOR;
        };

        PS_INPUT main(VS_INPUT input) {
            PS_INPUT output;
            output.position = mul(float4(input.position, 1.0f), viewProjection);
            output.color = input.color;
            return output;
        }
    )";

    static const char* g_pixelShaderCode = R"(
        struct PS_INPUT {
            float4 position : SV_POSITION;
            float4 color : COLOR;
        };

        float4 main(PS_INPUT input) : SV_TARGET {
            return input.color;
        }
    )";

    // ============================================
    // Singleton accessor
    // ============================================
    DebugRenderer& DebugRenderer::GetInstance() {
        static DebugRenderer instance;
        return instance;
    }

    // ============================================
    // Initialization
    // ============================================
    bool DebugRenderer::Initialize(ID3D11Device* device, ID3D11DeviceContext* context) {
        if (m_initialized) {
            return true;
        }

        if (!device || !context) {
            LogError("DebugRenderer: Invalid device or context");
            return false;
        }

        m_device = device;
        m_context = context;

        if (!CreateShaders()) {
            LogError("DebugRenderer: Failed to create shaders");
            ReleaseResources();
            return false;
        }

        if (!CreateBuffers()) {
            LogError("DebugRenderer: Failed to create buffers");
            ReleaseResources();
            return false;
        }

        if (!CreateStates()) {
            LogError("DebugRenderer: Failed to create render states");
            ReleaseResources();
            return false;
        }

        m_lineVertices.reserve(MAX_VERTICES);
        m_triangleVertices.reserve(MAX_VERTICES);

        m_initialized = true;
        LogInfo("DebugRenderer: Initialized successfully");
        return true;
    }

    void DebugRenderer::Shutdown() {
        if (!m_initialized) {
            return;
        }

        ReleaseResources();
        m_initialized = false;
        LogInfo("DebugRenderer: Shutdown complete");
    }

    bool DebugRenderer::CreateShaders() {
        HRESULT hr;
        ID3DBlob* vsBlob = nullptr;
        ID3DBlob* psBlob = nullptr;
        ID3DBlob* errorBlob = nullptr;

        // Compile vertex shader
        hr = D3DCompile(g_vertexShaderCode, strlen(g_vertexShaderCode), nullptr, nullptr, nullptr,
                        "main", "vs_4_0", D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &vsBlob, &errorBlob);
        if (FAILED(hr)) {
            if (errorBlob) {
                LogError("DebugRenderer VS compile error: " + std::string(static_cast<char*>(errorBlob->GetBufferPointer())));
                errorBlob->Release();
            }
            return false;
        }

        // Compile pixel shader
        hr = D3DCompile(g_pixelShaderCode, strlen(g_pixelShaderCode), nullptr, nullptr, nullptr,
                        "main", "ps_4_0", D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &psBlob, &errorBlob);
        if (FAILED(hr)) {
            if (errorBlob) {
                LogError("DebugRenderer PS compile error: " + std::string(static_cast<char*>(errorBlob->GetBufferPointer())));
                errorBlob->Release();
            }
            vsBlob->Release();
            return false;
        }

        // Create vertex shader
        hr = m_device->CreateVertexShader(vsBlob->GetBufferPointer(), vsBlob->GetBufferSize(), nullptr, &m_vertexShader);
        if (FAILED(hr)) {
            LogError("DebugRenderer: Failed to create vertex shader");
            vsBlob->Release();
            psBlob->Release();
            return false;
        }

        // Create pixel shader
        hr = m_device->CreatePixelShader(psBlob->GetBufferPointer(), psBlob->GetBufferSize(), nullptr, &m_pixelShader);
        if (FAILED(hr)) {
            LogError("DebugRenderer: Failed to create pixel shader");
            vsBlob->Release();
            psBlob->Release();
            return false;
        }

        // Create input layout
        D3D11_INPUT_ELEMENT_DESC inputLayout[] = {
            { "POSITION", 0, DXGI_FORMAT_R32G32B32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0 },
            { "COLOR", 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0, 12, D3D11_INPUT_PER_VERTEX_DATA, 0 },
        };

        hr = m_device->CreateInputLayout(inputLayout, 2, vsBlob->GetBufferPointer(), 
                                          vsBlob->GetBufferSize(), &m_inputLayout);
        vsBlob->Release();
        psBlob->Release();

        if (FAILED(hr)) {
            LogError("DebugRenderer: Failed to create input layout");
            return false;
        }

        return true;
    }

    bool DebugRenderer::CreateBuffers() {
        // Vertex buffer (dynamic, updated each frame)
        D3D11_BUFFER_DESC vbDesc = {};
        vbDesc.ByteWidth = static_cast<UINT>(MAX_VERTICES * sizeof(DebugVertex));
        vbDesc.Usage = D3D11_USAGE_DYNAMIC;
        vbDesc.BindFlags = D3D11_BIND_VERTEX_BUFFER;
        vbDesc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;

        HRESULT hr = m_device->CreateBuffer(&vbDesc, nullptr, &m_vertexBuffer);
        if (FAILED(hr)) {
            LogError("DebugRenderer: Failed to create vertex buffer");
            return false;
        }

        // Constant buffer
        D3D11_BUFFER_DESC cbDesc = {};
        cbDesc.ByteWidth = sizeof(DebugConstantBuffer);
        cbDesc.Usage = D3D11_USAGE_DYNAMIC;
        cbDesc.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
        cbDesc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;

        hr = m_device->CreateBuffer(&cbDesc, nullptr, &m_constantBuffer);
        if (FAILED(hr)) {
            LogError("DebugRenderer: Failed to create constant buffer");
            return false;
        }

        return true;
    }

    bool DebugRenderer::CreateStates() {
        // Rasterizer state (wireframe, cull back)
        D3D11_RASTERIZER_DESC rsDesc = {};
        rsDesc.FillMode = D3D11_FILL_SOLID;
        rsDesc.CullMode = D3D11_CULL_BACK;
        rsDesc.FrontCounterClockwise = FALSE;
        rsDesc.DepthClipEnable = TRUE;
        rsDesc.ScissorEnable = FALSE;  // Disable scissor testing for our geometry
        rsDesc.AntialiasedLineEnable = TRUE;

        HRESULT hr = m_device->CreateRasterizerState(&rsDesc, &m_rasterizerState);
        if (FAILED(hr)) {
            LogError("DebugRenderer: Failed to create rasterizer state");
            return false;
        }

        // Rasterizer state (no culling, no scissor, NO DEPTH CLIPPING)
        // DepthClipEnable = FALSE prevents near/far plane clipping of our overlay geometry
        rsDesc.CullMode = D3D11_CULL_NONE;
        rsDesc.ScissorEnable = FALSE;
        rsDesc.DepthClipEnable = FALSE;  // CRITICAL: Disable near/far plane clipping
        hr = m_device->CreateRasterizerState(&rsDesc, &m_rasterizerStateNoCull);
        if (FAILED(hr)) {
            LogError("DebugRenderer: Failed to create no-cull rasterizer state");
            return false;
        }

        // Depth stencil state (with depth test)
        D3D11_DEPTH_STENCIL_DESC dsDesc = {};
        dsDesc.DepthEnable = TRUE;
        dsDesc.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ZERO;  // Don't write to depth
        dsDesc.DepthFunc = D3D11_COMPARISON_LESS_EQUAL;

        hr = m_device->CreateDepthStencilState(&dsDesc, &m_depthStencilState);
        if (FAILED(hr)) {
            LogError("DebugRenderer: Failed to create depth stencil state");
            return false;
        }

        // Depth stencil state (no depth test - always on top)
        dsDesc.DepthEnable = FALSE;
        hr = m_device->CreateDepthStencilState(&dsDesc, &m_depthStencilStateNoDepth);
        if (FAILED(hr)) {
            LogError("DebugRenderer: Failed to create no-depth stencil state");
            return false;
        }

        // Blend state (alpha blending)
        D3D11_BLEND_DESC blendDesc = {};
        blendDesc.RenderTarget[0].BlendEnable = TRUE;
        blendDesc.RenderTarget[0].SrcBlend = D3D11_BLEND_SRC_ALPHA;
        blendDesc.RenderTarget[0].DestBlend = D3D11_BLEND_INV_SRC_ALPHA;
        blendDesc.RenderTarget[0].BlendOp = D3D11_BLEND_OP_ADD;
        blendDesc.RenderTarget[0].SrcBlendAlpha = D3D11_BLEND_ONE;
        blendDesc.RenderTarget[0].DestBlendAlpha = D3D11_BLEND_INV_SRC_ALPHA;
        blendDesc.RenderTarget[0].BlendOpAlpha = D3D11_BLEND_OP_ADD;
        blendDesc.RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;

        hr = m_device->CreateBlendState(&blendDesc, &m_blendState);
        if (FAILED(hr)) {
            LogError("DebugRenderer: Failed to create blend state");
            return false;
        }

        return true;
    }

    void DebugRenderer::ReleaseResources() {
        if (m_blendState) { m_blendState->Release(); m_blendState = nullptr; }
        if (m_depthStencilStateNoDepth) { m_depthStencilStateNoDepth->Release(); m_depthStencilStateNoDepth = nullptr; }
        if (m_depthStencilState) { m_depthStencilState->Release(); m_depthStencilState = nullptr; }
        if (m_rasterizerStateNoCull) { m_rasterizerStateNoCull->Release(); m_rasterizerStateNoCull = nullptr; }
        if (m_rasterizerState) { m_rasterizerState->Release(); m_rasterizerState = nullptr; }
        if (m_inputLayout) { m_inputLayout->Release(); m_inputLayout = nullptr; }
        if (m_pixelShader) { m_pixelShader->Release(); m_pixelShader = nullptr; }
        if (m_vertexShader) { m_vertexShader->Release(); m_vertexShader = nullptr; }
        if (m_constantBuffer) { m_constantBuffer->Release(); m_constantBuffer = nullptr; }
        if (m_vertexBuffer) { m_vertexBuffer->Release(); m_vertexBuffer = nullptr; }

        m_device = nullptr;
        m_context = nullptr;
    }

    // ============================================
    // Frame lifecycle
    // ============================================
    void DebugRenderer::BeginFrame() {
        if (!m_initialized || !m_enabled) {
            return;
        }

        m_lineVertices.clear();
        m_triangleVertices.clear();
        m_inFrame = true;

        // Clean up expired persistent primitives
        CleanupExpiredPrimitives();

        // Draw persistent primitives
        {
            std::lock_guard<std::mutex> lock(m_primitiveMutex);
            
            for (const auto& line : m_persistentLines) {
                DrawLine(line.primitive.start, line.primitive.end, 
                        line.primitive.color, line.primitive.thickness);
            }

            for (const auto& sphere : m_persistentSpheres) {
                DrawSphere(sphere.primitive.center, sphere.primitive.radius,
                          sphere.primitive.color, sphere.primitive.filled,
                          sphere.primitive.segments);
            }

            for (const auto& circle : m_persistentCircles) {
                DrawCircle(circle.primitive.center, circle.primitive.radius,
                          circle.primitive.color, circle.primitive.segments,
                          circle.primitive.filled);
            }

            for (const auto& path : m_persistentPaths) {
                DrawPath(path.primitive.points, path.primitive.color,
                        path.primitive.thickness, path.primitive.closed);
            }
        }
    }

    void DebugRenderer::EndFrame() {
        if (!m_initialized || !m_enabled || !m_inFrame) {
            return;
        }

        m_inFrame = false;

        // Update constant buffer
        UpdateConstantBuffer();

        // Save current state
        ID3D11RasterizerState* oldRs = nullptr;
        ID3D11DepthStencilState* oldDs = nullptr;
        UINT oldStencilRef = 0;
        ID3D11BlendState* oldBlend = nullptr;
        float oldBlendFactor[4];
        UINT oldSampleMask = 0;
        D3D11_VIEWPORT oldViewports[D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE];
        UINT numViewports = D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE;
        D3D11_RECT oldScissorRects[D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE];
        UINT numScissorRects = D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE;

        m_context->RSGetState(&oldRs);
        m_context->OMGetDepthStencilState(&oldDs, &oldStencilRef);
        m_context->OMGetBlendState(&oldBlend, oldBlendFactor, &oldSampleMask);
        m_context->RSGetViewports(&numViewports, oldViewports);
        m_context->RSGetScissorRects(&numScissorRects, oldScissorRects);

        // Set our viewport (full screen)
        D3D11_VIEWPORT viewport = {};
        viewport.TopLeftX = 0;
        viewport.TopLeftY = 0;
        viewport.Width = m_screenWidth;
        viewport.Height = m_screenHeight;
        viewport.MinDepth = 0.0f;
        viewport.MaxDepth = 1.0f;
        m_context->RSSetViewports(1, &viewport);
        
        // Set scissor rect to full screen (disable scissor clipping)
        D3D11_RECT scissorRect = { 0, 0, static_cast<LONG>(m_screenWidth), static_cast<LONG>(m_screenHeight) };
        m_context->RSSetScissorRects(1, &scissorRect);

        // Save and unbind render targets to ensure we're not using game's depth buffer
        ID3D11RenderTargetView* oldRTVs[D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT] = {};
        ID3D11DepthStencilView* oldDSV = nullptr;
        m_context->OMGetRenderTargets(D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT, oldRTVs, &oldDSV);
        
        // Re-bind render target with NO depth stencil - this ensures our geometry isn't depth-tested
        m_context->OMSetRenderTargets(1, &oldRTVs[0], nullptr);

        // Set our state
        m_context->RSSetState(m_rasterizerStateNoCull);
        m_context->OMSetDepthStencilState(m_depthStencilStateNoDepth, 0);  // Always no depth test
        float blendFactor[4] = { 0.0f, 0.0f, 0.0f, 0.0f };
        m_context->OMSetBlendState(m_blendState, blendFactor, 0xFFFFFFFF);

        // Set shaders and layout
        m_context->IASetInputLayout(m_inputLayout);
        m_context->VSSetShader(m_vertexShader, nullptr, 0);
        m_context->PSSetShader(m_pixelShader, nullptr, 0);
        m_context->VSSetConstantBuffers(0, 1, &m_constantBuffer);

        UINT stride = sizeof(DebugVertex);
        UINT offset = 0;
        m_context->IASetVertexBuffers(0, 1, &m_vertexBuffer, &stride, &offset);

        // Flush lines
        FlushLines();

        // Flush triangles
        FlushTriangles();

        // Restore render targets (including depth stencil)
        m_context->OMSetRenderTargets(D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT, oldRTVs, oldDSV);
        
        // Release saved render target views
        for (auto& rtv : oldRTVs) {
            if (rtv) rtv->Release();
        }
        if (oldDSV) oldDSV->Release();

        // Restore state
        m_context->RSSetViewports(numViewports, oldViewports);
        m_context->RSSetScissorRects(numScissorRects, oldScissorRects);
        m_context->RSSetState(oldRs);
        m_context->OMSetDepthStencilState(oldDs, oldStencilRef);
        m_context->OMSetBlendState(oldBlend, oldBlendFactor, oldSampleMask);

        if (oldRs) oldRs->Release();
        if (oldDs) oldDs->Release();
        if (oldBlend) oldBlend->Release();
    }

    void DebugRenderer::UpdateConstantBuffer() {
        D3D11_MAPPED_SUBRESOURCE mapped;
        HRESULT hr = m_context->Map(m_constantBuffer, 0, D3D11_MAP_WRITE_DISCARD, 0, &mapped);
        if (SUCCEEDED(hr)) {
            DebugConstantBuffer* cb = static_cast<DebugConstantBuffer*>(mapped.pData);
            cb->viewProjection = DirectX::XMMatrixTranspose(m_viewProjection);
            cb->screenSize = DirectX::XMFLOAT4(m_screenWidth, m_screenHeight, 
                                                1.0f / m_screenWidth, 1.0f / m_screenHeight);
            m_context->Unmap(m_constantBuffer, 0);
        }
    }

    void DebugRenderer::FlushLines() {
        if (m_lineVertices.empty()) {
            return;
        }

        size_t vertexCount = m_lineVertices.size();
        
        if (vertexCount > MAX_VERTICES) {
            vertexCount = MAX_VERTICES;
            LogWarning("DebugRenderer: Too many line vertices, truncating");
        }

        // Update vertex buffer
        D3D11_MAPPED_SUBRESOURCE mapped;
        HRESULT hr = m_context->Map(m_vertexBuffer, 0, D3D11_MAP_WRITE_DISCARD, 0, &mapped);
        if (SUCCEEDED(hr)) {
            memcpy(mapped.pData, m_lineVertices.data(), vertexCount * sizeof(DebugVertex));
            m_context->Unmap(m_vertexBuffer, 0);

            m_context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_LINELIST);
            m_context->Draw(static_cast<UINT>(vertexCount), 0);
        }
    }

    void DebugRenderer::FlushTriangles() {
        if (m_triangleVertices.empty()) {
            return;
        }

        size_t vertexCount = m_triangleVertices.size();
        if (vertexCount > MAX_VERTICES) {
            vertexCount = MAX_VERTICES;
            LogWarning("DebugRenderer: Too many triangle vertices, truncating");
        }

        // Update vertex buffer
        D3D11_MAPPED_SUBRESOURCE mapped;
        HRESULT hr = m_context->Map(m_vertexBuffer, 0, D3D11_MAP_WRITE_DISCARD, 0, &mapped);
        if (SUCCEEDED(hr)) {
            memcpy(mapped.pData, m_triangleVertices.data(), vertexCount * sizeof(DebugVertex));
            m_context->Unmap(m_vertexBuffer, 0);

            m_context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
            m_context->Draw(static_cast<UINT>(vertexCount), 0);
        }
    }

    // ============================================
    // Camera setup
    // ============================================
    void DebugRenderer::SetViewProjection(const DirectX::XMMATRIX& view, const DirectX::XMMATRIX& projection) {
        m_view = view;
        m_projection = projection;
        m_viewProjection = DirectX::XMMatrixMultiply(view, projection);
    }

    void DebugRenderer::SetViewProjectionDirect(const DirectX::XMMATRIX& viewProjection) {
        // Use the pre-computed ViewProjection directly - this is the game's perfectly synchronized matrix
        m_viewProjection = viewProjection;
        // Note: m_view and m_projection are NOT updated here, but that's fine
        // since we only use m_viewProjection for rendering
    }

    void DebugRenderer::SetScreenSize(float width, float height) {
        m_screenWidth = width;
        m_screenHeight = height;
    }

    void DebugRenderer::SetCameraFromGame(const CameraData& camera) {
        m_view = camera.view;
        m_projection = camera.projection;
        m_viewProjection = DirectX::XMMatrixMultiply(m_view, m_projection);
    }

    // ============================================
    // World to Screen projection
    // ============================================
    std::optional<DirectX::XMFLOAT2> DebugRenderer::WorldToScreen(const Vec3& worldPos) const {
        DirectX::XMVECTOR pos = DirectX::XMVectorSet(worldPos.x, worldPos.y, worldPos.z, 1.0f);
        DirectX::XMVECTOR projected = DirectX::XMVector4Transform(pos, m_viewProjection);

        float w = DirectX::XMVectorGetW(projected);
        if (w <= 0.0f) {
            return std::nullopt;  // Behind camera
        }

        float x = DirectX::XMVectorGetX(projected) / w;
        float y = DirectX::XMVectorGetY(projected) / w;

        // Clip space to screen space
        float screenX = (x * 0.5f + 0.5f) * m_screenWidth;
        float screenY = (-y * 0.5f + 0.5f) * m_screenHeight;

        // Check if on screen
        if (screenX < 0 || screenX > m_screenWidth || screenY < 0 || screenY > m_screenHeight) {
            return std::nullopt;
        }

        return DirectX::XMFLOAT2(screenX, screenY);
    }

    // ============================================
    // Immediate-mode drawing
    // ============================================
    void DebugRenderer::DrawLine(const Vec3& start, const Vec3& end, const Color& color, float thickness) {
        if (!m_inFrame) return;

        DirectX::XMFLOAT4 col(color.r, color.g, color.b, color.a);
        
        m_lineVertices.push_back({ { start.x, start.y, start.z }, col });
        m_lineVertices.push_back({ { end.x, end.y, end.z }, col });
    }

    // Draw a thick line using quads (two triangles) - worldThickness is in world units
    // Line is expanded horizontally (in XZ plane) for visibility from above
    void DebugRenderer::DrawThickLine(const Vec3& start, const Vec3& end, const Color& color, float worldThickness) {
        if (!m_inFrame) return;

        DirectX::XMFLOAT4 col(color.r, color.g, color.b, color.a);
        
        // Calculate line direction
        DirectX::XMVECTOR startVec = DirectX::XMVectorSet(start.x, start.y, start.z, 1.0f);
        DirectX::XMVECTOR endVec = DirectX::XMVectorSet(end.x, end.y, end.z, 1.0f);
        DirectX::XMVECTOR lineDir = DirectX::XMVectorSubtract(endVec, startVec);
        lineDir = DirectX::XMVector3Normalize(lineDir);
        
        // Use UP vector to get horizontal perpendicular (line dir × UP = horizontal perpendicular)
        DirectX::XMVECTOR upVec = DirectX::XMVectorSet(0.0f, 1.0f, 0.0f, 0.0f);
        DirectX::XMVECTOR perpendicular = DirectX::XMVector3Cross(lineDir, upVec);
        perpendicular = DirectX::XMVector3Normalize(perpendicular);
        
        // If perpendicular is zero (vertical line), fall back to X axis
        if (DirectX::XMVector3LengthSq(perpendicular).m128_f32[0] < 0.0001f) {
            perpendicular = DirectX::XMVectorSet(1.0f, 0.0f, 0.0f, 0.0f);
        }
        
        // Scale by half thickness
        float halfThick = worldThickness * 0.5f;
        DirectX::XMVECTOR offset = DirectX::XMVectorScale(perpendicular, halfThick);
        
        // Calculate 4 corners of the quad
        DirectX::XMVECTOR v0 = DirectX::XMVectorSubtract(startVec, offset);
        DirectX::XMVECTOR v1 = DirectX::XMVectorAdd(startVec, offset);
        DirectX::XMVECTOR v2 = DirectX::XMVectorAdd(endVec, offset);
        DirectX::XMVECTOR v3 = DirectX::XMVectorSubtract(endVec, offset);
        
        DirectX::XMFLOAT3 p0, p1, p2, p3;
        DirectX::XMStoreFloat3(&p0, v0);
        DirectX::XMStoreFloat3(&p1, v1);
        DirectX::XMStoreFloat3(&p2, v2);
        DirectX::XMStoreFloat3(&p3, v3);
        
        // Two triangles for the quad
        // Triangle 1: v0, v1, v2
        m_triangleVertices.push_back({ p0, col });
        m_triangleVertices.push_back({ p1, col });
        m_triangleVertices.push_back({ p2, col });
        
        // Triangle 2: v0, v2, v3
        m_triangleVertices.push_back({ p0, col });
        m_triangleVertices.push_back({ p2, col });
        m_triangleVertices.push_back({ p3, col });
    }

    void DebugRenderer::DrawSphere(const Vec3& center, float radius, const Color& color, 
                                    bool filled, int segments) {
        if (!m_inFrame) return;

        // Draw wireframe sphere using line segments
        const float pi = 3.14159265358979f;
        
        for (int i = 0; i < segments; ++i) {
            float theta1 = (static_cast<float>(i) / segments) * 2.0f * pi;
            float theta2 = (static_cast<float>(i + 1) / segments) * 2.0f * pi;

            // XZ circle (horizontal)
            Vec3 p1 = { center.x + radius * cosf(theta1), center.y, center.z + radius * sinf(theta1) };
            Vec3 p2 = { center.x + radius * cosf(theta2), center.y, center.z + radius * sinf(theta2) };
            DrawLine(p1, p2, color);

            // XY circle (vertical front)
            Vec3 p3 = { center.x + radius * cosf(theta1), center.y + radius * sinf(theta1), center.z };
            Vec3 p4 = { center.x + radius * cosf(theta2), center.y + radius * sinf(theta2), center.z };
            DrawLine(p3, p4, color);

            // YZ circle (vertical side)
            Vec3 p5 = { center.x, center.y + radius * sinf(theta1), center.z + radius * cosf(theta1) };
            Vec3 p6 = { center.x, center.y + radius * sinf(theta2), center.z + radius * cosf(theta2) };
            DrawLine(p5, p6, color);
        }
    }

    void DebugRenderer::DrawBox(const Vec3& center, const Vec3& halfExtents, const Color& color, bool filled) {
        if (!m_inFrame) return;

        // 8 corners of the box
        Vec3 corners[8] = {
            { center.x - halfExtents.x, center.y - halfExtents.y, center.z - halfExtents.z },
            { center.x + halfExtents.x, center.y - halfExtents.y, center.z - halfExtents.z },
            { center.x + halfExtents.x, center.y - halfExtents.y, center.z + halfExtents.z },
            { center.x - halfExtents.x, center.y - halfExtents.y, center.z + halfExtents.z },
            { center.x - halfExtents.x, center.y + halfExtents.y, center.z - halfExtents.z },
            { center.x + halfExtents.x, center.y + halfExtents.y, center.z - halfExtents.z },
            { center.x + halfExtents.x, center.y + halfExtents.y, center.z + halfExtents.z },
            { center.x - halfExtents.x, center.y + halfExtents.y, center.z + halfExtents.z },
        };

        // 12 edges
        DrawLine(corners[0], corners[1], color);
        DrawLine(corners[1], corners[2], color);
        DrawLine(corners[2], corners[3], color);
        DrawLine(corners[3], corners[0], color);
        DrawLine(corners[4], corners[5], color);
        DrawLine(corners[5], corners[6], color);
        DrawLine(corners[6], corners[7], color);
        DrawLine(corners[7], corners[4], color);
        DrawLine(corners[0], corners[4], color);
        DrawLine(corners[1], corners[5], color);
        DrawLine(corners[2], corners[6], color);
        DrawLine(corners[3], corners[7], color);
    }

    void DebugRenderer::DrawCircle(const Vec3& center, float radius, const Color& color, 
                                    int segments, bool filled) {
        if (!m_inFrame) return;

        const float pi = 3.14159265358979f;
        
        for (int i = 0; i < segments; ++i) {
            float theta1 = (static_cast<float>(i) / segments) * 2.0f * pi;
            float theta2 = (static_cast<float>(i + 1) / segments) * 2.0f * pi;

            Vec3 p1 = { center.x + radius * cosf(theta1), center.y, center.z + radius * sinf(theta1) };
            Vec3 p2 = { center.x + radius * cosf(theta2), center.y, center.z + radius * sinf(theta2) };
            DrawLine(p1, p2, color);

            if (filled) {
                DirectX::XMFLOAT4 col(color.r, color.g, color.b, color.a * 0.3f);  // Translucent fill
                
                // Front face (clockwise when viewed from above)
                m_triangleVertices.push_back({ { center.x, center.y, center.z }, col });
                m_triangleVertices.push_back({ { p1.x, p1.y, p1.z }, col });
                m_triangleVertices.push_back({ { p2.x, p2.y, p2.z }, col });
                
                // Back face (counter-clockwise - visible from below)
                m_triangleVertices.push_back({ { center.x, center.y, center.z }, col });
                m_triangleVertices.push_back({ { p2.x, p2.y, p2.z }, col });
                m_triangleVertices.push_back({ { p1.x, p1.y, p1.z }, col });
            }
        }
    }

    void DebugRenderer::DrawCylinder(const Vec3& base, float radius, float height, 
                                      const Color& color, int segments, bool filled) {
        if (!m_inFrame) return;

        Vec3 top = { base.x, base.y + height, base.z };
        
        // Draw bottom and top circles
        DrawCircle(base, radius, color, segments, filled);
        DrawCircle(top, radius, color, segments, filled);

        // Draw vertical lines
        const float pi = 3.14159265358979f;
        for (int i = 0; i < segments; i += 4) {  // Every 4th segment for vertical lines
            float theta = (static_cast<float>(i) / segments) * 2.0f * pi;
            Vec3 bottom = { base.x + radius * cosf(theta), base.y, base.z + radius * sinf(theta) };
            Vec3 topPt = { base.x + radius * cosf(theta), base.y + height, base.z + radius * sinf(theta) };
            DrawLine(bottom, topPt, color);
        }
    }

    void DebugRenderer::DrawCone(const Vec3& apex, const Vec3& direction, float radius, 
                                  float height, const Color& color, int segments) {
        if (!m_inFrame) return;

        // Normalize direction
        float len = sqrtf(direction.x * direction.x + direction.y * direction.y + direction.z * direction.z);
        Vec3 dir = { direction.x / len, direction.y / len, direction.z / len };

        // Base center
        Vec3 baseCenter = {
            apex.x + dir.x * height,
            apex.y + dir.y * height,
            apex.z + dir.z * height
        };

        // Draw base circle and lines to apex
        const float pi = 3.14159265358979f;
        for (int i = 0; i < segments; ++i) {
            float theta1 = (static_cast<float>(i) / segments) * 2.0f * pi;
            float theta2 = (static_cast<float>(i + 1) / segments) * 2.0f * pi;

            // Simple case: direction is mostly vertical
            Vec3 p1 = { baseCenter.x + radius * cosf(theta1), baseCenter.y, baseCenter.z + radius * sinf(theta1) };
            Vec3 p2 = { baseCenter.x + radius * cosf(theta2), baseCenter.y, baseCenter.z + radius * sinf(theta2) };
            
            DrawLine(p1, p2, color);  // Base circle
            DrawLine(apex, p1, color);  // Lines to apex
        }
    }

    void DebugRenderer::DrawArrow(const Vec3& start, const Vec3& end, const Color& color, 
                                   float thickness, float headSize) {
        if (!m_inFrame) return;

        // Main line
        DrawLine(start, end, color, thickness);

        // Calculate arrowhead direction
        Vec3 dir = { end.x - start.x, end.y - start.y, end.z - start.z };
        float len = sqrtf(dir.x * dir.x + dir.y * dir.y + dir.z * dir.z);
        if (len < 0.001f) return;

        dir = { dir.x / len, dir.y / len, dir.z / len };

        // Find perpendicular vectors
        Vec3 perp1, perp2;
        if (fabsf(dir.y) < 0.99f) {
            perp1 = { -dir.z, 0, dir.x };
        } else {
            perp1 = { 1, 0, 0 };
        }
        float pLen = sqrtf(perp1.x * perp1.x + perp1.z * perp1.z);
        perp1 = { perp1.x / pLen, 0, perp1.z / pLen };
        
        perp2 = { dir.y * perp1.z, dir.z * perp1.x - dir.x * perp1.z, -dir.y * perp1.x };

        // Arrowhead base
        Vec3 headBase = {
            end.x - dir.x * headSize,
            end.y - dir.y * headSize,
            end.z - dir.z * headSize
        };

        // Arrowhead points
        float headRadius = headSize * 0.4f;
        Vec3 h1 = { headBase.x + perp1.x * headRadius, headBase.y + perp1.y * headRadius, headBase.z + perp1.z * headRadius };
        Vec3 h2 = { headBase.x - perp1.x * headRadius, headBase.y - perp1.y * headRadius, headBase.z - perp1.z * headRadius };
        Vec3 h3 = { headBase.x + perp2.x * headRadius, headBase.y + perp2.y * headRadius, headBase.z + perp2.z * headRadius };
        Vec3 h4 = { headBase.x - perp2.x * headRadius, headBase.y - perp2.y * headRadius, headBase.z - perp2.z * headRadius };

        DrawLine(end, h1, color, thickness);
        DrawLine(end, h2, color, thickness);
        DrawLine(end, h3, color, thickness);
        DrawLine(end, h4, color, thickness);
    }

    void DebugRenderer::DrawPath(const std::vector<Vec3>& points, const Color& color, 
                                  float thickness, bool closed) {
        if (!m_inFrame || points.size() < 2) return;

        for (size_t i = 0; i < points.size() - 1; ++i) {
            DrawLine(points[i], points[i + 1], color, thickness);
        }

        if (closed && points.size() > 2) {
            DrawLine(points.back(), points.front(), color, thickness);
        }
    }

    void DebugRenderer::DrawRing(const Vec3& center, float innerRadius, float outerRadius, 
                                  float height, const Color& color, int segments) {
        if (!m_inFrame) return;

        // Draw inner and outer circles at bottom and top
        Vec3 top = { center.x, center.y + height, center.z };
        
        DrawCircle(center, innerRadius, color, segments);
        DrawCircle(center, outerRadius, color, segments);
        DrawCircle(top, innerRadius, color, segments);
        DrawCircle(top, outerRadius, color, segments);

        // Vertical lines at intervals
        const float pi = 3.14159265358979f;
        for (int i = 0; i < segments; i += 4) {
            float theta = (static_cast<float>(i) / segments) * 2.0f * pi;
            
            // Inner vertical
            Vec3 innerBottom = { center.x + innerRadius * cosf(theta), center.y, center.z + innerRadius * sinf(theta) };
            Vec3 innerTop = { center.x + innerRadius * cosf(theta), center.y + height, center.z + innerRadius * sinf(theta) };
            DrawLine(innerBottom, innerTop, color);

            // Outer vertical
            Vec3 outerBottom = { center.x + outerRadius * cosf(theta), center.y, center.z + outerRadius * sinf(theta) };
            Vec3 outerTop = { center.x + outerRadius * cosf(theta), center.y + height, center.z + outerRadius * sinf(theta) };
            DrawLine(outerBottom, outerTop, color);

            // Connect inner to outer at top and bottom
            DrawLine(innerBottom, outerBottom, color);
            DrawLine(innerTop, outerTop, color);
        }
    }

    void DebugRenderer::DrawText3D(const Vec3& position, const std::string& text, 
                                    const Color& color, float scale) {
        // Project to screen and use ImGui to draw
        auto screenPos = WorldToScreen(position);
        if (!screenPos) return;

        ImDrawList* drawList = ImGui::GetBackgroundDrawList();
        if (drawList) {
            drawList->AddText(ImVec2(screenPos->x, screenPos->y), color.ToABGR(), text.c_str());
        }
    }

    // ============================================
    // Persistent primitives
    // ============================================
    void DebugRenderer::AddLine(uint32_t id, const DebugLine& line, float lifetime) {
        auto expireTime = std::chrono::steady_clock::now() + 
                          std::chrono::milliseconds(static_cast<int64_t>(lifetime * 1000));
        
        std::lock_guard<std::mutex> lock(m_primitiveMutex);
        
        // Check if updating existing
        for (auto& existing : m_persistentLines) {
            if (existing.id == id) {
                existing.primitive = line;
                existing.expireTime = expireTime;
                return;
            }
        }
        
        m_persistentLines.push_back({ line, expireTime, id });
    }

    void DebugRenderer::AddSphere(uint32_t id, const DebugSphere& sphere, float lifetime) {
        auto expireTime = std::chrono::steady_clock::now() + 
                          std::chrono::milliseconds(static_cast<int64_t>(lifetime * 1000));
        
        std::lock_guard<std::mutex> lock(m_primitiveMutex);
        
        for (auto& existing : m_persistentSpheres) {
            if (existing.id == id) {
                existing.primitive = sphere;
                existing.expireTime = expireTime;
                return;
            }
        }
        
        m_persistentSpheres.push_back({ sphere, expireTime, id });
    }

    void DebugRenderer::AddCircle(uint32_t id, const DebugCircle& circle, float lifetime) {
        auto expireTime = std::chrono::steady_clock::now() + 
                          std::chrono::milliseconds(static_cast<int64_t>(lifetime * 1000));
        
        std::lock_guard<std::mutex> lock(m_primitiveMutex);
        
        for (auto& existing : m_persistentCircles) {
            if (existing.id == id) {
                existing.primitive = circle;
                existing.expireTime = expireTime;
                return;
            }
        }
        
        m_persistentCircles.push_back({ circle, expireTime, id });
    }

    void DebugRenderer::AddPath(uint32_t id, const DebugPath& path, float lifetime) {
        auto expireTime = std::chrono::steady_clock::now() + 
                          std::chrono::milliseconds(static_cast<int64_t>(lifetime * 1000));
        
        std::lock_guard<std::mutex> lock(m_primitiveMutex);
        
        for (auto& existing : m_persistentPaths) {
            if (existing.id == id) {
                existing.primitive = path;
                existing.expireTime = expireTime;
                return;
            }
        }
        
        m_persistentPaths.push_back({ path, expireTime, id });
    }

    void DebugRenderer::RemovePrimitive(uint32_t id) {
        std::lock_guard<std::mutex> lock(m_primitiveMutex);
        
        std::erase_if(m_persistentLines, [id](const auto& p) { return p.id == id; });
        std::erase_if(m_persistentSpheres, [id](const auto& p) { return p.id == id; });
        std::erase_if(m_persistentCircles, [id](const auto& p) { return p.id == id; });
        std::erase_if(m_persistentPaths, [id](const auto& p) { return p.id == id; });
    }

    void DebugRenderer::ClearAllPrimitives() {
        std::lock_guard<std::mutex> lock(m_primitiveMutex);
        
        m_persistentLines.clear();
        m_persistentSpheres.clear();
        m_persistentCircles.clear();
        m_persistentPaths.clear();
    }

    void DebugRenderer::ClearPrimitivesOfType(PrimitiveType type) {
        std::lock_guard<std::mutex> lock(m_primitiveMutex);
        
        switch (type) {
            case PrimitiveType::Line:
                m_persistentLines.clear();
                break;
            case PrimitiveType::Sphere:
                m_persistentSpheres.clear();
                break;
            case PrimitiveType::Circle:
                m_persistentCircles.clear();
                break;
            case PrimitiveType::Path:
                m_persistentPaths.clear();
                break;
            default:
                break;
        }
    }

    void DebugRenderer::CleanupExpiredPrimitives() {
        std::lock_guard<std::mutex> lock(m_primitiveMutex);
        
        std::erase_if(m_persistentLines, [](const auto& p) { return p.IsExpired(); });
        std::erase_if(m_persistentSpheres, [](const auto& p) { return p.IsExpired(); });
        std::erase_if(m_persistentCircles, [](const auto& p) { return p.IsExpired(); });
        std::erase_if(m_persistentPaths, [](const auto& p) { return p.IsExpired(); });
    }

    size_t DebugRenderer::GetPrimitiveCount() const {
        std::lock_guard<std::mutex> lock(m_primitiveMutex);
        return m_persistentLines.size() + m_persistentSpheres.size() + 
               m_persistentCircles.size() + m_persistentPaths.size();
    }

} // namespace SapphireHook::DebugVisuals
