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
	// ============================================
	class ViewProjectionHook {
	public:
		static ViewProjectionHook& GetInstance();

		ViewProjectionHook(const ViewProjectionHook&) = delete;
		ViewProjectionHook& operator=(const ViewProjectionHook&) = delete;

		bool Initialize();
		void Shutdown();

		bool GetViewProjectionMatrix(DirectX::XMMATRIX& outMatrix) const;
		bool GetCameraPosition(DirectX::XMFLOAT3& outPos) const;
		bool HasValidMatrix() const { return m_hasValidMatrix.load(); }

		uint64_t GetCaptureCount() const { return m_captureCount.load(); }
		uint64_t GetFrameOfLastCapture() const { return m_lastCaptureFrame.load(); }

		void OnNewFrame() { m_currentFrame.fetch_add(1); }

		bool IsHooked() const { return m_isHooked.load(); }
		uintptr_t GetHookedAddress() const { return m_hookedAddress; }

		static void CaptureMatrixFromArgs(const float* matrixPtr);

	private:
		ViewProjectionHook() = default;
		~ViewProjectionHook() = default;

		// Signature patterns for WorldToScreen function
		// Based on IDA analysis: sub_7FF69A5616A0
		bool ScanForWorldToScreen();
		bool ValidateWorldToScreenFunction(uintptr_t address);
		bool InstallHook(uintptr_t address);
		bool InstallSecondHook(uintptr_t address);

		std::atomic<bool> m_initialized{ false };
		std::atomic<bool> m_isHooked{ false };
		std::atomic<bool> m_hasValidMatrix{ false };

		uintptr_t m_hookedAddress = 0;
		void* m_originalFunction = nullptr;

		mutable std::mutex m_mutex;
		DirectX::XMMATRIX m_viewProjMatrix = DirectX::XMMatrixIdentity();
		DirectX::XMFLOAT3 m_cameraPosition = { 0, 0, 0 };

		std::atomic<uint64_t> m_captureCount{ 0 };
		std::atomic<uint64_t> m_lastCaptureFrame{ 0 };
		std::atomic<uint64_t> m_currentFrame{ 0 };
	};
} // namespace SapphireHook::DebugVisuals
