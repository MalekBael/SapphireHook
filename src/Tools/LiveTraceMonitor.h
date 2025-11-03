#pragma once

#include "../UI/UIModule.h"

#include <atomic>
#include <chrono>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <cstdint>

namespace SapphireHook {
	class LiveTraceMonitor : public UIModule {
	public:
		LiveTraceMonitor();
		~LiveTraceMonitor();

		const char* GetName() const override { return "LiveTraceMonitor"; }
		const char* GetDisplayName() const override { return "Live Trace Monitor"; }
		void Initialize() override;
		void RenderMenu() override;
		void RenderWindow() override;
		bool IsWindowOpen() const override { return m_windowOpen; }
		void SetWindowOpen(bool open) override { m_windowOpen = open; }

		// External producers (e.g., FunctionCallMonitor) push trace events here
		void AddTraceEntry(uintptr_t address, uintptr_t callerAddress, const std::string& functionName);

		// Global accessor for producers
		static LiveTraceMonitor* GetInstance() { return s_instance; }

	private:
		static LiveTraceMonitor* s_instance;

		struct TraceEntry {
			std::chrono::steady_clock::time_point timestamp{};
			uintptr_t address{};
			uintptr_t callerAddress{};
			std::string functionName;
		};

		struct {
			std::mutex mutex;
			std::vector<TraceEntry> entries;
			std::unordered_set<uintptr_t> uniqueFunctions;
			size_t totalCalls = 0;
			float callsPerSecond = 0.0f;
			bool capturing = false;
			std::chrono::steady_clock::time_point startTime{};
			std::chrono::steady_clock::time_point lastUpdateTime{};
		} m_traceState;

		bool m_windowOpen = false;

		std::atomic<bool> m_samplingActive{ false };
		std::thread m_samplingThread;

		void StartCapture();
		void StopCapture();
		void ClearTrace();
		void UpdateMetrics();
		void RenderTraceTable();
		void RenderMetrics();
	};
} // namespace SapphireHook