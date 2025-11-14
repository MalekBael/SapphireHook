#pragma once
#include "../UI/UIModule.h"
#include "../Analysis/FunctionScanner.h"
#include "../Core/FunctionDatabase.h"
#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <cstdint>

namespace SapphireHook {
	class MemoryScanner : public UIModule {
	public:
		MemoryScanner();
		~MemoryScanner();

		// UIModule interface
		const char* GetName() const override { return "MemoryScanner"; }
		const char* GetDisplayName() const override { return "Memory Scanner"; }
		void Initialize() override;
		void RenderMenu() override;
		void RenderWindow() override;
		bool IsWindowOpen() const override { return m_windowOpen; }
		void SetWindowOpen(bool open) override { m_windowOpen = open; }

		// Scan operations
		void StartScan(const std::vector<std::string>& targetStrings,
			bool scanPrologues, bool scanStrings);
		void StopScan();
		bool IsScanInProgress() const { return m_scanState.running; }

		// Results access
		std::vector<uintptr_t> GetDiscoveredFunctions() const;
		std::unordered_map<uintptr_t, std::vector<std::string>> GetFunctionTags() const;

		// Analysis helpers
		std::string GenerateFunctionAnalysis(uintptr_t address) const;
		void SelectFunctionForAnalysis(uintptr_t address);

		// Export functionality
		bool ExportAnalysis(const std::string& filename, const std::string& content);

	private:
		struct ScanState {
			// Phase control
			bool running = false;
			bool cancelled = false;
			bool scanPrologues = false;
			bool scanStrings = false;
			bool anchorsRebuilt = false;
			bool prologueCompleted = false;
			bool stringCompleted = false;
			bool uiFreeze = false;
			bool rowsCacheDirty = false;

			uint64_t lastStatusBuildTick = 0;

			// Async work (coarse-grained driver + optional per-phase futures)
			std::future<void> scanFuture;
			std::future<std::vector<uintptr_t>> prologueFuture;
			std::future<std::vector<StringScanResult>> stringFuture;

			// Inputs
			std::vector<std::string> targetStrings;

			// Results
			std::vector<uintptr_t> prologueFunctions;
			std::vector<StringScanResult> stringHits;

			// Timing/status
			std::chrono::steady_clock::time_point startTime{};
			std::string status;

			// Progress tracking
			std::atomic<size_t> prologueProcessed{ 0 };
			std::atomic<size_t> prologueTotal{ 0 };
			std::atomic<size_t> stringProcessed{ 0 };
			std::atomic<size_t> stringTotal{ 0 };

			// Coarse-grained progress (for simple progress bar)
			std::atomic<size_t> totalRegions{ 0 };
			std::atomic<size_t> regionsProcessed{ 0 };

			std::string lastProloguePhase;
			std::string lastStringPhase;
			std::mutex phaseMutex;

			// UI cache
			struct RowCache {
				uintptr_t addr{};
				std::string addrText;
				std::string name;
				std::string tagsShort;
			};
			std::vector<RowCache> rowCache;
			std::string filterText;
		};

		void ResetScanState();
		void UpdateScanAsync();
		void RebuildAnchorStringMatches();
		void RenderScanResults();
		void RenderAnalysisPanel();

		std::string BuildMultiDiffText(const std::vector<uintptr_t>& addrs);
		std::string GetPrologueBytes(uintptr_t address, size_t maxLen) const;
		bool DisassembleSnippet(uintptr_t address, std::string& out,
			int maxInstr = 8, size_t maxBytes = 64) const;
		bool IsSafeToRead(void* address, size_t size) const;

		bool m_windowOpen = false;
		ScanState m_scanState;

		std::shared_ptr<FunctionScanner> m_scanner;
		std::shared_ptr<FunctionDatabase> m_functionDB;

		// Merged results
		std::vector<uintptr_t> m_mergedFunctions;
		std::unordered_map<uintptr_t, std::vector<std::string>> m_functionTags;
		bool m_resultsDirty = true;

		// Analysis state
		uintptr_t m_selectedFunction = 0;
		std::string m_selectedAnalysis;
		std::vector<uintptr_t> m_multiSelected;
		std::string m_multiDiffText;

		bool m_showAnalysisPanel = true;
		bool m_showMultiDiff = false;
		bool m_showDisassembly = false;
		std::string m_lastExportStatus;

		// Sampling thread
		std::atomic<bool> m_samplingActive{ false };
		std::thread m_samplingThread;
		void SampleActiveModuleFunctions();
	};
} // namespace SapphireHook