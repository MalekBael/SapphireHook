#pragma once

#include "../UI/UIModule.h"
#include <atomic>
#include <chrono>
#include <future>
#include <string>
#include <vector>
#include <unordered_map> // added

namespace SapphireHook {
	class StringXrefAnalyzer : public UIModule {
	public:
		StringXrefAnalyzer();
		~StringXrefAnalyzer();

		const char* GetName() const override { return "StringXrefAnalyzer"; }
		const char* GetDisplayName() const override { return "String XREF Analyzer"; }
		void Initialize() override;
		void RenderMenu() override;
		void RenderWindow() override;
		bool IsWindowOpen() const override { return m_windowOpen; }
		void SetWindowOpen(bool open) override { m_windowOpen = open; }

		struct XrefRow {
			uintptr_t addr{};
			std::string name;
			std::vector<std::string> strings;
		};

		void StartAnalysis(int minStringLength, size_t maxStringsPerFunc);
		void CancelAnalysis();
		std::vector<XrefRow> GetResults() const;
		bool ExportResultsToText(std::string& outPath) const;

	private:
		bool m_windowOpen = false;

		struct AnalysisState {
			bool running = false;
			int minLen = 6;
			size_t maxStringsPerFn = 3;
			size_t totalAscii = 0;
			size_t totalUtf16 = 0;
			std::future<void> task;
			std::string status;
			std::atomic<bool> cancel{ false };
			std::chrono::steady_clock::time_point started{};
			std::vector<XrefRow> rows;

			// Progress
			std::atomic<size_t> mapProcessed{ 0 };
			size_t mapTotal = 0;

			// NEW: accumulate partial results for cancel
			std::unordered_map<uintptr_t, std::vector<std::string>> interimMap;
		} m_state;

		void RenderAnalysisTab();
		XrefRow BuildStringXrefs(uintptr_t functionAddr);
	};
} // namespace SapphireHook