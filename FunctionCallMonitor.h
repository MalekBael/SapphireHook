#pragma once
#include "UIModule.h"
#include <vector>
#include <string>
#include <mutex>
#include <chrono>
#include <cstdint>
#include "FunctionDatabase.h"
#include "SignatureDatabase.h"
#include <thread>
#include <atomic>
#include <map>

struct FunctionCall {
	std::string functionName;       // Full function name (e.g., "Client::ExdData::getBGM")
	uintptr_t address;
	std::chrono::steady_clock::time_point timestamp;
	std::string context; // e.g., "Movement", "Combat", "UI"
};

class FunctionCallMonitor : public UIModule
{
private:
	// Core functionality
	std::vector<FunctionCall> m_functionCalls;
	std::mutex m_callsMutex;
	bool m_windowOpen = false;
	bool m_autoScroll = true;
	bool m_showAddresses = true;
	bool m_showTimestamps = true;
	int m_maxEntries = 1000;
	char m_filterText[256] = "";

	// Function database integration
	FunctionDatabase m_functionDB;
	bool m_useFunctionDatabase = true;

	// Signature database integration
	SignatureDatabase m_signatureDB;
	bool m_useSignatureDatabase = true;
	std::atomic<bool> m_signatureResolutionInProgress{ false };
	std::thread m_signatureResolutionThread;

	// Hook management
	std::vector<uintptr_t> m_hookedFunctions;
	std::vector<uintptr_t> m_discoveredFunctions;

	// Hooking control
	bool m_enableRealHooking = false;

	// Function patterns to monitor
	struct FunctionPattern {
		const char* name;
		const char* pattern;
		const char* context;
	};

	static FunctionPattern s_patterns[];

	// New members for async scanning
	std::thread m_scanThread;
	std::atomic<bool> m_scanInProgress{ false };
	std::atomic<bool> m_stopScan{ false };

	// Type-aware function analysis (single declaration)
	std::map<std::string, std::vector<uintptr_t>> m_functionsByType;
	std::map<uintptr_t, std::string> m_functionSignatures;

	// Private methods
	bool CreateFunctionHook(uintptr_t address, const std::string& name, const std::string& context);
	bool CreateSafeLoggingHook(uintptr_t address, const std::string& name, const std::string& context);
	bool CreateRealLoggingHook(uintptr_t address, const std::string& name, const std::string& context);
	void SetupFunctionHooks();
	void ClearCalls();
	void HookCommonAPIs();
	void HookFunctionByAddress(uintptr_t address, const std::string& name);
	void RenderManualHookSection();
	void ScanAllFunctions();
	void ScanForFunctionPrologues(uintptr_t moduleBase, size_t moduleSize, std::vector<uintptr_t>& functions);
	void ScanExportedFunctions(std::vector<uintptr_t>& functions);
	void ScanCallTargets(uintptr_t moduleBase, size_t moduleSize, std::vector<uintptr_t>& functions);
	bool IsLikelyFunctionStart(uintptr_t address);
	void HookRandomFunctions(int count);
	static void __stdcall FunctionHookCallback(uintptr_t returnAddress, uintptr_t functionAddress);
	void ScanSafeRegion(uintptr_t baseAddr, size_t size, std::vector<uintptr_t>& functions);
	bool IsSafeAddress(uintptr_t address);
	void UnhookAllFunctions();

	// Database-aware function name resolution
	std::string ResolveFunctionName(uintptr_t address) const;

	// Enhanced signature-based methods
	void InitializeWithSignatures();
	void StartAsyncSignatureResolution();
	void IntegrateSignaturesWithDatabase();
	void RenderSignatureSection();
	void RenderEnhancedFunctionSearch();
	void DiscoverFunctionsFromSignatures();

	// Enhanced rendering methods
	void RenderTypeAwareFunctionSearch();
	void RenderClassHierarchyView();
	void RenderVirtualFunctionTable();

public:
	// Constructor
	FunctionCallMonitor();

	const char* GetName() const override { return "function_monitor"; }
	const char* GetDisplayName() const override { return "Function Call Monitor"; }

	void Initialize() override;
	void Shutdown() override;
	void RenderMenu() override;
	void RenderWindow() override;

	bool IsWindowOpen() const override { return m_windowOpen; }
	void SetWindowOpen(bool open) override { m_windowOpen = open; }

	// Public methods for external access
	void AddFunctionCall(const std::string& name, uintptr_t address, const std::string& context = "");
	void SetDiscoveredFunctions(const std::vector<uintptr_t>& functions);

	// Static instance for hook callbacks
	static FunctionCallMonitor* s_instance;

	// New methods for async scanning
	void StartAsyncScan();
	void StopScan();

	// Enhanced initialization (single declaration)
	void InitializeWithTypeInformation();

	// Type-aware function discovery
	void DiscoverFunctionsByType(const std::string& className);
	void AnalyzeVirtualFunctionTables();
	void GenerateTypeBasedHooks();
};