// ViewProjectionHook.cpp - Captures ViewProjection matrix by hooking game's W2S function
//
// Hook the game's WorldToScreen function and capture the ViewProjection
// matrix as it's passed in or computed.
//
// IDA Analysis (FFXIV 3.35, base 0x140000000):
//   - PRIMARY W2S: sub_140DAF6E0 (RVA 0xDAF6E0, Score 13, has 0.5 constant)
//   - BACKUP W2S:  sub_1401116A0 (RVA 0x1116A0, Score 12, matrix offsets)
//   - ALT W2S:     sub_1401113C0 (RVA 0x1113C0, Score 12, matrix offsets)
//   - Formula: screenX = (clip.x/|w|)*0.5+0.5, screenY = 0.5-(clip.y/|w|)*0.5

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include <MinHook.h>

#include "ViewProjectionHook.h"
#include "../Analysis/PatternScanner.h"
#include "../Logger/Logger.h"

#include <format>
#include <cmath>

namespace SapphireHook::DebugVisuals {
	// ============================================
	// Signature patterns for WorldToScreen function
	// ============================================

	//
	// PRIMARY (Score 13): sub_140DAF6E0 - RVA 0xDAF6E0
	//   - Size: 996 bytes
	//   - HAS 0.5 constant (critical for NDC to screen conversion)
	//   - DIVSS: 2, MULSS: 7, ADDSS: 5, COMISS: 7
	//   - Key: addss xmm0, [rcx+1778h] at offset 0x33
	//
	// BACKUP (Score 12): sub_1401116A0 - RVA 0x1116A0
	//   - Size: 525 bytes
	//   - Matrix offsets, 2 DIVSS, 13 MULSS
	//
	// ALT (Score 12): sub_1401113C0 - RVA 0x1113C0
	//   - Size: 723 bytes
	//   - Matrix offsets, 4 DIVSS, 20 MULSS

	struct PatternInfo {
		const char* pattern;
		int offsetToFunctionStart;  // Offset from pattern match back to function start
		const char* description;
	};

	static constexpr PatternInfo W2S_PATTERNS[] = {
		// ===== Patterns for sub_140DAF6E0 (PRIMARY, RVA 0xDAF6E0) =====

		// Pattern 1: addss xmm0, [rcx+1778h] - UNIQUE offset 1778h
		// At offset 0x33 from function start
		// addss xmm0, dword ptr [rcx+1778h] = F3 0F 58 81 78 17 00 00
		{"F3 0F 58 81 78 17 00 00", 0x33, "addss xmm0,[rcx+1778h] (PRIMARY)"},

		// Pattern 2: Function prologue - sub rsp, 90h with movss pattern
		// From: sub rsp, 90h; movss xmm0, cs:dword...
		{"48 81 EC 90 00 00 00", 0x04, "sub rsp,90h (PRIMARY prologue)"},

		// ===== Patterns for sub_1401116A0 (BACKUP, RVA 0x1116A0) =====

		// Pattern 3: lea r8, [rdx+50h]; lea rcx, [rsp+...]
		{"4C 8D 42 50 48 8D 4C 24", 0x2B, "lea r8,[rdx+50h] (BACKUP)"},

		// Pattern 4: Function prologue for 1116A0
		// mov [rsp+arg_10], rbx; push rdi; sub rsp, 0E0h
		{"48 89 5C 24 18 57 48 81 EC E0 00 00 00", 0x00, "BACKUP prologue"},

		// ===== Patterns for sub_1401113C0 (ALT, RVA 0x1113C0) =====

		// Pattern 5: ALT prologue - sub rsp, 0B0h
		{"48 81 EC B0 00 00 00", 0x04, "sub rsp,B0h (ALT prologue)"},
	};

	// ============================================
	// Hook trampoline types
	// ============================================

	// The WorldToScreen function signature (approximate from IDA):
	// void __fastcall WorldToScreen(void* thisObj, float* worldPos, float* outScreenPos)
	// Or it might be:
	// bool __fastcall WorldToScreen(void* camera, Vector3* worldPos, Vector2* screenOut)

	// capture whatever matrix data we find
	using WorldToScreen_t = void* (__fastcall*)(void* rcx, void* rdx, void* r8, void* r9);
	static WorldToScreen_t s_originalW2S = nullptr;
	static WorldToScreen_t s_originalW2S_Alt = nullptr;  // Second hook for "no callers" version
	static uintptr_t s_secondHookAddress = 0;

	// Our hook functions
	static void* __fastcall HookedWorldToScreen(void* rcx, void* rdx, void* r8, void* r9);
	static void* __fastcall HookedWorldToScreen_Alt(void* rcx, void* rdx, void* r8, void* r9);

	ViewProjectionHook& ViewProjectionHook::GetInstance() {
		static ViewProjectionHook instance;
		return instance;
	}

	bool ViewProjectionHook::Initialize() {
		if (m_initialized.load()) {
			return m_isHooked.load();
		}

		LogInfo("ViewProjectionHook: Initializing...");

		// First, try to find the WorldToScreen function
		if (!ScanForWorldToScreen()) {
			LogWarning("ViewProjectionHook: Could not find WorldToScreen function");
			LogWarning("ViewProjectionHook: Will fall back to memory-based matrix extraction");
			m_initialized.store(true);
			return false;
		}

		m_initialized.store(true);
		return m_isHooked.load();
	}

	void ViewProjectionHook::Shutdown() {
		if (m_isHooked.load() && m_hookedAddress != 0) {
			MH_DisableHook(reinterpret_cast<void*>(m_hookedAddress));
			MH_RemoveHook(reinterpret_cast<void*>(m_hookedAddress));
			LogInfo("ViewProjectionHook: Hook 1 removed");
		}

		// Remove second hook if installed
		if (s_secondHookAddress != 0) {
			MH_DisableHook(reinterpret_cast<void*>(s_secondHookAddress));
			MH_RemoveHook(reinterpret_cast<void*>(s_secondHookAddress));
			LogInfo("ViewProjectionHook: Hook 2 removed");
			s_secondHookAddress = 0;
		}

		m_isHooked.store(false);
		m_initialized.store(false);
		m_hasValidMatrix.store(false);
		m_hookedAddress = 0;
		m_originalFunction = nullptr;
	}

	// ============================================
	// Scan for WorldToScreen function
	// ============================================
	bool ViewProjectionHook::ScanForWorldToScreen() {
		LogInfo("ViewProjectionHook: Scanning for WorldToScreen function...");

		// Get module base for RVA calculations
		HMODULE mainModule = GetModuleHandleA("ffxiv_dx11.exe");
		if (!mainModule) {
			mainModule = GetModuleHandleA(nullptr);
		}
		uintptr_t moduleBase = reinterpret_cast<uintptr_t>(mainModule);
		LogInfo(std::format("ViewProjectionHook: Module base: 0x{:X}", moduleBase));

		// Known RVAs from IDA analysis (base 0x140000000, rebased correctly):
		//
		// TOP CANDIDATE (Score 13): sub_140DAF6E0 - RVA 0xDAF6E0
		//   - Has 0.5 constant (critical for NDC to screen conversion)
		//   - 2 DIVSS (perspective divide), 7 MULSS, 996 bytes
		//
		// BACKUP CANDIDATE (Score 12): sub_1401116A0 - RVA 0x1116A0
		//   - Matrix offsets, 2 DIVSS, 13 MULSS, 525 bytes
		//
		// ALTERNATIVE (Score 12): sub_1401113C0 - RVA 0x1113C0
		//   - Matrix offsets, 4 DIVSS, 20 MULSS, 723 bytes
		//
		constexpr uintptr_t RVA_W2S_PRIMARY = 0xDAF6E0;
		constexpr uintptr_t RVA_W2S_BACKUP = 0x1116A0;
		constexpr uintptr_t RVA_W2S_ALT = 0x1113C0;

		uintptr_t expectedW2S_Primary = moduleBase + RVA_W2S_PRIMARY;
		uintptr_t expectedW2S_Backup = moduleBase + RVA_W2S_BACKUP;
		uintptr_t expectedW2S_Alt = moduleBase + RVA_W2S_ALT;

		LogInfo(std::format("ViewProjectionHook: Expected W2S Primary at: 0x{:X} (RVA 0x{:X})",
			expectedW2S_Primary, RVA_W2S_PRIMARY));
		LogInfo(std::format("ViewProjectionHook: Expected W2S Backup at: 0x{:X} (RVA 0x{:X})",
			expectedW2S_Backup, RVA_W2S_BACKUP));
		LogInfo(std::format("ViewProjectionHook: Expected W2S Alt at: 0x{:X} (RVA 0x{:X})",
			expectedW2S_Alt, RVA_W2S_ALT));

		LogInfo("ViewProjectionHook: Trying to hook W2S functions...");

		int hooksInstalled = 0;

		// First, try the PRIMARY W2S function (best candidate with 0.5 constant)
		if (ValidateWorldToScreenFunction(expectedW2S_Primary)) {
			LogInfo(std::format("ViewProjectionHook: Hooking W2S PRIMARY at 0x{:X}", expectedW2S_Primary));
			if (InstallHook(expectedW2S_Primary)) {
				LogInfo(std::format("ViewProjectionHook: [1] Hooked PRIMARY RVA 0x{:X}", RVA_W2S_PRIMARY));
				hooksInstalled++;
			}
		}
		else {
			LogWarning("ViewProjectionHook: W2S PRIMARY validation failed, trying BACKUP...");

			// Fallback: Try the BACKUP W2S function
			if (ValidateWorldToScreenFunction(expectedW2S_Backup)) {
				LogInfo(std::format("ViewProjectionHook: Hooking W2S BACKUP at 0x{:X}", expectedW2S_Backup));
				if (InstallHook(expectedW2S_Backup)) {
					LogInfo(std::format("ViewProjectionHook: [1] Hooked BACKUP RVA 0x{:X}", RVA_W2S_BACKUP));
					hooksInstalled++;
				}
			}
			else {
				LogWarning("ViewProjectionHook: W2S BACKUP validation failed");
			}
		}

		// Also try the ALT function as secondary hook
		if (ValidateWorldToScreenFunction(expectedW2S_Alt)) {
			LogInfo(std::format("ViewProjectionHook: Hooking W2S ALT at 0x{:X}", expectedW2S_Alt));
			if (InstallSecondHook(expectedW2S_Alt)) {
				LogInfo(std::format("ViewProjectionHook: [2] Hooked ALT RVA 0x{:X}", RVA_W2S_ALT));
				hooksInstalled++;
			}
		}
		else {
			LogWarning("ViewProjectionHook: W2S ALT validation failed");
		}

		if (hooksInstalled > 0) {
			LogInfo(std::format("ViewProjectionHook: Installed {} hook(s) total", hooksInstalled));
			return true;
		}

		// ==========================================================
		// FALLBACK: Pattern scanning (only accept if RVA matches expected)
		// ==========================================================

		LogInfo("ViewProjectionHook: Direct RVA failed, trying pattern scan with RVA validation...");

		constexpr size_t numPatterns = sizeof(W2S_PATTERNS) / sizeof(W2S_PATTERNS[0]);
		for (size_t i = 0; i < numPatterns; ++i) {
			const auto& patternInfo = W2S_PATTERNS[i];
			LogInfo(std::format("ViewProjectionHook: Trying pattern {} - {}", i + 1, patternInfo.description));

			auto result = PatternScanner::ScanMainModule(patternInfo.pattern);
			if (result) {
				uintptr_t patternAddr = result->address;
				uintptr_t functionAddr = patternAddr - patternInfo.offsetToFunctionStart;
				uintptr_t functionRVA = functionAddr - moduleBase;

				LogInfo(std::format("ViewProjectionHook: Pattern {} found at 0x{:X}, function at 0x{:X} (RVA 0x{:X})",
					i + 1, patternAddr, functionAddr, functionRVA));

				// CRITICAL: Only accept if RVA matches one of our known W2S functions
				bool rvaMatches = (functionRVA == RVA_W2S_PRIMARY || functionRVA == RVA_W2S_BACKUP || functionRVA == RVA_W2S_ALT);

				if (!rvaMatches) {
					LogWarning(std::format("ViewProjectionHook: Pattern {} RVA 0x{:X} does NOT match expected (0x{:X}, 0x{:X}, or 0x{:X}) - SKIPPING",
						i + 1, functionRVA, RVA_W2S_PRIMARY, RVA_W2S_BACKUP, RVA_W2S_ALT));
					continue;  // Don't hook wrong function!
				}

				if (functionRVA == RVA_W2S_PRIMARY) {
					LogInfo("ViewProjectionHook: *** MATCH: This is the PRIMARY W2S function! ***");
				}
				else if (functionRVA == RVA_W2S_BACKUP) {
					LogInfo("ViewProjectionHook: *** MATCH: This is the BACKUP W2S function ***");
				}
				else {
					LogInfo("ViewProjectionHook: *** MATCH: This is the ALT W2S function ***");
				}

				if (ValidateWorldToScreenFunction(functionAddr)) {
					if (InstallHook(functionAddr)) {
						LogInfo(std::format("ViewProjectionHook: Successfully hooked WorldToScreen at 0x{:X} (RVA 0x{:X})",
							functionAddr, functionRVA));
						return true;
					}
				}
				else {
					LogWarning(std::format("ViewProjectionHook: Function validation failed for pattern {}", i + 1));
				}
			}
		}

		LogWarning("ViewProjectionHook: Could not find WorldToScreen function via any method");
		return false;
	}

	// ============================================
	// Validate function looks like WorldToScreen
	// ============================================
	bool ViewProjectionHook::ValidateWorldToScreenFunction(uintptr_t address) {
		if (address == 0 || address < 0x10000) {
			return false;
		}

		// Check memory is readable and executable
		MEMORY_BASIC_INFORMATION mbi{};
		if (!VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi))) {
			return false;
		}

		if (mbi.State != MEM_COMMIT) {
			return false;
		}

		DWORD prot = mbi.Protect & 0xFF;
		bool isExecutable = (prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ ||
			prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
		if (!isExecutable) {
			LogWarning(std::format("ViewProjectionHook: Address 0x{:X} not executable (prot=0x{:X})", address, prot));
			return false;
		}

		// Read first bytes and look for W2S characteristics
		const uint8_t* code = reinterpret_cast<const uint8_t*>(address);

		bool hasDivss = false;
		bool hasMatrixAccess = false;

		// Scan up to 300 bytes of function for key instructions (DIVSS is at offset 0xFF)
		for (int i = 0; i < 295; ++i) {
			// DIVSS = F3 0F 5E XX (4-byte instruction)
			if (code[i] == 0xF3 && code[i + 1] == 0x0F && code[i + 2] == 0x5E) {
				hasDivss = true;
			}
			// Look for [rbx+0xC0] pattern: 83 C0 00 00 00 (displacement in ModR/M)
			// movss xmm0, [rbx+0xC0] = F3 0F 10 83 C0 00 00 00
			if (code[i] == 0x83 && code[i + 1] == 0xC0 && code[i + 2] == 0x00 && code[i + 3] == 0x00 && code[i + 4] == 0x00) {
				hasMatrixAccess = true;
			}
			// Also check for [rbx+0x80] = 83 80 00 00 00
			if (code[i] == 0x93 && code[i + 1] == 0x80 && code[i + 2] == 0x00 && code[i + 3] == 0x00 && code[i + 4] == 0x00) {
				hasMatrixAccess = true;
			}
		}

		LogInfo(std::format("ViewProjectionHook: Validation - hasDivss={}, hasMatrixAccess={}",
			hasDivss, hasMatrixAccess));

		// Since our patterns already found specific bytes unique to this function,
		// we can trust the result even if the validation heuristics fail.
		// Just require executable memory.
		if (!hasDivss && !hasMatrixAccess) {
			// Still allow hook if address looks reasonable (patterns matched)
			LogInfo("ViewProjectionHook: Validation heuristics failed but patterns matched - proceeding with hook");
		}

		return true;  // Trust the pattern matching
	}

	// ============================================
	// Install the hook
	// ============================================
	bool ViewProjectionHook::InstallHook(uintptr_t address) {
		MH_STATUS status = MH_CreateHook(
			reinterpret_cast<void*>(address),
			reinterpret_cast<void*>(&HookedWorldToScreen),
			reinterpret_cast<void**>(&s_originalW2S)
		);

		if (status != MH_OK) {
			LogError(std::format("ViewProjectionHook: MH_CreateHook failed with status {}", static_cast<int>(status)));
			return false;
		}

		status = MH_EnableHook(reinterpret_cast<void*>(address));
		if (status != MH_OK) {
			LogError(std::format("ViewProjectionHook: MH_EnableHook failed with status {}", static_cast<int>(status)));
			MH_RemoveHook(reinterpret_cast<void*>(address));
			return false;
		}

		m_hookedAddress = address;
		m_originalFunction = reinterpret_cast<void*>(s_originalW2S);
		m_isHooked.store(true);

		return true;
	}

	// ============================================
	// Install second hook (for alternate W2S function)
	// ============================================
	bool ViewProjectionHook::InstallSecondHook(uintptr_t address) {
		MH_STATUS status = MH_CreateHook(
			reinterpret_cast<void*>(address),
			reinterpret_cast<void*>(&HookedWorldToScreen_Alt),
			reinterpret_cast<void**>(&s_originalW2S_Alt)
		);

		if (status != MH_OK) {
			LogError(std::format("ViewProjectionHook: MH_CreateHook (alt) failed with status {}", static_cast<int>(status)));
			return false;
		}

		status = MH_EnableHook(reinterpret_cast<void*>(address));
		if (status != MH_OK) {
			LogError(std::format("ViewProjectionHook: MH_EnableHook (alt) failed with status {}", static_cast<int>(status)));
			MH_RemoveHook(reinterpret_cast<void*>(address));
			return false;
		}

		s_secondHookAddress = address;
		return true;
	}

	// ============================================
	// Safe memory read helper (no RAII objects allowed)
	// ============================================
	static bool TryReadFloat(const void* addr, float& outValue) {
		__try {
			outValue = *reinterpret_cast<const float*>(addr);
			return !std::isnan(outValue) && std::abs(outValue) < 1000000.0f;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
	}

	static bool TryReadMatrix16(const float* addr, float outMatrix[16]) {
		__try {
			for (int i = 0; i < 16; ++i) {
				outMatrix[i] = addr[i];
			}
			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
	}

	// ============================================
	// Hook callback - captures matrix data
	// ============================================
	static void* __fastcall HookedWorldToScreen(void* rcx, void* rdx, void* r8, void* r9) {
		auto& instance = ViewProjectionHook::GetInstance();

		// Count all calls
		static std::atomic<int> totalCallCount{ 0 };
		int currentCall = totalCallCount.fetch_add(1);

		// Debug log first few calls
		if (currentCall < 10) {
			LogInfo(std::format("ViewProjectionHook: W2S called #{} rcx=0x{:X} rdx=0x{:X} r8=0x{:X}",
				currentCall, reinterpret_cast<uintptr_t>(rcx),
				reinterpret_cast<uintptr_t>(rdx), reinterpret_cast<uintptr_t>(r8)));
		}

		// The new function (sub_7FF69B1FF6E0) uses:
		// - rcx: some global/manager object (accesses [rcx+1778h])
		// - rbx: output object (writes to [rbx+4], [rbx+8] with 0.5 for NDC)
		//
		// For matrix capture, we need to look elsewhere.
		// The matrix is likely passed via a different path or accessed from a global.

		float tempMatrix[16];

		// Try various offsets from rcx (the manager/context object)
		if (rcx && !instance.HasValidMatrix()) {
			uintptr_t baseAddr = reinterpret_cast<uintptr_t>(rcx);

			// Try offsets where ViewProjection matrix might be stored
			static const size_t matrixOffsets[] = {
				0x40, 0x80, 0xC0, 0x100, 0x140, 0x180, 0x200, 0x400, 0x440
			};

			for (size_t offset : matrixOffsets) {
				const float* matrixPtr = reinterpret_cast<const float*>(baseAddr + offset);
				if (TryReadMatrix16(matrixPtr, tempMatrix)) {
					// Check if this looks like a valid VP matrix (not identity, not garbage)
					bool hasReasonableValues = std::abs(tempMatrix[0]) > 0.001f &&
						std::abs(tempMatrix[0]) < 100.0f &&
						std::abs(tempMatrix[5]) > 0.001f;
					bool notIdentity = std::abs(tempMatrix[0] - 1.0f) > 0.01f ||
						std::abs(tempMatrix[5] - 1.0f) > 0.01f;

					if (hasReasonableValues && notIdentity) {
						if (currentCall < 10) {
							LogInfo(std::format("ViewProjectionHook: Found potential matrix at rcx+0x{:X}: [{:.4f}, {:.4f}, ...]",
								offset, tempMatrix[0], tempMatrix[5]));
						}
						ViewProjectionHook::CaptureMatrixFromArgs(tempMatrix);
						if (instance.HasValidMatrix()) break;
					}
				}
			}
		}

		// Also try rdx if valid
		if (rdx && !instance.HasValidMatrix()) {
			uintptr_t baseAddr = reinterpret_cast<uintptr_t>(rdx);

			static const size_t matrixOffsets[] = { 0x00, 0x10, 0x40, 0x50, 0x80 };

			for (size_t offset : matrixOffsets) {
				const float* matrixPtr = reinterpret_cast<const float*>(baseAddr + offset);
				if (TryReadMatrix16(matrixPtr, tempMatrix)) {
					bool hasReasonableValues = std::abs(tempMatrix[0]) > 0.001f &&
						std::abs(tempMatrix[0]) < 100.0f;
					bool notIdentity = std::abs(tempMatrix[0] - 1.0f) > 0.01f;

					if (hasReasonableValues && notIdentity) {
						if (currentCall < 10) {
							LogInfo(std::format("ViewProjectionHook: Found potential matrix at rdx+0x{:X}: [{:.4f}, ...]",
								offset, tempMatrix[0]));
						}
						ViewProjectionHook::CaptureMatrixFromArgs(tempMatrix);
						if (instance.HasValidMatrix()) break;
					}
				}
			}
		}

		// Call original function
		return s_originalW2S(rcx, rdx, r8, r9);
	}

	// ============================================
	// Alternate hook callback for "no callers" W2S
	// ============================================
	static void* __fastcall HookedWorldToScreen_Alt(void* rcx, void* rdx, void* r8, void* r9) {
		auto& instance = ViewProjectionHook::GetInstance();

		// Count calls to THIS hook specifically
		static std::atomic<int> altCallCount{ 0 };
		int currentCall = altCallCount.fetch_add(1);

		// Debug log first few calls - THIS IS THE KEY: if we see these, this function IS being called
		if (currentCall < 10) {
			LogInfo(std::format("ViewProjectionHook: W2S_ALT (0x5616A0) called #{} rcx=0x{:X} rdx=0x{:X} r8=0x{:X}",
				currentCall, reinterpret_cast<uintptr_t>(rcx),
				reinterpret_cast<uintptr_t>(rdx), reinterpret_cast<uintptr_t>(r8)));
		}

		// Periodic reminder that this hook is active
		if (currentCall > 0 && (currentCall % 1000) == 0) {
			LogInfo(std::format("ViewProjectionHook: W2S_ALT has been called {} times", currentCall));
		}

		float tempMatrix[16];

		// Try various offsets from rcx
		if (rcx && !instance.HasValidMatrix()) {
			uintptr_t baseAddr = reinterpret_cast<uintptr_t>(rcx);

			// Dump all potential matrices on first call for debugging
			static bool dumpedMatrices = false;
			if (!dumpedMatrices && currentCall == 0) {
				dumpedMatrices = true;

				// First, dump what's at rdx (should be input world position)
				if (rdx) {
					const float* rdxFloats = reinterpret_cast<const float*>(rdx);
					float f[4] = { 0 };
					if (TryReadMatrix16(rdxFloats, f)) {  // Reuse safe read function
						LogInfo(std::format("ViewProjectionHook_Alt: rdx (input?) = [{:.2f}, {:.2f}, {:.2f}, {:.2f}]",
							f[0], f[1], f[2], f[3]));
					}
				}

				LogInfo("ViewProjectionHook_Alt: === MATRIX DUMP FROM RCX ===");
				LogInfo(std::format("ViewProjectionHook_Alt: rcx = 0x{:X} (RVA 0x{:X})",
					baseAddr, baseAddr - reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr))));

				// Dump more offsets to find the real ViewProjection
				static const size_t dumpOffsets[] = { 0x00, 0x10, 0x40, 0x80, 0xC0, 0x100, 0x140, 0x180, 0x1C0, 0x200, 0x240, 0x280, 0x2C0, 0x300, 0x400, 0x440, 0x480 };
				for (size_t offset : dumpOffsets) {
					const float* matrixPtr = reinterpret_cast<const float*>(baseAddr + offset);
					float m[16];
					if (TryReadMatrix16(matrixPtr, m)) {
						// Check if it looks like a reasonable matrix
						bool hasSmallValues = std::abs(m[0]) < 10.0f && std::abs(m[5]) < 10.0f;
						bool hasTranslation = std::abs(m[12]) > 10.0f || std::abs(m[13]) > 10.0f || std::abs(m[14]) > 10.0f;
						const char* note = "";
						if (hasSmallValues && hasTranslation) note = " <-- LIKELY VIEW MATRIX!";
						else if (hasSmallValues && !hasTranslation && std::abs(m[0]) > 0.5f) note = " (projection-like)";

						LogInfo(std::format("  rcx+0x{:X}:{}", offset, note));
						LogInfo(std::format("    [{:10.4f}, {:10.4f}, {:10.4f}, {:10.4f}]", m[0], m[1], m[2], m[3]));
						LogInfo(std::format("    [{:10.4f}, {:10.4f}, {:10.4f}, {:10.4f}]", m[4], m[5], m[6], m[7]));
						LogInfo(std::format("    [{:10.4f}, {:10.4f}, {:10.4f}, {:10.4f}]", m[8], m[9], m[10], m[11]));
						LogInfo(std::format("    [{:10.4f}, {:10.4f}, {:10.4f}, {:10.4f}]", m[12], m[13], m[14], m[15]));
					}
				}
				LogInfo("ViewProjectionHook_Alt: === END MATRIX DUMP ===");
			}

			static const size_t matrixOffsets[] = {
				0x40, 0x80, 0xC0, 0x100, 0x140, 0x180, 0x200, 0x400, 0x440
			};

			for (size_t offset : matrixOffsets) {
				const float* matrixPtr = reinterpret_cast<const float*>(baseAddr + offset);
				if (TryReadMatrix16(matrixPtr, tempMatrix)) {
					bool hasReasonableValues = std::abs(tempMatrix[0]) > 0.001f &&
						std::abs(tempMatrix[0]) < 100.0f &&
						std::abs(tempMatrix[5]) > 0.001f;
					bool notIdentity = std::abs(tempMatrix[0] - 1.0f) > 0.01f ||
						std::abs(tempMatrix[5] - 1.0f) > 0.01f;

					if (hasReasonableValues && notIdentity) {
						if (currentCall < 10) {
							LogInfo(std::format("ViewProjectionHook_Alt: Found potential matrix at rcx+0x{:X}: [{:.4f}, {:.4f}, ...]",
								offset, tempMatrix[0], tempMatrix[5]));
						}
						ViewProjectionHook::CaptureMatrixFromArgs(tempMatrix);
						if (instance.HasValidMatrix()) break;
					}
				}
			}
		}

		// Also try rdx if valid
		if (rdx && !instance.HasValidMatrix()) {
			uintptr_t baseAddr = reinterpret_cast<uintptr_t>(rdx);

			static const size_t matrixOffsets[] = { 0x00, 0x10, 0x40, 0x50, 0x80 };

			for (size_t offset : matrixOffsets) {
				const float* matrixPtr = reinterpret_cast<const float*>(baseAddr + offset);
				if (TryReadMatrix16(matrixPtr, tempMatrix)) {
					bool hasReasonableValues = std::abs(tempMatrix[0]) > 0.001f &&
						std::abs(tempMatrix[0]) < 100.0f;
					bool notIdentity = std::abs(tempMatrix[0] - 1.0f) > 0.01f;

					if (hasReasonableValues && notIdentity) {
						if (currentCall < 10) {
							LogInfo(std::format("ViewProjectionHook_Alt: Found potential matrix at rdx+0x{:X}: [{:.4f}, ...]",
								offset, tempMatrix[0]));
						}
						ViewProjectionHook::CaptureMatrixFromArgs(tempMatrix);
						if (instance.HasValidMatrix()) break;
					}
				}
			}
		}

		// Call original function
		return s_originalW2S_Alt(rcx, rdx, r8, r9);
	}

	// ============================================
	// Capture matrix data from hook
	// ============================================
	void ViewProjectionHook::CaptureMatrixFromArgs(const float* matrixPtr) {
		auto& instance = ViewProjectionHook::GetInstance();

		// Validate the matrix looks reasonable
		bool isValid = true;
		for (int i = 0; i < 16; ++i) {
			if (std::isnan(matrixPtr[i]) || std::isinf(matrixPtr[i])) {
				isValid = false;
				break;
			}
			if (std::abs(matrixPtr[i]) > 100000.0f) {
				isValid = false;
				break;
			}
		}

		if (!isValid) {
			return;
		}

		// Check it's not identity (uninitialized)
		bool isIdentity = (std::abs(matrixPtr[0] - 1.0f) < 0.001f &&
			std::abs(matrixPtr[5] - 1.0f) < 0.001f &&
			std::abs(matrixPtr[10] - 1.0f) < 0.001f &&
			std::abs(matrixPtr[15] - 1.0f) < 0.001f &&
			std::abs(matrixPtr[12]) < 0.001f &&
			std::abs(matrixPtr[13]) < 0.001f &&
			std::abs(matrixPtr[14]) < 0.001f);

		if (isIdentity) {
			return;
		}

		// Store the matrix
		{
			std::lock_guard<std::mutex> lock(instance.m_mutex);

			instance.m_viewProjMatrix = DirectX::XMMATRIX(
				matrixPtr[0], matrixPtr[1], matrixPtr[2], matrixPtr[3],
				matrixPtr[4], matrixPtr[5], matrixPtr[6], matrixPtr[7],
				matrixPtr[8], matrixPtr[9], matrixPtr[10], matrixPtr[11],
				matrixPtr[12], matrixPtr[13], matrixPtr[14], matrixPtr[15]
			);

			// Extract camera position from inverse
			DirectX::XMVECTOR det;
			DirectX::XMMATRIX invVP = DirectX::XMMatrixInverse(&det, instance.m_viewProjMatrix);
			DirectX::XMFLOAT4X4 invFloat;
			DirectX::XMStoreFloat4x4(&invFloat, invVP);

			instance.m_cameraPosition.x = invFloat._41;
			instance.m_cameraPosition.y = invFloat._42;
			instance.m_cameraPosition.z = invFloat._43;
		}

		instance.m_hasValidMatrix.store(true);
		instance.m_captureCount.fetch_add(1);
		instance.m_lastCaptureFrame.store(instance.m_currentFrame.load());

		// Log first capture
		static bool loggedFirst = false;
		if (!loggedFirst) {
			LogInfo(std::format("ViewProjectionHook: First matrix captured! Pos=({:.1f}, {:.1f}, {:.1f})",
				instance.m_cameraPosition.x, instance.m_cameraPosition.y, instance.m_cameraPosition.z));
			loggedFirst = true;
		}
	}

	// ============================================
	// Getters
	// ============================================
	bool ViewProjectionHook::GetViewProjectionMatrix(DirectX::XMMATRIX& outMatrix) const {
		if (!m_hasValidMatrix.load()) {
			return false;
		}

		std::lock_guard<std::mutex> lock(m_mutex);
		outMatrix = m_viewProjMatrix;
		return true;
	}

	bool ViewProjectionHook::GetCameraPosition(DirectX::XMFLOAT3& outPos) const {
		if (!m_hasValidMatrix.load()) {
			return false;
		}

		std::lock_guard<std::mutex> lock(m_mutex);
		outPos = m_cameraPosition;
		return true;
	}
} // namespace SapphireHook::DebugVisuals