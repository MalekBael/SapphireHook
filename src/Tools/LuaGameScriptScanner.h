#pragma once
#include <filesystem>
#include <vector>
#include <string>
#include <optional>

namespace SapphireHook {
	struct LuaPackHit {
		std::filesystem::path indexPath;   // physical index file (e.g. 0b0000.win32.index)
		std::filesystem::path datPath;     // physical dat file (e.g. 0b0000.win32.dat0)
		std::string displayPath;           // virtual Lua path (extracted / synthesized), UTF-8
		uint64_t indexHash = 0;            // file name hash (from index)
		uint32_t dataFileId = 0;           // datN id
		uint64_t fileOffset = 0;           // byte offset inside dat
		bool     bytecode = false;         // detected Lua bytecode
		bool     looksSource = false;      // reserved (not used now)
	};

	struct LuaScanSummary {
		std::vector<LuaPackHit> hits;
		size_t indexesScanned = 0;
		size_t entriesScanned = 0;
	};

	// Scan only game_script pack (0b0000) currently
	std::optional<LuaScanSummary> ScanGameScriptPacks(
		const std::filesystem::path& rootDir,
		size_t maxEntriesPerIndex = 20000,
		size_t maxProbeBytes = 0x2000);
} // namespace SapphireHook