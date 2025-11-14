#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <filesystem>
#include <fstream> // for std::ifstream used in ReadAll signature

namespace SqPack {
	enum class PlatformId : uint8_t { Win32 = 0, PS3 = 1, PS4 = 2 };

	struct SqPackHeader {
		char magic[8];           // "SqPack\0\0"
		PlatformId platformId;   // 0=Win32
		uint8_t padding0[3]{};
		uint32_t size = 0;       // absolute offset to first object after header
		uint32_t version = 0;
		uint32_t type = 0;       // 0x2=Index? (varies), not strictly needed here
	};

	struct SqPackIndexHeader {   // only in index1 files; actual size is 0x400, we only need first 16
		uint32_t size = 0;
		uint32_t type = 0;
		uint32_t indexDataOffset = 0; // absolute offset to table
		uint32_t indexDataSize = 0;   // sum of all entries
	};

	// Unified entry view for our purposes
	struct IndexEntry {
		// For index1: hash = (folderCrc32<<32)|fileCrc32
		// For index2: hash = fullPathCrc32 (lower 32 bits used)
		uint64_t hash = 0;
		uint32_t dataFileId = 0;
		uint32_t offsetUnits = 0; // multiply by 8 for absolute file offset
		bool isIndex2 = false;
	};

	struct LuaCandidate {
		// Index metadata
		uint64_t indexHash = 0;
		uint32_t dataFileId = 0;
		uint64_t dataFileOffset = 0; // absolute byte offset in the .datN
		std::filesystem::path datPath;

		// Probe results
		bool    likelyBytecode = false; // matched 0x1B 'L' 'u' 'a' 0x51/52/53
		bool    likelySource = false;   // heuristics (e.g. "function " / "local ")
		size_t  probeSize = 0;          // bytes read for probe
	};

	class Reader {
	public:
		// Load entries from an index file (.index or .index2).
		// indexPath: full path to e.g. "sqpack/.../020000.win32.index"
		// Returns entries with dataFileId and offsetUnits populated.
		static std::optional<std::vector<IndexEntry>> LoadIndex(const std::filesystem::path& indexPath, std::string& err);

		// Compute SqPack hashes for lookup:
		// - index1: folder/file lowercased, split by last '/'.
		// - index2: whole path lowercased.
		static uint64_t HashIndex1(const std::string& fullPathLower);
		static uint32_t HashIndex2(const std::string& fullPathLower);

		// Given the index path and an entry, return the corresponding .dat file path.
		// Example: 020000.win32.index -> 020000.win32.dat{dataFileId}
		static std::filesystem::path DatPathFor(const std::filesystem::path& indexPath, uint32_t dataFileId);

		// Quick probe a subset of entries for Lua magic.
		// maxEntries: cap to avoid huge scans; maxProbeBytes: read this many bytes starting at offset*8.
		static std::vector<LuaCandidate> ProbeForLua(
			const std::filesystem::path& indexPath,
			const std::vector<IndexEntry>& entries,
			size_t maxEntries = 5000,
			size_t maxProbeBytes = 0x2000);

	private:
		static uint32_t Crc32(const uint8_t* data, size_t len);

		// Helpers
		static bool ReadAll(std::ifstream& ifs, uint64_t offset, void* buf, size_t bytes);
		static bool IsLuaBytecodeMagic(const uint8_t* p, size_t n);
		static bool LooksLikeLuaSource(const uint8_t* p, size_t n);
	};
} // namespace SqPack