#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <filesystem>
#include <fstream>
#include <span>

namespace SqPack {
	// ===== Platform & Header Structures =====
	enum class PlatformId : uint8_t { Win32 = 0, PS3 = 1, PS4 = 2 };

	struct SqPackHeader {
		char magic[8];           // "SqPack\0\0"
		PlatformId platformId;   // 0=Win32
		uint8_t padding0[3]{};
		uint32_t size = 0;       // absolute offset to first object after header
		uint32_t version = 0;
		uint32_t type = 0;
	};

	// ===== Index Structures =====
	struct SqPackIndexHeader {
		uint32_t size = 0;
		uint32_t type = 0;
	};

	struct SqPackBlockHash {
		uint8_t  hash[0x14];
		uint32_t padding[0xB];
	};

	struct IndexBlockRecord {
		uint32_t offset;
		uint32_t size;
		SqPackBlockHash blockHash;
	};

	// Index1 file entry (with separate folder/file hashes)
	struct IndexFileEntry {
		uint32_t fileNameHash;
		uint32_t folderHash;
		uint32_t dataOffset;     // lower 4 bits: datId*2, rest: offset units
		uint32_t padding;

		[[nodiscard]] uint32_t GetDatId() const { return (dataOffset & 0xF) / 2; }
		[[nodiscard]] uint64_t GetFileOffset() const { return static_cast<uint64_t>(dataOffset & ~0xF) * 8ULL; }
	};

	static_assert(sizeof(SqPackIndexHeader) == 8);
	static_assert(sizeof(SqPackBlockHash) == 0x40);
	static_assert(sizeof(IndexBlockRecord) == 0x48);
	static_assert(sizeof(IndexFileEntry) == 16);

	// ===== Dat File Structures =====
	struct DataEntryHeader {
		uint32_t headerLength;
		uint32_t contentType;    // 0x02 = binary/standard, 0x03 = model, 0x04 = texture
		uint32_t uncompressedSize;
		uint32_t unknown;
		uint32_t blockBufferSize;
		uint32_t numBlocks;
	};

	struct Type2BlockEntry {
		uint32_t offset;
		uint16_t blockSize;
		uint16_t decompressedDataSize;
	};

	struct BlockHeader {
		uint32_t headerSize;     // always 0x10
		uint32_t null;
		uint32_t compressedLength;   // 32000 = uncompressed
		uint32_t decompressedLength;

		[[nodiscard]] bool IsUncompressed() const { return compressedLength == 32000; }
	};

	// ===== Result Types =====
	struct ExtractResult {
		std::vector<uint8_t> data;
		uint32_t contentType = 0;
		bool success = false;
		std::string error;
	};

	// ===== Reader Class =====
	class Reader {
	public:
		// ----- Index Operations -----
		
		// Load all file entries from an index file (.index)
		// Returns empty vector on failure, logs errors
		static std::vector<IndexFileEntry> LoadIndex(const std::filesystem::path& indexPath);
		
		// Compute the dat file path for a given index path and dat ID
		// Example: 0b0000.win32.index + datId=0 -> 0b0000.win32.dat0
		static std::filesystem::path DatPathFor(const std::filesystem::path& indexPath, uint32_t dataFileId);

		// ----- File Extraction -----
		
		// Extract file data from a dat file given an index entry
		// Handles block decompression automatically
		// maxBytes: limit extraction size (0 = full file)
		static ExtractResult ExtractFile(
			const std::filesystem::path& datPath,
			const IndexFileEntry& entry,
			size_t maxBytes = 0);

		// Extract file data given explicit offset (for when you don't have IndexFileEntry)
		static ExtractResult ExtractFileAt(
			const std::filesystem::path& datPath,
			uint64_t fileOffset,
			size_t maxBytes = 0);

		// ----- Hash Utilities -----
		
		// Compute CRC32 hash (SqPack uses IEEE 802.3 polynomial)
		static uint32_t Crc32(const uint8_t* data, size_t len);
		static uint32_t Crc32(std::string_view str);

		// Compute index1 combined hash: (folderCrc32 << 32) | fileCrc32
		static uint64_t HashIndex1(std::string_view fullPathLower);

		// ----- Content Detection -----
		
		// Check if data starts with Lua bytecode magic (0x1B 'L' 'u' 'a' + version)
		static bool IsLuaBytecode(std::span<const uint8_t> data);
		
		// Check if data contains Lua bytecode magic anywhere in first N bytes
		static bool ContainsLuaBytecode(std::span<const uint8_t> data);

		// ----- Decompression -----
		
		// Decompress a single block using zlib (raw deflate, windowBits=-15)
		static bool DecompressBlock(
			const uint8_t* compressedData, size_t compressedSize,
			uint8_t* outputBuffer, size_t outputSize);

	private:
		// Low-level IO helper
		static bool ReadAt(std::ifstream& stream, uint64_t offset, void* buffer, size_t bytes);

		// Initialize CRC table (lazy, thread-safe via static local)
		static const uint32_t* GetCrcTable();
	};

} // namespace SqPack