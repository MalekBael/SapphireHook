#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <filesystem>
#include <fstream>
#include <span>

namespace SqPack {
	enum class PlatformId : uint8_t { Win32 = 0, PS3 = 1, PS4 = 2 };

	struct SqPackHeader {
		char magic[8];
		PlatformId platformId;
		uint8_t padding0[3]{};
		uint32_t size = 0;
		uint32_t version = 0;
		uint32_t type = 0;
	};

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

	struct IndexFileEntry {
		uint32_t fileNameHash;
		uint32_t folderHash;
		uint32_t dataOffset;
		uint32_t padding;

		[[nodiscard]] uint32_t GetDatId() const { return (dataOffset & 0xF) / 2; }
		[[nodiscard]] uint64_t GetFileOffset() const { return static_cast<uint64_t>(dataOffset & ~0xF) * 8ULL; }
	};

	static_assert(sizeof(SqPackIndexHeader) == 8);
	static_assert(sizeof(SqPackBlockHash) == 0x40);
	static_assert(sizeof(IndexBlockRecord) == 0x48);
	static_assert(sizeof(IndexFileEntry) == 16);

	struct DataEntryHeader {
		uint32_t headerLength;
		uint32_t contentType;
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
		uint32_t headerSize;
		uint32_t null;
		uint32_t compressedLength;
		uint32_t decompressedLength;

		[[nodiscard]] bool IsUncompressed() const { return compressedLength == 32000; }
	};

	struct ExtractResult {
		std::vector<uint8_t> data;
		uint32_t contentType = 0;
		bool success = false;
		std::string error;
	};

	class Reader {
	public:
		static std::vector<IndexFileEntry> LoadIndex(const std::filesystem::path& indexPath);

		static std::filesystem::path DatPathFor(const std::filesystem::path& indexPath, uint32_t dataFileId);

		static ExtractResult ExtractFile(
			const std::filesystem::path& datPath,
			const IndexFileEntry& entry,
			size_t maxBytes = 0);

		static ExtractResult ExtractFileAt(
			const std::filesystem::path& datPath,
			uint64_t fileOffset,
			size_t maxBytes = 0);

		static uint32_t Crc32(const uint8_t* data, size_t len);
		static uint32_t Crc32(std::string_view str);

		static uint64_t HashIndex1(std::string_view fullPathLower);

		static bool IsLuaBytecode(std::span<const uint8_t> data);

		static bool ContainsLuaBytecode(std::span<const uint8_t> data);

		static bool DecompressBlock(
			const uint8_t* compressedData, size_t compressedSize,
			uint8_t* outputBuffer, size_t outputSize);

	private:
		static bool ReadAt(std::ifstream& stream, uint64_t offset, void* buffer, size_t bytes);

		static const uint32_t* GetCrcTable();
	};
}