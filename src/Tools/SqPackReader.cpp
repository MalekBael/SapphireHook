#include "SqPackReader.h"
#include "../Logger/Logger.h"
#include <fstream>
#include <cstring>
#include <algorithm>
#include <zlib.h>

// Prevent Windows min/max macros from interfering
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

namespace SqPack {

	// ===== CRC32 Implementation (IEEE 802.3) =====
	const uint32_t* Reader::GetCrcTable() {
		static uint32_t table[256] = {};
		static bool initialized = false;
		if (!initialized) {
			for (uint32_t i = 0; i < 256; ++i) {
				uint32_t c = i;
				for (int k = 0; k < 8; ++k)
					c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
				table[i] = c;
			}
			initialized = true;
		}
		return table;
	}

	uint32_t Reader::Crc32(const uint8_t* data, size_t len) {
		const uint32_t* table = GetCrcTable();
		uint32_t c = 0xFFFFFFFFu;
		for (size_t i = 0; i < len; ++i)
			c = table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
		return ~c;
	}

	uint32_t Reader::Crc32(std::string_view str) {
		return Crc32(reinterpret_cast<const uint8_t*>(str.data()), str.size());
	}

	// ===== IO Helpers =====
	bool Reader::ReadAt(std::ifstream& stream, uint64_t offset, void* buffer, size_t bytes) {
		stream.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
		if (!stream.good()) return false;
		stream.read(reinterpret_cast<char*>(buffer), static_cast<std::streamsize>(bytes));
		return stream.good() || stream.gcount() == static_cast<std::streamsize>(bytes);
	}

	// ===== Hash Utilities =====
	uint64_t Reader::HashIndex1(std::string_view fullPathLower) {
		auto pos = fullPathLower.find_last_of('/');
		std::string_view folder = (pos == std::string_view::npos) ? std::string_view{} : fullPathLower.substr(0, pos);
		std::string_view file = (pos == std::string_view::npos) ? fullPathLower : fullPathLower.substr(pos + 1);

		auto folderCrc = Crc32(reinterpret_cast<const uint8_t*>(folder.data()), folder.size());
		auto fileCrc = Crc32(reinterpret_cast<const uint8_t*>(file.data()), file.size());
		return (static_cast<uint64_t>(folderCrc) << 32) | static_cast<uint64_t>(fileCrc);
	}

	std::filesystem::path Reader::DatPathFor(const std::filesystem::path& indexPath, uint32_t dataFileId) {
		auto name = indexPath.filename().string();
		// Replace .index or .index2 with .dat{N}
		std::string base = name;
		if (base.size() >= 7 && base.rfind(".index2") == base.size() - 7) {
			base.erase(base.size() - 7);
		}
		else if (base.size() >= 6 && base.rfind(".index") == base.size() - 6) {
			base.erase(base.size() - 6);
		}
		base += ".dat" + std::to_string(dataFileId);
		return indexPath.parent_path() / base;
	}

	// ===== Content Detection =====
	bool Reader::IsLuaBytecode(std::span<const uint8_t> data) {
		if (data.size() < 5) return false;
		if (data[0] != 0x1B || data[1] != 'L' || data[2] != 'u' || data[3] != 'a') return false;
		uint8_t ver = data[4];
		return ver == 0x51 || ver == 0x52 || ver == 0x53;
	}

	bool Reader::ContainsLuaBytecode(std::span<const uint8_t> data) {
		if (data.size() < 5) return false;
		for (size_t i = 0; i + 5 <= data.size(); ++i) {
			if (data[i] == 0x1B && data[i + 1] == 'L' && data[i + 2] == 'u' && data[i + 3] == 'a') {
				uint8_t v = data[i + 4];
				if (v == 0x51 || v == 0x52 || v == 0x53) return true;
			}
		}
		return false;
	}

	// ===== Decompression =====
	bool Reader::DecompressBlock(const uint8_t* compressedData, size_t compressedSize,
		uint8_t* outputBuffer, size_t outputSize) {
		z_stream strm{};
		strm.avail_in = static_cast<uInt>(compressedSize);
		strm.next_in = const_cast<Bytef*>(compressedData);
		if (inflateInit2(&strm, -15) != Z_OK) return false;
		strm.avail_out = static_cast<uInt>(outputSize);
		strm.next_out = outputBuffer;
		int ret = inflate(&strm, Z_NO_FLUSH);
		inflateEnd(&strm);
		return ret == Z_STREAM_END;
	}

	// ===== Index Loading =====
	std::vector<IndexFileEntry> Reader::LoadIndex(const std::filesystem::path& indexPath) {
		std::vector<IndexFileEntry> entries;
		std::ifstream fs(indexPath, std::ios::binary);
		if (!fs.is_open()) {
			SapphireHook::LogError("SqPack: Cannot open index: " + indexPath.string());
			return entries;
		}

		// Skip to index header at 0x400
		fs.seekg(0x400, std::ios::beg);
		SqPackIndexHeader hdr{};
		if (!fs.read(reinterpret_cast<char*>(&hdr), sizeof(hdr))) {
			SapphireHook::LogError("SqPack: Index header read failed");
			return entries;
		}

		IndexBlockRecord rec{};
		if (!fs.read(reinterpret_cast<char*>(&rec), sizeof(rec))) {
			SapphireHook::LogError("SqPack: Block record read failed");
			return entries;
		}

		auto totalSize = std::filesystem::file_size(indexPath);
		if (rec.offset == 0 || rec.size == 0 ||
			rec.offset + rec.size > totalSize ||
			(rec.size % sizeof(IndexFileEntry)) != 0) {
			SapphireHook::LogError("SqPack: Invalid block record");
			return entries;
		}

		fs.seekg(rec.offset, std::ios::beg);
		size_t count = rec.size / sizeof(IndexFileEntry);
		entries.resize(count);
		if (!fs.read(reinterpret_cast<char*>(entries.data()), rec.size)) {
			SapphireHook::LogError("SqPack: File entries read failure");
			entries.clear();
		}
		else {
			SapphireHook::LogInfo("SqPack: Loaded " + std::to_string(entries.size()) + " entries from " + indexPath.filename().string());
		}
		return entries;
	}

	// ===== File Extraction =====
	ExtractResult Reader::ExtractFile(const std::filesystem::path& datPath, const IndexFileEntry& entry, size_t maxBytes) {
		return ExtractFileAt(datPath, entry.GetFileOffset(), maxBytes);
	}

	ExtractResult Reader::ExtractFileAt(const std::filesystem::path& datPath, uint64_t fileOffset, size_t maxBytes) {
		ExtractResult result;

		std::ifstream dat(datPath, std::ios::binary);
		if (!dat.is_open()) {
			result.error = "Cannot open dat file";
			return result;
		}

		auto datSize = std::filesystem::file_size(datPath);
		constexpr uint32_t DATA_START = 0x800;

		if (fileOffset < DATA_START || fileOffset >= datSize) {
			result.error = "Invalid file offset";
			return result;
		}

		// Read data entry header
		dat.seekg(static_cast<std::streamoff>(fileOffset), std::ios::beg);
		DataEntryHeader header{};
		if (!dat.read(reinterpret_cast<char*>(&header), sizeof(header))) {
			result.error = "Failed to read data entry header";
			return result;
		}

		result.contentType = header.contentType;

		// Only handle type 2 (binary/standard) for now
		if (header.contentType != 0x02 || header.uncompressedSize == 0 || header.numBlocks == 0) {
			result.error = "Unsupported content type or empty file";
			return result;
		}

		// Read block entries
		std::vector<Type2BlockEntry> blocks(header.numBlocks);
		if (!dat.read(reinterpret_cast<char*>(blocks.data()), header.numBlocks * sizeof(Type2BlockEntry))) {
			result.error = "Failed to read block entries";
			return result;
		}

		// Determine how much to extract
		size_t targetSize = header.uncompressedSize;
		if (maxBytes > 0 && maxBytes < targetSize) {
			targetSize = maxBytes;
		}
		result.data.reserve(targetSize);

		// Extract blocks
		for (size_t bi = 0; bi < blocks.size() && result.data.size() < targetSize; ++bi) {
			const auto& be = blocks[bi];
			uint64_t blockPos = fileOffset + header.headerLength + be.offset;

			dat.seekg(static_cast<std::streamoff>(blockPos), std::ios::beg);
			BlockHeader bh{};
			if (!dat.read(reinterpret_cast<char*>(&bh), sizeof(bh)) || bh.headerSize != 0x10) {
				result.error = "Invalid block header";
				break;
			}

			if (bh.IsUncompressed()) {
				// Uncompressed block
				size_t toRead = std::min<size_t>(bh.decompressedLength, targetSize - result.data.size());
				size_t oldSize = result.data.size();
				result.data.resize(oldSize + toRead);
				if (!dat.read(reinterpret_cast<char*>(result.data.data() + oldSize), toRead)) {
					result.data.resize(oldSize);
					result.error = "Failed to read uncompressed block";
					break;
				}
			}
			else {
				// Compressed block
				std::vector<uint8_t> compressed(bh.compressedLength);
				if (!dat.read(reinterpret_cast<char*>(compressed.data()), compressed.size())) {
					result.error = "Failed to read compressed block";
					break;
				}

				std::vector<uint8_t> decompressed(bh.decompressedLength);
				if (!DecompressBlock(compressed.data(), compressed.size(), decompressed.data(), decompressed.size())) {
					result.error = "Decompression failed";
					break;
				}

				size_t toCopy = std::min(decompressed.size(), targetSize - result.data.size());
				result.data.insert(result.data.end(), decompressed.begin(), decompressed.begin() + toCopy);
			}
		}

		result.success = !result.data.empty();
		return result;
	}

} // namespace SqPack