#include "LuaGameScriptScanner.h"
#include "../Logger/Logger.h"
#include "SqPackReader.h"
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <optional>
#include <algorithm>
#include <map>
#include <zlib.h>
#include <cstring>
#include <cctype>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif
#endif

namespace SapphireHook {
	// Index simplified reference structs
	struct SqPackIndexHeaderRef {
		uint32_t size;
		uint32_t type;
	};

	struct SqPackBlockHashRef {
		uint8_t  hash[0x14];
		uint32_t padding[0xB]; // total 0x40
	};

	struct IndexBlockRecordRef {
		uint32_t offset;
		uint32_t size;
		SqPackBlockHashRef blockHash;
	};

	static_assert(sizeof(SqPackIndexHeaderRef) == 8);
	static_assert(sizeof(SqPackBlockHashRef) == 0x40);
	static_assert(sizeof(IndexBlockRecordRef) == 0x48);

	// File entry (16 bytes)
	struct IndexFileEntry {
		uint32_t fileNameHash;
		uint32_t filePathHash;
		uint32_t dataOffset;
		uint32_t padding;
	};

	// Dat structures
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
	};

	// Helpers
	static std::string HexDump(const uint8_t* data, size_t len, size_t max = 32) {
		std::string result;
		size_t limit = (len < max) ? len : max;
		char buf[4];
		for (size_t i = 0; i < limit; ++i) {
			std::snprintf(buf, sizeof(buf), "%02X ", data[i]);
			result += buf;
		}
		if (len > max) result += "...";
		return result;
	}

	static bool ContainsLuaBytecode(const uint8_t* data, size_t len) {
		if (len < 5) return false;
		for (size_t i = 0; i + 5 <= len; ++i) {
			if (data[i] == 0x1B && data[i + 1] == 'L' && data[i + 2] == 'u' && data[i + 3] == 'a') {
				uint8_t v = data[i + 4];
				if (v == 0x51 || v == 0x52 || v == 0x53) return true;
			}
		}
		return false;
	}

	static bool DecompressBlock(const uint8_t* in, size_t in_size, uint8_t* out, size_t out_size) {
		z_stream strm{};
		strm.avail_in = static_cast<uInt>(in_size);
		strm.next_in = const_cast<Bytef*>(in);
		if (inflateInit2(&strm, -15) != Z_OK) return false;
		strm.avail_out = static_cast<uInt>(out_size);
		strm.next_out = out;
		int ret = inflate(&strm, Z_NO_FLUSH);
		inflateEnd(&strm);
		return ret == Z_STREAM_END;
	}

	static std::string TryExtractLuabName(const uint8_t* data, size_t len) {
		auto isPathChar = [](uint8_t c) {
			return (c >= 32 && c <= 126) &&
				(std::isalnum(c) || c == '/' || c == '\\' || c == '.' || c == '_' || c == '-' || c == '@');
			};
		const char* exts[] = { ".luab", ".lua", ".LUAB", ".LUA" };
		for (const char* ext : exts) {
			const size_t extLen = std::strlen(ext);
			const uint8_t* p = data;
			size_t remain = len;
			while (remain >= extLen) {
				const uint8_t* found = std::search(p, p + remain, ext, ext + extLen);
				if (found == p + remain) break;
				const uint8_t* start = found;
				while (start > data && isPathChar(*(start - 1))) start--;
				const uint8_t* end = found + extLen;
				while (end < data + len && isPathChar(*end)) end++;
				if (end - start >= extLen + 1) {
					std::string s(reinterpret_cast<const char*>(start), end - start);
					for (auto& ch : s) if (ch == '\\') ch = '/';
					return s;
				}
				size_t advance = (found - p) + 1;
				p += advance;
				remain -= advance;
			}
		}
		return {};
	}

	static std::string ExtractLua51SourceName(const uint8_t* data, size_t len) {
		if (len < 12) return {};
		if (!(data[0] == 0x1B && data[1] == 'L' && data[2] == 'u' && data[3] == 'a')) return {};
		if (data[4] != 0x51) return {}; // only Lua 5.1
		uint8_t endian = data[6];
		uint8_t szSizeT = data[8];
		if (szSizeT == 0) return {};
		size_t pos = 12;

		auto read_uN = [&](size_t n) -> uint64_t {
			if (pos + n > len) return 0;
			uint64_t v = 0;
			if (endian == 1) { // little
				for (size_t i = 0; i < n; ++i) v |= (uint64_t)data[pos + i] << (8 * i);
			}
			else {
				for (size_t i = 0; i < n; ++i) v = (v << 8) | data[pos + i];
			}
			pos += n;
			return v;
			};

		uint64_t sz = read_uN(szSizeT);
		if (sz == 0) return {};
		if (sz == 1) { // empty
			if (pos + 1 <= len) pos += 1;
			return {};
		}
		if (pos + sz > len) return {};
		std::string s(reinterpret_cast<const char*>(data + pos), (size_t)sz - 1);
		pos += (size_t)sz;
		if (!s.empty() && s[0] == '@') s.erase(0, 1);
		for (auto& ch : s) if (ch == '\\') ch = '/';
		return s;
	}

	static std::string SanitizeToUtf8Path(std::string_view s) {
		std::string out;
		out.reserve(s.size());
		auto allow = [](char ch) {
			return std::isalnum(static_cast<unsigned char>(ch)) ||
				ch == '/' || ch == '.' || ch == '_' || ch == '-' || ch == '@';
			};
		for (char ch : s) {
			if (ch == '\\') ch = '/';
			if (ch >= 0x20 && ch <= 0x7E && allow(ch))
				out.push_back(ch);
			else if (ch == 0)
				continue;
			else
				out.push_back('_');
		}
		// collapse //
		std::string collapsed;
		collapsed.reserve(out.size());
		bool prevSlash = false;
		for (char c : out) {
			if (c == '/') {
				if (!prevSlash) collapsed.push_back(c);
				prevSlash = true;
			}
			else {
				prevSlash = false;
				collapsed.push_back(c);
			}
		}
		// trim leading slash
		while (!collapsed.empty() && collapsed.front() == '/') collapsed.erase(collapsed.begin());
		return collapsed;
	}

	static std::vector<IndexFileEntry> ReadIndexFile(const std::filesystem::path& indexPath) {
		std::vector<IndexFileEntry> entries;
		std::ifstream fs(indexPath, std::ios::binary);
		if (!fs.is_open()) {
			LogError("Cannot open index: " + indexPath.string());
			return entries;
		}
		fs.seekg(0x400, std::ios::beg);
		SqPackIndexHeaderRef hdr{};
		if (!fs.read(reinterpret_cast<char*>(&hdr), sizeof(hdr))) {
			LogError("Index: header read failed");
			return entries;
		}
		IndexBlockRecordRef rec{};
		if (!fs.read(reinterpret_cast<char*>(&rec), sizeof(rec))) {
			LogError("Index: block record read failed");
			return entries;
		}
		auto totalSize = std::filesystem::file_size(indexPath);
		if (rec.offset == 0 || rec.size == 0 ||
			rec.offset + rec.size > totalSize ||
			(rec.size % sizeof(IndexFileEntry)) != 0) {
			LogError("Index: invalid block");
			return entries;
		}
		fs.seekg(rec.offset, std::ios::beg);
		size_t count = rec.size / sizeof(IndexFileEntry);
		entries.resize(count);
		if (!fs.read(reinterpret_cast<char*>(entries.data()), rec.size)) {
			LogError("Index: file entries read failure");
			entries.clear();
		}
		else {
			LogInfo("Index: loaded " + std::to_string(entries.size()) + " entries");
		}
		return entries;
	}

	std::optional<LuaScanSummary> ScanGameScriptPacks(const std::filesystem::path& rootDir,
		size_t maxEntriesPerIndex,
		size_t previewLimit) {
		LuaScanSummary summary{};
		const auto ffxivDir = rootDir / "ffxiv";
		const auto indexPath = ffxivDir / "0b0000.win32.index";
		const auto datPath = ffxivDir / "0b0000.win32.dat0";

		if (!std::filesystem::exists(indexPath)) {
			LogError("Missing index: " + indexPath.string());
			return std::nullopt;
		}
		if (!std::filesystem::exists(datPath)) {
			LogError("Missing dat: " + datPath.string());
			return std::nullopt;
		}

		auto datSize = std::filesystem::file_size(datPath);
		LogInfo("Dat size: " + std::to_string(datSize));

		auto entries = ReadIndexFile(indexPath);
		if (entries.empty()) return std::nullopt;

		// Map dat counts
		std::map<uint32_t, size_t> datCounts;
		for (auto& e : entries)
			datCounts[(e.dataOffset & 0xF) / 2]++;

		for (auto& kv : datCounts)
			LogInfo("dat" + std::to_string(kv.first) + ": " + std::to_string(kv.second));

		std::ifstream dat(datPath, std::ios::binary);
		if (!dat.is_open()) {
			LogError("Failed opening dat");
			return std::nullopt;
		}

		const uint32_t DATA_START = 0x800;
		size_t scanned = 0;
		size_t luaFiles = 0;
		size_t binaries = 0;

		for (auto& e : entries) {
			if (scanned >= maxEntriesPerIndex) break;
			uint32_t datId = (e.dataOffset & 0xF) / 2;
			if (datId != 0) continue;

			uint64_t offset = static_cast<uint64_t>(e.dataOffset & ~0xF) * 8ULL;
			if (offset < DATA_START || offset >= datSize)
				continue;

			dat.seekg(offset, std::ios::beg);
			DataEntryHeader header{};
			if (!dat.read(reinterpret_cast<char*>(&header), sizeof(header)))
				continue;
			scanned++;

			if (header.contentType != 0x02 || header.uncompressedSize == 0 || header.numBlocks == 0)
				continue;

			binaries++;

			std::vector<Type2BlockEntry> blocks(header.numBlocks);
			if (!dat.read(reinterpret_cast<char*>(blocks.data()), header.numBlocks * sizeof(Type2BlockEntry)))
				continue;

			std::vector<uint8_t> fileData;
			size_t maxExtract = std::min<size_t>(header.uncompressedSize, previewLimit);
			fileData.reserve(maxExtract);

			for (size_t bi = 0; bi < blocks.size() && fileData.size() < maxExtract; ++bi) {
				const auto& be = blocks[bi];
				uint64_t blockPos = offset + header.headerLength + be.offset;
				dat.seekg(blockPos, std::ios::beg);
				BlockHeader bh{};
				if (!dat.read(reinterpret_cast<char*>(&bh), sizeof(bh)) || bh.headerSize != 0x10)
					break;

				if (bh.compressedLength == 32000) {
					size_t toRead = std::min<size_t>(bh.decompressedLength, maxExtract - fileData.size());
					size_t old = fileData.size();
					fileData.resize(old + toRead);
					if (!dat.read(reinterpret_cast<char*>(fileData.data() + old), toRead)) {
						fileData.resize(old);
						break;
					}
				}
				else {
					std::vector<uint8_t> comp(bh.compressedLength);
					if (!dat.read(reinterpret_cast<char*>(comp.data()), comp.size()))
						break;
					std::vector<uint8_t> dec(bh.decompressedLength);
					if (!DecompressBlock(comp.data(), comp.size(), dec.data(), dec.size()))
						break;
					size_t toCopy = std::min(dec.size(), maxExtract - fileData.size());
					fileData.insert(fileData.end(), dec.begin(), dec.begin() + toCopy);
				}
			}

			if (!fileData.empty() && ContainsLuaBytecode(fileData.data(), fileData.size())) {
				luaFiles++;
				std::string name = ExtractLua51SourceName(fileData.data(), fileData.size());
				if (name.empty())
					name = TryExtractLuabName(fileData.data(), fileData.size());
				name = SanitizeToUtf8Path(name);
				if (name.empty()) {
					char fallback[128];
					std::snprintf(fallback, sizeof(fallback), "luab/%08X/%08X.luab",
						e.filePathHash, e.fileNameHash);
					name = fallback;
				}
				LuaPackHit hit{};
				hit.indexPath = indexPath;      // physical index file
				hit.datPath = datPath;        // physical dat file
				hit.displayPath = name;           // virtual script path
				hit.indexHash = e.fileNameHash;
				hit.dataFileId = datId;
				hit.fileOffset = offset;
				hit.bytecode = true;
				summary.hits.emplace_back(std::move(hit));

				if (luaFiles <= 3) {
					LogInfo("*** LUA: " + name + " @0x" + std::to_string(offset) +
						" size=" + std::to_string(fileData.size()));
					LogInfo("  Preview: " + HexDump(fileData.data(), fileData.size(), 64));
				}
			}
		}

		summary.indexesScanned = 1;
		summary.entriesScanned = scanned;

		LogInfo("========== SCAN COMPLETE ==========");
		LogInfo("Entries scanned: " + std::to_string(scanned));
		LogInfo("Binary files: " + std::to_string(binaries));
		LogInfo("Lua scripts: " + std::to_string(luaFiles));
		LogInfo("===================================");

		return summary;
	}
} // namespace SapphireHook