#include "SqPackReader.h"
#include <fstream>
#include <cstring>
#include <algorithm>

namespace SqPack {
	// ===== CRC32 (IEEE 802.3) =====
	static uint32_t CRC_TABLE[256];
	static bool CRC_INIT = false;
	static void InitCrc()
	{
		if (CRC_INIT) return;
		for (uint32_t i = 0; i < 256; ++i) {
			uint32_t c = i;
			for (int k = 0; k < 8; ++k)
				c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
			CRC_TABLE[i] = c;
		}
		CRC_INIT = true;
	}
	uint32_t Reader::Crc32(const uint8_t* data, size_t len)
	{
		InitCrc();
		uint32_t c = 0xFFFFFFFFu;
		for (size_t i = 0; i < len; ++i)
			c = CRC_TABLE[(c ^ data[i]) & 0xFF] ^ (c >> 8);
		return ~c;
	}

	// ===== IO helpers =====
	bool Reader::ReadAll(std::ifstream& ifs, uint64_t offset, void* buf, size_t bytes)
	{
		ifs.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
		if (!ifs.good()) return false;
		ifs.read(reinterpret_cast<char*>(buf), static_cast<std::streamsize>(bytes));
		return ifs.good() || ifs.gcount() == static_cast<std::streamsize>(bytes);
	}

	static bool IsAsciiAlphaNumOrSep(char c)
	{
		unsigned char uc = static_cast<unsigned char>(c);
		return (uc >= 'a' && uc <= 'z') || (uc >= 'A' && uc <= 'Z') ||
			(uc >= '0' && uc <= '9') || uc == '/' || uc == '_' || uc == '.' || uc == '-';
	}

	// ===== Hash helpers =====
	uint64_t Reader::HashIndex1(const std::string& fullPathLower)
	{
		// Split by last '/'
		auto pos = fullPathLower.find_last_of('/');
		std::string folder = (pos == std::string::npos) ? std::string() : fullPathLower.substr(0, pos);
		std::string file = (pos == std::string::npos) ? fullPathLower : fullPathLower.substr(pos + 1);

		// Folder/file must not contain directory separator (file)
		auto folderCrc = Crc32(reinterpret_cast<const uint8_t*>(folder.data()), folder.size());
		auto fileCrc = Crc32(reinterpret_cast<const uint8_t*>(file.data()), file.size());
		return (static_cast<uint64_t>(folderCrc) << 32) | static_cast<uint64_t>(fileCrc);
	}

	uint32_t Reader::HashIndex2(const std::string& fullPathLower)
	{
		return Crc32(reinterpret_cast<const uint8_t*>(fullPathLower.data()), fullPathLower.size());
	}

	std::filesystem::path Reader::DatPathFor(const std::filesystem::path& indexPath, uint32_t dataFileId)
	{
		auto name = indexPath.filename().string();
		// Replace .index or .index2 with .dat{N}
		const char* suffix1 = ".index2";
		const char* suffix2 = ".index";
		std::string base = name;
		if (base.size() >= 7 && base.rfind(suffix1) == base.size() - 7) {
			base.erase(base.size() - 7);
		}
		else if (base.size() >= 6 && base.rfind(suffix2) == base.size() - 6) {
			base.erase(base.size() - 6);
		}
		base += ".dat" + std::to_string(dataFileId);

		auto dir = indexPath.parent_path();
		return dir / base;
	}

	// ===== Lua probes =====
	bool Reader::IsLuaBytecodeMagic(const uint8_t* p, size_t n)
	{
		// Lua bytecode magic: 0x1B 'L' 'u' 'a' version (0x51, 0x52, 0x53) at start
		if (n < 5) return false;
		if (p[0] != 0x1B || p[1] != 'L' || p[2] != 'u' || p[3] != 'a') return false;
		uint8_t ver = p[4];
		return ver == 0x51 || ver == 0x52 || ver == 0x53;
	}

	bool Reader::LooksLikeLuaSource(const uint8_t* p, size_t n)
	{
		if (n < 32) return false;
		// Cheap heuristic: ASCII ratio and presence of common tokens
		size_t ascii = 0;
		for (size_t i = 0; i < std::min<size_t>(n, 256); ++i)
			ascii += IsAsciiAlphaNumOrSep(static_cast<char>(p[i])) ? 1u : 0u;

		const auto has = [&](const char* s) {
			const uint8_t* f = std::search(p, p + n, s, s + std::strlen(s));
			return f != (p + n);
			};

		bool tokens = has("function") || has("local ") || has("return ") || has("end")
			|| has("pairs(") || has("ipairs(");

		return (ascii > (n / 2)) && tokens;
	}

	// ===== Index loading =====
	std::optional<std::vector<IndexEntry>> Reader::LoadIndex(const std::filesystem::path& indexPath, std::string& err)
	{
		err.clear();
		std::ifstream ifs(indexPath, std::ios::binary);
		if (!ifs.is_open()) { err = "Open failed"; return std::nullopt; }

		SqPackHeader hdr{};
		if (!ReadAll(ifs, 0, &hdr, sizeof(hdr))) { err = "Read header failed"; return std::nullopt; }
		if (std::memcmp(hdr.magic, "SqPack", 6) != 0) { err = "Bad magic"; return std::nullopt; }
		if (hdr.size < sizeof(hdr)) { err = "Bad size"; return std::nullopt; }

		// Try to read index1 header
		SqPackIndexHeader idx1{};
		if (ReadAll(ifs, sizeof(hdr), &idx1, sizeof(idx1)) && idx1.indexDataOffset != 0 && idx1.indexDataSize != 0) {
			// index1 path
			const uint64_t tableOff = idx1.indexDataOffset;
			const uint64_t tableEnd = tableOff + idx1.indexDataSize;
			ifs.seekg(0, std::ios::end);
			const uint64_t fileEnd = static_cast<uint64_t>(ifs.tellg());
			if (tableEnd > fileEnd) { err = "Index1 table range invalid"; return std::nullopt; }

			struct IndexHashTableEntry {
				uint64_t hash;
				uint32_t packed; // bitfield: unknown:1, dataFileId:3, offset:28
				uint32_t padding;
			};

			std::vector<IndexEntry> entries;
			const size_t count = static_cast<size_t>(idx1.indexDataSize / sizeof(IndexHashTableEntry));
			entries.reserve(count);

			uint64_t off = tableOff;
			for (size_t i = 0; i < count; ++i, off += sizeof(IndexHashTableEntry)) {
				IndexHashTableEntry e{};
				if (!ReadAll(ifs, off, &e, sizeof(e))) break;
				IndexEntry out{};
				out.hash = e.hash;
				out.isIndex2 = false;
				uint32_t packed = e.packed;
				out.dataFileId = (packed >> 28) & 0x7;     // top 3 bits after dropping unknown
				out.offsetUnits = (packed & 0x0FFFFFFF);   // 28 bits
				entries.emplace_back(out);
			}
			return entries;
		}

		// Else assume index2: data starts at hdr.size and is a stream of Index2HashTableEntry until EOF or zero hash
		struct Index2HashTableEntry {
			uint32_t hash;
			uint32_t packed; // bitfield: unknown:1, dataFileId:3, offset:28
		};

		ifs.seekg(0, std::ios::end);
		const uint64_t fileEnd = static_cast<uint64_t>(ifs.tellg());
		uint64_t off = hdr.size;
		if (off + sizeof(Index2HashTableEntry) > fileEnd) { err = "Index2 table missing"; return std::nullopt; }

		std::vector<IndexEntry> entries;
		entries.reserve(16384);

		while (off + sizeof(Index2HashTableEntry) <= fileEnd) {
			Index2HashTableEntry e{};
			if (!ReadAll(ifs, off, &e, sizeof(e))) break;
			off += sizeof(e);
			if (e.hash == 0) continue; // skip empty

			IndexEntry out{};
			out.hash = e.hash; // 32-bit payload in lower half
			out.isIndex2 = true;
			uint32_t packed = e.packed;
			out.dataFileId = (packed >> 28) & 0x7;
			out.offsetUnits = (packed & 0x0FFFFFFF);
			entries.emplace_back(out);
		}
		if (entries.empty()) { err = "No entries parsed (index2)"; return std::nullopt; }
		return entries;
	}

	std::vector<LuaCandidate> Reader::ProbeForLua(
		const std::filesystem::path& indexPath,
		const std::vector<IndexEntry>& entries,
		size_t maxEntries,
		size_t maxProbeBytes)
	{
		std::vector<LuaCandidate> hits;
		hits.reserve(256);

		const size_t toScan = std::min(entries.size(), maxEntries);
		for (size_t i = 0; i < toScan; ++i) {
			const auto& ent = entries[i];
			const auto dat = Reader::DatPathFor(indexPath, ent.dataFileId); // explicit qualification

			std::ifstream dfs(dat, std::ios::binary);
			if (!dfs.is_open()) continue;

			const uint64_t fileOffset = static_cast<uint64_t>(ent.offsetUnits) * 8ull;
			std::vector<uint8_t> buf(maxProbeBytes);
			if (!ReadAll(dfs, fileOffset, buf.data(), buf.size())) continue;

			bool bc = IsLuaBytecodeMagic(buf.data(), buf.size());
			bool src = !bc && LooksLikeLuaSource(buf.data(), buf.size());

			if (bc || src) {
				LuaCandidate c{};
				c.indexHash = ent.hash;
				c.dataFileId = ent.dataFileId;
				c.dataFileOffset = fileOffset;
				c.datPath = dat;
				c.likelyBytecode = bc;
				c.likelySource = src;
				c.probeSize = buf.size();
				hits.emplace_back(std::move(c));
			}
		}
		return hits;
	}
} // namespace SqPack