#include "LuaGameScriptScanner.h"
#include "SqPackReader.h"
#include "../Logger/Logger.h"
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <optional>
#include <algorithm>
#include <map>
#include <unordered_map>
#include <sstream>
#include <cstring>
#include <cctype>

#ifdef _WIN32
#include <Windows.h>
#include "../resources/Resources.h"
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

	// ===== Path Sanitization =====
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
		// Collapse //
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
		// Trim leading slash
		while (!collapsed.empty() && collapsed.front() == '/')
			collapsed.erase(collapsed.begin());
		return collapsed;
	}

	// Parse CSV from memory buffer into hash->name map
	static bool LoadCsvHashMapFromMemory(const char* data, size_t len,
		std::unordered_map<int64_t, std::string>& out) {
		std::string all(data, len);
		std::istringstream iss(all);
		std::string line;
		bool first = true;
		size_t added = 0;

		auto trim = [](std::string& s) {
			auto is_space = [](unsigned char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
			while (!s.empty() && is_space((unsigned char)s.front())) s.erase(s.begin());
			while (!s.empty() && is_space((unsigned char)s.back()))  s.pop_back();
			if (!s.empty() && s.front() == '"' && s.back() == '"' && s.size() >= 2) {
				s = s.substr(1, s.size() - 2);
			}
			};

		while (std::getline(iss, line)) {
			if (line.empty()) continue;

			// Strip UTF-8 BOM on first line
			if (first && line.size() >= 3 &&
				(unsigned char)line[0] == 0xEF &&
				(unsigned char)line[1] == 0xBB &&
				(unsigned char)line[2] == 0xBF) {
				line.erase(0, 3);
			}
			first = false;

			auto comma = line.find(',');
			if (comma == std::string::npos) continue;

			std::string idStr = line.substr(0, comma);
			std::string text = line.substr(comma + 1);
			trim(idStr); trim(text);

			// Skip header rows
			if (idStr.empty() || !(std::isdigit((unsigned char)idStr[0]) ||
				idStr[0] == '-' || idStr[0] == '+')) continue;

			int64_t id = 0;
			try { id = std::stoll(idStr); }
			catch (...) { continue; }

			// Normalize slashes
			for (auto& ch : text) if (ch == '\\') ch = '/';
			out[id] = std::move(text);
			++added;
		}
		return added > 0;
	}

#ifdef _WIN32
	// Load an embedded RCDATA resource into a string
	static std::string LoadEmbeddedResourceUtf8(int resId) {
		HMODULE mod = nullptr;
		// Get handle of this module using address of this function
		if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
			GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCWSTR>(&LoadEmbeddedResourceUtf8), &mod)) {
			return {};
		}
		HRSRC hRes = FindResourceW(mod, MAKEINTRESOURCEW(resId), MAKEINTRESOURCEW(RT_RCDATA));
		if (!hRes) return {};
		HGLOBAL hData = LoadResource(mod, hRes);
		if (!hData) return {};
		DWORD size = SizeofResource(mod, hRes);
		const void* ptr = LockResource(hData);
		if (!ptr || size == 0) return {};
		return std::string(static_cast<const char*>(ptr), size);
	}

	static void VerifyEmbeddedResources() {
		HMODULE mod = nullptr;
		if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
			GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCWSTR>(&VerifyEmbeddedResources), &mod)) {
			LogError("Failed to get module handle");
			return;
		}

		// FIX: Use MAKEINTRESOURCEW for RT_RCDATA
		HRSRC hFolders = FindResourceW(mod, MAKEINTRESOURCEW(IDR_FOLDERS_CSV),
			MAKEINTRESOURCEW(RT_RCDATA));
		if (hFolders) {
			DWORD size = SizeofResource(mod, hFolders);
			LogInfo("Folders CSV resource found: " + std::to_string(size) + " bytes");
		}
		else {
			LogError("Folders CSV resource NOT FOUND - check RC file and build");
		}

		HRSRC hFiles = FindResourceW(mod, MAKEINTRESOURCEW(IDR_FILENAMES_CSV),
			MAKEINTRESOURCEW(RT_RCDATA));
		if (hFiles) {
			DWORD size = SizeofResource(mod, hFiles);
			LogInfo("Filenames CSV resource found: " + std::to_string(size) + " bytes");
		}
		else {
			LogError("Filenames CSV resource NOT FOUND - check RC file and build");
		}
	}
#endif

	// Hash name resolver
	struct HashNameResolver {
		std::unordered_map<int64_t, std::string> dirNames;
		std::unordered_map<int64_t, std::string> fileNames;

		static int64_t KeyFromU32(uint32_t v) {
			return static_cast<int64_t>(static_cast<int32_t>(v));
		}

		std::optional<std::string> Resolve(uint32_t dirHash, uint32_t fileHash) const {
			auto dit = dirNames.find(KeyFromU32(dirHash));
			auto fit = fileNames.find(KeyFromU32(fileHash));

			// If we have both, return the full path
			if (dit != dirNames.end() && fit != fileNames.end()) {
				std::string p = dit->second;
				if (!p.empty() && p.back() != '/') p.push_back('/');
				p += fit->second;
				return p;
			}

			// If we only have the filename, return it with a hash prefix for the directory
			if (fit != fileNames.end()) {
				char prefix[32];
				std::snprintf(prefix, sizeof(prefix), "dir_%08X/", dirHash);
				return std::string(prefix) + fit->second;
			}

			// If we only have the directory, return it with a hash suffix for the file
			if (dit != dirNames.end()) {
				std::string p = dit->second;
				if (!p.empty() && p.back() != '/') p.push_back('/');
				char suffix[32];
				std::snprintf(suffix, sizeof(suffix), "file_%08X.luab", fileHash);
				return p + suffix;
			}

			// Neither found - return nullopt to trigger full hash fallback
			return std::nullopt;
		}
	};

	// Lazy singleton for embedded CSVs
	static const HashNameResolver& GetEmbeddedResolver() {
		static HashNameResolver resolver;
		static bool loaded = false;
		if (!loaded) {
#ifdef _WIN32
			std::string folders = LoadEmbeddedResourceUtf8(IDR_FOLDERS_CSV);
			std::string files = LoadEmbeddedResourceUtf8(IDR_FILENAMES_CSV);
			if (!folders.empty())
				LoadCsvHashMapFromMemory(folders.data(), folders.size(), resolver.dirNames);
			if (!files.empty())
				LoadCsvHashMapFromMemory(files.data(), files.size(), resolver.fileNames);
			LogInfo("Embedded resolver: folders=" + std::to_string(resolver.dirNames.size()) +
				" files=" + std::to_string(resolver.fileNames.size()));
#endif
			loaded = true;
		}
		return resolver;
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

		// Get embedded name resolver
		const auto& nameResolver = GetEmbeddedResolver();

		// Use SqPack::Reader for index loading
		auto entries = SqPack::Reader::LoadIndex(indexPath);
		if (entries.empty()) return std::nullopt;

		std::map<uint32_t, size_t> datCounts;
		for (const auto& e : entries)
			datCounts[e.GetDatId()]++;

		for (const auto& kv : datCounts)
			LogInfo("dat" + std::to_string(kv.first) + ": " + std::to_string(kv.second));

		size_t scanned = 0;
		size_t luaFiles = 0;
		size_t binaries = 0;

		for (const auto& e : entries) {
			if (scanned >= maxEntriesPerIndex) break;
			
			// Only process dat0 entries
			if (e.GetDatId() != 0) continue;

			scanned++;

			// Use SqPack::Reader for file extraction
			auto result = SqPack::Reader::ExtractFile(datPath, e, previewLimit);
			if (!result.success) continue;

			// Count binary files (contentType 0x02)
			if (result.contentType == 0x02) {
				binaries++;
			}

			// Check for Lua bytecode using SqPack::Reader
			if (!result.data.empty() && SqPack::Reader::ContainsLuaBytecode(result.data)) {
				luaFiles++;

				// Try embedded resolver first
				std::string name;
				if (auto resolved = nameResolver.Resolve(e.folderHash, e.fileNameHash)) {
					name = *resolved;
				}

				name = SanitizeToUtf8Path(name);
				if (name.empty()) {
					char fallback[128];
					std::snprintf(fallback, sizeof(fallback), "luab/%08X/%08X.luab",
						e.folderHash, e.fileNameHash);
					name = fallback;
				}

				LuaPackHit hit{};
				hit.indexPath = indexPath;
				hit.datPath = datPath;
				hit.displayPath = name;
				hit.indexHash = e.fileNameHash;
				hit.dataFileId = e.GetDatId();
				hit.fileOffset = e.GetFileOffset();
				hit.bytecode = true;
				summary.hits.emplace_back(std::move(hit));

				if (luaFiles <= 3) {
					LogInfo("*** LUA: " + name + " @" + Logger::HexFormat(e.GetFileOffset()) +
						" size=" + std::to_string(result.data.size()));
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