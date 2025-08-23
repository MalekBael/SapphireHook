#include "FunctionDatabase.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <Windows.h>

// Static helper function to get the DLL's directory path
static std::string GetCurrentDllDirectory()
{
	char dllPath[MAX_PATH];
	HMODULE hModule = NULL;

	// Get handle to this DLL
	GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
		GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCSTR)&GetCurrentDllDirectory,  // Changed reference to match new function name
		&hModule);

	if (hModule && GetModuleFileNameA(hModule, dllPath, MAX_PATH))
	{
		// Remove the filename to get just the directory
		char* lastSlash = strrchr(dllPath, '\\');
		if (lastSlash)
		{
			*lastSlash = '\0';
		}
		return std::string(dllPath);
	}

	return "";
}

// Static helper function to get game directory path
static std::string GetGameDirectory()
{
	// Get the path of the main executable (ffxiv_dx11.exe)
	char exePath[MAX_PATH];
	HMODULE hMainModule = GetModuleHandleW(NULL); // NULL gets the main executable module

	if (hMainModule && GetModuleFileNameA(hMainModule, exePath, MAX_PATH))
	{
		// Remove the filename to get just the directory
		char* lastSlash = strrchr(exePath, '\\');
		if (lastSlash)
		{
			*lastSlash = '\0';
		}
		return std::string(exePath);
	}

	return "";
}

FunctionDatabase::FunctionDatabase()
{
	// Try multiple locations in order of preference:
	// 1. DLL directory (where your build output is)
	// 2. Game directory (where ffxiv_dx11.exe is)
	// 3. Current working directory
	// 4. Relative paths

	std::vector<std::string> searchPaths;

	// Priority 1: DLL directory (build output folder)
	std::string dllDir = GetCurrentDllDirectory();  // Updated function call
	if (!dllDir.empty())
	{
		searchPaths.push_back(dllDir + "\\data.yml");
	}

	// Priority 2: Game directory
	std::string gameDir = GetGameDirectory();
	if (!gameDir.empty())
	{
		searchPaths.push_back(gameDir + "\\data.yml");
	}

	// Priority 3: Current working directory and relative paths
	searchPaths.push_back("data.yml");
	searchPaths.push_back(".\\data.yml");
	searchPaths.push_back("..\\data.yml");

	// Try each path until we find the file
	for (const auto& path : searchPaths)
	{
		std::ifstream testFile(path);
		if (testFile.is_open())
		{
			m_databasePath = path;
			printf("[FunctionDB] Found data.yml at: %s\n", path.c_str());
			testFile.close();
			break;
		}
	}

	// If no file found, default to DLL directory for saving new files
	if (m_databasePath.empty())
	{
		if (!dllDir.empty())
		{
			m_databasePath = dllDir + "\\data.yml";
		}
		else
		{
			m_databasePath = "data.yml";
		}
		printf("[FunctionDB] No existing data.yml found, will create at: %s\n", m_databasePath.c_str());
	}

	// Initialize default categories
	m_categories["ExdData"] = "ExdData functions - data access functions for game databases";
	m_categories["Concurrency"] = "Microsoft Concurrency Runtime functions";
	m_categories["Movement"] = "Player and object movement";
	m_categories["Camera"] = "Camera and view controls";
	m_categories["Combat"] = "Combat system and actions";
	m_categories["UI"] = "User interface and menus";
	m_categories["Network"] = "Network communication";
	m_categories["System"] = "Core system functions";
	m_categories["Graphics"] = "Rendering and graphics";
	m_categories["Audio"] = "Sound and music";
	m_categories["Client"] = "Client-side functions";
	m_categories["Unknown"] = "Uncategorized functions";
}

std::string FunctionDatabase::Trim(const std::string& str)
{
	size_t start = str.find_first_not_of(" \t\n\r");
	if (start == std::string::npos) return "";

	size_t end = str.find_last_not_of(" \t\n\r");
	return str.substr(start, end - start + 1);
}

std::pair<std::string, std::string> FunctionDatabase::ParseKeyValue(const std::string& line)
{
	size_t colonPos = line.find(':');
	if (colonPos == std::string::npos)
	{
		return { "", "" };
	}

	std::string key = Trim(line.substr(0, colonPos));
	std::string value = Trim(line.substr(colonPos + 1));

	// Remove quotes if present
	if (value.length() >= 2 && value.front() == '"' && value.back() == '"')
	{
		value = value.substr(1, value.length() - 2);
	}

	return { key, value };
}

uintptr_t FunctionDatabase::ParseAddress(const std::string& addrStr)
{
	try
	{
		if (addrStr.substr(0, 2) == "0x" || addrStr.substr(0, 2) == "0X")
		{
			return std::stoull(addrStr, nullptr, 16);
		}
		else
		{
			return std::stoull(addrStr, nullptr, 10);
		}
	}
	catch (...)
	{
		return 0;
	}
}

bool FunctionDatabase::LoadYamlFile(const std::string& filepath)
{
	std::ifstream file(filepath);
	if (!file.is_open())
	{
		printf("[FunctionDB] Could not open %s\n", filepath.c_str());
		return false;
	}

	std::string line;
	std::string currentSection;
	int functionsLoaded = 0;

	printf("[FunctionDB] Loading function database from %s\n", filepath.c_str());

	while (std::getline(file, line))
	{
		line = Trim(line);

		// Skip comments and empty lines
		if (line.empty() || line[0] == '#') continue;

		// Check for sections
		if (line == "functions:")
		{
			currentSection = "functions";
			continue;
		}
		else if (line == "categories:")
		{
			currentSection = "categories";
			continue;
		}

		if (currentSection == "functions")
		{
			// Parse simple format: 0x00007FF749055DE0: j_au_re_Client::ExdData::getRacingChocoboItem_8
			auto [addrStr, functionName] = ParseKeyValue(line);
			if (!addrStr.empty() && !functionName.empty())
			{
				uintptr_t address = ParseAddress(addrStr);
				if (address != 0)
				{
					// Determine category from function name
					std::string category = "Unknown";
					if (functionName.find("ExdData") != std::string::npos)
					{
						category = "ExdData";
					}
					else if (functionName.find("Concurrency") != std::string::npos)
					{
						category = "Concurrency";
					}
					else if (functionName.find("Client::") != std::string::npos ||
						functionName.find("au_re_Client::") != std::string::npos ||
						functionName.find("j_au_re_Client::") != std::string::npos)
					{
						category = "Client";
					}
					else if (functionName.find("Movement") != std::string::npos ||
						functionName.find("move") != std::string::npos)
					{
						category = "Movement";
					}
					else if (functionName.find("Camera") != std::string::npos ||
						functionName.find("camera") != std::string::npos)
					{
						category = "Camera";
					}
					else if (functionName.find("Combat") != std::string::npos ||
						functionName.find("action") != std::string::npos)
					{
						category = "Combat";
					}
					else if (functionName.find("UI") != std::string::npos ||
						functionName.find("ui") != std::string::npos)
					{
						category = "UI";
					}
					else if (functionName.find("Network") != std::string::npos ||
						functionName.find("network") != std::string::npos)
					{
						category = "Network";
					}
					else if (functionName.find("sub_") == 0)
					{
						category = "Unknown";
					}

					FunctionInfo info;
					info.name = functionName;
					info.description = ""; // No descriptions in data.yml
					info.category = category;
					info.address = address;

					m_functions[address] = info;
					functionsLoaded++;
				}
			}
		}
		else if (currentSection == "categories")
		{
			auto [key, value] = ParseKeyValue(line);
			if (!key.empty() && !value.empty())
			{
				m_categories[key] = value;
			}
		}
	}

	printf("[FunctionDB] Successfully loaded %d functions and %zu categories from %s\n",
		functionsLoaded, m_categories.size(), filepath.c_str());

	return functionsLoaded > 0;
}

bool FunctionDatabase::SaveYamlFile(const std::string& filepath)
{
	std::ofstream file(filepath);
	if (!file.is_open())
	{
		printf("[FunctionDB] Failed to open %s for writing\n", filepath.c_str());
		return false;
	}

	file << "# FFXIV Function and Global Database\n";
	file << "# Based on IDA analysis and reverse engineering\n";
	file << "# Generated by SapphireHook\n";
	file << "version: 2025.08.22.0022.3914\n\n";

	// Write categories first
	file << "categories:\n";
	for (const auto& [category, description] : m_categories)
	{
		file << "  " << category << ": \"" << description << "\"\n";
	}
	file << "\n";

	// Write functions in simple format
	file << "functions:\n";

	// Group functions by category for better organization
	std::map<std::string, std::vector<std::pair<uintptr_t, FunctionInfo>>> groupedFunctions;
	for (const auto& [address, info] : m_functions)
	{
		groupedFunctions[info.category].push_back({ address, info });
	}

	for (const auto& [category, functions] : groupedFunctions)
	{
		if (!functions.empty())
		{
			file << "  # " << category << " functions";
			if (m_categories.find(category) != m_categories.end())
			{
				file << " - " << m_categories.at(category);
			}
			file << "\n";

			// Sort functions by address for consistent output
			auto sortedFunctions = functions;
			std::sort(sortedFunctions.begin(), sortedFunctions.end(),
				[](const auto& a, const auto& b) { return a.first < b.first; });

			for (const auto& [address, info] : sortedFunctions)
			{
				file << "  0x" << std::hex << std::uppercase << address << ": " << info.name << "\n";
			}
			file << "\n";
		}
	}

	printf("[FunctionDB] Saved %zu functions to %s\n", m_functions.size(), filepath.c_str());
	return true;
}

bool FunctionDatabase::Load(const std::string& filepath)
{
	if (!filepath.empty())
	{
		m_databasePath = filepath;
	}
	return LoadYamlFile(m_databasePath);
}

bool FunctionDatabase::Save(const std::string& filepath)
{
	std::string savePath = filepath.empty() ? m_databasePath : filepath;
	return SaveYamlFile(savePath);
}

void FunctionDatabase::AddFunction(uintptr_t address, const std::string& name,
	const std::string& description, const std::string& category)
{
	FunctionInfo info(name, description, category);
	info.address = address;
	m_functions[address] = info;
	printf("[FunctionDB] Added function: %s at 0x%llx (%s)\n", name.c_str(), address, category.c_str());
}

void FunctionDatabase::RemoveFunction(uintptr_t address)
{
	auto it = m_functions.find(address);
	if (it != m_functions.end())
	{
		printf("[FunctionDB] Removed function: %s at 0x%llx\n", it->second.name.c_str(), address);
		m_functions.erase(it);
	}
}

bool FunctionDatabase::HasFunction(uintptr_t address) const
{
	return m_functions.find(address) != m_functions.end();
}

FunctionInfo FunctionDatabase::GetFunction(uintptr_t address) const
{
	auto it = m_functions.find(address);
	return (it != m_functions.end()) ? it->second : FunctionInfo();
}

std::string FunctionDatabase::GetFunctionName(uintptr_t address) const
{
	auto it = m_functions.find(address);
	if (it != m_functions.end() && !it->second.name.empty())
	{
		return it->second.name;
	}

	// Fallback to hex address
	std::stringstream ss;
	ss << "sub_" << std::hex << std::uppercase << address;
	return ss.str();
}

std::string FunctionDatabase::GetFunctionDescription(uintptr_t address) const
{
	auto it = m_functions.find(address);
	return (it != m_functions.end()) ? it->second.description : "";
}

std::string FunctionDatabase::GetFunctionCategory(uintptr_t address) const
{
	auto it = m_functions.find(address);
	return (it != m_functions.end()) ? it->second.category : "Unknown";
}

void FunctionDatabase::AddCategory(const std::string& name, const std::string& description)
{
	m_categories[name] = description;
	printf("[FunctionDB] Added category: %s - %s\n", name.c_str(), description.c_str());
}

std::vector<std::string> FunctionDatabase::GetFunctionsByCategory(const std::string& category) const
{
	std::vector<std::string> functions;
	for (const auto& [address, info] : m_functions)
	{
		if (info.category == category)
		{
			functions.push_back(info.name);
		}
	}
	return functions;
}

std::string FunctionDatabase::GetSimpleFunctionName(uintptr_t address) const
{
	auto it = m_functions.find(address);
	if (it != m_functions.end() && !it->second.name.empty())
	{
		std::string fullName = it->second.name;

		// Extract simple function name from various patterns:
		// Client::ExdData::getBGM -> getBGM
		// au_re_Client::ExdData::getRacingChocoboItem_8 -> getRacingChocoboItem_8
		// j_au_re_Client::ExdData::getOnlineStatus -> getOnlineStatus

		size_t lastColonPos = fullName.find_last_of("::");
		if (lastColonPos != std::string::npos && lastColonPos < fullName.length() - 1)
		{
			return fullName.substr(lastColonPos + 1);
		}

		// If no :: found, check for other patterns
		// For functions like "au_re_memmove", "std::vector<void *>::begin", etc.
		size_t lastDotPos = fullName.find_last_of(".");
		if (lastDotPos != std::string::npos && lastDotPos < fullName.length() - 1)
		{
			return fullName.substr(lastDotPos + 1);
		}

		// If it's a sub_ function, return empty to indicate no simple name available
		if (fullName.find("sub_") == 0)
		{
			return "";
		}

		// Return the full name if no pattern matches
		return fullName;
	}

	return ""; // No simple name available
}