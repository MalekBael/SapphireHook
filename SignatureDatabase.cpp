#include "SignatureDatabase.h"
#include "patternscanner.h"
#include <fstream>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <regex>

SignatureDatabase::SignatureDatabase()
{
	LoadTypeDefinitions();
}

void SignatureDatabase::LoadTypeDefinitions()
{
	// Map common FFXIV types from the IDA header
	m_typeDefinitions["Client::Game::Object::GameObject"] = "GameObject*";
	m_typeDefinitions["Client::Game::Character::Character"] = "Character*";
	m_typeDefinitions["Client::Game::Character::BattleChara"] = "BattleChara*";
	m_typeDefinitions["Client::UI::Agent::AgentInterface"] = "AgentInterface*";
	m_typeDefinitions["Component::GUI::AtkUnitManager"] = "AtkUnitManager*";
	m_typeDefinitions["Component::GUI::AtkResNode"] = "AtkResNode*";
	m_typeDefinitions["Client::Graphics::Scene::Object"] = "SceneObject*";
	m_typeDefinitions["Client::System::Framework::Framework"] = "Framework*";
	m_typeDefinitions["Client::Game::ActionManager"] = "ActionManager*";
	m_typeDefinitions["Client::Game::InventoryManager"] = "InventoryManager*";
	m_typeDefinitions["Client::Network::NetworkModule"] = "NetworkModule*";

	// Class hierarchy from IDA analysis
	m_classHierarchy["Client::Game::Object::GameObject"] = {
		"Client::Game::Character::Character",
		"Client::Game::Character::BattleChara",
		"Client::Game::Character::Companion"
	};

	m_classHierarchy["Client::UI::Agent::AgentInterface"] = {
		"Client::UI::Agent::AgentContext",
		"Client::UI::Agent::AgentLobby",
		"Client::UI::Agent::AgentSalvage"
	};

	m_classHierarchy["Component::GUI::AtkUnitManager"] = {
		"Component::GUI::AtkUnitBase"
	};

	// Initialize known FFXIV classes and their categories
	m_knownClasses["Client::Game::Object::GameObject"] = "Game Object System";
	m_knownClasses["Client::Game::Character::Character"] = "Character System";
	m_knownClasses["Client::Game::Character::BattleChara"] = "Combat System";
	m_knownClasses["Client::UI::Agent::AgentInterface"] = "UI Agent System";
	m_knownClasses["Component::GUI::AtkUnitManager"] = "UI Management";
	m_knownClasses["Component::GUI::AtkResNode"] = "UI Components";
	m_knownClasses["Client::Graphics::Scene::Object"] = "Graphics System";
	m_knownClasses["Client::System::Framework::Framework"] = "Core Framework";
	m_knownClasses["Client::Network::NetworkModule"] = "Network System";
	m_knownClasses["Client::Game::ActionManager"] = "Action System";
	m_knownClasses["Client::Game::InventoryManager"] = "Inventory System";

	// Categorize classes
	m_classCategories["UI"] = {
		"Client::UI::Agent::AgentInterface",
		"Component::GUI::AtkUnitManager",
		"Component::GUI::AtkResNode"
	};

	m_classCategories["Game"] = {
		"Client::Game::Object::GameObject",
		"Client::Game::Character::Character",
		"Client::Game::Character::BattleChara",
		"Client::Game::ActionManager",
		"Client::Game::InventoryManager"
	};

	m_classCategories["Graphics"] = {
		"Client::Graphics::Scene::Object"
	};

	m_classCategories["System"] = {
		"Client::System::Framework::Framework",
		"Client::Network::NetworkModule"
	};

	printf("[SignatureDB] Loaded %zu type definitions, %zu class hierarchies, and %zu known classes in %zu categories\n",
		m_typeDefinitions.size(), m_classHierarchy.size(), m_knownClasses.size(), m_classCategories.size());
}

std::string SignatureDatabase::ResolveTypeName(const std::string& rawType)
{
	auto it = m_typeDefinitions.find(rawType);
	if (it != m_typeDefinitions.end())
	{
		return it->second;
	}

	// Handle common patterns
	if (rawType.find("::") != std::string::npos)
	{
		// Namespace qualified type
		size_t lastColon = rawType.find_last_of("::");
		if (lastColon != std::string::npos && lastColon > 0)
		{
			return rawType.substr(lastColon - 1) + "*";
		}
	}

	return rawType;
}

std::string SignatureDatabase::Trim(const std::string& str) const
{
	size_t start = str.find_first_not_of(" \t\r\n");
	if (start == std::string::npos) return "";
	size_t end = str.find_last_not_of(" \t\r\n");
	return str.substr(start, end - start + 1);
}

bool SignatureDatabase::ParseSignatureLine(const std::string& line, const std::string& currentClass, bool inGlobalSigs, bool inFunctionSigs)
{
	size_t colonPos = line.find(':');
	if (colonPos == std::string::npos) return false;

	std::string name = Trim(line.substr(0, colonPos));
	std::string signature = Trim(line.substr(colonPos + 1));

	// Skip None/null signatures
	if (signature == "None" || signature == "null" || signature.empty())
	{
		return false;
	}

	SignatureInfo info;
	info.functionName = name;
	info.signature = signature;

	if (inGlobalSigs)
	{
		info.className = "Global";
		info.category = "Global Functions";
		info.description = "Global function: " + name;
		m_globalSignatures[name] = info;
		return true;
	}
	else if (inFunctionSigs && !currentClass.empty())
	{
		info.className = currentClass;

		// Set category based on class
		bool foundCategory = false;
		for (const auto& [category, classes] : m_classCategories)
		{
			if (std::find(classes.begin(), classes.end(), currentClass) != classes.end())
			{
				info.category = category;
				foundCategory = true;
				break;
			}
		}
		if (!foundCategory)
		{
			info.category = "Unknown";
		}

		info.description = currentClass + "::" + name;

		// Detect if it might be virtual (simple heuristic)
		if (name.find("vf") == 0 || name.find("virtual") != std::string::npos)
		{
			info.isVirtual = true;
		}

		// Try to resolve type information from class name
		info.returnType = ResolveTypeName(currentClass);

		m_classSignatures[currentClass][name] = info;
		return true;
	}

	return false;
}

bool SignatureDatabase::LoadSignatureFile(const std::string& filepath)
{
	std::ifstream file(filepath);
	if (!file.is_open())
	{
		printf("[SignatureDB] Failed to open %s\n", filepath.c_str());
		return false;
	}

	std::string line;
	std::string currentClass = "";
	bool inFunctionSigs = false;
	bool inGlobalSigs = false;
	size_t globalCount = 0;
	size_t classCount = 0;

	printf("[SignatureDB] Loading signatures from %s...\n", filepath.c_str());

	while (std::getline(file, line))
	{
		line = Trim(line);

		// Skip empty lines, comments, and YAML tags
		if (line.empty() || line[0] == '#' || line.find('!') == 0) continue;

		// Check for section headers
		if (line == "global_sigs:")
		{
			inGlobalSigs = true;
			inFunctionSigs = false;
			currentClass = "";
			printf("[SignatureDB] Entering global signatures section\n");
			continue;
		}

		if (line == "classes:")
		{
			inGlobalSigs = false;
			inFunctionSigs = false;
			printf("[SignatureDB] Entering classes section\n");
			continue;
		}

		if (line.find("func_sigs:") != std::string::npos)
		{
			inFunctionSigs = true;
			printf("[SignatureDB] Entering function signatures for class: %s\n", currentClass.c_str());
			continue;
		}

		// Check for class definitions (ignore the YAML tag part)
		if (line.find(":") != std::string::npos && !inGlobalSigs && !inFunctionSigs)
		{
			size_t colonPos = line.find(":");
			std::string className = Trim(line.substr(0, colonPos));
			// Remove any YAML tag content
			if (className.find(' ') != std::string::npos)
			{
				className = className.substr(0, className.find(' '));
			}
			currentClass = className;
			inFunctionSigs = false;
			printf("[SignatureDB] Found class: %s\n", currentClass.c_str());
			continue;
		}

		// Parse signature entries
		if ((inGlobalSigs || inFunctionSigs) && line.find(":") != std::string::npos)
		{
			if (ParseSignatureLine(line, currentClass, inGlobalSigs, inFunctionSigs))
			{
				if (inGlobalSigs)
				{
					globalCount++;
				}
				else
				{
					classCount++;
				}
			}
		}
	}

	printf("[SignatureDB] Loaded %zu global signatures and %zu class function signatures\n",
		globalCount, classCount);

	return globalCount > 0 || classCount > 0;
}

bool SignatureDatabase::Load(const std::string& filepath)
{
	m_databasePath = filepath;
	m_globalSignatures.clear();
	m_classSignatures.clear();

	return LoadSignatureFile(filepath);
}

void SignatureDatabase::ResolveAllSignatures()
{
	printf("[SignatureDB] Starting signature resolution...\n");

	size_t moduleSize = 0;
	uintptr_t moduleBase = GetModuleBaseAddress(L"ffxiv_dx11.exe", moduleSize);

	if (moduleBase == 0)
	{
		printf("[SignatureDB] Failed to get module base address\n");
		return;
	}

	printf("[SignatureDB] Module base: 0x%llx, size: 0x%llx\n", moduleBase, moduleSize);

	size_t resolved = 0;
	size_t total = m_globalSignatures.size();

	// Resolve global signatures
	for (auto& [name, info] : m_globalSignatures)
	{
		uintptr_t address = patternscan(moduleBase, moduleSize, info.signature.c_str());
		if (address != 0)
		{
			info.resolvedAddress = address;
			info.isResolved = true;
			resolved++;
			printf("[SignatureDB] Resolved global %s -> 0x%llx\n", name.c_str(), address);
		}
		else
		{
			printf("[SignatureDB] Failed to resolve global %s\n", name.c_str());
		}
	}

	// Resolve class function signatures
	for (auto& [className, functions] : m_classSignatures)
	{
		for (auto& [funcName, info] : functions)
		{
			total++;
			uintptr_t address = patternscan(moduleBase, moduleSize, info.signature.c_str());
			if (address != 0)
			{
				info.resolvedAddress = address;
				info.isResolved = true;
				resolved++;
				printf("[SignatureDB] Resolved %s::%s -> 0x%llx\n",
					className.c_str(), funcName.c_str(), address);
			}
		}
	}

	printf("[SignatureDB] Resolution complete: %zu/%zu signatures resolved (%.1f%%)\n",
		resolved, total, total > 0 ? (float)resolved / total * 100.0f : 0.0f);
}

uintptr_t SignatureDatabase::GetGlobalAddress(const std::string& name) const
{
	auto it = m_globalSignatures.find(name);
	if (it != m_globalSignatures.end() && it->second.isResolved)
	{
		return it->second.resolvedAddress;
	}
	return 0;
}

uintptr_t SignatureDatabase::GetClassFunctionAddress(const std::string& className, const std::string& functionName) const
{
	auto classIt = m_classSignatures.find(className);
	if (classIt != m_classSignatures.end())
	{
		auto funcIt = classIt->second.find(functionName);
		if (funcIt != classIt->second.end() && funcIt->second.isResolved)
		{
			return funcIt->second.resolvedAddress;
		}
	}
	return 0;
}

std::vector<std::pair<uintptr_t, std::string>> SignatureDatabase::GetResolvedFunctions() const
{
	std::vector<std::pair<uintptr_t, std::string>> result;

	// Add global signatures
	for (const auto& [name, info] : m_globalSignatures)
	{
		if (info.isResolved)
		{
			result.emplace_back(info.resolvedAddress, "Global::" + name);
		}
	}

	// Add class function signatures
	for (const auto& [className, functions] : m_classSignatures)
	{
		for (const auto& [funcName, info] : functions)
		{
			if (info.isResolved)
			{
				result.emplace_back(info.resolvedAddress, className + "::" + funcName);
			}
		}
	}

	return result;
}

std::vector<std::pair<uintptr_t, SignatureInfo>> SignatureDatabase::GetResolvedFunctionsWithInfo() const
{
	std::vector<std::pair<uintptr_t, SignatureInfo>> result;

	// Add global signatures
	for (const auto& [name, info] : m_globalSignatures)
	{
		if (info.isResolved)
		{
			result.emplace_back(info.resolvedAddress, info);
		}
	}

	// Add class function signatures
	for (const auto& [className, functions] : m_classSignatures)
	{
		for (const auto& [funcName, info] : functions)
		{
			if (info.isResolved)
			{
				result.emplace_back(info.resolvedAddress, info);
			}
		}
	}

	return result;
}

std::vector<SignatureInfo> SignatureDatabase::FindFunctionsByReturnType(const std::string& returnType) const
{
	std::vector<SignatureInfo> results;

	for (const auto& [className, functions] : m_classSignatures)
	{
		for (const auto& [funcName, info] : functions)
		{
			if (info.returnType == returnType && info.isResolved)
			{
				results.push_back(info);
			}
		}
	}

	for (const auto& [name, info] : m_globalSignatures)
	{
		if (info.returnType == returnType && info.isResolved)
		{
			results.push_back(info);
		}
	}

	return results;
}

std::vector<SignatureInfo> SignatureDatabase::FindFunctionsByParameter(const std::string& paramType) const
{
	std::vector<SignatureInfo> results;

	for (const auto& [className, functions] : m_classSignatures)
	{
		for (const auto& [funcName, info] : functions)
		{
			if (info.isResolved)
			{
				for (const auto& param : info.parameterTypes)
				{
					if (param.find(paramType) != std::string::npos)
					{
						results.push_back(info);
						break;
					}
				}
			}
		}
	}

	return results;
}

std::vector<SignatureInfo> SignatureDatabase::FindFunctionsByClass(const std::string& className) const
{
	std::vector<SignatureInfo> result;

	auto it = m_classSignatures.find(className);
	if (it != m_classSignatures.end())
	{
		for (const auto& [funcName, info] : it->second)
		{
			if (info.isResolved)
			{
				result.push_back(info);
			}
		}
	}

	return result;
}

std::vector<SignatureInfo> SignatureDatabase::FindFunctionsByCategory(const std::string& category) const
{
	std::vector<SignatureInfo> result;

	for (const auto& [className, functions] : m_classSignatures)
	{
		for (const auto& [funcName, info] : functions)
		{
			if (info.category == category && info.isResolved)
			{
				result.push_back(info);
			}
		}
	}

	return result;
}

std::vector<SignatureInfo> SignatureDatabase::FindFunctionsByName(const std::string& namePattern) const
{
	std::vector<SignatureInfo> result;

	std::regex pattern(namePattern, std::regex_constants::icase);

	// Search global signatures
	for (const auto& [name, info] : m_globalSignatures)
	{
		if (std::regex_search(name, pattern) && info.isResolved)
		{
			result.push_back(info);
		}
	}

	// Search class signatures
	for (const auto& [className, functions] : m_classSignatures)
	{
		for (const auto& [funcName, info] : functions)
		{
			if (std::regex_search(funcName, pattern) && info.isResolved)
			{
				result.push_back(info);
			}
		}
	}

	return result;
}

std::vector<std::string> SignatureDatabase::GetDerivedClasses(const std::string& baseClass) const
{
	auto it = m_classHierarchy.find(baseClass);
	if (it != m_classHierarchy.end())
	{
		return it->second;
	}
	return {};
}

std::vector<std::string> SignatureDatabase::GetVirtualFunctions(const std::string& className) const
{
	std::vector<std::string> result;

	auto it = m_classSignatures.find(className);
	if (it != m_classSignatures.end())
	{
		for (const auto& [funcName, info] : it->second)
		{
			if (info.isVirtual && info.isResolved)
			{
				result.push_back(funcName);
			}
		}
	}

	return result;
}

std::vector<std::string> SignatureDatabase::GetAllClasses() const
{
	std::vector<std::string> result;
	for (const auto& [className, functions] : m_classSignatures)
	{
		result.push_back(className);
	}
	return result;
}

std::vector<std::string> SignatureDatabase::GetAllCategories() const
{
	std::vector<std::string> result;
	for (const auto& [category, classes] : m_classCategories)
	{
		result.push_back(category);
	}
	return result;
}

size_t SignatureDatabase::GetTotalSignatures() const
{
	size_t total = m_globalSignatures.size();
	for (const auto& [className, functions] : m_classSignatures)
	{
		total += functions.size();
	}
	return total;
}

size_t SignatureDatabase::GetResolvedSignatures() const
{
	size_t resolved = 0;

	for (const auto& [name, info] : m_globalSignatures)
	{
		if (info.isResolved) resolved++;
	}

	for (const auto& [className, functions] : m_classSignatures)
	{
		for (const auto& [funcName, info] : functions)
		{
			if (info.isResolved) resolved++;
		}
	}

	return resolved;
}