#pragma once
#include <string>
#include <map>
#include <vector>

struct FunctionInfo {
	std::string name;
	std::string description;
	std::string category;
	uintptr_t address = 0;

	FunctionInfo() = default;
	FunctionInfo(const std::string& n, const std::string& d, const std::string& c)
		: name(n), description(d), category(c)
	{
	}
};

class FunctionDatabase {
private:
	std::map<uintptr_t, FunctionInfo> m_functions;
	std::map<std::string, std::string> m_categories;
	std::string m_databasePath;

	// Simple YAML parsing functions
	std::string Trim(const std::string& str);
	std::pair<std::string, std::string> ParseKeyValue(const std::string& line);
	uintptr_t ParseAddress(const std::string& addrStr);
	bool LoadYamlFile(const std::string& filepath);
	bool SaveYamlFile(const std::string& filepath);

public:
	FunctionDatabase();
	~FunctionDatabase() = default;

	// Database operations
	bool Load(const std::string& filepath = "data.yml");
	bool Save(const std::string& filepath = "");

	// Function management
	void AddFunction(uintptr_t address, const std::string& name,
		const std::string& description = "", const std::string& category = "Unknown");
	void RemoveFunction(uintptr_t address);
	bool HasFunction(uintptr_t address) const;

	// Function retrieval
	FunctionInfo GetFunction(uintptr_t address) const;
	std::string GetFunctionName(uintptr_t address) const;
	std::string GetFunctionDescription(uintptr_t address) const;
	std::string GetFunctionCategory(uintptr_t address) const;
	std::string GetSimpleFunctionName(uintptr_t address) const;

	// Get all functions
	const std::map<uintptr_t, FunctionInfo>& GetAllFunctions() const { return m_functions; }

	// Category management
	void AddCategory(const std::string& name, const std::string& description);
	const std::map<std::string, std::string>& GetCategories() const { return m_categories; }

	// Statistics
	size_t GetFunctionCount() const { return m_functions.size(); }
	size_t GetCategoryCount() const { return m_categories.size(); }
	std::vector<std::string> GetFunctionsByCategory(const std::string& category) const;
};