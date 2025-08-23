#pragma once
#include <string>
#include <map>
#include <vector>
#include <cstdint>

struct SignatureInfo {
	std::string className;
	std::string functionName;
	std::string signature;
	uintptr_t resolvedAddress = 0;
	bool isResolved = false;

	// Enhanced type information
	std::string returnType;
	std::vector<std::string> parameterTypes;
	std::string callingConvention;
	bool isVirtual = false;
	size_t vtableOffset = 0;

	// Class hierarchy information
	std::string baseClass;
	std::vector<std::string> interfaces;

	// Additional fields that your .cpp file uses
	std::string description;
	std::string category;
};

class SignatureDatabase {
private:
	std::map<std::string, std::map<std::string, SignatureInfo>> m_classSignatures;
	std::map<std::string, SignatureInfo> m_globalSignatures;
	std::string m_databasePath;

	// Type resolution from IDA headers
	std::map<std::string, std::string> m_typeDefinitions;
	std::map<std::string, std::vector<std::string>> m_classHierarchy;

	// Common FFXIV class information (hardcoded from knowledge)
	std::map<std::string, std::string> m_knownClasses;
	std::map<std::string, std::vector<std::string>> m_classCategories;

	// Private helper methods
	void LoadTypeDefinitions();
	std::string ResolveTypeName(const std::string& rawType);
	std::string Trim(const std::string& str) const;
	bool ParseSignatureLine(const std::string& line, const std::string& currentClass, bool inGlobalSigs, bool inFunctionSigs);
	bool LoadSignatureFile(const std::string& filepath);

public:
	SignatureDatabase();
	~SignatureDatabase() = default;

	// Database operations
	bool Load(const std::string& filepath = "data-sig.yml");
	void ResolveAllSignatures();

	// Get resolved addresses
	uintptr_t GetGlobalAddress(const std::string& name) const;
	uintptr_t GetClassFunctionAddress(const std::string& className, const std::string& functionName) const;

	// Get all resolved functions for integration with FunctionDatabase
	std::vector<std::pair<uintptr_t, std::string>> GetResolvedFunctions() const;
	std::vector<std::pair<uintptr_t, SignatureInfo>> GetResolvedFunctionsWithInfo() const;

	// Enhanced search capabilities
	std::vector<SignatureInfo> FindFunctionsByClass(const std::string& className) const;
	std::vector<SignatureInfo> FindFunctionsByCategory(const std::string& category) const;
	std::vector<SignatureInfo> FindFunctionsByName(const std::string& namePattern) const;
	std::vector<SignatureInfo> FindFunctionsByReturnType(const std::string& returnType) const;
	std::vector<SignatureInfo> FindFunctionsByParameter(const std::string& paramType) const;

	// Class hierarchy navigation
	std::vector<std::string> GetDerivedClasses(const std::string& baseClass) const;
	std::vector<std::string> GetVirtualFunctions(const std::string& className) const;
	std::vector<std::string> GetAllClasses() const;
	std::vector<std::string> GetAllCategories() const;

	// Statistics
	size_t GetTotalSignatures() const;
	size_t GetResolvedSignatures() const;

	// Access to signature info
	const std::map<std::string, SignatureInfo>& GetGlobalSignatures() const { return m_globalSignatures; }
	const std::map<std::string, std::map<std::string, SignatureInfo>>& GetClassSignatures() const { return m_classSignatures; }

	// Legacy compatibility method (renamed from GetResolvedFunctionsWithTypes)
	std::vector<std::pair<uintptr_t, SignatureInfo>> GetResolvedFunctionsWithTypes() const
	{
		return GetResolvedFunctionsWithInfo();
	}
};