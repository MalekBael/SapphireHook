#pragma once
#include <string>
#include <map>
#include <vector>
#include <cstdint>
#include <atomic>        
#include <thread>        
#include <functional>    

namespace SapphireHook {

    struct SignatureInfo {
        std::string className;
        std::string functionName;
        std::string signature;
        uintptr_t resolvedAddress = 0;
        bool isResolved = false;

        std::string returnType;
        std::vector<std::string> parameterTypes;
        std::string callingConvention;
        bool isVirtual = false;
        size_t vtableOffset = 0;

        std::string baseClass;
        std::vector<std::string> interfaces;

        std::string description;
        std::string category;
    };

    using ProgressCallback = std::function<void(size_t current, size_t total, const std::string& currentSignature)>;

    class SignatureDatabase {
    private:
        std::map<std::string, std::map<std::string, SignatureInfo>> m_classSignatures;
        std::map<std::string, SignatureInfo> m_globalSignatures;
        std::string m_databasePath;

        std::map<std::string, std::string> m_typeDefinitions;
        std::map<std::string, std::vector<std::string>> m_classHierarchy;

        std::map<std::string, std::string> m_knownClasses;
        std::map<std::string, std::vector<std::string>> m_classCategories;

        std::atomic<bool> m_scanInProgress{ false };
        std::atomic<bool> m_stopScan{ false };
        std::atomic<size_t> m_scannedCount{ 0 };
        std::atomic<size_t> m_totalCount{ 0 };
        std::thread m_scanThread;
        ProgressCallback m_progressCallback;

        void LoadTypeDefinitions();
        std::string ResolveTypeName(const std::string& rawType);
        std::string Trim(const std::string& str) const;
        bool ParseSignatureLine(const std::string& line, const std::string& currentClass, bool inGlobalSigs, bool inFunctionSigs);
        bool LoadSignatureFile(const std::string& filepath);

        void AsyncScanWorker(uintptr_t moduleBase, size_t moduleSize, ProgressCallback callback);

    public:
        SignatureDatabase();
        ~SignatureDatabase();

        bool Load(const std::string& filepath = "data-sig.yml");
        void ResolveAllSignatures();

        void ResolveAllSignaturesAsync(ProgressCallback callback = nullptr);
        void StopAsyncScanning();
        bool IsAsyncScanInProgress() const { return m_scanInProgress.load(); }
        size_t GetScanProgress() const { return m_scannedCount.load(); }
        size_t GetTotalScanCount() const { return m_totalCount.load(); }

        std::vector<std::pair<uintptr_t, std::string>> GetResolvedFunctions() const;
        std::vector<std::pair<uintptr_t, SignatureInfo>> GetResolvedFunctionsWithInfo() const;

        std::vector<SignatureInfo> FindFunctionsByClass(const std::string& className) const;

        std::vector<std::string> GetDerivedClasses(const std::string& baseClass) const;
        std::vector<std::string> GetVirtualFunctions(const std::string& className) const;
        std::vector<std::string> GetAllClasses() const;
        std::vector<std::string> GetAllCategories() const;

        size_t GetTotalSignatures() const;
        size_t GetResolvedSignatures() const;

        const std::map<std::string, SignatureInfo>& GetGlobalSignatures() const { return m_globalSignatures; }
        const std::map<std::string, std::map<std::string, SignatureInfo>>& GetClassSignatures() const { return m_classSignatures; }

        std::vector<std::pair<uintptr_t, SignatureInfo>> GetResolvedFunctionsWithTypes() const
        {
            return GetResolvedFunctionsWithInfo();
        }

    private:
        bool LoadFromJSON(const std::string& filepath);
    };

} // namespace SapphireHook