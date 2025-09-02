#pragma once
#include <string>
#include <memory>

namespace SapphireHook {

    class FunctionDatabase;
    class SignatureDatabase;

    class FunctionAnalyzer {
    public:
        FunctionAnalyzer();
        ~FunctionAnalyzer();

        void SetFunctionDatabase(std::shared_ptr<FunctionDatabase> database);
        void SetSignatureDatabase(std::shared_ptr<SignatureDatabase> database);

        // Address parsing and conversion
        uintptr_t ResolveManualAddress(const std::string& input);
        bool ParseAddressInput(const std::string& input, uintptr_t& result);
        uintptr_t ConvertRVAToRuntimeAddress(uintptr_t rva);

        // Validation and debugging
        bool ValidateAndDebugAddress(uintptr_t address, const std::string& name);
        void DebugAddressSource(uintptr_t address, const std::string& name);
        void DebugIdaAddress(const std::string& address);

        // Database operations
        void VerifyDatabaseLoading();
        void TestAndDebugEmbeddedData();

        // Signature operations
        void InitializeWithSignatures();
        void StartAsyncSignatureResolution();
        void IntegrateSignaturesWithDatabase();
        void DiscoverFunctionsFromSignatures();

        // Type information operations
        void InitializeWithTypeInformation();
        void DiscoverFunctionsByType(const std::string& className);
        void AnalyzeVirtualFunctionTables();
        void GenerateTypeBasedHooks();

        // Diagnostics
        void DiagnoseSignatureIssues();
        void EnhancedSignatureResolution();
        void DebugSignatureScanning();

    private:
        class Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace SapphireHook