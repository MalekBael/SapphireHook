#pragma once
#pragma once
#include <cstdint>
#include <string>
#include <optional>

namespace SapphireHook {

    class FunctionDatabase;

    // Generic command invoker that uses resolved game functions if available.
    class CommandInvoker {
    public:
        static CommandInvoker& Instance();

        // Attempt to resolve targets from the function DB (by name pattern) and optional config.
        // Returns number of targets resolved.
        int ConfigureFromFunctionDB(const FunctionDatabase& db,
            const std::string& optionalConfigJsonPath = "");

        // Send chat (prefers wide-char chat API; falls back to ansi if only that is available).
        // Returns true if sent via real function, false if caller should simulate.
        bool SendChat(const std::wstring& text);
        bool SendChatAnsi(const std::string& text);

        // Send raw IPC (opcode + payload)
        bool SendIPC(uint16_t opcode, const void* payload, uint32_t length);

        // Manual overrides (e.g., loaded from config)
        void SetChatThis(void* chatThis) { m_chatThis = chatThis; }
        void SetNetworkThis(void* netThis) { m_networkThis = netThis; }

    private:
        CommandInvoker() = default;

        // Prototype families
        using ChatSendW_Fn = bool(__fastcall*)(void* thisPtr, const wchar_t* text, void* unused);
        using ChatSendA_Fn = bool(__fastcall*)(void* thisPtr, const char* text, void* unused);
        using SendIPCFn = bool(__fastcall*)(void* netThis, uint16_t opcode, const void* data, uint32_t len);

        // Resolved targets
        ChatSendW_Fn m_chatSendW = nullptr;
        ChatSendA_Fn m_chatSendA = nullptr;
        SendIPCFn    m_sendIpc = nullptr;

        void* m_chatThis = nullptr;
        void* m_networkThis = nullptr;

        // Helpers
        int ResolveFromDB(const FunctionDatabase& db);
        int LoadConfig(const std::string& path);
        static bool LooksLikeAddress(const std::string& s);
    };

} // namespace SapphireHook