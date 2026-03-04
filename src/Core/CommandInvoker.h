#pragma once
#pragma once
#include <cstdint>
#include <string>
#include <optional>

namespace SapphireHook {

    class FunctionDatabase;

    class CommandInvoker {
    public:
        static CommandInvoker& Instance();

        int ConfigureFromFunctionDB(const FunctionDatabase& db,
            const std::string& optionalConfigJsonPath = "");

        bool SendChat(const std::wstring& text);
        bool SendChatAnsi(const std::string& text);

        bool SendIPC(uint16_t opcode, const void* payload, uint32_t length);

        void SetChatThis(void* chatThis) { m_chatThis = chatThis; }
        void SetNetworkThis(void* netThis) { m_networkThis = netThis; }

    private:
        CommandInvoker() = default;

        using ChatSendW_Fn = bool(__fastcall*)(void* thisPtr, const wchar_t* text, void* unused);
        using ChatSendA_Fn = bool(__fastcall*)(void* thisPtr, const char* text, void* unused);
        using SendIPCFn = bool(__fastcall*)(void* netThis, uint16_t opcode, const void* data, uint32_t len);

        ChatSendW_Fn m_chatSendW = nullptr;
        ChatSendA_Fn m_chatSendA = nullptr;
        SendIPCFn    m_sendIpc = nullptr;

        void* m_chatThis = nullptr;
        void* m_networkThis = nullptr;

        int ResolveFromDB(const FunctionDatabase& db);
        int LoadConfig(const std::string& path);
        static bool LooksLikeAddress(const std::string& s);
    };

}   