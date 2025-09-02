#include "CommandInvoker.h"
#include "FunctionDatabase.h"
#include "../Logger/Logger.h"
#include "SimpleJSON.h"
#include <regex>
#include <fstream>
#include <algorithm>
#include <locale>
#include <codecvt>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

using namespace SapphireHook;

CommandInvoker& CommandInvoker::Instance()
{
    static CommandInvoker s;
    return s;
}

static uint64_t ParseUintFlexibleLocal(const std::string& s)
{
    std::string t = s;
    t.erase(0, t.find_first_not_of(" \t\r\n"));
    if (t.empty()) return 0;
    if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0)
    {
        return std::stoull(t.substr(2), nullptr, 16);
    }
    // If contains hex alpha, consider hex
    auto hasHexAlpha = std::find_if(t.begin(), t.end(), [](unsigned char c)
        {
            c = static_cast<unsigned char>(std::toupper(c));
            return (c >= 'A' && c <= 'F');
        }) != t.end();
    return std::stoull(t, nullptr, hasHexAlpha ? 16 : 10);
}

bool CommandInvoker::LooksLikeAddress(const std::string& s)
{
    if (s.size() >= 3 && (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0)) return true;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c); });
}

int CommandInvoker::ConfigureFromFunctionDB(const FunctionDatabase& db, const std::string& optionalConfigJsonPath)
{
    int count = 0;
    count += ResolveFromDB(db);
    if (!optionalConfigJsonPath.empty())
    {
        count += LoadConfig(optionalConfigJsonPath);
    }
    if (count == 0)
    {
        LogWarning("CommandInvoker: no real targets resolved; will fall back to simulation.");
    }
    return count;
}

int CommandInvoker::ResolveFromDB(const FunctionDatabase& db)
{
    int resolved = 0;

    // Scan function names with heuristics
    // You can extend these patterns to match your data.json naming scheme.
    const std::vector<std::regex> chatPatternsW = {
        std::regex("SendChat|Chat.*Send|ExecuteCommand|ProcessChat", std::regex::icase),
        std::regex("ChatLog.*(Send|Exec|Process)", std::regex::icase),
        std::regex("Shell.*(Exec|Command)", std::regex::icase)
    };
    const std::vector<std::regex> chatPatternsA = {
        std::regex("SendChatA|Chat.*SendA", std::regex::icase)
    };
    const std::vector<std::regex> ipcPatterns = {
        std::regex("SendIPC|SendPacket|Network.*Send", std::regex::icase),
        std::regex("Ipc.*Send", std::regex::icase)
    };

    // Iterate DB (public API)
    auto all = db.GetAllFunctions();

    auto tryMatch = [&](const std::regex& re, auto& outFn, const char* tag) -> bool
        {
            for (const auto& kv : all)
            {
                const auto& name = kv.second.name;
                if (std::regex_search(name, re))
                {
                    auto addr = kv.first;
                    outFn = reinterpret_cast<decltype(outFn)>(addr);
                    LogInfo(std::string("CommandInvoker: resolved ") + tag + " at " + std::to_string(addr) + " (" + name + ")");
                    return true;
                }
            }
            return false;
        };

    if (!m_chatSendW)
    {
        for (const auto& re : chatPatternsW)
        {
            if (tryMatch(re, m_chatSendW, "ChatSendW")) { resolved++; break; }
        }
    }
    if (!m_chatSendA)
    {
        for (const auto& re : chatPatternsA)
        {
            if (tryMatch(re, m_chatSendA, "ChatSendA")) { resolved++; break; }
        }
    }
    if (!m_sendIpc)
    {
        for (const auto& re : ipcPatterns)
        {
            if (tryMatch(re, m_sendIpc, "SendIPC")) { resolved++; break; }
        }
    }

    return resolved;
}

int CommandInvoker::LoadConfig(const std::string& path)
{
    std::ifstream f(path);
    if (!f.is_open())
    {
        LogWarning("CommandInvoker: config not found: " + path);
        return 0;
    }
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    int resolved = 0;

    try
    {
        auto json = SimpleJSON::Parse(content);

        auto getStr = [&](const char* key) -> std::optional<std::string>
            {
                if (!json.HasKey(key)) return std::nullopt;
                auto& v = json.data[key];
                if (std::holds_alternative<std::string>(v)) return std::get<std::string>(v);
                return std::nullopt;
            };

        if (auto v = getStr("chat_send_w"))
        {
            uint64_t addr = LooksLikeAddress(*v) ? ParseUintFlexibleLocal(*v) : 0;
            if (addr) { m_chatSendW = reinterpret_cast<ChatSendW_Fn>(addr); resolved++; }
        }
        if (auto v = getStr("chat_send_a"))
        {
            uint64_t addr = LooksLikeAddress(*v) ? ParseUintFlexibleLocal(*v) : 0;
            if (addr) { m_chatSendA = reinterpret_cast<ChatSendA_Fn>(addr); resolved++; }
        }
        if (auto v = getStr("send_ipc"))
        {
            uint64_t addr = LooksLikeAddress(*v) ? ParseUintFlexibleLocal(*v) : 0;
            if (addr) { m_sendIpc = reinterpret_cast<SendIPCFn>(addr); resolved++; }
        }
        if (auto v = getStr("chat_this"))
        {
            uint64_t p = LooksLikeAddress(*v) ? ParseUintFlexibleLocal(*v) : 0;
            if (p) { m_chatThis = reinterpret_cast<void*>(p); }
        }
        if (auto v = getStr("network_this"))
        {
            uint64_t p = LooksLikeAddress(*v) ? ParseUintFlexibleLocal(*v) : 0;
            if (p) { m_networkThis = reinterpret_cast<void*>(p); }
        }

        LogInfo("CommandInvoker: config loaded from " + path + " (resolved " + std::to_string(resolved) + " entries)");
    }
    catch (const std::exception& e)
    {
        LogError(std::string("CommandInvoker: config parse error: ") + e.what());
    }
    return resolved;
}

static std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
#if defined(_WIN32)
    int size = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                   nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string out(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                        out.data(), size, nullptr, nullptr);
    return out;
#else
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
    return conv.to_bytes(w);
#endif
}

bool CommandInvoker::SendChat(const std::wstring& text)
{
    if (m_chatSendW)
    {
        if (!m_chatThis)
        {
            LogWarning("CommandInvoker: ChatSendW resolved but this==nullptr; call may crash. Set chat_this in config.");
        }
        try
        {
            bool ok = m_chatSendW(m_chatThis, text.c_str(), nullptr);
            LogInfo(std::string("CommandInvoker: SendChat(W) ") + (ok ? "OK" : "FAIL"));
            return ok;
        }
        catch (...)
        {
            LogError("CommandInvoker: exception in ChatSendW");
            return false;
        }
    }
    // fallback to ANSI path if available
    if (m_chatSendA)
    {
        std::string utf8 = WideToUtf8(text);
        return SendChatAnsi(utf8);
    }
    return false;
}

bool CommandInvoker::SendChatAnsi(const std::string& text)
{
    if (!m_chatSendA) return false;
    if (!m_chatThis)
    {
        LogWarning("CommandInvoker: ChatSendA resolved but this==nullptr; set chat_this in config.");
    }
    try
    {
        bool ok = m_chatSendA(m_chatThis, text.c_str(), nullptr);
        LogInfo(std::string("CommandInvoker: SendChat(A) ") + (ok ? "OK" : "FAIL"));
        return ok;
    }
    catch (...)
    {
        LogError("CommandInvoker: exception in ChatSendA");
        return false;
    }
}

bool CommandInvoker::SendIPC(uint16_t opcode, const void* payload, uint32_t length)
{
    if (!m_sendIpc) return false;
    if (!m_networkThis)
    {
        LogWarning("CommandInvoker: SendIPC resolved but networkThis==nullptr; set network_this in config.");
    }
    try
    {
        bool ok = m_sendIpc(m_networkThis, opcode, payload, length);
        LogInfo(std::string("CommandInvoker: SendIPC ") + (ok ? "OK" : "FAIL") + " opcode=0x" + std::to_string(opcode));
        return ok;
    }
    catch (...)
    {
        LogError("CommandInvoker: exception in SendIPC");
        return false;
    }
}