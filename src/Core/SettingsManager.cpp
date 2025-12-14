#include "SettingsManager.h"
#include "../Logger/Logger.h"
#include "PacketInjector.h"  // For SetPacketLogMode runtime function
#include <windows.h>
#include <fstream>
#include <nlohmann/json.hpp>

using namespace SapphireHook;
using json = nlohmann::json;

SettingsManager& SettingsManager::Instance()
{
    static SettingsManager instance;
    return instance;
}

std::filesystem::path SettingsManager::GetSettingsFilePath() const
{
    // Store settings in the same directory as the DLL
    HMODULE hModule = nullptr;
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(&SettingsManager::Instance),
        &hModule);
    
    wchar_t dllPath[MAX_PATH] = {};
    GetModuleFileNameW(hModule, dllPath, MAX_PATH);
    
    std::filesystem::path settingsPath(dllPath);
    settingsPath = settingsPath.parent_path() / "sapphire_settings.json";
    return settingsPath;
}

void SettingsManager::Initialize()
{
    if (m_initialized)
        return;
    
    Load();
    ApplySettings();
    m_initialized = true;
    
    // Notify callbacks
    for (auto& callback : m_loadCallbacks)
    {
        callback();
    }
}

void SettingsManager::Load()
{
    try
    {
        std::filesystem::path path = GetSettingsFilePath();
        if (!std::filesystem::exists(path))
        {
            LogDebug("[SettingsManager] No settings file found, using defaults");
            return;
        }
        
        std::ifstream file(path);
        if (!file.is_open())
        {
            return;
        }
        
        json settings = json::parse(file);
        file.close();
        
        // Logger settings
        if (settings.contains("logLevel"))
        {
            int level = settings["logLevel"].get<int>();
            if (level >= 0 && level <= 4)
            {
                m_logLevel = level;
            }
        }
        
        if (settings.contains("consoleOutput"))
        {
            m_consoleOutput = settings["consoleOutput"].get<bool>();
        }
        
        // Packet logging
        if (settings.contains("packetLogMode"))
        {
            int mode = settings["packetLogMode"].get<int>();
            if (mode >= 0 && mode <= 2)
            {
                m_packetLogMode = mode;
            }
        }
        
        // Weather favorites
        if (settings.contains("weatherFavorites") && settings["weatherFavorites"].is_array())
        {
            m_weatherFavorites.clear();
            for (const auto& item : settings["weatherFavorites"])
            {
                if (item.is_number_unsigned())
                {
                    m_weatherFavorites.push_back(item.get<uint32_t>());
                }
            }
        }
        
        // Custom sqpack path
        if (settings.contains("sqpackPath") && settings["sqpackPath"].is_string())
        {
            std::string pathStr = settings["sqpackPath"].get<std::string>();
            if (!pathStr.empty())
            {
                m_sqpackPath = std::filesystem::path(pathStr);
                LogInfo("[SettingsManager] Using custom sqpack path: " + pathStr);
            }
        }
        
        LogInfo("[SettingsManager] Loaded from " + path.string());
    }
    catch (const std::exception& e)
    {
        LogError(std::string("[SettingsManager] Failed to load: ") + e.what());
    }
}

void SettingsManager::ApplySettings()
{
    // Apply logger settings
    auto& logger = Logger::Instance();
    logger.SetMinimumLevel(static_cast<LogLevel>(m_logLevel));
    logger.SetConsoleOutput(m_consoleOutput);
    
    // Apply packet log mode to runtime (calls PacketInjector's setter)
    SapphireHook::SetPacketLogMode(static_cast<PacketLogMode>(m_packetLogMode));
}

void SettingsManager::Save()
{
    try
    {
        json settings;
        settings["logLevel"] = m_logLevel;
        settings["consoleOutput"] = m_consoleOutput;
        settings["packetLogMode"] = m_packetLogMode;
        
        // Weather favorites
        settings["weatherFavorites"] = json::array();
        for (uint32_t id : m_weatherFavorites)
        {
            settings["weatherFavorites"].push_back(id);
        }
        
        // Custom sqpack path
        settings["sqpackPath"] = m_sqpackPath.string();
        
        std::filesystem::path path = GetSettingsFilePath();
        std::ofstream file(path);
        if (file.is_open())
        {
            file << settings.dump(2);
            file.close();
            LogDebug("[SettingsManager] Saved to " + path.string());
        }
    }
    catch (const std::exception& e)
    {
        LogError(std::string("[SettingsManager] Failed to save: ") + e.what());
    }
}

void SettingsManager::SetLogLevel(int level)
{
    if (level >= 0 && level <= 4)
    {
        m_logLevel = level;
        Logger::Instance().SetMinimumLevel(static_cast<LogLevel>(level));
        Save();
    }
}

void SettingsManager::SetConsoleOutput(bool enabled)
{
    m_consoleOutput = enabled;
    Logger::Instance().SetConsoleOutput(enabled);
    Save();
}

void SettingsManager::SetPacketLogMode(int mode)
{
    if (mode >= 0 && mode <= 2)
    {
        m_packetLogMode = mode;
        // Update the runtime value in PacketInjector
        SapphireHook::SetPacketLogMode(static_cast<PacketLogMode>(mode));
        Save();
    }
}

void SettingsManager::SetWeatherFavorites(const std::vector<uint32_t>& favorites)
{
    m_weatherFavorites = favorites;
    Save();
}

void SettingsManager::AddWeatherFavorite(uint32_t id)
{
    // Avoid duplicates
    for (uint32_t existing : m_weatherFavorites)
    {
        if (existing == id)
            return;
    }
    m_weatherFavorites.push_back(id);
    Save();
}

void SettingsManager::RemoveWeatherFavorite(uint32_t id)
{
    auto it = std::find(m_weatherFavorites.begin(), m_weatherFavorites.end(), id);
    if (it != m_weatherFavorites.end())
    {
        m_weatherFavorites.erase(it);
        Save();
    }
}

void SettingsManager::RegisterLoadCallback(SettingsLoadedCallback callback)
{
    m_loadCallbacks.push_back(callback);
}

void SettingsManager::SetSqpackPath(const std::filesystem::path& path)
{
    m_sqpackPath = path;
    Save();
}
