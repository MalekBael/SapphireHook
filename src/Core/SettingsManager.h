#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <filesystem>
#include <functional>

namespace SapphireHook {

    // ============================================
    // Centralized Settings Manager
    // All persistent settings go through this singleton.
    // Settings are stored in sapphire_settings.json next to the DLL.
    // ============================================
    class SettingsManager {
    public:
        static SettingsManager& Instance();

        // Initialize and load settings from disk
        void Initialize();

        // Save all settings to disk
        void Save();

        // Get the settings file path
        std::filesystem::path GetSettingsFilePath() const;

        // ===== Logger Settings =====
        int GetLogLevel() const { return m_logLevel; }
        void SetLogLevel(int level);

        bool GetConsoleOutput() const { return m_consoleOutput; }
        void SetConsoleOutput(bool enabled);

        // ===== Packet Logging Settings =====
        int GetPacketLogMode() const { return m_packetLogMode; }
        void SetPacketLogMode(int mode);

        // ===== Weather Favorites =====
        const std::vector<uint32_t>& GetWeatherFavorites() const { return m_weatherFavorites; }
        void SetWeatherFavorites(const std::vector<uint32_t>& favorites);
        void AddWeatherFavorite(uint32_t id);
        void RemoveWeatherFavorite(uint32_t id);

        // Register a callback to be notified when settings are loaded
        // This allows modules to react to setting changes
        using SettingsLoadedCallback = std::function<void()>;
        void RegisterLoadCallback(SettingsLoadedCallback callback);

    private:
        SettingsManager() = default;
        ~SettingsManager() = default;
        SettingsManager(const SettingsManager&) = delete;
        SettingsManager& operator=(const SettingsManager&) = delete;

        void Load();
        void ApplySettings();  // Apply loaded settings to runtime systems

        // Settings values
        int m_logLevel = 1;           // LogLevel::Information
        bool m_consoleOutput = true;
        int m_packetLogMode = 1;      // PacketLogMode::Summary
        std::vector<uint32_t> m_weatherFavorites;

        bool m_initialized = false;
        std::vector<SettingsLoadedCallback> m_loadCallbacks;
    };

} // namespace SapphireHook
