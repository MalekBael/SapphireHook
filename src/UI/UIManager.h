#pragma once
#include <vector>
#include <memory>
#include <string>

namespace SapphireHook
{
    class UIModule;  // Forward declaration inside namespace

    class UIManager
    {
    public:
        static UIManager& GetInstance();
        static bool HasInstance();  // ADD THIS LINE
        static void Shutdown();

        void Initialize();
        void Render();
        void RegisterModule(std::unique_ptr<UIModule> module);
        UIModule* GetModule(const char* name);
        void RegisterDefaultModules();

        void RenderMainMenu();
        void RenderAllWindows();

        void ToggleMenu() { m_showMenu = !m_showMenu; }
        bool IsMenuVisible() const { return m_showMenu; }
        size_t GetModuleCount() const;

    private:
        UIManager();
        ~UIManager();
        UIManager(const UIManager&) = delete;
        UIManager& operator=(const UIManager&) = delete;

        static UIManager* s_instance;
        static bool s_unloadRequested;
        std::vector<std::unique_ptr<UIModule>> m_modules;
        bool m_showMenu = false;
        bool m_showDemoWindow = false;
    public:
        static void RequestUnload();
        static bool IsUnloadRequested();
        const std::vector<std::unique_ptr<UIModule>>& GetModules() const { return m_modules; }
    };
}