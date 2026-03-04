#pragma once
#include "../../vendor/imgui/ImGuiNotify.hpp"
#include <cstdarg>

namespace SapphireHook
{
    class Notify
    {
    public:
        static void Success(const char* format, ...)
        {
            ImGuiToast toast(ImGuiToastType::Success);
            va_list args;
            va_start(args, format);
            char buffer[NOTIFY_MAX_MSG_LENGTH];
            vsnprintf(buffer, sizeof(buffer), format, args);
            va_end(args);
            toast.setContent("%s", buffer);
            ImGui::InsertNotification(toast);
        }

        static void Success(int dismissMs, const char* format, ...)
        {
            ImGuiToast toast(ImGuiToastType::Success, dismissMs);
            va_list args;
            va_start(args, format);
            char buffer[NOTIFY_MAX_MSG_LENGTH];
            vsnprintf(buffer, sizeof(buffer), format, args);
            va_end(args);
            toast.setContent("%s", buffer);
            ImGui::InsertNotification(toast);
        }

        static void Error(const char* format, ...)
        {
            ImGuiToast toast(ImGuiToastType::Error);
            va_list args;
            va_start(args, format);
            char buffer[NOTIFY_MAX_MSG_LENGTH];
            vsnprintf(buffer, sizeof(buffer), format, args);
            va_end(args);
            toast.setContent("%s", buffer);
            ImGui::InsertNotification(toast);
        }

        static void Error(int dismissMs, const char* format, ...)
        {
            ImGuiToast toast(ImGuiToastType::Error, dismissMs);
            va_list args;
            va_start(args, format);
            char buffer[NOTIFY_MAX_MSG_LENGTH];
            vsnprintf(buffer, sizeof(buffer), format, args);
            va_end(args);
            toast.setContent("%s", buffer);
            ImGui::InsertNotification(toast);
        }

        static void Warning(const char* format, ...)
        {
            ImGuiToast toast(ImGuiToastType::Warning);
            va_list args;
            va_start(args, format);
            char buffer[NOTIFY_MAX_MSG_LENGTH];
            vsnprintf(buffer, sizeof(buffer), format, args);
            va_end(args);
            toast.setContent("%s", buffer);
            ImGui::InsertNotification(toast);
        }

        static void Warning(int dismissMs, const char* format, ...)
        {
            ImGuiToast toast(ImGuiToastType::Warning, dismissMs);
            va_list args;
            va_start(args, format);
            char buffer[NOTIFY_MAX_MSG_LENGTH];
            vsnprintf(buffer, sizeof(buffer), format, args);
            va_end(args);
            toast.setContent("%s", buffer);
            ImGui::InsertNotification(toast);
        }

        static void Info(const char* format, ...)
        {
            ImGuiToast toast(ImGuiToastType::Info);
            va_list args;
            va_start(args, format);
            char buffer[NOTIFY_MAX_MSG_LENGTH];
            vsnprintf(buffer, sizeof(buffer), format, args);
            va_end(args);
            toast.setContent("%s", buffer);
            ImGui::InsertNotification(toast);
        }

        static void Info(int dismissMs, const char* format, ...)
        {
            ImGuiToast toast(ImGuiToastType::Info, dismissMs);
            va_list args;
            va_start(args, format);
            char buffer[NOTIFY_MAX_MSG_LENGTH];
            vsnprintf(buffer, sizeof(buffer), format, args);
            va_end(args);
            toast.setContent("%s", buffer);
            ImGui::InsertNotification(toast);
        }

        static void Custom(ImGuiToastType type, const char* title, const char* content)
        {
            ImGuiToast toast(type);
            toast.setTitle("%s", title);
            toast.setContent("%s", content);
            ImGui::InsertNotification(toast);
        }

        static void WithButton(ImGuiToastType type, const char* content, 
                               const char* buttonLabel, std::function<void()> onClick)
        {
            ImGuiToast toast(type, NOTIFY_DEFAULT_DISMISS, buttonLabel, onClick, content);
            ImGui::InsertNotification(toast);
        }
    };
}
