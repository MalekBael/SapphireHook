#pragma once
/**
 * @file NotificationSystem.h
 * @brief Simple wrapper for ImGuiNotify toast notifications.
 * 
 * Usage:
 *   SapphireHook::Notify::Success("Hook installed successfully!");
 *   SapphireHook::Notify::Error("Failed to initialize: %s", reason.c_str());
 *   SapphireHook::Notify::Warning("Memory pattern not found");
 *   SapphireHook::Notify::Info("Loaded %d packets", count);
 * 
 * All notifications auto-dismiss after 3 seconds by default.
 * For custom timing: SapphireHook::Notify::Success(5000, "Message with 5s timeout");
 */

#include "../../vendor/imgui/ImGuiNotify.hpp"
#include <cstdarg>

namespace SapphireHook
{
    /**
     * @brief Global toast notification helper functions.
     * 
     * Provides simple static methods to show toast notifications from anywhere.
     * The overlay must be initialized for notifications to display.
     */
    class Notify
    {
    public:
        /**
         * @brief Show a success toast (green icon).
         * @param format Printf-style format string.
         */
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

        /**
         * @brief Show a success toast with custom dismiss time.
         * @param dismissMs Time in milliseconds before auto-dismiss.
         * @param format Printf-style format string.
         */
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

        /**
         * @brief Show an error toast (red icon).
         * @param format Printf-style format string.
         */
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

        /**
         * @brief Show an error toast with custom dismiss time.
         * @param dismissMs Time in milliseconds before auto-dismiss.
         * @param format Printf-style format string.
         */
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

        /**
         * @brief Show a warning toast (yellow icon).
         * @param format Printf-style format string.
         */
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

        /**
         * @brief Show a warning toast with custom dismiss time.
         * @param dismissMs Time in milliseconds before auto-dismiss.
         * @param format Printf-style format string.
         */
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

        /**
         * @brief Show an info toast (blue icon).
         * @param format Printf-style format string.
         */
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

        /**
         * @brief Show an info toast with custom dismiss time.
         * @param dismissMs Time in milliseconds before auto-dismiss.
         * @param format Printf-style format string.
         */
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

        /**
         * @brief Show a toast with custom title.
         * @param type Toast type (Success, Error, Warning, Info).
         * @param title Custom title text.
         * @param content Message content.
         */
        static void Custom(ImGuiToastType type, const char* title, const char* content)
        {
            ImGuiToast toast(type);
            toast.setTitle("%s", title);
            toast.setContent("%s", content);
            ImGui::InsertNotification(toast);
        }

        /**
         * @brief Show a toast with an action button.
         * @param type Toast type.
         * @param content Message content.
         * @param buttonLabel Label for the action button.
         * @param onClick Callback when button is clicked.
         */
        static void WithButton(ImGuiToastType type, const char* content, 
                               const char* buttonLabel, std::function<void()> onClick)
        {
            ImGuiToast toast(type, NOTIFY_DEFAULT_DISMISS, buttonLabel, onClick, content);
            ImGui::InsertNotification(toast);
        }
    };
}
