#include "ResourceLoader.h"
#include "../Logger/Logger.h"
#include <Windows.h>
#include <vector>
#include <optional>
#include <filesystem>

namespace fs = std::filesystem;

namespace SapphireHook
{

    static std::wstring GetModulePathW()
    {
        wchar_t buf[MAX_PATH] = {};
        if (GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(std::size(buf))) == 0)
            return {};
        return std::wstring(buf);
    }

    std::optional<fs::path> FindResourceFile(const std::string& filename, int upSearchLevels)
    {
        try
        {
            // 1) Current working directory
            fs::path candidate = fs::current_path() / filename;
            if (fs::exists(candidate))
            {
                LogInfo("FindResourceFile: found '" + filename + "' in current working directory: " + candidate.string());
                return fs::absolute(candidate);
            }

            // 2) Executable directory (ffxiv_dx11.exe or host exe)
            std::wstring exePathW = GetModulePathW();
            if (!exePathW.empty())
            {
                fs::path exePath = fs::path(exePathW);
                fs::path exeDir = exePath.parent_path();

                // direct exe dir
                candidate = exeDir / filename;
                if (fs::exists(candidate))
                {
                    LogInfo("FindResourceFile: found '" + filename + "' next to executable: " + candidate.string());
                    return fs::absolute(candidate);
                }

                // 3) walk up parent dirs (useful when resources are in a sibling 'game' folder)
                fs::path parent = exeDir;
                for (int i = 0; i < upSearchLevels; ++i)
                {
                    parent = parent.parent_path();
                    if (parent.empty()) break;
                    candidate = parent / filename;
                    if (fs::exists(candidate))
                    {
                        LogInfo("FindResourceFile: found '" + filename + "' in parent directory: " + candidate.string());
                        return fs::absolute(candidate);
                    }
                    // also check common sibling directories like "game"
                    candidate = parent / "game" / filename;
                    if (fs::exists(candidate))
                    {
                        LogInfo("FindResourceFile: found '" + filename + "' in parent/game: " + candidate.string());
                        return fs::absolute(candidate);
                    }
                }
            }

            LogDebug("FindResourceFile: '" + filename + "' not found by search paths");
            return std::nullopt;
        }
        catch (const std::exception& e)
        {
            LogError("FindResourceFile exception: " + std::string(e.what()));
            return std::nullopt;
        }
    }

} // namespace SapphireHook