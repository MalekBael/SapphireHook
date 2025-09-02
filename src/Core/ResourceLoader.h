#pragma once
#include <optional>
#include <string>
#include <filesystem>

namespace SapphireHook
{
    // Search common locations for a resource file and return the found absolute path.
    // Search order:
    // 1) current working directory
    // 2) executable directory (ffxiv_dx11.exe when present)  
    // 3) parent directories of executable (walk up N levels)
    std::optional<std::filesystem::path> FindResourceFile(const std::string& filename, int upSearchLevels = 3);
}