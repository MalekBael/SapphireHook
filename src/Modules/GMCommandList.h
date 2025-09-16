#pragma once
#include <array>
#include <cstddef>

namespace GMCommands
{
    // Extend this enum as you add more GM commands
    enum Id : int
    {
        Invisible = 13,
        Wireframe = 550,
        Teri_Info = 605,
        Quest_Accept = 300,
    };

    struct Entry
    {
        int id;
        const char* name;          // command path/name (e.g., "quest accept")
        const char* argsHint;      // argument hint only (e.g., "<questid> <player>")
        const char* description;   // short help text
    };

    // Single source of truth for the dropdown
    inline constexpr std::array<Entry, 4> kList = {
        Entry{ Invisible, "invisible", "[targetId]", "Toggle invisibility. Optional target actor id." },
        Entry{ Wireframe, "wireframe", "[0|1]", "Enable/disable wireframe rendering (1=on, 0=off)." },
        Entry{ Teri_Info, "teri_info", "", "Dump teri/terrain related info (no args)." },
        Entry{ Quest_Accept, "quest_accept", "[questId]", " Accepts quest." },
    };
}



