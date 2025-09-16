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
    };

    struct Entry
    {
        int id;
        const char* name;
    };

    // Single source of truth for the dropdown
    inline constexpr std::array<Entry, 3> kList = {
        Entry{ Invisible, "invisible" },
        Entry{ Wireframe, "wireframe" },
        Entry{ Teri_Info, "teri_info" },
    };
}



