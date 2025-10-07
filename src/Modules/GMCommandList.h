#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

namespace GMCommands
{
    // GM Command levels/types
    enum class CommandLevel : int
    {
        GM1 = 1,
        GM2 = 2,
        Unknown = 0  // For discovery purposes
    };

    // Separate ID spaces for GM1 and GM2 (IDs can overlap across levels)
    enum GM1 : int
    {
        //inv = 0, doesnt work currently
        //orchestrion = 0, doesnt work currently
        lvl = 1,
        race = 2,
        tribe = 3,
        sex = 4,
        time = 5,
        weather = 6,
        call = 7,
        inspect = 8,
        speed = 9,
        Invisible = 13,
        kill = 14,
        // raise is GM2
        icon = 18,
        hp = 100,
        mp = 101,
        tp = 102,
        gp = 103, //might be wrong, the command seems to set HP
        exp = 104,
		inv = 106, //invincibility toggle
		orchestrion = 116, //orchestrion unlock
        item = 200,
        gil = 201,
        collect = 202, 
        quest_accept = 300,
        quest_cancel = 301,
        quest_complete = 302,
        quest_incomplete = 303,
        quest_sequence = 304,
        gc = 340,
        gcrank = 341,
        aetheryte = 350,
        Wireframe = 550,
        teri = 600,
        kick = 604,
        Teri_Info = 605, // GM1: overlaps GM2::player_search
        jump = 606,
        getpos = 999, //need to discover id
    };

    enum GM2 : int
    {
        raise = 16,            // GM2: raise (overlaps GM1 space numerically)
        player_search = 605,   // GM2: player search (overlaps GM1::Teri_Info)
    };

    struct Entry
    {
        int id;                // numeric id within GM1/GM2 space
        const char* name;      // command path/name (e.g., "quest accept")
        const char* argsHint;  // argument hint only (e.g., "<questid> <player>")
        const char* description; // short help text
        CommandLevel level;    // GM1 or GM2 command level
    };

    // Single source of truth for the dropdown - with GM levels
    inline constexpr std::array<Entry, 35> kList = {
        Entry{ GM1::lvl, "lvl", "<level>", "Set character level.", CommandLevel::GM1 },
        Entry{ GM1::race, "race", "<raceId>", "Change character race.", CommandLevel::GM1 },
        Entry{ GM1::tribe, "tribe", "<tribeId>", "Change character tribe.", CommandLevel::GM1 },
        Entry{ GM1::sex, "sex", "<0|1>", "Change character gender (0=male, 1=female).", CommandLevel::GM1 },
        Entry{ GM1::time, "time", "<hour>", "Set time of day.", CommandLevel::GM1 },
        Entry{ GM1::weather, "weather", "<weatherId>", "Change weather conditions.", CommandLevel::GM1 },
        Entry{ GM1::call, "call", "<targetId>", "Call/summon target.", CommandLevel::GM1 },
        Entry{ GM1::inspect, "inspect", "<targetId>", "Inspect target character.", CommandLevel::GM1 },
        Entry{ GM1::speed, "speed", "<multiplier>", "Set movement speed multiplier.", CommandLevel::GM1 },
        Entry{ GM1::Invisible, "invisible", "[targetId]", "Toggle invisibility. Optional target actor id.", CommandLevel::GM1 },
        Entry{ GM1::kill, "kill", "[targetId]", "Kill target or self.", CommandLevel::GM1 },
        Entry{ GM1::icon, "icon", "<iconId>", "Set character icon/status.", CommandLevel::GM1 },
        Entry{ GM1::hp, "hp", "<amount>", "Set HP amount.", CommandLevel::GM1 },
        Entry{ GM1::mp, "mp", "<amount>", "Set MP amount.", CommandLevel::GM1 },
        Entry{ GM1::tp, "tp", "<amount>", "Set TP amount.", CommandLevel::GM1 },
        Entry{ GM1::gp, "gp", "<amount>", "Set GP amount (affects HP for some reason).", CommandLevel::GM1 },
        Entry{ GM1::exp, "exp", "<amount>", "Set experience points.", CommandLevel::GM1 },
        Entry{ GM1::item, "item", "<itemId> [quantity]", "Give item to character.", CommandLevel::GM1 },
        Entry{ GM1::gil, "gil", "<amount>", "Set gil amount.", CommandLevel::GM1 },
        Entry{ GM1::collect, "collect", "[quantity]", "Remove gil amount - must target self.", CommandLevel::GM1 },
        Entry{ GM1::quest_accept, "quest accept", "<questId>", "Accept specified quest.", CommandLevel::GM1 },
        Entry{ GM1::quest_cancel, "quest cancel", "<questId>", "Cancel specified quest.", CommandLevel::GM1 },
        Entry{ GM1::quest_complete, "quest complete", "<questId>", "Complete specified quest.", CommandLevel::GM1 },
        Entry{ GM1::quest_incomplete, "quest incomplete", "<questId>", "Mark quest as incomplete.", CommandLevel::GM1 },
        Entry{ GM1::quest_sequence, "quest sequence", "<questId> <sequence>", "Set quest sequence step.", CommandLevel::GM1 },
        Entry{ GM1::gc, "gc", "<companyId>", "Set Grand Company affiliation.", CommandLevel::GM1 },
        Entry{ GM1::gcrank, "gcrank", "<rank>", "Set Grand Company rank.", CommandLevel::GM1 },
        Entry{ GM1::aetheryte, "aetheryte", "<aetheryteId>", "Unlock aetheryte.", CommandLevel::GM1 },
        Entry{ GM1::Wireframe, "wireframe", "[0|1]", "Enable/disable wireframe rendering (1=on, 0=off).", CommandLevel::GM1 },
        Entry{ GM1::teri, "teri", "<territoryId>", "Change territory/zone.", CommandLevel::GM1 },
        Entry{ GM1::kick, "kick", "<playerId>", "Kick player from server.", CommandLevel::GM1 },
        Entry{ GM1::Teri_Info, "teri_info", "", "Dump teri/terrain related info (no args).", CommandLevel::GM1 },
        Entry{ GM1::jump, "jump", "<x> <y> <z>", "Jump to coordinates.", CommandLevel::GM1 },
        Entry{ GM1::getpos, "getpos", "", "Show coordinates.", CommandLevel::GM1 },

		// These are newly discovered. need to figure out syntax and effects.
        Entry{ GM2::player_search, "player_search", "", "Open/trigger player search (GM2).", CommandLevel::GM2 },
        //[error] You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '' at line 1
    };

    // Helper functions to determine command type
    inline CommandLevel GetCommandLevel(int commandId)
    {
        // NOTE: ambiguous when IDs overlap; prefer using the Entry directly when possible.
        for (const auto& entry : kList)
        {
            if (entry.id == commandId)
                return entry.level;
        }
        return CommandLevel::Unknown;
    }

    // Get appropriate IPC opcode for command level
    inline uint16_t GetIPCOpcode(CommandLevel level)
    {
        switch (level)
        {
            case CommandLevel::GM1:
                return 0x0197;  // Current GM1 opcode
            case CommandLevel::GM2:
                return 0x0198;  // Current GM2 opcode (verify on your build)
            default:
                return 0x0197;  // Default to GM1
        }
    }
}