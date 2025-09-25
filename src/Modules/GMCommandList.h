#pragma once
#include <array>
#include <cstddef>

namespace GMCommands
{
    // GM Command levels/types
    enum class CommandLevel : int
    {
        GM1 = 1,
        GM2 = 2,
        Unknown = 0  // For discovery purposes
    };

    // Extend this enum as you add more GM commands
    enum Id : int
    {
        //collect = 0, doesnt work currently
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
        raise = 16,
        icon = 18,
        hp = 100,
        mp = 101,
        tp = 102,
        gp = 103, //might be wrong, the command seems to set HP
        exp = 104,
        item = 200,
        gil = 201,
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
        Teri_Info = 605,
        jump = 606,
    };

    struct Entry
    {
        int id;
        const char* name;          // command path/name (e.g., "quest accept")
        const char* argsHint;      // argument hint only (e.g., "<questid> <player>")
        const char* description;   // short help text
        CommandLevel level;        // GM1 or GM2 command level
    };

    // Single source of truth for the dropdown - with GM levels
    inline constexpr std::array<Entry, 33> kList = {
        Entry{ lvl, "lvl", "<level>", "Set character level.", CommandLevel::GM1 },
        Entry{ race, "race", "<raceId>", "Change character race.", CommandLevel::GM1 },
        Entry{ tribe, "tribe", "<tribeId>", "Change character tribe.", CommandLevel::GM1 },
        Entry{ sex, "sex", "<0|1>", "Change character gender (0=male, 1=female).", CommandLevel::GM1 },
        Entry{ time, "time", "<hour>", "Set time of day.", CommandLevel::GM1 },
        Entry{ weather, "weather", "<weatherId>", "Change weather conditions.", CommandLevel::GM1 },
        Entry{ call, "call", "<targetId>", "Call/summon target.", CommandLevel::GM1 },
        Entry{ inspect, "inspect", "<targetId>", "Inspect target character.", CommandLevel::GM1 },
        Entry{ speed, "speed", "<multiplier>", "Set movement speed multiplier.", CommandLevel::GM1 },
        Entry{ Invisible, "invisible", "[targetId]", "Toggle invisibility. Optional target actor id.", CommandLevel::GM1 },
        Entry{ kill, "kill", "[targetId]", "Kill target or self.", CommandLevel::GM1 },
        Entry{ raise, "raise", "[targetId]", "Raise/resurrect target or self.", CommandLevel::GM2 },  // This is GM2!
        Entry{ icon, "icon", "<iconId>", "Set character icon/status.", CommandLevel::GM1 },
        Entry{ hp, "hp", "<amount>", "Set HP amount.", CommandLevel::GM1 },
        Entry{ mp, "mp", "<amount>", "Set MP amount.", CommandLevel::GM1 },
        Entry{ tp, "tp", "<amount>", "Set TP amount.", CommandLevel::GM1 },
        Entry{ gp, "gp", "<amount>", "Set GP amount (affects HP for some reason).", CommandLevel::GM1 },
        Entry{ exp, "exp", "<amount>", "Set experience points.", CommandLevel::GM1 },
        Entry{ item, "item", "<itemId> [quantity]", "Give item to character.", CommandLevel::GM1 },
        Entry{ gil, "gil", "<amount>", "Set gil amount.", CommandLevel::GM1 },
        Entry{ quest_accept, "quest accept", "<questId>", "Accept specified quest.", CommandLevel::GM1 },
        Entry{ quest_cancel, "quest cancel", "<questId>", "Cancel specified quest.", CommandLevel::GM1 },
        Entry{ quest_complete, "quest complete", "<questId>", "Complete specified quest.", CommandLevel::GM1 },
        Entry{ quest_incomplete, "quest incomplete", "<questId>", "Mark quest as incomplete.", CommandLevel::GM1 },
        Entry{ quest_sequence, "quest sequence", "<questId> <sequence>", "Set quest sequence step.", CommandLevel::GM1 },
        Entry{ gc, "gc", "<companyId>", "Set Grand Company affiliation.", CommandLevel::GM1 },
        Entry{ gcrank, "gcrank", "<rank>", "Set Grand Company rank.", CommandLevel::GM1 },
        Entry{ aetheryte, "aetheryte", "<aetheryteId>", "Unlock aetheryte.", CommandLevel::GM1 },
        Entry{ Wireframe, "wireframe", "[0|1]", "Enable/disable wireframe rendering (1=on, 0=off).", CommandLevel::GM1 },
        Entry{ teri, "teri", "<territoryId>", "Change territory/zone.", CommandLevel::GM1 },
        Entry{ kick, "kick", "<playerId>", "Kick player from server.", CommandLevel::GM1 },
        Entry{ Teri_Info, "teri_info", "", "Dump teri/terrain related info (no args).", CommandLevel::GM1 },
        Entry{ jump, "jump", "<x> <y> <z>", "Jump to coordinates.", CommandLevel::GM1 }
    };

    // Helper functions to determine command type
    inline CommandLevel GetCommandLevel(int commandId)
    {
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
                return 0x0198;  // Likely GM2 opcode (you'll need to verify this)
            default:
                return 0x0197;  // Default to GM1
        }
    }
}