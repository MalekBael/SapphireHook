#pragma once
#include <cstdint>

namespace PacketStructures::Client::Lobby {

    struct FFXIVIpcSync {
        uint32_t clientTimeValue;
    };

    struct FFXIVIpcLogin {
        uint32_t requestNumber;
        uint32_t clientTimeValue;
        uint16_t clientLangCode;
        uint16_t lobbyLoginMode;
        uint16_t platformType;
        uint16_t platformMode;
        char sessionId[64];
        char version[128];
    };

    struct FFXIVIpcServiceLogin {
        uint32_t requestNumber;
        uint32_t clientTimeValue;
        uint8_t accountIndex;
        uint8_t loginParam1 : 4;
        uint8_t protoVersion : 4;
        uint16_t loginParam2;
        uint64_t accountId;
    };

    struct FFXIVIpcGameLogin {
        uint32_t requestNumber;
        uint32_t clientTimeValue;
        uint64_t characterId;
        uint64_t playerId;
        uint8_t characterIndex;
        uint8_t operation;
        uint16_t worldId;
    };

    struct FFXIVIpcLoginEx {
        uint32_t requestNumber;
        uint32_t clientTimeValue;
        uint16_t clientLangCode;
        uint16_t lobbyLoginMode;
        uint16_t platformType;
        uint16_t platformMode;
        char sessionId[64];
        char version[128];
        char platformData[32];
    };

    struct FFXIVIpcShandaLogin {
        uint32_t requestNumber;
        uint32_t clientTimeValue;
        uint16_t clientLangCode;
        uint16_t lobbyLoginMode;
        uint16_t platformType;
        uint16_t platformMode;
        char sessionId[384];
        char version[128];
        char platformData[32];
    };

    enum CharacterOperation : uint8_t {
        CHARAOPE_UNKNOWN = 0x0,
        CHARAOPE_RESERVENAME = 0x1,
        CHARAOPE_MAKECHARA = 0x2,
        CHARAOPE_RENAMECHARA = 0x3,
        CHARAOPE_DELETECHARA = 0x4,
        CHARAOPE_MOVECHARA = 0x5,
        CHARAOPE_RENAMERETAINER = 0x6,
        CHARAOPE_REMAKECHARA = 0x7,
    };

    struct FFXIVIpcCharaMake {
        uint32_t requestNumber;
        uint32_t clientTimeValue;
        uint64_t characterId;
        uint64_t playerId;
        uint8_t characterIndex;
        CharacterOperation operation;
        uint16_t worldId;
        char chracterName[32];
        char charaMakeData[400];
        uint64_t retainerId;
        uint8_t retainerSlotId;
        uint8_t param1;
        uint16_t param2;
    };

    struct FFXIVIpcCharaOperation {
        uint32_t requestNumber;
        uint32_t clientTimeValue;
        uint64_t characterId;
        uint64_t playerId;
        uint8_t characterIndex;
        uint8_t operation;
        uint16_t worldId;
        char chracterName[32];
        uint64_t retainerId;
        uint8_t retainerSlotId;
        uint8_t param1;
        uint16_t param2;
    };

    struct FFXIVIpcCharaRename {
        uint32_t requestNumber;
        uint32_t clientTimeValue;
        uint64_t characterId;
        uint64_t playerId;
        uint8_t characterIndex;
        uint8_t operation;
        uint16_t worldId;
        char chracterName[32];
    };

    struct FFXIVIpcCharaDelete {
        uint32_t requestNumber;
        uint32_t clientTimeValue;
        uint64_t characterId;
        uint8_t characterIndex;
        uint8_t padding1;
        uint16_t padding2;
        char chracterName[32];
    };

    struct FFXIVIpcCharaUpdateRetainerSlots {
        uint32_t requestNumber;
        uint32_t clientTimeValue;
        uint32_t param0;
        uint8_t param1;
        uint8_t padding1;
        uint16_t padding2;
        uint64_t characterIdArray[8];
        uint8_t flags[96];
    };

    struct FFXIVIpcDebugNull {
        uint32_t dummyArgument;
    };

    struct FFXIVIpcDebugLogin {
        uint32_t requestNumber;
        uint32_t ticketNumber;
        char ticketString[32];
    };

    struct FFXIVIpcDebugLogin2 {
        uint32_t requestNumber;
        uint32_t ticketNumber;
        char ticketString[32];
        char zoneLoginData[64];
        char zoneName[32];
    };

} // namespace PacketStructures::Client::Lobby