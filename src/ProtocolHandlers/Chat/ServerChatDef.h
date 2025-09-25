#pragma once
#include <cstdint>

namespace PacketStructures::Server::Chat {

    struct FFXIVChatFrom {
        uint64_t fromCharacterID;
        uint8_t type;
        char fromName[32];
        char message[1024];
    };

    struct FFXIVChatToChannel {
        uint64_t channelID;
        uint64_t speakerCharacterID;
        uint32_t speakerEntityID;
        uint8_t type;
        char speakerName[32];
        char message[1024];
    };

    struct FFXIVJoinChannelResult {
        uint64_t channelID;
        uint64_t characterID;
        uint8_t result;
    };

    struct FFXIVRecvBusyStatus {
        char toName[32];
    };

    struct FFXIVRecvFinderStatus {
        char toName[32];
    };

    struct FFXIVIpcTellNotFound {
        char toName[32];
    };

} // namespace PacketStructures::Server::Chat