#include "PacketRegistration.h"
#include "PacketRegistration.Macros.h"

#include "../ProtocolHandlers/Chat/ServerChatDef.h"

using namespace PacketDecoding;
using namespace PacketStructures;

void PacketDecoding::RegisterChatPackets() {
    // TRUE chat server packets (connection type 2) - based on ServerChatIpcType
    using namespace PacketStructures::Server::Chat;

    // Note: Most FFXIV "chat" goes through zone connection (type 1), not chat server (type 2)

    REGISTER_PACKET(2, false, 0x0064, FFXIVChatFrom,  // ChatFrom
        FIELD("Type", FieldToString(pkt->type)),
        FIELD("FromCharacterId", FormatHex(pkt->fromCharacterID)),
        FIELD("FromName", FormatString(pkt->fromName, 32)),
        FIELD("Message", FormatString(pkt->message, std::min<size_t>(200, sizeof(pkt->message))))
    );

    REGISTER_PACKET(2, false, 0x0066, FFXIVIpcTellNotFound,  // TellNotFound
        FIELD("ToName", FormatString(pkt->toName, 32))
    );

    REGISTER_PACKET(2, false, 0x0067, FFXIVRecvBusyStatus,  // RecvBusyStatus
        FIELD("ToName", FormatString(pkt->toName, 32))
    );

    REGISTER_PACKET(2, false, 0x006A, FFXIVRecvFinderStatus,  // RecvFinderStatus
        FIELD("ToName", FormatString(pkt->toName, 32))
    );
}