#include "PacketRegistration.h"
#include "PacketRegistration.Macros.h"

#include "../ProtocolHandlers/Lobby/ServerLobbyDef.h"
#include "../ProtocolHandlers/Lobby/ClientLobbyDef.h"

using namespace PacketDecoding;
using namespace PacketStructures;

void PacketDecoding::RegisterLobbyPackets() {
    using namespace PacketStructures::Client::Lobby;
    using namespace PacketStructures::Server::Lobby;

    // Client lobby packets (connection type 3)
    REGISTER_PACKET(3, true, 0x0002, PacketStructures::Client::Lobby::FFXIVIpcLogin,  // Login
        FIELD("RequestNumber", FieldToString(pkt->requestNumber)),
        FIELD("ClientLangCode", FieldToString(pkt->clientLangCode)),
        FIELD("PlatformType", FieldToString(pkt->platformType)),
        FIELD("Version", FormatString(pkt->version, sizeof(pkt->version)))
    );

    // Server lobby packets (connection type 3)
    REGISTER_PACKET(3, false, 0x000C, PacketStructures::Server::Lobby::FFXIVIpcLoginReply,  // LoginReply
        FIELD("RequestNumber", FieldToString(pkt->requestNumber)),
        FIELD("AccountCount", FieldToString(pkt->activeAccountCount)),
        FIELD("RegionCode", FieldToString(pkt->regionCode))
    );
}