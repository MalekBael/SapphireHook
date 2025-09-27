#include "PacketRegistration.h"
#include "PacketDecoder.h"

// Include the packet structures that need field declarations
#include "../ProtocolHandlers/Zone/ServerZoneDef.h"

// Moved to split compilation units:
// - PacketRegistration.Zone.cpp
// - PacketRegistration.Chat.cpp
// - PacketRegistration.Lobby.cpp
// - PacketRegistration.Generic.cpp
// - PacketRegistration.Init.cpp

namespace PacketDecoding {
    thread_local PacketOverlayContext g_tlsOverlayCtx;
    PacketOverlayContext& GetOverlayContext() { return g_tlsOverlayCtx; }
}