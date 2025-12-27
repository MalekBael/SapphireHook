#include "PacketRegistration.h"
#include "PacketRegistration.Macros.h"

using namespace PacketDecoding;

void PacketDecoding::RegisterGenericPackets() {
    // Only register opcodes that don't have specific structure decoders
    REGISTER_GENERIC_PACKET(1, false, 0x0069, "RegionInfo");
    REGISTER_GENERIC_PACKET(1, false, 0x0073, "SetPSNId");
    REGISTER_GENERIC_PACKET(1, false, 0x0075, "SetBillingTime");
    REGISTER_GENERIC_PACKET(1, false, 0x00CC, "GetCommonlistResult");
    REGISTER_GENERIC_PACKET(1, false, 0x00CD, "GetCommonlistDetailResult");
    REGISTER_GENERIC_PACKET(1, false, 0x00CE, "SetProfileResult");
    REGISTER_GENERIC_PACKET(1, false, 0x00CF, "GetProfileResult");
    REGISTER_GENERIC_PACKET(1, false, 0x00D0, "GetSearchCommentResult");
    REGISTER_GENERIC_PACKET(1, false, 0x00D1, "GetCharacterNameResult");
    REGISTER_GENERIC_PACKET(1, false, 0x00D2, "ChatChannelResult");
    REGISTER_GENERIC_PACKET(1, false, 0x00D3, "SendSystemMessage");
    REGISTER_GENERIC_PACKET(1, false, 0x00D4, "SendLoginMessage");
    REGISTER_GENERIC_PACKET(1, false, 0x00D5, "UpdateOnlineStatus");
    REGISTER_GENERIC_PACKET(1, false, 0x0145, "Resting");
    REGISTER_GENERIC_PACKET(1, false, 0x0149, "FreeCompany");
    REGISTER_GENERIC_PACKET(1, false, 0x014A, "RecastGroup");
    
    // Quest Tracker UI packets (S→C)
    REGISTER_GENERIC_PACKET(1, false, 0x0150, "SetQuestUIFlag");
    REGISTER_GENERIC_PACKET(1, false, 0x0151, "QuestTrackerData");
    REGISTER_GENERIC_PACKET(1, false, 0x0152, "QuestTrackerEntry");
    REGISTER_GENERIC_PACKET(1, false, 0x0153, "QuestTracker40");
    REGISTER_GENERIC_PACKET(1, false, 0x0154, "QuestTracker60");
    REGISTER_GENERIC_PACKET(1, false, 0x0155, "QuestTracker60Entry");
    REGISTER_GENERIC_PACKET(1, false, 0x0156, "QuestTracker80");
    REGISTER_GENERIC_PACKET(1, false, 0x0157, "QuestTrackerBig");
    REGISTER_GENERIC_PACKET(1, false, 0x0158, "QuestTrackerBigEntry");
    REGISTER_GENERIC_PACKET(1, false, 0x0159, "QuestUIState");
    REGISTER_GENERIC_PACKET(1, false, 0x015A, "QuestFlags");
    REGISTER_GENERIC_PACKET(1, false, 0x015B, "QuestComplete");
    
    REGISTER_GENERIC_PACKET(1, false, 0x0191, "Delete");
    REGISTER_GENERIC_PACKET(1, false, 0x019D, "CreateObject");
    REGISTER_GENERIC_PACKET(1, false, 0x019E, "DeleteObject");
    REGISTER_GENERIC_PACKET(1, false, 0x019F, "PlayerStatusUpdate");
    REGISTER_GENERIC_PACKET(1, true, 0x0069, "SetLanguage");
    REGISTER_GENERIC_PACKET(1, true, 0x0190, "ZoneJump");
    REGISTER_GENERIC_PACKET(1, true, 0x0194, "NewDiscovery");
    REGISTER_GENERIC_PACKET(1, true, 0x0197, "GMCommand");
    REGISTER_GENERIC_PACKET(1, true, 0x0198, "GMCommandName");
    REGISTER_GENERIC_PACKET(1, false, 0x028B, "TitleList");
    REGISTER_GENERIC_PACKET(1, false, 0x028C, "DiscoveryReply");
    REGISTER_GENERIC_PACKET(1, false, 0x02D6, "EnableLogout");
    REGISTER_GENERIC_PACKET(1, false, 0x02DD, "Achievement");
    REGISTER_GENERIC_PACKET(1, false, 0x02DE, "NotifyFindContentStatus");
    REGISTER_GENERIC_PACKET(1, false, 0x02E1, "ResponsePenalties");
    REGISTER_GENERIC_PACKET(1, false, 0x02E4, "UpdateContent");
    REGISTER_GENERIC_PACKET(1, false, 0x0339, "FinishContentMatchToClient");
    REGISTER_GENERIC_PACKET(1, true, 0x01F9, "FindContent");
    REGISTER_GENERIC_PACKET(1, true, 0x01FA, "FindContentAsRoulette");
    REGISTER_GENERIC_PACKET(1, true, 0x01FB, "AcceptContent");
    REGISTER_GENERIC_PACKET(1, true, 0x01FC, "CancelFindContent");
    REGISTER_GENERIC_PACKET(1, true, 0x01FD, "Find5Contents");
    REGISTER_GENERIC_PACKET(1, true, 0x01FE, "FindContentAsRandom");
    REGISTER_GENERIC_PACKET(1, true, 0x02CB, "RequestPenalties");
    REGISTER_GENERIC_PACKET(1, true, 0x02CC, "RequestBonus");
}