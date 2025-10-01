#pragma once
#include <cstdint>
#include "../ProtocolHandlers/CommonTypes.h"
#include "../Network/PacketRegistration.Macros.h"

#ifdef __INTELLISENSE__
#  ifdef DECLARE_PACKET_FIELDS
#    undef DECLARE_PACKET_FIELDS
#  endif
#  define DECLARE_PACKET_FIELDS(PacketType, ...)
#  ifdef STRUCT_FIELD
#    undef STRUCT_FIELD
#  endif
#  define STRUCT_FIELD(PacketType, member)
#endif

namespace PacketStructures::Client::Zone {

    struct FFXIVIpcGmCommand {
        uint32_t Id;
        uint32_t Arg0;
        uint32_t Arg1;
        uint32_t Arg2;
        uint32_t Arg3;
        uint64_t Target;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGmCommand,
        STRUCT_FIELD(FFXIVIpcGmCommand, Id),
        STRUCT_FIELD(FFXIVIpcGmCommand, Arg0),
        STRUCT_FIELD(FFXIVIpcGmCommand, Arg1),
        STRUCT_FIELD(FFXIVIpcGmCommand, Arg2),
        STRUCT_FIELD(FFXIVIpcGmCommand, Arg3),
        STRUCT_FIELD(FFXIVIpcGmCommand, Target)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGmCommandName {
        uint32_t Id;
        uint32_t Arg0;
        uint32_t Arg1;
        uint32_t Arg2;
        uint32_t Arg3;
        char Name[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGmCommandName,
        STRUCT_FIELD(FFXIVIpcGmCommandName, Id),
        STRUCT_FIELD(FFXIVIpcGmCommandName, Arg0),
        STRUCT_FIELD(FFXIVIpcGmCommandName, Arg1),
        STRUCT_FIELD(FFXIVIpcGmCommandName, Arg2),
        STRUCT_FIELD(FFXIVIpcGmCommandName, Arg3),
        STRUCT_FIELD(FFXIVIpcGmCommandName, Name)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcClientTrigger {
        uint32_t Id;
        uint32_t Arg0;
        uint32_t Arg1;
        uint32_t Arg2;
        uint32_t Arg3;
        uint64_t Target;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcClientTrigger,
        STRUCT_FIELD(FFXIVIpcClientTrigger, Id),
        STRUCT_FIELD(FFXIVIpcClientTrigger, Arg0),
        STRUCT_FIELD(FFXIVIpcClientTrigger, Arg1),
        STRUCT_FIELD(FFXIVIpcClientTrigger, Arg2),
        STRUCT_FIELD(FFXIVIpcClientTrigger, Arg3),
        STRUCT_FIELD(FFXIVIpcClientTrigger, Target)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcUpdatePosition {
        float dir;
        float dirBeforeSlip;
        uint8_t flag;
        uint8_t flag2;
        uint8_t flag_unshared;
        uint8_t __padding1;
        FFXIVARR_POSITION3 pos;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcUpdatePosition,
        STRUCT_FIELD(FFXIVIpcUpdatePosition, dir),
        STRUCT_FIELD(FFXIVIpcUpdatePosition, dirBeforeSlip),
        STRUCT_FIELD(FFXIVIpcUpdatePosition, flag),
        STRUCT_FIELD(FFXIVIpcUpdatePosition, flag2),
        STRUCT_FIELD(FFXIVIpcUpdatePosition, flag_unshared),
        STRUCT_FIELD(FFXIVIpcUpdatePosition, pos)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcUpdatePositionInstance {
        float dir;
        float predictedDir;
        float dirBeforeSlip;
        uint8_t flag;
        uint8_t flag2;
        uint8_t flag_unshared;
        uint8_t __padding1;
        FFXIVARR_POSITION3 pos;
        FFXIVARR_POSITION3 predictedPos;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcUpdatePositionInstance,
        STRUCT_FIELD(FFXIVIpcUpdatePositionInstance, dir),
        STRUCT_FIELD(FFXIVIpcUpdatePositionInstance, predictedDir),
        STRUCT_FIELD(FFXIVIpcUpdatePositionInstance, dirBeforeSlip),
        STRUCT_FIELD(FFXIVIpcUpdatePositionInstance, flag),
        STRUCT_FIELD(FFXIVIpcUpdatePositionInstance, flag2),
        STRUCT_FIELD(FFXIVIpcUpdatePositionInstance, flag_unshared),
        STRUCT_FIELD(FFXIVIpcUpdatePositionInstance, pos),
        STRUCT_FIELD(FFXIVIpcUpdatePositionInstance, predictedPos)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcActionRequest {
        uint8_t ExecProc;
        uint8_t ActionKind;
        uint8_t __padding1;
        uint8_t __padding2;
        uint32_t ActionKey;
        uint32_t RequestId;
        uint16_t Dir;
        uint16_t DirTarget;
        uint64_t Target;
        uint32_t Arg;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcActionRequest,
        STRUCT_FIELD(FFXIVIpcActionRequest, ExecProc),
        STRUCT_FIELD(FFXIVIpcActionRequest, ActionKind),
        STRUCT_FIELD(FFXIVIpcActionRequest, ActionKey),
        STRUCT_FIELD(FFXIVIpcActionRequest, RequestId),
        STRUCT_FIELD(FFXIVIpcActionRequest, Dir),
        STRUCT_FIELD(FFXIVIpcActionRequest, DirTarget),
        STRUCT_FIELD(FFXIVIpcActionRequest, Target),
        STRUCT_FIELD(FFXIVIpcActionRequest, Arg)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcSelectGroundActionRequest {
        uint8_t ExecProc;
        uint8_t ActionKind;
        uint8_t __padding1;
        uint8_t __padding2;
        uint32_t ActionKey;
        uint32_t RequestId;
        uint16_t Dir;
        uint16_t DirTarget;
        FFXIVARR_POSITION3 Pos;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcSelectGroundActionRequest,
        STRUCT_FIELD(FFXIVIpcSelectGroundActionRequest, ExecProc),
        STRUCT_FIELD(FFXIVIpcSelectGroundActionRequest, ActionKind),
        STRUCT_FIELD(FFXIVIpcSelectGroundActionRequest, ActionKey),
        STRUCT_FIELD(FFXIVIpcSelectGroundActionRequest, RequestId),
        STRUCT_FIELD(FFXIVIpcSelectGroundActionRequest, Dir),
        STRUCT_FIELD(FFXIVIpcSelectGroundActionRequest, DirTarget),
        STRUCT_FIELD(FFXIVIpcSelectGroundActionRequest, Pos)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcZoneJump {
        uint32_t ExitBox;
        float X;
        float Y;
        float Z;
        int32_t LandSetIndex;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcZoneJump,
        STRUCT_FIELD(FFXIVIpcZoneJump, ExitBox),
        STRUCT_FIELD(FFXIVIpcZoneJump, X),
        STRUCT_FIELD(FFXIVIpcZoneJump, Y),
        STRUCT_FIELD(FFXIVIpcZoneJump, Z),
        STRUCT_FIELD(FFXIVIpcZoneJump, LandSetIndex)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcNewDiscovery {
        uint32_t LayoutId;
        float PositionX;
        float PositionY;
        float PositionZ;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcNewDiscovery,
        STRUCT_FIELD(FFXIVIpcNewDiscovery, LayoutId),
        STRUCT_FIELD(FFXIVIpcNewDiscovery, PositionX),
        STRUCT_FIELD(FFXIVIpcNewDiscovery, PositionY),
        STRUCT_FIELD(FFXIVIpcNewDiscovery, PositionZ)
    );
#endif // DECLARE_PACKET_FIELDS

    template<uint32_t Size>
    struct FFXIVIpcEventHandlerReturnN {
        uint32_t handlerId;
        uint16_t sceneId;
        uint8_t errorCode;
        uint8_t numOfResults;
        uint32_t results[Size];
    };

    template<uint32_t Size>
    struct FFXIVIpcYieldEventSceneN {
        uint32_t handlerId;
        uint16_t sceneId;
        uint8_t yieldId;
        uint8_t numOfResults;
        uint32_t results[Size];
    };

    template<uint32_t Size>
    struct YieldEventSceneStringN {
        uint32_t handlerId;
        uint16_t sceneId;
        uint8_t yieldId;
        char result[Size];
    };

    struct FFXIVIpcYieldEventSceneIntAndString {
        uint32_t handlerId;
        uint16_t sceneId;
        uint8_t yieldId;
        uint8_t __padding1;
        uint64_t integer;
        char str[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcYieldEventSceneIntAndString,
        STRUCT_FIELD(FFXIVIpcYieldEventSceneIntAndString, handlerId),
        STRUCT_FIELD(FFXIVIpcYieldEventSceneIntAndString, sceneId),
        STRUCT_FIELD(FFXIVIpcYieldEventSceneIntAndString, yieldId),
        STRUCT_FIELD(FFXIVIpcYieldEventSceneIntAndString, integer),
        STRUCT_FIELD(FFXIVIpcYieldEventSceneIntAndString, str)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcEnterTerritoryHandler {
        uint32_t eventId;
        uint16_t param1;
        uint16_t param2;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEnterTerritoryHandler,
        STRUCT_FIELD(FFXIVIpcEnterTerritoryHandler, eventId),
        STRUCT_FIELD(FFXIVIpcEnterTerritoryHandler, param1),
        STRUCT_FIELD(FFXIVIpcEnterTerritoryHandler, param2)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcEventHandlerOutsideRange {
        uint32_t param1;
        uint32_t eventId;
        FFXIVARR_POSITION3 position;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEventHandlerOutsideRange,
        STRUCT_FIELD(FFXIVIpcEventHandlerOutsideRange, param1),
        STRUCT_FIELD(FFXIVIpcEventHandlerOutsideRange, eventId),
        STRUCT_FIELD(FFXIVIpcEventHandlerOutsideRange, position)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcEventHandlerWithinRange {
        uint32_t param1;
        uint32_t eventId;
        FFXIVARR_POSITION3 position;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEventHandlerWithinRange,
        STRUCT_FIELD(FFXIVIpcEventHandlerWithinRange, param1),
        STRUCT_FIELD(FFXIVIpcEventHandlerWithinRange, eventId),
        STRUCT_FIELD(FFXIVIpcEventHandlerWithinRange, position)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcEventHandlerEmote {
        uint64_t actorId;
        uint32_t eventId;
        uint16_t emoteId;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEventHandlerEmote,
        STRUCT_FIELD(FFXIVIpcEventHandlerEmote, actorId),
        STRUCT_FIELD(FFXIVIpcEventHandlerEmote, eventId),
        STRUCT_FIELD(FFXIVIpcEventHandlerEmote, emoteId)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcEventHandlerTalk {
        uint64_t actorId;
        uint32_t eventId;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEventHandlerTalk,
        STRUCT_FIELD(FFXIVIpcEventHandlerTalk, actorId),
        STRUCT_FIELD(FFXIVIpcEventHandlerTalk, eventId)
    );
#endif // DECLARE_PACKET_FIELDS

    struct ZoneProtoUpClientPos {
        uint32_t originEntityId;
        float pos[3];
        float dir;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoUpClientPos,
        STRUCT_FIELD(ZoneProtoUpClientPos, originEntityId),
        STRUCT_FIELD(ZoneProtoUpClientPos, pos),
        STRUCT_FIELD(ZoneProtoUpClientPos, dir)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcPingHandler {
        uint32_t clientTimeValue;
        ZoneProtoUpClientPos position;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcPingHandler,
        STRUCT_FIELD(FFXIVIpcPingHandler, clientTimeValue),
        STRUCT_FIELD(FFXIVIpcPingHandler, position)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcLoginHandler {
        uint32_t clientTimeValue;
        uint32_t arg2;
        uint64_t arg3;
        uint64_t arg4;
        int32_t contentFinderStatus;
        int32_t contentFinderFlags;
        char name[32];
        char arg1[48];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcLoginHandler,
        STRUCT_FIELD(FFXIVIpcLoginHandler, clientTimeValue),
        STRUCT_FIELD(FFXIVIpcLoginHandler, arg2),
        STRUCT_FIELD(FFXIVIpcLoginHandler, arg3),
        STRUCT_FIELD(FFXIVIpcLoginHandler, arg4),
        STRUCT_FIELD(FFXIVIpcLoginHandler, contentFinderStatus),
        STRUCT_FIELD(FFXIVIpcLoginHandler, contentFinderFlags),
        STRUCT_FIELD(FFXIVIpcLoginHandler, name),
        STRUCT_FIELD(FFXIVIpcLoginHandler, arg1)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcFindContent {
        uint16_t territoryType;
        uint8_t unknown1;
        uint8_t unknown2;
        uint8_t acceptHalfway;
        uint8_t language;
        uint8_t flags;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcFindContent,
        STRUCT_FIELD(FFXIVIpcFindContent, territoryType),
        STRUCT_FIELD(FFXIVIpcFindContent, unknown1),
        STRUCT_FIELD(FFXIVIpcFindContent, unknown2),
        STRUCT_FIELD(FFXIVIpcFindContent, acceptHalfway),
        STRUCT_FIELD(FFXIVIpcFindContent, language),
        STRUCT_FIELD(FFXIVIpcFindContent, flags)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcFind5Contents {
        uint8_t acceptHalfway;
        uint8_t language;
        uint16_t territoryTypes[5];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcFind5Contents,
        STRUCT_FIELD(FFXIVIpcFind5Contents, acceptHalfway),
        STRUCT_FIELD(FFXIVIpcFind5Contents, language),
        STRUCT_FIELD(FFXIVIpcFind5Contents, territoryTypes)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcAcceptContent {
        uint8_t accept;
        uint8_t padding1;
        uint16_t territoryType;
        uint64_t territoryId;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcAcceptContent,
        STRUCT_FIELD(FFXIVIpcAcceptContent, accept),
        STRUCT_FIELD(FFXIVIpcAcceptContent, territoryType),
        STRUCT_FIELD(FFXIVIpcAcceptContent, territoryId)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcCancelFindContent {
        uint8_t cause;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcCancelFindContent,
        STRUCT_FIELD(FFXIVIpcCancelFindContent, cause)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcFindContentAsRandom {
        uint8_t randomContentType;
        uint8_t acceptHalfway;
        uint8_t language;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcFindContentAsRandom,
        STRUCT_FIELD(FFXIVIpcFindContentAsRandom, randomContentType),
        STRUCT_FIELD(FFXIVIpcFindContentAsRandom, acceptHalfway),
        STRUCT_FIELD(FFXIVIpcFindContentAsRandom, language)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcRequestPenalties {
        uint8_t value;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcRequestPenalties,
        STRUCT_FIELD(FFXIVIpcRequestPenalties, value)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcSetSearchInfo {
        uint64_t OnlineStatus;
        uint64_t SelectClassID;
        uint8_t CurrentSelectClassID;
        uint8_t Region;
        char SearchComment[193];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcSetSearchInfo,
        STRUCT_FIELD(FFXIVIpcSetSearchInfo, OnlineStatus),
        STRUCT_FIELD(FFXIVIpcSetSearchInfo, SelectClassID),
        STRUCT_FIELD(FFXIVIpcSetSearchInfo, CurrentSelectClassID),
        STRUCT_FIELD(FFXIVIpcSetSearchInfo, Region),
        STRUCT_FIELD(FFXIVIpcSetSearchInfo, SearchComment)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcChatTo {
        uint8_t type;
        char toName[32];
        char message[1024];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChatTo,
        STRUCT_FIELD(FFXIVIpcChatTo, type),
        STRUCT_FIELD(FFXIVIpcChatTo, toName),
        STRUCT_FIELD(FFXIVIpcChatTo, message)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcChatToChannel {
        uint64_t channelID;
        char message[1024];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChatToChannel,
        STRUCT_FIELD(FFXIVIpcChatToChannel, channelID),
        STRUCT_FIELD(FFXIVIpcChatToChannel, message)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcChatHandler {
        uint32_t clientTimeValue;
        ZoneProtoUpClientPos position;
        ChatType chatType;
        char message[1024];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChatHandler,
        STRUCT_FIELD(FFXIVIpcChatHandler, clientTimeValue),
        STRUCT_FIELD(FFXIVIpcChatHandler, position),
        STRUCT_FIELD(FFXIVIpcChatHandler, chatType),
        STRUCT_FIELD(FFXIVIpcChatHandler, message)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcJoinChatChannel {
        uint64_t ChannelID;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcJoinChatChannel,
        STRUCT_FIELD(FFXIVIpcJoinChatChannel, ChannelID)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcLinkshellJoin {
        uint64_t LinkshellID;
        char MemberCharacterName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcLinkshellJoin,
        STRUCT_FIELD(FFXIVIpcLinkshellJoin, LinkshellID),
        STRUCT_FIELD(FFXIVIpcLinkshellJoin, MemberCharacterName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcLinkshellLeave {
        uint64_t LinkshellID;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcLinkshellLeave,
        STRUCT_FIELD(FFXIVIpcLinkshellLeave, LinkshellID)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcLinkshellJoinOfficial {
        uint64_t LinkshellID;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcLinkshellJoinOfficial,
        STRUCT_FIELD(FFXIVIpcLinkshellJoinOfficial, LinkshellID)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcLinkshellChangeMaster {
        uint64_t LinkshellID;
        uint64_t NextMasterCharacterID;
        char NextMasterCharacterName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcLinkshellChangeMaster,
        STRUCT_FIELD(FFXIVIpcLinkshellChangeMaster, LinkshellID),
        STRUCT_FIELD(FFXIVIpcLinkshellChangeMaster, NextMasterCharacterID),
        STRUCT_FIELD(FFXIVIpcLinkshellChangeMaster, NextMasterCharacterName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcLinkshellKick {
        uint64_t LinkshellID;
        uint64_t LeaveCharacterID;
        char LeaveCharacterName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcLinkshellKick,
        STRUCT_FIELD(FFXIVIpcLinkshellKick, LinkshellID),
        STRUCT_FIELD(FFXIVIpcLinkshellKick, LeaveCharacterID),
        STRUCT_FIELD(FFXIVIpcLinkshellKick, LeaveCharacterName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcLinkshellAddLeader {
        uint64_t LinkshellID;
        uint64_t MemberCharacterID;
        char MemberCharacterName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcLinkshellAddLeader,
        STRUCT_FIELD(FFXIVIpcLinkshellAddLeader, LinkshellID),
        STRUCT_FIELD(FFXIVIpcLinkshellAddLeader, MemberCharacterID),
        STRUCT_FIELD(FFXIVIpcLinkshellAddLeader, MemberCharacterName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcLinkshellRemoveLeader {
        uint64_t LinkshellID;
        uint64_t MemberCharacterID;
        char MemberCharacterName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcLinkshellRemoveLeader,
        STRUCT_FIELD(FFXIVIpcLinkshellRemoveLeader, LinkshellID),
        STRUCT_FIELD(FFXIVIpcLinkshellRemoveLeader, MemberCharacterID),
        STRUCT_FIELD(FFXIVIpcLinkshellRemoveLeader, MemberCharacterName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcLinkshellDeclineLeader {
        uint64_t LinkshellID;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcLinkshellDeclineLeader,
        STRUCT_FIELD(FFXIVIpcLinkshellDeclineLeader, LinkshellID)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcShopEventHandler {
        uint32_t eventId;
        uint32_t param;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcShopEventHandler,
        STRUCT_FIELD(FFXIVIpcShopEventHandler, eventId),
        STRUCT_FIELD(FFXIVIpcShopEventHandler, param)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcStartSayEventHandler {
        uint64_t targetId;
        uint32_t handlerId;
        uint32_t sayId;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcStartSayEventHandler,
        STRUCT_FIELD(FFXIVIpcStartSayEventHandler, targetId),
        STRUCT_FIELD(FFXIVIpcStartSayEventHandler, handlerId),
        STRUCT_FIELD(FFXIVIpcStartSayEventHandler, sayId)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcClientInventoryItemOperation {
        uint32_t ContextId;
        uint8_t OperationType;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        uint32_t SrcActorId;
        uint32_t SrcStorageId;
        int16_t SrcContainerIndex;
        uint8_t __padding4;
        uint8_t __padding5;
        uint32_t SrcStack;
        uint32_t SrcCatalogId;
        uint32_t DstActorId;
        uint32_t DstStorageId;
        int16_t DstContainerIndex;
        uint8_t __padding6;
        uint8_t __padding7;
        uint32_t DstStack;
        uint32_t DstCatalogId;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcClientInventoryItemOperation,
        STRUCT_FIELD(FFXIVIpcClientInventoryItemOperation, ContextId),
        STRUCT_FIELD(FFXIVIpcClientInventoryItemOperation, OperationType),
        STRUCT_FIELD(FFXIVIpcClientInventoryItemOperation, SrcActorId),
        STRUCT_FIELD(FFXIVIpcClientInventoryItemOperation, SrcStorageId),
        STRUCT_FIELD(FFXIVIpcClientInventoryItemOperation, SrcContainerIndex),
        STRUCT_FIELD(FFXIVIpcClientInventoryItemOperation, SrcStack),
        STRUCT_FIELD(FFXIVIpcClientInventoryItemOperation, SrcCatalogId),
        STRUCT_FIELD(FFXIVIpcClientInventoryItemOperation, DstActorId),
        STRUCT_FIELD(FFXIVIpcClientInventoryItemOperation, DstStorageId),
        STRUCT_FIELD(FFXIVIpcClientInventoryItemOperation, DstContainerIndex),
        STRUCT_FIELD(FFXIVIpcClientInventoryItemOperation, DstStack),
        STRUCT_FIELD(FFXIVIpcClientInventoryItemOperation, DstCatalogId)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingExteriorChange {
        LandIdent landIdOrIndex;
        uint8_t RemoveFlags;
        uint8_t __padding1;
        uint16_t StorageId[9];
        int16_t ContainerIndex[9];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingExteriorChange,
        STRUCT_FIELD(FFXIVIpcHousingExteriorChange, landIdOrIndex),
        STRUCT_FIELD(FFXIVIpcHousingExteriorChange, RemoveFlags),
        STRUCT_FIELD(FFXIVIpcHousingExteriorChange, StorageId),
        STRUCT_FIELD(FFXIVIpcHousingExteriorChange, ContainerIndex)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingPlaceYardItem {
        LandIdent landIdOrIndex;
        uint16_t StorageId;
        int16_t ContainerIndex;
        FFXIVARR_POSITION3 Pos;
        float Rotation;
        uint32_t UserData;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingPlaceYardItem,
        STRUCT_FIELD(FFXIVIpcHousingPlaceYardItem, landIdOrIndex),
        STRUCT_FIELD(FFXIVIpcHousingPlaceYardItem, StorageId),
        STRUCT_FIELD(FFXIVIpcHousingPlaceYardItem, ContainerIndex),
        STRUCT_FIELD(FFXIVIpcHousingPlaceYardItem, Pos),
        STRUCT_FIELD(FFXIVIpcHousingPlaceYardItem, Rotation),
        STRUCT_FIELD(FFXIVIpcHousingPlaceYardItem, UserData)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingInteriorChange {
        LandIdent landIdOrIndex;
        uint16_t StorageId[10];
        int16_t ContainerIndex[10];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingInteriorChange,
        STRUCT_FIELD(FFXIVIpcHousingInteriorChange, landIdOrIndex),
        STRUCT_FIELD(FFXIVIpcHousingInteriorChange, StorageId),
        STRUCT_FIELD(FFXIVIpcHousingInteriorChange, ContainerIndex)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcMarketBoardRequestItemListings {
        uint16_t padding1;
        uint16_t itemCatalogId;
        uint32_t padding2;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcMarketBoardRequestItemListings,
        STRUCT_FIELD(FFXIVIpcMarketBoardRequestItemListings, itemCatalogId)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingHouseName {
        LandIdent landId;
        char houseName[20];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingHouseName,
        STRUCT_FIELD(FFXIVIpcHousingHouseName, landId),
        STRUCT_FIELD(FFXIVIpcHousingHouseName, houseName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcBuildPresetHandler {
        uint32_t itemId;
        uint8_t plotNum;
        char stateString[27];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcBuildPresetHandler,
        STRUCT_FIELD(FFXIVIpcBuildPresetHandler, itemId),
        STRUCT_FIELD(FFXIVIpcBuildPresetHandler, plotNum),
        STRUCT_FIELD(FFXIVIpcBuildPresetHandler, stateString)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingGreeting {
        LandIdent landId;
        char greeting[193];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingGreeting,
        STRUCT_FIELD(FFXIVIpcHousingGreeting, landId),
        STRUCT_FIELD(FFXIVIpcHousingGreeting, greeting)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingChangeLayout {
        LandIdent landId;
        uint8_t storageIndex;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        float posX;
        float posY;
        float posZ;
        float rotY;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingChangeLayout,
        STRUCT_FIELD(FFXIVIpcHousingChangeLayout, landId),
        STRUCT_FIELD(FFXIVIpcHousingChangeLayout, storageIndex),
        STRUCT_FIELD(FFXIVIpcHousingChangeLayout, posX),
        STRUCT_FIELD(FFXIVIpcHousingChangeLayout, posY),
        STRUCT_FIELD(FFXIVIpcHousingChangeLayout, posZ),
        STRUCT_FIELD(FFXIVIpcHousingChangeLayout, rotY)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingChangeLayoutMulti {
        LandIdent landId;
        float posXs[10];
        float posYs[10];
        float posZs[10];
        float rotYs[10];
        uint8_t storageIndex[10];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingChangeLayoutMulti,
        STRUCT_FIELD(FFXIVIpcHousingChangeLayoutMulti, landId),
        STRUCT_FIELD(FFXIVIpcHousingChangeLayoutMulti, posXs),
        STRUCT_FIELD(FFXIVIpcHousingChangeLayoutMulti, posYs),
        STRUCT_FIELD(FFXIVIpcHousingChangeLayoutMulti, posZs),
        STRUCT_FIELD(FFXIVIpcHousingChangeLayoutMulti, rotYs),
        STRUCT_FIELD(FFXIVIpcHousingChangeLayoutMulti, storageIndex)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcCatalogSearch {
        uint32_t NextIndex;
        uint8_t RequestKey;
        uint8_t Type;
        uint8_t SearchCategory;
        uint8_t MinLevel;
        uint8_t MaxLevel;
        uint8_t ClassJob;
        char ItemName[121];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcCatalogSearch,
        STRUCT_FIELD(FFXIVIpcCatalogSearch, NextIndex),
        STRUCT_FIELD(FFXIVIpcCatalogSearch, RequestKey),
        STRUCT_FIELD(FFXIVIpcCatalogSearch, Type),
        STRUCT_FIELD(FFXIVIpcCatalogSearch, SearchCategory),
        STRUCT_FIELD(FFXIVIpcCatalogSearch, MinLevel),
        STRUCT_FIELD(FFXIVIpcCatalogSearch, MaxLevel),
        STRUCT_FIELD(FFXIVIpcCatalogSearch, ClassJob),
        STRUCT_FIELD(FFXIVIpcCatalogSearch, ItemName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGearSetEquip {
        uint32_t contextId;
        uint16_t storageId[14];
        int16_t containerIndex[14];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGearSetEquip,
        STRUCT_FIELD(FFXIVIpcGearSetEquip, contextId),
        STRUCT_FIELD(FFXIVIpcGearSetEquip, storageId),
        STRUCT_FIELD(FFXIVIpcGearSetEquip, containerIndex)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcMarketBoardRequestItemListingInfo {
        uint32_t catalogId;
        uint32_t requestId;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcMarketBoardRequestItemListingInfo,
        STRUCT_FIELD(FFXIVIpcMarketBoardRequestItemListingInfo, catalogId),
        STRUCT_FIELD(FFXIVIpcMarketBoardRequestItemListingInfo, requestId)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcConfig {
        uint16_t flag;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcConfig,
        STRUCT_FIELD(FFXIVIpcConfig, flag)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetFcProfile {
        uint64_t TargetCharacterID;
        uint32_t TargetEntityID;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetFcProfile,
        STRUCT_FIELD(FFXIVIpcGetFcProfile, TargetCharacterID),
        STRUCT_FIELD(FFXIVIpcGetFcProfile, TargetEntityID)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetBlacklist {
        uint8_t NextIndex;
        uint8_t RequestKey;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetBlacklist,
        STRUCT_FIELD(FFXIVIpcGetBlacklist, NextIndex),
        STRUCT_FIELD(FFXIVIpcGetBlacklist, RequestKey)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcBlacklistAdd {
        char TargetCharacterName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcBlacklistAdd,
        STRUCT_FIELD(FFXIVIpcBlacklistAdd, TargetCharacterName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcBlacklistRemove {
        uint64_t TargetCharacterID;
        char TargetCharacterName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcBlacklistRemove,
        STRUCT_FIELD(FFXIVIpcBlacklistRemove, TargetCharacterID),
        STRUCT_FIELD(FFXIVIpcBlacklistRemove, TargetCharacterName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcInvite {
        uint8_t AuthType;
        char TargetName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcInvite,
        STRUCT_FIELD(FFXIVIpcInvite, AuthType),
        STRUCT_FIELD(FFXIVIpcInvite, TargetName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcInviteReply {
        uint64_t InviteCharacterID;
        uint8_t AuthType;
        uint8_t Answer;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcInviteReply,
        STRUCT_FIELD(FFXIVIpcInviteReply, InviteCharacterID),
        STRUCT_FIELD(FFXIVIpcInviteReply, AuthType),
        STRUCT_FIELD(FFXIVIpcInviteReply, Answer)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetCommonlist {
        uint64_t CommunityID;
        uint16_t NextIndex;
        uint8_t ListType;
        uint8_t RequestKey;
        uint8_t RequestParam;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetCommonlist,
        STRUCT_FIELD(FFXIVIpcGetCommonlist, CommunityID),
        STRUCT_FIELD(FFXIVIpcGetCommonlist, NextIndex),
        STRUCT_FIELD(FFXIVIpcGetCommonlist, ListType),
        STRUCT_FIELD(FFXIVIpcGetCommonlist, RequestKey),
        STRUCT_FIELD(FFXIVIpcGetCommonlist, RequestParam)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetCommonlistDetail {
        uint64_t DetailCharacterID;
        uint64_t CommunityID;
        uint8_t ListType;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetCommonlistDetail,
        STRUCT_FIELD(FFXIVIpcGetCommonlistDetail, DetailCharacterID),
        STRUCT_FIELD(FFXIVIpcGetCommonlistDetail, CommunityID),
        STRUCT_FIELD(FFXIVIpcGetCommonlistDetail, ListType)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcFriendlistRemove {
        uint64_t TargetCharacterID;
        char TargetCharacterName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcFriendlistRemove,
        STRUCT_FIELD(FFXIVIpcFriendlistRemove, TargetCharacterID),
        STRUCT_FIELD(FFXIVIpcFriendlistRemove, TargetCharacterName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcSetFriendlistGroup {
        uint64_t TargetCharacterID;
        uint8_t group;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcSetFriendlistGroup,
        STRUCT_FIELD(FFXIVIpcSetFriendlistGroup, TargetCharacterID),
        STRUCT_FIELD(FFXIVIpcSetFriendlistGroup, group)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcPcSearch {
        uint64_t ClassID;
        uint16_t MinLevel;
        uint16_t MaxLevel;
        uint64_t GrandCompanyID;
        uint64_t Region;
        uint64_t OnlineStatus;
        uint16_t AreaList[50];
        char CharacterName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcPcSearch,
        STRUCT_FIELD(FFXIVIpcPcSearch, ClassID),
        STRUCT_FIELD(FFXIVIpcPcSearch, MinLevel),
        STRUCT_FIELD(FFXIVIpcPcSearch, MaxLevel),
        STRUCT_FIELD(FFXIVIpcPcSearch, GrandCompanyID),
        STRUCT_FIELD(FFXIVIpcPcSearch, Region),
        STRUCT_FIELD(FFXIVIpcPcSearch, OnlineStatus),
        STRUCT_FIELD(FFXIVIpcPcSearch, AreaList),
        STRUCT_FIELD(FFXIVIpcPcSearch, CharacterName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcPcPartyLeave {
        uint32_t Reserve;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcPcPartyLeave,
        STRUCT_FIELD(FFXIVIpcPcPartyLeave, Reserve)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcPcPartyDisband {
        uint32_t Reserve;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcPcPartyDisband,
        STRUCT_FIELD(FFXIVIpcPcPartyDisband, Reserve)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcPcPartyKick {
        char LeaveCharacterName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcPcPartyKick,
        STRUCT_FIELD(FFXIVIpcPcPartyKick, LeaveCharacterName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcPcPartyChangeLeader {
        char NextLeaderCharacterName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcPcPartyChangeLeader,
        STRUCT_FIELD(FFXIVIpcPcPartyChangeLeader, NextLeaderCharacterName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetFcInviteList {
        uint32_t Reserve;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetFcInviteList,
        STRUCT_FIELD(FFXIVIpcGetFcInviteList, Reserve)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetFcHierarchy {
        uint8_t ListType;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetFcHierarchy,
        STRUCT_FIELD(FFXIVIpcGetFcHierarchy, ListType)
    );
#endif // DECLARE_PACKET_FIELDS

} // namespace PacketStructures::Client::Zone