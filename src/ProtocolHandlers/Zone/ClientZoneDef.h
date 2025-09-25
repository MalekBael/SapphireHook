#pragma once
#include <cstdint>
#include "../ProtocolHandlers/CommonTypes.h"

namespace PacketStructures::Client::Zone {

    struct FFXIVIpcGmCommand {
        uint32_t Id;
        uint32_t Arg0;
        uint32_t Arg1;
        uint32_t Arg2;
        uint32_t Arg3;
        uint64_t Target;
    };

    struct FFXIVIpcGmCommandName {
        uint32_t Id;
        uint32_t Arg0;
        uint32_t Arg1;
        uint32_t Arg2;
        uint32_t Arg3;
        char Name[32];
    };

    struct FFXIVIpcClientTrigger {
        uint32_t Id;
        uint32_t Arg0;
        uint32_t Arg1;
        uint32_t Arg2;
        uint32_t Arg3;
        uint64_t Target;
    };

    struct FFXIVIpcUpdatePosition {
        float dir;
        float dirBeforeSlip;
        uint8_t flag;
        uint8_t flag2;
        uint8_t flag_unshared;
        uint8_t __padding1;
        FFXIVARR_POSITION3 pos;
    };

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

    struct FFXIVIpcZoneJump {
        uint32_t ExitBox;
        float X;
        float Y;
        float Z;
        int32_t LandSetIndex;
    };

    struct FFXIVIpcNewDiscovery {
        uint32_t LayoutId;
        float PositionX;
        float PositionY;
        float PositionZ;
    };

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

    struct FFXIVIpcEnterTerritoryHandler {
        uint32_t eventId;
        uint16_t param1;
        uint16_t param2;
    };

    struct FFXIVIpcEventHandlerOutsideRange {
        uint32_t param1;
        uint32_t eventId;
        FFXIVARR_POSITION3 position;
    };

    struct FFXIVIpcEventHandlerWithinRange {
        uint32_t param1;
        uint32_t eventId;
        FFXIVARR_POSITION3 position;
    };

    struct FFXIVIpcEventHandlerEmote {
        uint64_t actorId;
        uint32_t eventId;
        uint16_t emoteId;
    };

    struct FFXIVIpcEventHandlerTalk {
        uint64_t actorId;
        uint32_t eventId;
    };

    struct ZoneProtoUpClientPos {
        uint32_t originEntityId;
        float pos[3];
        float dir;
    };

    struct FFXIVIpcPingHandler {
        uint32_t clientTimeValue;
        ZoneProtoUpClientPos position;
    };

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

    struct FFXIVIpcFindContent {
        uint16_t territoryType;
        uint8_t unknown1;
        uint8_t unknown2;
        uint8_t acceptHalfway;
        uint8_t language;
        uint8_t flags;
    };

    struct FFXIVIpcFind5Contents {
        uint8_t acceptHalfway;
        uint8_t language;
        uint16_t territoryTypes[5];
    };

    struct FFXIVIpcAcceptContent {
        uint8_t accept;
        uint8_t padding1;
        uint16_t territoryType;
        uint64_t territoryId;
    };

    struct FFXIVIpcCancelFindContent {
        uint8_t cause;
    };

    struct FFXIVIpcFindContentAsRandom {
        uint8_t randomContentType;
        uint8_t acceptHalfway;
        uint8_t language;
    };

    struct FFXIVIpcRequestPenalties {
        uint8_t value;
    };

    struct FFXIVIpcSetSearchInfo {
        uint64_t OnlineStatus;
        uint64_t SelectClassID;
        uint8_t CurrentSelectClassID;
        uint8_t Region;
        char SearchComment[193];
    };

    struct FFXIVIpcChatTo {
        uint8_t type;
        char toName[32];
        char message[1024];
    };

    struct FFXIVIpcChatToChannel {
        uint64_t channelID;
        char message[1024];
    };

    struct FFXIVIpcChatHandler {
        uint32_t clientTimeValue;
        ZoneProtoUpClientPos position;
        ChatType chatType;
        char message[1024];
    };

    struct FFXIVIpcJoinChatChannel {
        uint64_t ChannelID;
    };

    struct FFXIVIpcLinkshellJoin {
        uint64_t LinkshellID;
        char MemberCharacterName[32];
    };

    struct FFXIVIpcLinkshellLeave {
        uint64_t LinkshellID;
    };

    struct FFXIVIpcLinkshellJoinOfficial {
        uint64_t LinkshellID;
    };

    struct FFXIVIpcLinkshellChangeMaster {
        uint64_t LinkshellID;
        uint64_t NextMasterCharacterID;
        char NextMasterCharacterName[32];
    };

    struct FFXIVIpcLinkshellKick {
        uint64_t LinkshellID;
        uint64_t LeaveCharacterID;
        char LeaveCharacterName[32];
    };

    struct FFXIVIpcLinkshellAddLeader {
        uint64_t LinkshellID;
        uint64_t MemberCharacterID;
        char MemberCharacterName[32];
    };

    struct FFXIVIpcLinkshellRemoveLeader {
        uint64_t LinkshellID;
        uint64_t MemberCharacterID;
        char MemberCharacterName[32];
    };

    struct FFXIVIpcLinkshellDeclineLeader {
        uint64_t LinkshellID;
    };

    struct FFXIVIpcShopEventHandler {
        uint32_t eventId;
        uint32_t param;
    };

    struct FFXIVIpcStartSayEventHandler {
        uint64_t targetId;
        uint32_t handlerId;
        uint32_t sayId;
    };

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

    struct FFXIVIpcHousingExteriorChange {
        LandIdent landIdOrIndex;
        uint8_t RemoveFlags;
        uint8_t __padding1;
        uint16_t StorageId[9];
        int16_t ContainerIndex[9];
    };

    struct FFXIVIpcHousingPlaceYardItem {
        LandIdent landIdOrIndex;
        uint16_t StorageId;
        int16_t ContainerIndex;
        FFXIVARR_POSITION3 Pos;
        float Rotation;
        uint32_t UserData;
    };

    struct FFXIVIpcHousingInteriorChange {
        LandIdent landIdOrIndex;
        uint16_t StorageId[10];
        int16_t ContainerIndex[10];
    };

    struct FFXIVIpcMarketBoardRequestItemListings {
        uint16_t padding1;
        uint16_t itemCatalogId;
        uint32_t padding2;
    };

    struct FFXIVIpcHousingHouseName {
        LandIdent landId;
        char houseName[20];
    };

    struct FFXIVIpcBuildPresetHandler {
        uint32_t itemId;
        uint8_t plotNum;
        char stateString[27];
    };

    struct FFXIVIpcHousingGreeting {
        LandIdent landId;
        char greeting[193];
    };

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

    struct FFXIVIpcHousingChangeLayoutMulti {
        LandIdent landId;
        float posXs[10];
        float posYs[10];
        float posZs[10];
        float rotYs[10];
        uint8_t storageIndex[10];
    };

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

    struct FFXIVIpcGearSetEquip {
        uint32_t contextId;
        uint16_t storageId[14];
        int16_t containerIndex[14];
    };

    struct FFXIVIpcMarketBoardRequestItemListingInfo {
        uint32_t catalogId;
        uint32_t requestId;
    };

    struct FFXIVIpcConfig {
        uint16_t flag;
    };

    struct FFXIVIpcGetFcProfile {
        uint64_t TargetCharacterID;
        uint32_t TargetEntityID;
    };

    struct FFXIVIpcGetBlacklist {
        uint8_t NextIndex;
        uint8_t RequestKey;
    };

    struct FFXIVIpcBlacklistAdd {
        char TargetCharacterName[32];
    };

    struct FFXIVIpcBlacklistRemove {
        uint64_t TargetCharacterID;
        char TargetCharacterName[32];
    };

    struct FFXIVIpcInvite {
        uint8_t AuthType;
        char TargetName[32];
    };

    struct FFXIVIpcInviteReply {
        uint64_t InviteCharacterID;
        uint8_t AuthType;
        uint8_t Answer;
    };

    struct FFXIVIpcGetCommonlist {
        uint64_t CommunityID;
        uint16_t NextIndex;
        uint8_t ListType;
        uint8_t RequestKey;
        uint8_t RequestParam;
    };

    struct FFXIVIpcGetCommonlistDetail {
        uint64_t DetailCharacterID;
        uint64_t CommunityID;
        uint8_t ListType;
    };

    struct FFXIVIpcFriendlistRemove {
        uint64_t TargetCharacterID;
        char TargetCharacterName[32];
    };

    struct FFXIVIpcSetFriendlistGroup {
        uint64_t TargetCharacterID;
        uint8_t group;
    };

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

    struct FFXIVIpcPcPartyLeave {
        uint32_t Reserve;
    };

    struct FFXIVIpcPcPartyDisband {
        uint32_t Reserve;
    };

    struct FFXIVIpcPcPartyKick {
        char LeaveCharacterName[32];
    };

    struct FFXIVIpcPcPartyChangeLeader {
        char NextLeaderCharacterName[32];
    };

    struct FFXIVIpcGetFcInviteList {
        uint32_t Reserve;
    };

    struct FFXIVIpcGetFcHierarchy {
        uint8_t ListType;
    };

} // namespace PacketStructures::Client::Zone