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

namespace PacketStructures::Server::Zone {

    struct ZoneProtoDownServerPos {
        uint32_t originEntityId;
        float pos[3];
        float dir;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoDownServerPos,
        STRUCT_FIELD(ZoneProtoDownServerPos, originEntityId),
        STRUCT_FIELD(ZoneProtoDownServerPos, pos),
        STRUCT_FIELD(ZoneProtoDownServerPos, dir)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcSync {
        uint32_t clientTimeValue;
        uint32_t transmissionInterval;
        ZoneProtoDownServerPos position;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcSync,
        STRUCT_FIELD(FFXIVIpcSync, clientTimeValue),
        STRUCT_FIELD(FFXIVIpcSync, transmissionInterval),
        STRUCT_FIELD(FFXIVIpcSync, position)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcLogin {
        uint32_t clientTimeValue;
        uint32_t loginTicketId;
        uint32_t playerActorId;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcLogin,
        STRUCT_FIELD(FFXIVIpcLogin, clientTimeValue),
        STRUCT_FIELD(FFXIVIpcLogin, loginTicketId),
        STRUCT_FIELD(FFXIVIpcLogin, playerActorId)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcChat {
        uint16_t type;
        uint8_t __padding1;
        uint8_t __padding2;
        uint32_t entityId;
        uint64_t characterId;
        uint32_t __unknown3;
        char speakerName[32];
        char message[1024];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChat,
        STRUCT_FIELD(FFXIVIpcChat, type),
        STRUCT_FIELD(FFXIVIpcChat, entityId),
        STRUCT_FIELD(FFXIVIpcChat, characterId),
        STRUCT_FIELD(FFXIVIpcChat, speakerName),
        STRUCT_FIELD(FFXIVIpcChat, message)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcEnableLogout {
        uint8_t content;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEnableLogout,
        STRUCT_FIELD(FFXIVIpcEnableLogout, content)
    );
#endif // DECLARE_PACKET_FIELDS

    struct PlayerEntry {
        uint64_t CharacterID;
        uint32_t Timestamp;
        uint32_t TerritoryID;
        uint8_t HierarchyStatus;
        uint8_t HierarchyType;
        uint8_t HierarchyGroup;
        uint8_t IsDeleted;
        uint16_t TerritoryType;
        uint8_t GrandCompanyID;
        uint8_t Region;
        uint8_t SelectRegion;
        uint8_t IsSearchComment;
        uint8_t __padding1;
        uint8_t __padding2;
        uint64_t OnlineStatus;
        uint8_t CurrentClassID;
        uint8_t SelectClassID;
        uint16_t CurrentLevel;
        uint16_t SelectLevel;
        uint8_t Identity;
        char CharacterName[32];
        char FcTag[7];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(PlayerEntry,
        STRUCT_FIELD(PlayerEntry, CharacterID),
        STRUCT_FIELD(PlayerEntry, Timestamp),
        STRUCT_FIELD(PlayerEntry, TerritoryID),
        STRUCT_FIELD(PlayerEntry, HierarchyStatus),
        STRUCT_FIELD(PlayerEntry, HierarchyType),
        STRUCT_FIELD(PlayerEntry, HierarchyGroup),
        STRUCT_FIELD(PlayerEntry, IsDeleted),
        STRUCT_FIELD(PlayerEntry, TerritoryType),
        STRUCT_FIELD(PlayerEntry, GrandCompanyID),
        STRUCT_FIELD(PlayerEntry, Region),
        STRUCT_FIELD(PlayerEntry, SelectRegion),
        STRUCT_FIELD(PlayerEntry, IsSearchComment),
        STRUCT_FIELD(PlayerEntry, OnlineStatus),
        STRUCT_FIELD(PlayerEntry, CurrentClassID),
        STRUCT_FIELD(PlayerEntry, SelectClassID),
        STRUCT_FIELD(PlayerEntry, CurrentLevel),
        STRUCT_FIELD(PlayerEntry, SelectLevel),
        STRUCT_FIELD(PlayerEntry, Identity),
        STRUCT_FIELD(PlayerEntry, CharacterName),
        STRUCT_FIELD(PlayerEntry, FcTag)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetCommonlistResult {
        uint64_t CommunityID;
        uint16_t NextIndex;
        uint16_t Index;
        uint8_t ListType;
        uint8_t RequestKey;
        uint8_t RequestParam;
        uint8_t __padding1;
        PlayerEntry entries[10];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetCommonlistResult,
        STRUCT_FIELD(FFXIVIpcGetCommonlistResult, CommunityID),
        STRUCT_FIELD(FFXIVIpcGetCommonlistResult, NextIndex),
        STRUCT_FIELD(FFXIVIpcGetCommonlistResult, Index),
        STRUCT_FIELD(FFXIVIpcGetCommonlistResult, ListType),
        STRUCT_FIELD(FFXIVIpcGetCommonlistResult, RequestKey),
        STRUCT_FIELD(FFXIVIpcGetCommonlistResult, RequestParam),
        STRUCT_FIELD(FFXIVIpcGetCommonlistResult, entries)
    );
#endif // DECLARE_PACKET_FIELDS

    struct ClassJobEntry {
        uint16_t id;
        uint16_t level;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ClassJobEntry,
        STRUCT_FIELD(ClassJobEntry, id),
        STRUCT_FIELD(ClassJobEntry, level)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetCommonlistDetailResult {
        uint64_t DetailCharacterID;
        uint64_t CommunityID;
        uint64_t SelectClassID;
        uint64_t CrestID;
        uint8_t ListType;
        char SearchComment[193];
        char FreeCompanyName[23];
        uint8_t GrandCompanyRank[3];
        ClassJobEntry ClassData[34];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetCommonlistDetailResult,
        STRUCT_FIELD(FFXIVIpcGetCommonlistDetailResult, DetailCharacterID),
        STRUCT_FIELD(FFXIVIpcGetCommonlistDetailResult, CommunityID),
        STRUCT_FIELD(FFXIVIpcGetCommonlistDetailResult, SelectClassID),
        STRUCT_FIELD(FFXIVIpcGetCommonlistDetailResult, CrestID),
        STRUCT_FIELD(FFXIVIpcGetCommonlistDetailResult, ListType),
        STRUCT_FIELD(FFXIVIpcGetCommonlistDetailResult, SearchComment),
        STRUCT_FIELD(FFXIVIpcGetCommonlistDetailResult, FreeCompanyName),
        STRUCT_FIELD(FFXIVIpcGetCommonlistDetailResult, GrandCompanyRank),
        STRUCT_FIELD(FFXIVIpcGetCommonlistDetailResult, ClassData)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcPcSearchResult {
        int16_t ResultCount;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcPcSearchResult,
        STRUCT_FIELD(FFXIVIpcPcSearchResult, ResultCount)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcLinkshellResult {
        uint64_t LinkshellID;
        uint64_t TargetCharacterID;
        uint32_t UpPacketNo;
        uint32_t Result;
        uint8_t UpdateStatus;
        uint8_t Identity;
        char LinkshellName[32];
        char TargetName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcLinkshellResult,
        STRUCT_FIELD(FFXIVIpcLinkshellResult, LinkshellID),
        STRUCT_FIELD(FFXIVIpcLinkshellResult, TargetCharacterID),
        STRUCT_FIELD(FFXIVIpcLinkshellResult, UpPacketNo),
        STRUCT_FIELD(FFXIVIpcLinkshellResult, Result),
        STRUCT_FIELD(FFXIVIpcLinkshellResult, UpdateStatus),
        STRUCT_FIELD(FFXIVIpcLinkshellResult, Identity),
        STRUCT_FIELD(FFXIVIpcLinkshellResult, LinkshellName),
        STRUCT_FIELD(FFXIVIpcLinkshellResult, TargetName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcInviteResult {
        uint32_t Result;
        uint8_t AuthType;
        uint8_t Identity;
        char TargetName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcInviteResult,
        STRUCT_FIELD(FFXIVIpcInviteResult, Result),
        STRUCT_FIELD(FFXIVIpcInviteResult, AuthType),
        STRUCT_FIELD(FFXIVIpcInviteResult, Identity),
        STRUCT_FIELD(FFXIVIpcInviteResult, TargetName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcInviteReplyResult {
        uint32_t Result;
        uint8_t AuthType;
        uint8_t Answer;
        uint8_t Identity;
        char InviteCharacterName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcInviteReplyResult,
        STRUCT_FIELD(FFXIVIpcInviteReplyResult, Result),
        STRUCT_FIELD(FFXIVIpcInviteReplyResult, AuthType),
        STRUCT_FIELD(FFXIVIpcInviteReplyResult, Answer),
        STRUCT_FIELD(FFXIVIpcInviteReplyResult, Identity),
        STRUCT_FIELD(FFXIVIpcInviteReplyResult, InviteCharacterName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcInviteUpdate {
        uint64_t InviteCharacterID;
        uint32_t InviteTime;
        uint8_t AuthType;
        uint8_t InviteCount;
        uint8_t Result;
        uint8_t Identity;
        char InviteName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcInviteUpdate,
        STRUCT_FIELD(FFXIVIpcInviteUpdate, InviteCharacterID),
        STRUCT_FIELD(FFXIVIpcInviteUpdate, InviteTime),
        STRUCT_FIELD(FFXIVIpcInviteUpdate, AuthType),
        STRUCT_FIELD(FFXIVIpcInviteUpdate, InviteCount),
        STRUCT_FIELD(FFXIVIpcInviteUpdate, Result),
        STRUCT_FIELD(FFXIVIpcInviteUpdate, Identity),
        STRUCT_FIELD(FFXIVIpcInviteUpdate, InviteName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcFriendlistRemoveResult {
        uint64_t RemovedCharacterID;
        uint32_t Result;
        uint8_t Identity;
        char RemovedCharacterName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcFriendlistRemoveResult,
        STRUCT_FIELD(FFXIVIpcFriendlistRemoveResult, RemovedCharacterID),
        STRUCT_FIELD(FFXIVIpcFriendlistRemoveResult, Result),
        STRUCT_FIELD(FFXIVIpcFriendlistRemoveResult, Identity),
        STRUCT_FIELD(FFXIVIpcFriendlistRemoveResult, RemovedCharacterName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcFreeCompanyResult {
        uint64_t FreeCompanyID;
        uint64_t Arg;
        uint32_t Type;
        uint32_t Result;
        uint8_t UpdateStatus;
        uint8_t Identity;
        char FreeCompanyName[46];
        char TargetName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcFreeCompanyResult,
        STRUCT_FIELD(FFXIVIpcFreeCompanyResult, FreeCompanyID),
        STRUCT_FIELD(FFXIVIpcFreeCompanyResult, Arg),
        STRUCT_FIELD(FFXIVIpcFreeCompanyResult, Type),
        STRUCT_FIELD(FFXIVIpcFreeCompanyResult, Result),
        STRUCT_FIELD(FFXIVIpcFreeCompanyResult, UpdateStatus),
        STRUCT_FIELD(FFXIVIpcFreeCompanyResult, Identity),
        STRUCT_FIELD(FFXIVIpcFreeCompanyResult, FreeCompanyName),
        STRUCT_FIELD(FFXIVIpcFreeCompanyResult, TargetName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetFcStatusResult {
        uint64_t FreeCompanyID;
        uint64_t AuthorityList;
        uint64_t ChannelID;
        uint64_t CrestID;
        uint32_t CharaFcState;
        uint32_t CharaFcParam;
        uint16_t Param;
        uint8_t FcStatus;
        uint8_t GrandCompanyID;
        uint8_t HierarchyType;
        uint8_t FcRank;
        uint8_t IsCrest;
        uint8_t IsDecal;
        uint8_t IsFcAction;
        uint8_t IsChestExt1;
        uint8_t IsChestLock;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetFcStatusResult,
        STRUCT_FIELD(FFXIVIpcGetFcStatusResult, FreeCompanyID),
        STRUCT_FIELD(FFXIVIpcGetFcStatusResult, AuthorityList),
        STRUCT_FIELD(FFXIVIpcGetFcStatusResult, ChannelID),
        STRUCT_FIELD(FFXIVIpcGetFcStatusResult, CrestID),
        STRUCT_FIELD(FFXIVIpcGetFcStatusResult, CharaFcState),
        STRUCT_FIELD(FFXIVIpcGetFcStatusResult, CharaFcParam),
        STRUCT_FIELD(FFXIVIpcGetFcStatusResult, Param),
        STRUCT_FIELD(FFXIVIpcGetFcStatusResult, FcStatus),
        STRUCT_FIELD(FFXIVIpcGetFcStatusResult, GrandCompanyID),
        STRUCT_FIELD(FFXIVIpcGetFcStatusResult, HierarchyType),
        STRUCT_FIELD(FFXIVIpcGetFcStatusResult, FcRank),
        STRUCT_FIELD(FFXIVIpcGetFcStatusResult, IsCrest),
        STRUCT_FIELD(FFXIVIpcGetFcStatusResult, IsDecal),
        STRUCT_FIELD(FFXIVIpcGetFcStatusResult, IsFcAction),
        STRUCT_FIELD(FFXIVIpcGetFcStatusResult, IsChestExt1),
        STRUCT_FIELD(FFXIVIpcGetFcStatusResult, IsChestLock)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcSetProfileResult {
        uint64_t OnlineStatus;
        uint64_t SelectClassID;
        uint32_t Result;
        uint8_t CurrentSelectClassID;
        uint8_t Region;
        char SearchComment[193];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcSetProfileResult,
        STRUCT_FIELD(FFXIVIpcSetProfileResult, OnlineStatus),
        STRUCT_FIELD(FFXIVIpcSetProfileResult, SelectClassID),
        STRUCT_FIELD(FFXIVIpcSetProfileResult, Result),
        STRUCT_FIELD(FFXIVIpcSetProfileResult, CurrentSelectClassID),
        STRUCT_FIELD(FFXIVIpcSetProfileResult, Region),
        STRUCT_FIELD(FFXIVIpcSetProfileResult, SearchComment)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetProfileResult {
        uint64_t OnlineStatus;
        uint64_t SelectClassID;
        uint8_t CurrentSelectClassID;
        uint8_t Region;
        char SearchComment[193];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetProfileResult,
        STRUCT_FIELD(FFXIVIpcGetProfileResult, OnlineStatus),
        STRUCT_FIELD(FFXIVIpcGetProfileResult, SelectClassID),
        STRUCT_FIELD(FFXIVIpcGetProfileResult, CurrentSelectClassID),
        STRUCT_FIELD(FFXIVIpcGetProfileResult, Region),
        STRUCT_FIELD(FFXIVIpcGetProfileResult, SearchComment)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetSearchCommentResult {
        uint32_t TargetEntityID;
        char SearchComment[193];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetSearchCommentResult,
        STRUCT_FIELD(FFXIVIpcGetSearchCommentResult, TargetEntityID),
        STRUCT_FIELD(FFXIVIpcGetSearchCommentResult, SearchComment)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetCharacterNameResult {
        uint64_t CharacterID;
        char CharacterName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetCharacterNameResult,
        STRUCT_FIELD(FFXIVIpcGetCharacterNameResult, CharacterID),
        STRUCT_FIELD(FFXIVIpcGetCharacterNameResult, CharacterName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcSendSystemMessage {
        uint8_t MessageParam;
        char Message[769];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcSendSystemMessage,
        STRUCT_FIELD(FFXIVIpcSendSystemMessage, MessageParam),
        STRUCT_FIELD(FFXIVIpcSendSystemMessage, Message)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcSendLoginMessage {
        uint8_t MessageParam;
        char Message[769];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcSendLoginMessage,
        STRUCT_FIELD(FFXIVIpcSendLoginMessage, MessageParam),
        STRUCT_FIELD(FFXIVIpcSendLoginMessage, Message)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcSetOnlineStatus {
        uint64_t onlineStatusFlags;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcSetOnlineStatus,
        STRUCT_FIELD(FFXIVIpcSetOnlineStatus, onlineStatusFlags)
    );
#endif // DECLARE_PACKET_FIELDS

    struct BlacklistCharacter {
        uint64_t CharacterID;
        char CharacterName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(BlacklistCharacter,
        STRUCT_FIELD(BlacklistCharacter, CharacterID),
        STRUCT_FIELD(BlacklistCharacter, CharacterName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcBlacklistAddResult {
        BlacklistCharacter AddedCharacter;
        uint32_t Result;
        uint8_t Identity;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcBlacklistAddResult,
        STRUCT_FIELD(FFXIVIpcBlacklistAddResult, AddedCharacter),
        STRUCT_FIELD(FFXIVIpcBlacklistAddResult, Result),
        STRUCT_FIELD(FFXIVIpcBlacklistAddResult, Identity)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcBlacklistRemoveResult {
        BlacklistCharacter RemovedCharacter;
        uint32_t Result;
        uint8_t Identity;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcBlacklistRemoveResult,
        STRUCT_FIELD(FFXIVIpcBlacklistRemoveResult, RemovedCharacter),
        STRUCT_FIELD(FFXIVIpcBlacklistRemoveResult, Result),
        STRUCT_FIELD(FFXIVIpcBlacklistRemoveResult, Identity)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetBlacklistResult {
        BlacklistCharacter Blacklist[20];
        uint8_t NextIndex;
        uint8_t Index;
        uint8_t RequestKey;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetBlacklistResult,
        STRUCT_FIELD(FFXIVIpcGetBlacklistResult, Blacklist),
        STRUCT_FIELD(FFXIVIpcGetBlacklistResult, NextIndex),
        STRUCT_FIELD(FFXIVIpcGetBlacklistResult, Index),
        STRUCT_FIELD(FFXIVIpcGetBlacklistResult, RequestKey)
    );
#endif // DECLARE_PACKET_FIELDS

    struct ZoneProtoDownLinkshell {
        uint64_t LinkshellID;
        uint64_t ChannelID;
        uint32_t HierarchyID;
        char LinkshellName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoDownLinkshell,
        STRUCT_FIELD(ZoneProtoDownLinkshell, LinkshellID),
        STRUCT_FIELD(ZoneProtoDownLinkshell, ChannelID),
        STRUCT_FIELD(ZoneProtoDownLinkshell, HierarchyID),
        STRUCT_FIELD(ZoneProtoDownLinkshell, LinkshellName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetLinkshellListResult {
        ZoneProtoDownLinkshell LinkshellList[8];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetLinkshellListResult,
        STRUCT_FIELD(FFXIVIpcGetLinkshellListResult, LinkshellList)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcChatChannelResult {
        uint64_t ChannelID;
        uint64_t CommunityID;
        uint64_t TargetCharacterID;
        uint32_t UpPacketNo;
        uint32_t Result;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChatChannelResult,
        STRUCT_FIELD(FFXIVIpcChatChannelResult, ChannelID),
        STRUCT_FIELD(FFXIVIpcChatChannelResult, CommunityID),
        STRUCT_FIELD(FFXIVIpcChatChannelResult, TargetCharacterID),
        STRUCT_FIELD(FFXIVIpcChatChannelResult, UpPacketNo),
        STRUCT_FIELD(FFXIVIpcChatChannelResult, Result)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcAchievement {
        uint8_t complete[256];
        uint16_t history[5];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcAchievement,
        STRUCT_FIELD(FFXIVIpcAchievement, complete),
        STRUCT_FIELD(FFXIVIpcAchievement, history)
    );
#endif // DECLARE_PACKET_FIELDS

    // Letter/Mail structures
    struct ZoneProtoDownLetterBoxAppendItemBase {
        uint32_t CatalogID;
        uint32_t Stack;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoDownLetterBoxAppendItemBase,
        STRUCT_FIELD(ZoneProtoDownLetterBoxAppendItemBase, CatalogID),
        STRUCT_FIELD(ZoneProtoDownLetterBoxAppendItemBase, Stack)
    );
#endif // DECLARE_PACKET_FIELDS

    struct ZoneProtoDownLetterBoxAppendItem {
        ZoneProtoDownLetterBoxAppendItemBase ItemList[5];
        ZoneProtoDownLetterBoxAppendItemBase Gil;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoDownLetterBoxAppendItem,
        STRUCT_FIELD(ZoneProtoDownLetterBoxAppendItem, ItemList),
        STRUCT_FIELD(ZoneProtoDownLetterBoxAppendItem, Gil)
    );
#endif // DECLARE_PACKET_FIELDS

    struct ZoneProtoDownLetterMessage {
        uint64_t SenderCharacterID;
        uint32_t Date;
        ZoneProtoDownLetterBoxAppendItem AppendItem;
        uint8_t IsRead;
        uint8_t Type;
        uint8_t IsMessageEnd;
        char SenderCharacterName[32];
        char Message[61];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoDownLetterMessage,
        STRUCT_FIELD(ZoneProtoDownLetterMessage, SenderCharacterID),
        STRUCT_FIELD(ZoneProtoDownLetterMessage, Date),
        STRUCT_FIELD(ZoneProtoDownLetterMessage, AppendItem),
        STRUCT_FIELD(ZoneProtoDownLetterMessage, IsRead),
        STRUCT_FIELD(ZoneProtoDownLetterMessage, Type),
        STRUCT_FIELD(ZoneProtoDownLetterMessage, IsMessageEnd),
        STRUCT_FIELD(ZoneProtoDownLetterMessage, SenderCharacterName),
        STRUCT_FIELD(ZoneProtoDownLetterMessage, Message)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetLetterMessageResult {
        ZoneProtoDownLetterMessage LetterMessage[5];
        uint8_t NextIndex;
        uint8_t Index;
        uint8_t RequestKey;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetLetterMessageResult,
        STRUCT_FIELD(FFXIVIpcGetLetterMessageResult, LetterMessage),
        STRUCT_FIELD(FFXIVIpcGetLetterMessageResult, NextIndex),
        STRUCT_FIELD(FFXIVIpcGetLetterMessageResult, Index),
        STRUCT_FIELD(FFXIVIpcGetLetterMessageResult, RequestKey)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetLetterMessageDetailResult {
        uint64_t SenderCharacterID;
        uint32_t Date;
        char Message[601];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetLetterMessageDetailResult,
        STRUCT_FIELD(FFXIVIpcGetLetterMessageDetailResult, SenderCharacterID),
        STRUCT_FIELD(FFXIVIpcGetLetterMessageDetailResult, Date),
        STRUCT_FIELD(FFXIVIpcGetLetterMessageDetailResult, Message)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcLetterResult {
        uint32_t UpPacketNo;
        uint64_t SenderCharacterID;
        uint32_t Date;
        ZoneProtoDownLetterBoxAppendItem AppendItem;
        uint32_t Result;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcLetterResult,
        STRUCT_FIELD(FFXIVIpcLetterResult, UpPacketNo),
        STRUCT_FIELD(FFXIVIpcLetterResult, SenderCharacterID),
        STRUCT_FIELD(FFXIVIpcLetterResult, Date),
        STRUCT_FIELD(FFXIVIpcLetterResult, AppendItem),
        STRUCT_FIELD(FFXIVIpcLetterResult, Result)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetLetterStatusResult {
        uint32_t NoreceiveCount;
        uint16_t ItemCount;
        uint8_t UnreadCount;
        uint8_t TotalCount;
        uint8_t GiftCount;
        uint8_t GmCount;
        uint8_t UnreadGmCount;
        uint8_t SupportCount;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetLetterStatusResult,
        STRUCT_FIELD(FFXIVIpcGetLetterStatusResult, NoreceiveCount),
        STRUCT_FIELD(FFXIVIpcGetLetterStatusResult, ItemCount),
        STRUCT_FIELD(FFXIVIpcGetLetterStatusResult, UnreadCount),
        STRUCT_FIELD(FFXIVIpcGetLetterStatusResult, TotalCount),
        STRUCT_FIELD(FFXIVIpcGetLetterStatusResult, GiftCount),
        STRUCT_FIELD(FFXIVIpcGetLetterStatusResult, GmCount),
        STRUCT_FIELD(FFXIVIpcGetLetterStatusResult, UnreadGmCount),
        STRUCT_FIELD(FFXIVIpcGetLetterStatusResult, SupportCount)
    );
#endif // DECLARE_PACKET_FIELDS

    // Item search structures
    struct FFFXIVIpcItemSearchResult {
        uint32_t CatalogID;
        uint32_t Result;
        uint8_t SubQuality;
        uint8_t MateriaCount;
        uint8_t Count;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFFXIVIpcItemSearchResult,
        STRUCT_FIELD(FFFXIVIpcItemSearchResult, CatalogID),
        STRUCT_FIELD(FFFXIVIpcItemSearchResult, Result),
        STRUCT_FIELD(FFFXIVIpcItemSearchResult, SubQuality),
        STRUCT_FIELD(FFFXIVIpcItemSearchResult, MateriaCount),
        STRUCT_FIELD(FFFXIVIpcItemSearchResult, Count)
    );
#endif // DECLARE_PACKET_FIELDS

    struct ZoneProtoDownItemSearchData {
        uint64_t ItemID;
        uint64_t SellRetainerID;
        uint64_t OwnerCharacterID;
        uint64_t SignatureID;
        uint32_t SellPrice;
        uint32_t BuyTax;
        uint32_t Stack;
        uint32_t CatalogID;
        uint32_t SellRealDate;
        uint16_t StorageID;
        uint16_t ContainerIndex;
        uint16_t Durability;
        uint16_t Refine;
        uint16_t Materia[8];
        char SellRetainerName[32];
        uint8_t SubQuality;
        uint8_t MateriaCount;
        uint8_t RegisterMarket;
        uint8_t Stain;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoDownItemSearchData,
        STRUCT_FIELD(ZoneProtoDownItemSearchData, ItemID),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, SellRetainerID),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, OwnerCharacterID),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, SignatureID),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, SellPrice),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, BuyTax),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, Stack),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, CatalogID),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, SellRealDate),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, StorageID),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, ContainerIndex),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, Durability),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, Refine),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, Materia),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, SellRetainerName),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, SubQuality),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, MateriaCount),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, RegisterMarket),
        STRUCT_FIELD(ZoneProtoDownItemSearchData, Stain)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetItemSearchListResult {
        ZoneProtoDownItemSearchData ItemSearchList[10];
        uint8_t NextIndex;
        uint8_t Index;
        uint8_t RequestKey;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetItemSearchListResult,
        STRUCT_FIELD(FFXIVIpcGetItemSearchListResult, ItemSearchList),
        STRUCT_FIELD(FFXIVIpcGetItemSearchListResult, NextIndex),
        STRUCT_FIELD(FFXIVIpcGetItemSearchListResult, Index),
        STRUCT_FIELD(FFXIVIpcGetItemSearchListResult, RequestKey)
    );
#endif // DECLARE_PACKET_FIELDS

    struct ZoneProtoDownItemHistoryData {
        uint32_t CatalogID;
        uint32_t SellPrice;
        uint32_t BuyRealDate;
        uint32_t Stack;
        uint8_t SubQuality;
        uint8_t MateriaCount;
        char BuyCharacterName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoDownItemHistoryData,
        STRUCT_FIELD(ZoneProtoDownItemHistoryData, CatalogID),
        STRUCT_FIELD(ZoneProtoDownItemHistoryData, SellPrice),
        STRUCT_FIELD(ZoneProtoDownItemHistoryData, BuyRealDate),
        STRUCT_FIELD(ZoneProtoDownItemHistoryData, Stack),
        STRUCT_FIELD(ZoneProtoDownItemHistoryData, SubQuality),
        STRUCT_FIELD(ZoneProtoDownItemHistoryData, MateriaCount),
        STRUCT_FIELD(ZoneProtoDownItemHistoryData, BuyCharacterName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetItemHistoryResult {
        uint32_t CatalogID;
        ZoneProtoDownItemHistoryData ItemHistoryList[20];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetItemHistoryResult,
        STRUCT_FIELD(FFXIVIpcGetItemHistoryResult, CatalogID),
        STRUCT_FIELD(FFXIVIpcGetItemHistoryResult, ItemHistoryList)
    );
#endif // DECLARE_PACKET_FIELDS

    struct ZoneProtoDownCatalogSearchData {
        uint32_t CatalogID;
        uint16_t StockCount;
        uint16_t RequestItemCount;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoDownCatalogSearchData,
        STRUCT_FIELD(ZoneProtoDownCatalogSearchData, CatalogID),
        STRUCT_FIELD(ZoneProtoDownCatalogSearchData, StockCount),
        STRUCT_FIELD(ZoneProtoDownCatalogSearchData, RequestItemCount)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcCatalogSearchResult {
        ZoneProtoDownCatalogSearchData CatalogList[20];
        uint32_t NextIndex;
        uint32_t Result;
        uint32_t Index;
        uint8_t RequestKey;
        uint8_t Type;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcCatalogSearchResult,
        STRUCT_FIELD(FFXIVIpcCatalogSearchResult, CatalogList),
        STRUCT_FIELD(FFXIVIpcCatalogSearchResult, NextIndex),
        STRUCT_FIELD(FFXIVIpcCatalogSearchResult, Result),
        STRUCT_FIELD(FFXIVIpcCatalogSearchResult, Index),
        STRUCT_FIELD(FFXIVIpcCatalogSearchResult, RequestKey),
        STRUCT_FIELD(FFXIVIpcCatalogSearchResult, Type)
    );
#endif // DECLARE_PACKET_FIELDS

    struct IntegrityStatus {
        uint8_t Slot;
        uint8_t __padding1;
        uint16_t Id;
        int16_t SystemParam;
        uint8_t __padding2;
        uint8_t __padding3;
        float Time;
        uint32_t Source;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(IntegrityStatus,
        STRUCT_FIELD(IntegrityStatus, Slot),
        STRUCT_FIELD(IntegrityStatus, Id),
        STRUCT_FIELD(IntegrityStatus, SystemParam),
        STRUCT_FIELD(IntegrityStatus, Time),
        STRUCT_FIELD(IntegrityStatus, Source)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcActionIntegrity {
        uint32_t ResultId;
        uint32_t Target;
        uint8_t ResultIndex;
        uint8_t ClassJob;
        uint8_t __padding1;
        uint8_t __padding2;
        uint32_t Hp;
        uint16_t Mp;
        uint16_t Tp;
        uint32_t HpMax;
        uint16_t MpMax;
        uint8_t StatusCount;
        uint8_t unknown_E0;
        IntegrityStatus Status[4];
        uint32_t __padding3;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcActionIntegrity,
        STRUCT_FIELD(FFXIVIpcActionIntegrity, ResultId),
        STRUCT_FIELD(FFXIVIpcActionIntegrity, Target),
        STRUCT_FIELD(FFXIVIpcActionIntegrity, ResultIndex),
        STRUCT_FIELD(FFXIVIpcActionIntegrity, ClassJob),
        STRUCT_FIELD(FFXIVIpcActionIntegrity, Hp),
        STRUCT_FIELD(FFXIVIpcActionIntegrity, Mp),
        STRUCT_FIELD(FFXIVIpcActionIntegrity, Tp),
        STRUCT_FIELD(FFXIVIpcActionIntegrity, HpMax),
        STRUCT_FIELD(FFXIVIpcActionIntegrity, MpMax),
        STRUCT_FIELD(FFXIVIpcActionIntegrity, StatusCount),
        STRUCT_FIELD(FFXIVIpcActionIntegrity, unknown_E0),
        STRUCT_FIELD(FFXIVIpcActionIntegrity, Status)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcActorControl {
        uint16_t category;
        uint16_t padding;
        uint32_t param1;
        uint32_t param2;
        uint32_t param3;
        uint32_t param4;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcActorControl,
        STRUCT_FIELD(FFXIVIpcActorControl, category),
        STRUCT_FIELD(FFXIVIpcActorControl, param1),
        STRUCT_FIELD(FFXIVIpcActorControl, param2),
        STRUCT_FIELD(FFXIVIpcActorControl, param3),
        STRUCT_FIELD(FFXIVIpcActorControl, param4)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcActorControlSelf {
        uint16_t category;
        uint16_t padding;
        uint32_t param1;
        uint32_t param2;
        uint32_t param3;
        uint32_t param4;
        uint32_t param5;
        uint32_t param6;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcActorControlSelf,
        STRUCT_FIELD(FFXIVIpcActorControlSelf, category),
        STRUCT_FIELD(FFXIVIpcActorControlSelf, param1),
        STRUCT_FIELD(FFXIVIpcActorControlSelf, param2),
        STRUCT_FIELD(FFXIVIpcActorControlSelf, param3),
        STRUCT_FIELD(FFXIVIpcActorControlSelf, param4),
        STRUCT_FIELD(FFXIVIpcActorControlSelf, param5),
        STRUCT_FIELD(FFXIVIpcActorControlSelf, param6)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcActorControlTarget {
        uint16_t category;
        uint16_t padding;
        uint32_t param1;
        uint32_t param2;
        uint32_t param3;
        uint32_t param4;
        uint64_t targetId;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcActorControlTarget,
        STRUCT_FIELD(FFXIVIpcActorControlTarget, category),
        STRUCT_FIELD(FFXIVIpcActorControlTarget, param1),
        STRUCT_FIELD(FFXIVIpcActorControlTarget, param2),
        STRUCT_FIELD(FFXIVIpcActorControlTarget, param3),
        STRUCT_FIELD(FFXIVIpcActorControlTarget, param4),
        STRUCT_FIELD(FFXIVIpcActorControlTarget, targetId)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcResting {
        uint32_t Hp;
        uint16_t Mp;
        uint16_t Tp;
        uint16_t Gp;
        uint32_t Unknown_3_2;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcResting,
        STRUCT_FIELD(FFXIVIpcResting, Hp),
        STRUCT_FIELD(FFXIVIpcResting, Mp),
        STRUCT_FIELD(FFXIVIpcResting, Tp),
        STRUCT_FIELD(FFXIVIpcResting, Gp),
        STRUCT_FIELD(FFXIVIpcResting, Unknown_3_2)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcRecastGroup {
        float Recast[80];
        float RecastMax[80];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcRecastGroup,
        STRUCT_FIELD(FFXIVIpcRecastGroup, Recast),
        STRUCT_FIELD(FFXIVIpcRecastGroup, RecastMax)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHudParam {
        uint8_t ClassJob;
        uint8_t Lv;
        uint8_t OrgLv;
        uint8_t LvSync;
        uint32_t Hp;
        uint32_t HpMax;
        uint16_t Mp;
        uint16_t MpMax;
        uint16_t Tp;
        uint8_t __padding1;
        uint8_t __padding2;
        StatusWork effect[30];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHudParam,
        STRUCT_FIELD(FFXIVIpcHudParam, ClassJob),
        STRUCT_FIELD(FFXIVIpcHudParam, Lv),
        STRUCT_FIELD(FFXIVIpcHudParam, OrgLv),
        STRUCT_FIELD(FFXIVIpcHudParam, LvSync),
        STRUCT_FIELD(FFXIVIpcHudParam, Hp),
        STRUCT_FIELD(FFXIVIpcHudParam, HpMax),
        STRUCT_FIELD(FFXIVIpcHudParam, Mp),
        STRUCT_FIELD(FFXIVIpcHudParam, MpMax),
        STRUCT_FIELD(FFXIVIpcHudParam, Tp),
        STRUCT_FIELD(FFXIVIpcHudParam, effect)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcActionResult {
        uint64_t MainTarget;
        uint16_t Action;
        uint8_t ActionArg;
        uint8_t ActionKind;
        uint32_t ActionKey;
        uint32_t RequestId;
        uint32_t ResultId;
        float LockTime;
        uint16_t DirTarget;
        uint8_t Flag;
        uint8_t TargetCount;
        uint32_t BallistaEntityId;
        CalcResult CalcResult[16];
        uint32_t Padding;
        uint64_t Target[16];
        uint16_t TargetPos[3];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcActionResult,
        STRUCT_FIELD(FFXIVIpcActionResult, MainTarget),
        STRUCT_FIELD(FFXIVIpcActionResult, Action),
        STRUCT_FIELD(FFXIVIpcActionResult, ActionArg),
        STRUCT_FIELD(FFXIVIpcActionResult, ActionKind),
        STRUCT_FIELD(FFXIVIpcActionResult, ActionKey),
        STRUCT_FIELD(FFXIVIpcActionResult, RequestId),
        STRUCT_FIELD(FFXIVIpcActionResult, ResultId),
        STRUCT_FIELD(FFXIVIpcActionResult, LockTime),
        STRUCT_FIELD(FFXIVIpcActionResult, DirTarget),
        STRUCT_FIELD(FFXIVIpcActionResult, Flag),
        STRUCT_FIELD(FFXIVIpcActionResult, TargetCount),
        STRUCT_FIELD(FFXIVIpcActionResult, BallistaEntityId),
        STRUCT_FIELD(FFXIVIpcActionResult, CalcResult),
        STRUCT_FIELD(FFXIVIpcActionResult, Padding),
        STRUCT_FIELD(FFXIVIpcActionResult, Target),
        STRUCT_FIELD(FFXIVIpcActionResult, TargetPos)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcActionResult1 {
        uint64_t MainTarget;
        uint16_t Action;
        uint8_t ActionArg;
        uint8_t ActionKind;
        uint32_t ActionKey;
        uint32_t RequestId;
        uint32_t ResultId;
        float LockTime;
        uint8_t Flag;
        uint8_t __padding1;
        uint16_t DirTarget;
        uint64_t Target;
        uint32_t BallistaEntityId;
        CalcResult CalcResult;
        uint32_t __padding2;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcActionResult1,
        STRUCT_FIELD(FFXIVIpcActionResult1, MainTarget),
        STRUCT_FIELD(FFXIVIpcActionResult1, Action),
        STRUCT_FIELD(FFXIVIpcActionResult1, ActionArg),
        STRUCT_FIELD(FFXIVIpcActionResult1, ActionKind),
        STRUCT_FIELD(FFXIVIpcActionResult1, ActionKey),
        STRUCT_FIELD(FFXIVIpcActionResult1, RequestId),
        STRUCT_FIELD(FFXIVIpcActionResult1, ResultId),
        STRUCT_FIELD(FFXIVIpcActionResult1, LockTime),
        STRUCT_FIELD(FFXIVIpcActionResult1, Flag),
        STRUCT_FIELD(FFXIVIpcActionResult1, DirTarget),
        STRUCT_FIELD(FFXIVIpcActionResult1, Target),
        STRUCT_FIELD(FFXIVIpcActionResult1, BallistaEntityId),
        STRUCT_FIELD(FFXIVIpcActionResult1, CalcResult)
    );
#endif // DECLARE_PACKET_FIELDS

    struct MountStruct {
        uint8_t Id;
        uint8_t EquipmentHead;
        uint8_t EquipmentBody;
        uint8_t EquipmentLeg;
        uint8_t Stain;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        float Time;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(MountStruct,
        STRUCT_FIELD(MountStruct, Id),
        STRUCT_FIELD(MountStruct, EquipmentHead),
        STRUCT_FIELD(MountStruct, EquipmentBody),
        STRUCT_FIELD(MountStruct, EquipmentLeg),
        STRUCT_FIELD(MountStruct, Stain),
        STRUCT_FIELD(MountStruct, Time)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcPlayerSpawn {
        uint32_t LayoutId;
        uint32_t NameId;
        uint32_t NpcId;
        uint32_t BindId;
        uint32_t ContentId;
        uint32_t OwnerId;
        uint32_t TriggerId;
        uint32_t ChannelingTarget;
        uint64_t MainTarget;
        uint16_t FATE;
        uint16_t WorldId;   
        uint8_t GMRank;
        uint8_t Index;
        uint8_t Mode;
        uint8_t ModeArgs;
        uint8_t ActiveType;
        uint8_t Rank;
        uint8_t ObjKind;
        uint8_t ObjType;
        uint32_t ParentId;
        uint8_t Voice;
        uint8_t BuddyScale;
        uint8_t CrestEnable;
        uint8_t Channeling;
        uint32_t Padding__;
        uint64_t Crest;
        uint64_t MainWeapon;
        uint64_t SubWeapon;
        uint64_t SystemWeapon;
        uint16_t Dir;
        uint16_t ModelCharaId;
        uint16_t Title;
        uint8_t Battalion;
        uint8_t Companion;
        uint8_t GrandCompany;
        uint8_t GrandCompanyRank;
        uint8_t Lv;
        uint8_t ClassJob;
        uint32_t Hp;
        uint16_t Mp;
        uint16_t Tp;
        uint32_t HpMax;
        uint16_t MpMax;
        uint16_t NormalAI;
        uint8_t OnlineStatus;
        uint8_t PermissionInvisibility;
        uint8_t PermissionInvisibility1;
        uint8_t FirstAttackType;
        uint64_t FirstAttackId;
        uint8_t LinkReply;
        uint8_t LinkCountLimit;
        uint8_t LinkGroup;
        uint8_t LinkRange;
        uint8_t LinkFamily;
        uint8_t LinkParent;
        uint8_t PoseEmote;
        uint8_t __padding1;
        uint32_t Flag;
        StatusWork Status[30];
        MountStruct Mount;
        uint8_t Name[32];
        uint8_t Customize[26];
        uint32_t Equipment[10];
        float Pos[3];
        uint8_t FreeCompanyTag[6];
        uint8_t PartsState[3];
        uint8_t State[3];
    };


#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcPlayerSpawn,
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, LayoutId),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, NameId),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, NpcId),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, BindId),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, ContentId),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, OwnerId),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, TriggerId),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, ChannelingTarget),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, MainTarget),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, FATE),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, WorldId),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, GMRank),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Index),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Mode),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, ModeArgs),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, ActiveType),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Rank),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, ObjKind),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, ObjType),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, ParentId),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Voice),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, BuddyScale),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, CrestEnable),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Channeling),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Padding__),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Crest),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, MainWeapon),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, SubWeapon),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, SystemWeapon),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Dir),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, ModelCharaId),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Title),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Battalion),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Companion),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, GrandCompany),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, GrandCompanyRank),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Lv),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, ClassJob),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Hp),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Mp),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Tp),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, HpMax),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, MpMax),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, NormalAI),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, OnlineStatus),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, PermissionInvisibility),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, PermissionInvisibility1),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, FirstAttackType),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, FirstAttackId),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, LinkReply),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, LinkCountLimit),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, LinkGroup),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, LinkRange),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, LinkFamily),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, LinkParent),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, PoseEmote),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Flag),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Status),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Mount),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Name),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Customize),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Equipment),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, Pos),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, FreeCompanyTag),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, PartsState),
        STRUCT_FIELD(FFXIVIpcPlayerSpawn, State)
    );
#endif // DECLARE_PACKET_FIELDS


    struct FFXIVIpcActorFreeSpawn {
        uint32_t spawnId;
        uint32_t actorId;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcActorFreeSpawn,
        STRUCT_FIELD(FFXIVIpcActorFreeSpawn, spawnId),
        STRUCT_FIELD(FFXIVIpcActorFreeSpawn, actorId)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcActorMove {
        uint8_t dir;
        uint8_t dirBeforeSlip;
        uint8_t flag;
        uint8_t flag2;
        uint8_t speed;
        uint8_t __padding1;
        uint16_t pos[3];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcActorMove,
        STRUCT_FIELD(FFXIVIpcActorMove, dir),
        STRUCT_FIELD(FFXIVIpcActorMove, dirBeforeSlip),
        STRUCT_FIELD(FFXIVIpcActorMove, flag),
        STRUCT_FIELD(FFXIVIpcActorMove, flag2),
        STRUCT_FIELD(FFXIVIpcActorMove, speed),
        STRUCT_FIELD(FFXIVIpcActorMove, pos)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcTransfer {
        uint16_t dir;
        uint8_t padding1;
        uint8_t padding2;
        float duration;
        uint8_t flag;
        uint8_t padding3;
        uint16_t pos[3];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcTransfer,
        STRUCT_FIELD(FFXIVIpcTransfer, dir),
        STRUCT_FIELD(FFXIVIpcTransfer, padding1),
        STRUCT_FIELD(FFXIVIpcTransfer, padding2),
        STRUCT_FIELD(FFXIVIpcTransfer, duration),
        STRUCT_FIELD(FFXIVIpcTransfer, flag),
        STRUCT_FIELD(FFXIVIpcTransfer, padding3),
        STRUCT_FIELD(FFXIVIpcTransfer, pos)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcWarp {
        uint16_t Dir;
        uint8_t Type;
        uint8_t TypeArg;
        uint32_t LayerSet;
        float x;
        float y;
        float z;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcWarp,
        STRUCT_FIELD(FFXIVIpcWarp, Dir),
        STRUCT_FIELD(FFXIVIpcWarp, Type),
        STRUCT_FIELD(FFXIVIpcWarp, TypeArg),
        STRUCT_FIELD(FFXIVIpcWarp, LayerSet),
        STRUCT_FIELD(FFXIVIpcWarp, x),
        STRUCT_FIELD(FFXIVIpcWarp, y),
        STRUCT_FIELD(FFXIVIpcWarp, z)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcActorCast {
        uint16_t Action;
        uint8_t ActionKind;
        uint8_t __padding1;
        uint32_t ActionKey;
        float CastTime;
        uint32_t Target;
        float Dir;
        uint32_t BallistaEntityId;
        uint16_t TargetPos[3];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcActorCast,
        STRUCT_FIELD(FFXIVIpcActorCast, Action),
        STRUCT_FIELD(FFXIVIpcActorCast, ActionKind),
        STRUCT_FIELD(FFXIVIpcActorCast, ActionKey),
        STRUCT_FIELD(FFXIVIpcActorCast, CastTime),
        STRUCT_FIELD(FFXIVIpcActorCast, Target),
        STRUCT_FIELD(FFXIVIpcActorCast, Dir),
        STRUCT_FIELD(FFXIVIpcActorCast, BallistaEntityId),
        STRUCT_FIELD(FFXIVIpcActorCast, TargetPos)
    );
#endif // DECLARE_PACKET_FIELDS

    struct ZoneProtoDownHater {
        uint32_t Id;
        uint8_t Rate;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoDownHater,
        STRUCT_FIELD(ZoneProtoDownHater, Id),
        STRUCT_FIELD(ZoneProtoDownHater, Rate)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHaterList {
        uint8_t Count;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        ZoneProtoDownHater List[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHaterList,
        STRUCT_FIELD(FFXIVIpcHaterList, Count),
        STRUCT_FIELD(FFXIVIpcHaterList, List)
    );
#endif // DECLARE_PACKET_FIELDS

    struct ZoneProtoDownHate {
        uint32_t Id;
        uint32_t Value;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoDownHate,
        STRUCT_FIELD(ZoneProtoDownHate, Id),
        STRUCT_FIELD(ZoneProtoDownHate, Value)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHateList {
        uint8_t Count;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        ZoneProtoDownHate List[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHateList,
        STRUCT_FIELD(FFXIVIpcHateList, Count),
        STRUCT_FIELD(FFXIVIpcHateList, List)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcTitleList {
        uint8_t TitleFlagsArray[48];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcTitleList,
        STRUCT_FIELD(FFXIVIpcTitleList, TitleFlagsArray)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcInitZone {
        uint16_t ZoneId;
        uint16_t TerritoryType;
        uint16_t TerritoryIndex;
        uint8_t __padding1;
        uint8_t __padding2;
        uint32_t LayerSetId;
        uint32_t LayoutId;
        uint8_t WeatherId;
        uint8_t Flag;
        uint16_t FestivalEid0;
        uint16_t FestivalPid0;
        uint16_t FestivalEid1;
        uint16_t FestivalPid1;
        uint8_t __padding3;
        uint8_t __padding4;
        float Pos[3];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcInitZone,
        STRUCT_FIELD(FFXIVIpcInitZone, ZoneId),
        STRUCT_FIELD(FFXIVIpcInitZone, TerritoryType),
        STRUCT_FIELD(FFXIVIpcInitZone, TerritoryIndex),
        STRUCT_FIELD(FFXIVIpcInitZone, LayerSetId),
        STRUCT_FIELD(FFXIVIpcInitZone, LayoutId),
        STRUCT_FIELD(FFXIVIpcInitZone, WeatherId),
        STRUCT_FIELD(FFXIVIpcInitZone, Flag),
        STRUCT_FIELD(FFXIVIpcInitZone, FestivalEid0),
        STRUCT_FIELD(FFXIVIpcInitZone, FestivalPid0),
        STRUCT_FIELD(FFXIVIpcInitZone, FestivalEid1),
        STRUCT_FIELD(FFXIVIpcInitZone, FestivalPid1),
        STRUCT_FIELD(FFXIVIpcInitZone, Pos)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcPlayerStatus {
        uint64_t CharaId;
        uint64_t Crest;
        uint32_t EntityId;
        uint32_t RestPoint;
        uint8_t Unknown8;
        uint8_t Unknown9;
        uint8_t Unknown10;
        uint8_t ExpansionLevel;
        uint8_t Race;
        uint8_t Tribe;
        uint8_t Sex;
        uint8_t ClassJob;
        uint8_t FirstClass;
        uint8_t GuardianDeity;
        uint8_t BirthMonth;
        uint8_t Birthday;
        uint8_t StartTown;
        uint8_t HomePoint;
        uint8_t GrandCompany;
        uint8_t Pet;
        uint8_t BuddyRank;
        uint8_t BuddyRankExceeded;
        uint8_t BuddySkillPoint;
        uint8_t BuddyCommand;
        uint8_t BuddyStain;
        uint8_t BuddyFavorite;
        uint8_t LegacyCompleteFlag;
        float BuddyTimer;
        uint32_t BuddyExp;
        uint32_t GCSupplySeed;
        uint32_t CatchCount;
        uint32_t UseBaitCatalogId;
        uint32_t PvPWeeklyPoint;
        uint16_t PvPMatchCount;
        uint16_t PvPWinCount;
        uint16_t PvPWeeklyMatchCount;
        uint16_t PvPWeeklyWinCount;
        uint16_t MVPPoint;
        uint16_t DailyQuestLastAcceptTime;
        uint8_t DailyQuestSeed;
        uint8_t TreasureObtainedFlag;
        uint8_t AdventureNotePhase;
        uint8_t RetainerCount;
        uint8_t Unknown4;
        uint8_t __padding5;
        uint8_t RelicKey;
        uint8_t RelicNoteKey;
        uint32_t Frontline01MatchCount;
        uint16_t Frontline01WeeklyMatchCount;
        uint8_t Unknown1[10];
        uint8_t Anima;
        uint8_t Unknown11;
        uint8_t MobHuntWeeklyOrder;
        uint8_t Name[32];
        uint8_t PSNId[17];
        uint16_t Lv[23];
        uint32_t Exp[23];
        uint8_t Reward[64];
        uint8_t Aetheryte[12];
        uint8_t FavoritePoint[3];
        uint8_t SuperFavoritePoint[1];
        uint8_t Discovery16[320];
        uint8_t Discovery32[80];
        uint8_t HowTo[32];
        uint8_t Companion[28];
        uint8_t ChocoboTaxiStand[8];
        uint8_t CutScene[91];
        uint8_t BuddyPossession[8];
        uint8_t BuddyEquip[3];
        uint8_t GCSupplyItemFlags[4];
        uint8_t GCSupplyClassLevel[11];
        char BuddyName[21];
        char BuddySkillLine[3];
        char MountList[9];
        uint8_t IsFishCatched[61];
        uint8_t IsSpotVisited[25];
        uint16_t ListFishId[18];
        uint16_t ListFishSize[18];
        uint8_t __padding6;
        uint32_t PvPPoint[3];
        uint8_t PvPRank[3];
        uint8_t PvPSkillPoint[3];
        uint8_t __padding9;
        uint8_t __padding10;
        uint32_t PvPAction[10];
        uint8_t BeastReputationRank[8];
        uint8_t __padding11;
        uint16_t BeastReputationValue[8];
        uint8_t RandomContentRewardCounter[9];
        uint16_t CycleTime[2];
        uint8_t PoseEmoteType[5];
        uint8_t __padding_;
        uint8_t Unknown;
        uint8_t ContentsNoteComplete[6];
        uint8_t SecretRecipeAcquireFlags[4];
        uint8_t SystemFlag[2];
        uint8_t GuildOrderClassClearFlags[28];
        uint8_t Unknown2[5];
        uint8_t RelicNoteCount[10];
        uint8_t RelicNoteFlags[2];
        uint8_t AdventureNoteSpotClearFlags[19];
        uint32_t Frontline01RankCount[3];
        uint16_t Frontline01WeeklyRankCount[3];
        uint8_t MobHuntOrderState[3];
        uint8_t MobHuntKillsCount[29];
        uint8_t TripleTriadAcquireFlags[20];
        uint8_t padding[100];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcPlayerStatus,
        STRUCT_FIELD(FFXIVIpcPlayerStatus, CharaId),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Crest),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, EntityId),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, RestPoint),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Unknown8),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Unknown9),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Unknown10),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, ExpansionLevel),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Race),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Tribe),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Sex),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, ClassJob),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, FirstClass),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, GuardianDeity),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, BirthMonth),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Birthday),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, StartTown),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, HomePoint),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, GrandCompany),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Pet),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, BuddyRank),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, BuddyRankExceeded),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, BuddySkillPoint),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, BuddyCommand),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, BuddyStain),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, BuddyFavorite),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, LegacyCompleteFlag),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, BuddyTimer),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, BuddyExp),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, GCSupplySeed),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, CatchCount),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, UseBaitCatalogId),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, PvPWeeklyPoint),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, PvPMatchCount),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, PvPWinCount),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, PvPWeeklyMatchCount),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, PvPWeeklyWinCount),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, MVPPoint),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, DailyQuestLastAcceptTime),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, DailyQuestSeed),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, TreasureObtainedFlag),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, AdventureNotePhase),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, RetainerCount),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Unknown4),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, RelicKey),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, RelicNoteKey),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Frontline01MatchCount),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Frontline01WeeklyMatchCount),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Unknown1),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Anima),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Unknown11),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, MobHuntWeeklyOrder),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Name),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, PSNId),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Lv),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Exp),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Reward),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Aetheryte),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, FavoritePoint),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, SuperFavoritePoint),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Discovery16),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Discovery32),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, HowTo),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Companion),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, ChocoboTaxiStand),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, CutScene),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, BuddyPossession),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, BuddyEquip),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, GCSupplyItemFlags),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, GCSupplyClassLevel),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, BuddyName),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, BuddySkillLine),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, MountList),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, IsFishCatched),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, IsSpotVisited),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, ListFishId),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, ListFishSize),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, PvPPoint),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, PvPRank),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, PvPSkillPoint),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, PvPAction),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, BeastReputationRank),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, BeastReputationValue),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, RandomContentRewardCounter),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, CycleTime),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, PoseEmoteType),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, ContentsNoteComplete),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, SecretRecipeAcquireFlags),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, SystemFlag),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, GuildOrderClassClearFlags),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Unknown2),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, RelicNoteCount),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, RelicNoteFlags),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, AdventureNoteSpotClearFlags),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Frontline01RankCount),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, Frontline01WeeklyRankCount),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, MobHuntOrderState),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, MobHuntKillsCount),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, TripleTriadAcquireFlags),
        STRUCT_FIELD(FFXIVIpcPlayerStatus, padding)
    );
#endif // DECLARE_PACKET_FIELDS


    struct FFXIVIpcBaseParam {
        uint32_t Param[50];
        uint32_t OriginalParam[6];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcBaseParam,
        STRUCT_FIELD(FFXIVIpcBaseParam, Param),
        STRUCT_FIELD(FFXIVIpcBaseParam, OriginalParam)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcFirstAttack {
        uint8_t Type;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        uint64_t Id;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcFirstAttack,
        STRUCT_FIELD(FFXIVIpcFirstAttack, Type),
        STRUCT_FIELD(FFXIVIpcFirstAttack, Id)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcCondition {
        uint8_t flags[12];
        uint32_t padding;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcCondition,
        STRUCT_FIELD(FFXIVIpcCondition, flags),
        STRUCT_FIELD(FFXIVIpcCondition, padding)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcPlayerStatusUpdate {
        uint8_t ClassJob;
        uint8_t __padding1;
        uint16_t Lv;
        uint16_t Lv1;
        uint16_t LvSync;
        uint32_t Exp;
        uint32_t RestPoint;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcPlayerStatusUpdate,
        STRUCT_FIELD(FFXIVIpcPlayerStatusUpdate, ClassJob),
        STRUCT_FIELD(FFXIVIpcPlayerStatusUpdate, Lv),
        STRUCT_FIELD(FFXIVIpcPlayerStatusUpdate, Lv1),
        STRUCT_FIELD(FFXIVIpcPlayerStatusUpdate, LvSync),
        STRUCT_FIELD(FFXIVIpcPlayerStatusUpdate, Exp),
        STRUCT_FIELD(FFXIVIpcPlayerStatusUpdate, RestPoint)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcChangeClass {
        uint8_t ClassJob;
        uint8_t Penalty;
        uint8_t Login;
        uint8_t __padding1;
        uint16_t Lv1;
        uint16_t Lv;
        uint32_t BorrowAction[10];
        uint8_t PhysicalBonus[6];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChangeClass,
        STRUCT_FIELD(FFXIVIpcChangeClass, ClassJob),
        STRUCT_FIELD(FFXIVIpcChangeClass, Penalty),
        STRUCT_FIELD(FFXIVIpcChangeClass, Login),
        STRUCT_FIELD(FFXIVIpcChangeClass, Lv1),
        STRUCT_FIELD(FFXIVIpcChangeClass, Lv),
        STRUCT_FIELD(FFXIVIpcChangeClass, BorrowAction),
        STRUCT_FIELD(FFXIVIpcChangeClass, PhysicalBonus)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcStatus {
        StatusWork effect[30];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcStatus,
        STRUCT_FIELD(FFXIVIpcStatus, effect)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcEquip {
        uint64_t MainWeapon;
        uint64_t SubWeapon;
        uint8_t CrestEnable;
        uint8_t __padding1;
        uint16_t PatternInvalid;
        uint32_t Equipment[10];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEquip,
        STRUCT_FIELD(FFXIVIpcEquip, MainWeapon),
        STRUCT_FIELD(FFXIVIpcEquip, SubWeapon),
        STRUCT_FIELD(FFXIVIpcEquip, CrestEnable),
        STRUCT_FIELD(FFXIVIpcEquip, PatternInvalid),
        STRUCT_FIELD(FFXIVIpcEquip, Equipment)
    );
#endif // DECLARE_PACKET_FIELDS

    struct ZoneProtoDownMateriaWork {
        uint16_t Type;
        uint8_t Grade;
    };

    struct ZoneProtoDownEquipWork {
        uint32_t CatalogId;
        uint32_t Pattern;
        uint64_t Signature;
        uint8_t HQ;
        uint8_t Stain;
        ZoneProtoDownMateriaWork Materia[5];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoDownEquipWork,
        STRUCT_FIELD(ZoneProtoDownEquipWork, CatalogId),
        STRUCT_FIELD(ZoneProtoDownEquipWork, Pattern),
        STRUCT_FIELD(ZoneProtoDownEquipWork, Signature),
        STRUCT_FIELD(ZoneProtoDownEquipWork, HQ),
        STRUCT_FIELD(ZoneProtoDownEquipWork, Stain),
        STRUCT_FIELD(ZoneProtoDownEquipWork, Materia)
    );
#endif // DECLARE_PACKET_FIELDS

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoDownMateriaWork,
        STRUCT_FIELD(ZoneProtoDownMateriaWork, Type),
        STRUCT_FIELD(ZoneProtoDownMateriaWork, Grade)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcInspect {
        uint8_t ObjType;
        uint8_t Sex;
        uint8_t ClassJob;
        uint8_t Lv;
        uint8_t LvSync;
        uint8_t __padding1;
        uint16_t Title;
        uint8_t GrandCompany;
        uint8_t GrandCompanyRank;
        uint8_t Flag;
        uint8_t __padding2;
        uint64_t Crest;
        uint8_t CrestEnable;
        uint8_t __padding3;
        uint8_t __padding4;
        uint8_t __padding5;
        uint64_t MainWeaponModelId;
        uint64_t SubWeaponModelId;
        uint16_t PatternInvalid;
        uint8_t Rank;
        uint8_t __padding6;
        uint32_t Exp;
        uint8_t ItemLv;
        uint8_t __padding7;
        uint8_t __padding8;
        uint8_t __padding9;
        ZoneProtoDownEquipWork Equipment[14];
        char Name[32];
        uint8_t PSNId[17];
        uint8_t Customize[26];
        uint8_t __padding10;
        uint8_t __padding11;
        uint8_t __padding12;
        uint32_t ModelId[10];
        uint8_t MasterName[32];
        uint8_t SkillLv[3];
        uint8_t __padding13;
        uint32_t BaseParam[50];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcInspect,
        STRUCT_FIELD(FFXIVIpcInspect, ObjType),
        STRUCT_FIELD(FFXIVIpcInspect, Sex),
        STRUCT_FIELD(FFXIVIpcInspect, ClassJob),
        STRUCT_FIELD(FFXIVIpcInspect, Lv),
        STRUCT_FIELD(FFXIVIpcInspect, LvSync),
        STRUCT_FIELD(FFXIVIpcInspect, Title),
        STRUCT_FIELD(FFXIVIpcInspect, GrandCompany),
        STRUCT_FIELD(FFXIVIpcInspect, GrandCompanyRank),
        STRUCT_FIELD(FFXIVIpcInspect, Flag),
        STRUCT_FIELD(FFXIVIpcInspect, Crest),
        STRUCT_FIELD(FFXIVIpcInspect, CrestEnable),
        STRUCT_FIELD(FFXIVIpcInspect, MainWeaponModelId),
        STRUCT_FIELD(FFXIVIpcInspect, SubWeaponModelId),
        STRUCT_FIELD(FFXIVIpcInspect, PatternInvalid),
        STRUCT_FIELD(FFXIVIpcInspect, Rank),
        STRUCT_FIELD(FFXIVIpcInspect, Exp),
        STRUCT_FIELD(FFXIVIpcInspect, ItemLv),
        STRUCT_FIELD(FFXIVIpcInspect, Equipment),
        STRUCT_FIELD(FFXIVIpcInspect, Name),
        STRUCT_FIELD(FFXIVIpcInspect, PSNId),
        STRUCT_FIELD(FFXIVIpcInspect, Customize),
        STRUCT_FIELD(FFXIVIpcInspect, ModelId),
        STRUCT_FIELD(FFXIVIpcInspect, MasterName),
        STRUCT_FIELD(FFXIVIpcInspect, SkillLv),
        STRUCT_FIELD(FFXIVIpcInspect, BaseParam)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcName {
        uint64_t contentId;
        char name[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcName,
        STRUCT_FIELD(FFXIVIpcName, contentId),
        STRUCT_FIELD(FFXIVIpcName, name)
    );
#endif // DECLARE_PACKET_FIELDS

    struct ZoneProtoDownItemStorage {
        uint32_t storageId;
        uint16_t type;
        int16_t index;
        uint32_t containerSize;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoDownItemStorage,
        STRUCT_FIELD(ZoneProtoDownItemStorage, storageId),
        STRUCT_FIELD(ZoneProtoDownItemStorage, type),
        STRUCT_FIELD(ZoneProtoDownItemStorage, index),
        STRUCT_FIELD(ZoneProtoDownItemStorage, containerSize)
    );
#endif // DECLARE_PACKET_FIELDS

    struct ZoneProtoDownNormalItem {
        uint16_t storageId;
        uint16_t containerIndex;
        uint32_t stack;
        uint32_t catalogId;
        uint64_t signatureId;
        uint8_t flags;
        uint8_t __padding1;
        uint16_t durability;
        uint16_t refine;
        uint8_t stain;
        uint8_t __padding2;
        uint32_t pattern;
        uint16_t materiaType[5];
        uint8_t materiaGrade[5];
        uint8_t buffer[5];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoDownNormalItem,
        STRUCT_FIELD(ZoneProtoDownNormalItem, storageId),
        STRUCT_FIELD(ZoneProtoDownNormalItem, containerIndex),
        STRUCT_FIELD(ZoneProtoDownNormalItem, stack),
        STRUCT_FIELD(ZoneProtoDownNormalItem, catalogId),
        STRUCT_FIELD(ZoneProtoDownNormalItem, signatureId),
        STRUCT_FIELD(ZoneProtoDownNormalItem, flags),
        STRUCT_FIELD(ZoneProtoDownNormalItem, durability),
        STRUCT_FIELD(ZoneProtoDownNormalItem, refine),
        STRUCT_FIELD(ZoneProtoDownNormalItem, stain),
        STRUCT_FIELD(ZoneProtoDownNormalItem, pattern),
        STRUCT_FIELD(ZoneProtoDownNormalItem, materiaType),
        STRUCT_FIELD(ZoneProtoDownNormalItem, materiaGrade),
        STRUCT_FIELD(ZoneProtoDownNormalItem, buffer)
    );
#endif // DECLARE_PACKET_FIELDS

    struct ZoneProtoDownGilItem {
        uint16_t storageId;
        uint16_t containerIndex;
        uint32_t stack;
        uint8_t subquarity;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        uint32_t catalogId;
        uint16_t buffer[4];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoDownGilItem,
        STRUCT_FIELD(ZoneProtoDownGilItem, storageId),
        STRUCT_FIELD(ZoneProtoDownGilItem, containerIndex),
        STRUCT_FIELD(ZoneProtoDownGilItem, stack),
        STRUCT_FIELD(ZoneProtoDownGilItem, subquarity),
        STRUCT_FIELD(ZoneProtoDownGilItem, catalogId),
        STRUCT_FIELD(ZoneProtoDownGilItem, buffer)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcNormalItem {
        uint32_t contextId;
        ZoneProtoDownNormalItem item;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcNormalItem,
        STRUCT_FIELD(FFXIVIpcNormalItem, contextId),
        STRUCT_FIELD(FFXIVIpcNormalItem, item)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcUpdateItem {
        uint32_t contextId;
        ZoneProtoDownNormalItem item;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcUpdateItem,
        STRUCT_FIELD(FFXIVIpcUpdateItem, contextId),
        STRUCT_FIELD(FFXIVIpcUpdateItem, item)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcItemSize {
        uint32_t contextId;
        int32_t size;
        uint32_t storageId;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcItemSize,
        STRUCT_FIELD(FFXIVIpcItemSize, contextId),
        STRUCT_FIELD(FFXIVIpcItemSize, size),
        STRUCT_FIELD(FFXIVIpcItemSize, storageId)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcItemStorage {
        uint32_t contextId;
        ZoneProtoDownItemStorage storage;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcItemStorage,
        STRUCT_FIELD(FFXIVIpcItemStorage, contextId),
        STRUCT_FIELD(FFXIVIpcItemStorage, storage)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGilItem {
        uint32_t contextId;
        ZoneProtoDownGilItem item;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGilItem,
        STRUCT_FIELD(FFXIVIpcGilItem, contextId),
        STRUCT_FIELD(FFXIVIpcGilItem, item)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcItemOperation {
        uint32_t contextId;
        uint8_t operationType;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        uint32_t srcEntity;
        uint32_t srcStorageId;
        int16_t srcContainerIndex;
        uint8_t __padding4;
        uint8_t __padding5;
        uint32_t srcStack;
        uint32_t srcCatalogId;
        uint32_t dstEntity;
        uint32_t dstStorageId;
        int16_t dstContainerIndex;
        uint8_t __padding6;
        uint8_t __padding7;
        uint32_t dstStack;
        uint32_t dstCatalogId;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcItemOperation,
        STRUCT_FIELD(FFXIVIpcItemOperation, contextId),
        STRUCT_FIELD(FFXIVIpcItemOperation, operationType),
        STRUCT_FIELD(FFXIVIpcItemOperation, srcEntity),
        STRUCT_FIELD(FFXIVIpcItemOperation, srcStorageId),
        STRUCT_FIELD(FFXIVIpcItemOperation, srcContainerIndex),
        STRUCT_FIELD(FFXIVIpcItemOperation, srcStack),
        STRUCT_FIELD(FFXIVIpcItemOperation, srcCatalogId),
        STRUCT_FIELD(FFXIVIpcItemOperation, dstEntity),
        STRUCT_FIELD(FFXIVIpcItemOperation, dstStorageId),
        STRUCT_FIELD(FFXIVIpcItemOperation, dstContainerIndex),
        STRUCT_FIELD(FFXIVIpcItemOperation, dstStack),
        STRUCT_FIELD(FFXIVIpcItemOperation, dstCatalogId)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcItemOperationBatch {
        uint32_t contextId;
        uint32_t operationId;
        uint8_t operationType;
        uint8_t errorType;
        uint8_t packetNum;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcItemOperationBatch,
        STRUCT_FIELD(FFXIVIpcItemOperationBatch, contextId),
        STRUCT_FIELD(FFXIVIpcItemOperationBatch, operationId),
        STRUCT_FIELD(FFXIVIpcItemOperationBatch, operationType),
        STRUCT_FIELD(FFXIVIpcItemOperationBatch, errorType),
        STRUCT_FIELD(FFXIVIpcItemOperationBatch, packetNum)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcEventStart {
        uint64_t targetId;
        uint32_t handlerId;
        uint8_t event;
        uint8_t flags;
        uint8_t __padding1;
        uint8_t __padding2;
        uint32_t eventArg;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEventStart,
        STRUCT_FIELD(FFXIVIpcEventStart, targetId),
        STRUCT_FIELD(FFXIVIpcEventStart, handlerId),
        STRUCT_FIELD(FFXIVIpcEventStart, event),
        STRUCT_FIELD(FFXIVIpcEventStart, flags),
        STRUCT_FIELD(FFXIVIpcEventStart, eventArg)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcMonsterNoteCategory {
        uint32_t contextId;
        uint8_t currentRank;
        uint8_t categoryIndex;
        uint8_t killCount[40];
        uint8_t __padding1;
        uint8_t __padding2;
        uint64_t completeFlags;
        uint32_t isNewFlags;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcMonsterNoteCategory,
        STRUCT_FIELD(FFXIVIpcMonsterNoteCategory, contextId),
        STRUCT_FIELD(FFXIVIpcMonsterNoteCategory, currentRank),
        STRUCT_FIELD(FFXIVIpcMonsterNoteCategory, categoryIndex),
        STRUCT_FIELD(FFXIVIpcMonsterNoteCategory, killCount),
        STRUCT_FIELD(FFXIVIpcMonsterNoteCategory, completeFlags),
        STRUCT_FIELD(FFXIVIpcMonsterNoteCategory, isNewFlags)
    );
#endif // DECLARE_PACKET_FIELDS

    // Template structs for variable-sized packets
    template<int ArgCount>
    struct FFXIVIpcMapMarkerN {
        uint8_t numOfMarkers;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        uint32_t iconIds[ArgCount];
        uint32_t layoutIds[ArgCount];
        uint32_t handlerIds[ArgCount];
    };

    template<int ArgCount>
    struct FFXIVIpcBattleTalkN {
        uint32_t handlerId;
        uint64_t talkerId;
        uint8_t kind;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        uint32_t nameId;
        uint32_t battleTalkId;
        uint32_t time;
        uint8_t numOfArgs;
        uint8_t __padding4;
        uint8_t __padding5;
        uint8_t __padding6;
        uint32_t args[ArgCount];
    };

    template<int ArgCount>
    struct FFXIVIpcEventLogMessageN {
        uint32_t handlerId;
        uint32_t messageId;
        uint8_t numOfArgs;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        uint32_t args[ArgCount];
        uint32_t unknown_1;
    };

    template<int ArgCount>
    struct FFXIVIpcUpdateEventSceneN {
        uint32_t handlerId;
        uint16_t sceneId;
        uint8_t numOfArgs;
        uint8_t __padding1;
        uint32_t args[ArgCount];
    };

    template<int ArgCount>
    struct FFXIVIpcPlayEventSceneN {
        uint64_t actorId;
        uint32_t eventId;
        uint16_t scene;
        uint16_t padding;
        uint32_t sceneFlags;
        uint8_t paramCount;
        uint8_t padding2[3];
        uint32_t params[ArgCount];
    };

    DECLARE_PACKET_FIELDS(FFXIVIpcPlayEventSceneN<8>,
        STRUCT_FIELD(FFXIVIpcPlayEventSceneN<8>, actorId),
        STRUCT_FIELD(FFXIVIpcPlayEventSceneN<8>, eventId),
        STRUCT_FIELD(FFXIVIpcPlayEventSceneN<8>, scene),
        STRUCT_FIELD(FFXIVIpcPlayEventSceneN<8>, padding),
        STRUCT_FIELD(FFXIVIpcPlayEventSceneN<8>, sceneFlags),
        STRUCT_FIELD(FFXIVIpcPlayEventSceneN<8>, paramCount),
        STRUCT_FIELD(FFXIVIpcPlayEventSceneN<8>, padding2),
        STRUCT_FIELD(FFXIVIpcPlayEventSceneN<8>, params)
    );

    struct FFXIVIpcDirectorPlayScene {
        uint64_t actorId;
        uint32_t eventId;
        uint16_t scene;
        uint16_t padding;
        uint32_t flags;
        uint32_t param3;
        uint8_t param4;
        uint8_t padding1[3];
        uint32_t param5;
        uint8_t unknown8[0x08];
        uint8_t unknown[0x38];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcDirectorPlayScene,
        STRUCT_FIELD(FFXIVIpcDirectorPlayScene, actorId),
        STRUCT_FIELD(FFXIVIpcDirectorPlayScene, eventId),
        STRUCT_FIELD(FFXIVIpcDirectorPlayScene, scene),
        STRUCT_FIELD(FFXIVIpcDirectorPlayScene, padding),
        STRUCT_FIELD(FFXIVIpcDirectorPlayScene, flags),
        STRUCT_FIELD(FFXIVIpcDirectorPlayScene, param3),
        STRUCT_FIELD(FFXIVIpcDirectorPlayScene, param4),
        STRUCT_FIELD(FFXIVIpcDirectorPlayScene, param5),
        STRUCT_FIELD(FFXIVIpcDirectorPlayScene, unknown8),
        STRUCT_FIELD(FFXIVIpcDirectorPlayScene, unknown)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcEventFinish {
        uint32_t handlerId;
        uint8_t event;
        uint8_t result;
        uint8_t __padding1;
        uint8_t __padding2;
        uint32_t eventArg;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEventFinish,
        STRUCT_FIELD(FFXIVIpcEventFinish, handlerId),
        STRUCT_FIELD(FFXIVIpcEventFinish, event),
        STRUCT_FIELD(FFXIVIpcEventFinish, result),
        STRUCT_FIELD(FFXIVIpcEventFinish, eventArg)
    );
#endif // DECLARE_PACKET_FIELDS

    template<int ArgCount>
    struct FFXIVIpcResumeEventSceneN {
        uint32_t handlerId;
        uint16_t sceneId;
        uint8_t resumeId;
        uint8_t numOfArgs;
        uint32_t args[ArgCount];
    };

    struct FFXIVIpcQuests {
        QuestData activeQuests[30];
    };


#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuests,
        STRUCT_FIELD(FFXIVIpcQuests, activeQuests)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcQuest {
        uint8_t index;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        QuestData questInfo;
    };


#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuest,
        STRUCT_FIELD(FFXIVIpcQuest, index),
        STRUCT_FIELD(FFXIVIpcQuest, questInfo)
    );
#endif // DECLARE_PACKET_FIELDS


    struct FFXIVIpcQuestCompleteList {
        uint8_t questCompleteMask[310];
        uint8_t unknownCompleteMask[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuestCompleteList,
        STRUCT_FIELD(FFXIVIpcQuestCompleteList, questCompleteMask),
        STRUCT_FIELD(FFXIVIpcQuestCompleteList, unknownCompleteMask)
    );
#endif // DECLARE_PACKET_FIELDS


    struct FFXIVIpcLegacyQuestCompleteList {
        uint8_t completeFlagArray[40];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcLegacyQuestCompleteList,
        STRUCT_FIELD(FFXIVIpcLegacyQuestCompleteList, completeFlagArray)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcQuestFinish {
        uint16_t questId;
        uint8_t flag1;
        uint8_t flag2;
        uint32_t padding;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuestFinish,
        STRUCT_FIELD(FFXIVIpcQuestFinish, questId),
        STRUCT_FIELD(FFXIVIpcQuestFinish, flag1),
        STRUCT_FIELD(FFXIVIpcQuestFinish, flag2),
        STRUCT_FIELD(FFXIVIpcQuestFinish, padding)
    );
#endif // DECLARE_PACKET_FIELDS

    template<int Size>
    struct FFXIVIpcNoticeN {
        uint32_t handlerId;
        uint8_t noticeId;
        uint8_t numOfArgs;
        uint8_t __padding1;
        uint8_t __padding2;
        uint32_t args[Size];
    };

    struct TrackerEntry {
        uint8_t active;
        uint8_t questIndex;
    };

    struct FFXIVIpcQuestTracker {
        TrackerEntry entry[5];
        uint16_t padding[3];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuestTracker,
        STRUCT_FIELD(FFXIVIpcQuestTracker, entry),
        STRUCT_FIELD(FFXIVIpcQuestTracker, padding)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcWeatherId {
        uint8_t WeatherId;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        float TransitionTime;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcWeatherId,
        STRUCT_FIELD(FFXIVIpcWeatherId, WeatherId),
        STRUCT_FIELD(FFXIVIpcWeatherId, TransitionTime)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcDiscoveryReply {
        uint32_t mapPartId;
        uint32_t mapId;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcDiscoveryReply,
        STRUCT_FIELD(FFXIVIpcDiscoveryReply, mapPartId),
        STRUCT_FIELD(FFXIVIpcDiscoveryReply, mapId)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcMoveTerritory {
        int16_t index;
        uint8_t territoryType;
        uint8_t zoneId;
        uint16_t worldId;
        uint16_t worldId1;
        int64_t landSetId;
        int64_t landId;
        int64_t landTerritoryId;
        char worldName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcMoveTerritory,
        STRUCT_FIELD(FFXIVIpcMoveTerritory, index),
        STRUCT_FIELD(FFXIVIpcMoveTerritory, territoryType),
        STRUCT_FIELD(FFXIVIpcMoveTerritory, zoneId),
        STRUCT_FIELD(FFXIVIpcMoveTerritory, worldId),
        STRUCT_FIELD(FFXIVIpcMoveTerritory, worldId1),
        STRUCT_FIELD(FFXIVIpcMoveTerritory, landSetId),
        STRUCT_FIELD(FFXIVIpcMoveTerritory, landId),
        STRUCT_FIELD(FFXIVIpcMoveTerritory, landTerritoryId),
        STRUCT_FIELD(FFXIVIpcMoveTerritory, worldName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcMoveInstance {
        uint64_t characterId;
        uint32_t entityId;
        uint16_t worldId;
        uint16_t worldId1;
        uint64_t unknown1;
        uint64_t unknown2;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcMoveInstance,
        STRUCT_FIELD(FFXIVIpcMoveInstance, characterId),
        STRUCT_FIELD(FFXIVIpcMoveInstance, entityId),
        STRUCT_FIELD(FFXIVIpcMoveInstance, worldId),
        STRUCT_FIELD(FFXIVIpcMoveInstance, worldId1),
        STRUCT_FIELD(FFXIVIpcMoveInstance, unknown1),
        STRUCT_FIELD(FFXIVIpcMoveInstance, unknown2)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcQuestRepeatFlags {
        uint8_t update;
        uint8_t repeatFlagArray[1];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuestRepeatFlags,
        STRUCT_FIELD(FFXIVIpcQuestRepeatFlags, update),
        STRUCT_FIELD(FFXIVIpcQuestRepeatFlags, repeatFlagArray)
    );
#endif // DECLARE_PACKET_FIELDS

    struct DailyQuest {
        uint16_t questId;
        uint8_t flags;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(DailyQuest,
        STRUCT_FIELD(DailyQuest, questId),
        STRUCT_FIELD(DailyQuest, flags)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcDailyQuests {
        uint8_t update;
        uint8_t __padding1;
        uint8_t __padding2;
        DailyQuest dailyQuestArray[12];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcDailyQuests,
        STRUCT_FIELD(FFXIVIpcDailyQuests, update),
        STRUCT_FIELD(FFXIVIpcDailyQuests, dailyQuestArray)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcUpdateContent {
        uint16_t territoryType;
        uint16_t padding;
        uint32_t kind;
        uint32_t value1;
        uint32_t value2;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcUpdateContent,
        STRUCT_FIELD(FFXIVIpcUpdateContent, territoryType),
        STRUCT_FIELD(FFXIVIpcUpdateContent, padding),
        STRUCT_FIELD(FFXIVIpcUpdateContent, kind),
        STRUCT_FIELD(FFXIVIpcUpdateContent, value1),
        STRUCT_FIELD(FFXIVIpcUpdateContent, value2)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcUpdateFindContent {
        uint32_t kind;
        uint32_t value1;
        uint32_t value2;
        uint32_t value3;
        uint32_t value4;
        uint16_t Unknown;
        uint16_t territoryType;
        uint16_t Unknown1;
        uint16_t Unknown2;
        uint16_t Unknown3;
        uint16_t Unknown4;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcUpdateFindContent,
        STRUCT_FIELD(FFXIVIpcUpdateFindContent, kind),
        STRUCT_FIELD(FFXIVIpcUpdateFindContent, value1),
        STRUCT_FIELD(FFXIVIpcUpdateFindContent, value2),
        STRUCT_FIELD(FFXIVIpcUpdateFindContent, value3),
        STRUCT_FIELD(FFXIVIpcUpdateFindContent, value4),
        STRUCT_FIELD(FFXIVIpcUpdateFindContent, Unknown),
        STRUCT_FIELD(FFXIVIpcUpdateFindContent, territoryType),
        STRUCT_FIELD(FFXIVIpcUpdateFindContent, Unknown1),
        STRUCT_FIELD(FFXIVIpcUpdateFindContent, Unknown2),
        STRUCT_FIELD(FFXIVIpcUpdateFindContent, Unknown3),
        STRUCT_FIELD(FFXIVIpcUpdateFindContent, Unknown4)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcNotifyFindContentStatus {
        uint16_t territoryType;
        uint16_t padding;
        uint8_t status;
        uint8_t tankRoleCount;
        uint8_t dpsRoleCount;
        uint8_t healerRoleCount;
        uint8_t matchingTime;
        uint8_t unknown;
        uint8_t unknown1;
        uint8_t unknown2;
        uint8_t unknown3;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcNotifyFindContentStatus,
        STRUCT_FIELD(FFXIVIpcNotifyFindContentStatus, territoryType),
        STRUCT_FIELD(FFXIVIpcNotifyFindContentStatus, padding),
        STRUCT_FIELD(FFXIVIpcNotifyFindContentStatus, status),
        STRUCT_FIELD(FFXIVIpcNotifyFindContentStatus, tankRoleCount),
        STRUCT_FIELD(FFXIVIpcNotifyFindContentStatus, dpsRoleCount),
        STRUCT_FIELD(FFXIVIpcNotifyFindContentStatus, healerRoleCount),
        STRUCT_FIELD(FFXIVIpcNotifyFindContentStatus, matchingTime),
        STRUCT_FIELD(FFXIVIpcNotifyFindContentStatus, unknown),
        STRUCT_FIELD(FFXIVIpcNotifyFindContentStatus, unknown1),
        STRUCT_FIELD(FFXIVIpcNotifyFindContentStatus, unknown2),
        STRUCT_FIELD(FFXIVIpcNotifyFindContentStatus, unknown3)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcFinishContentMatchToClient {
        uint8_t classJob;
        uint8_t progress;
        uint8_t playerNum;
        uint8_t unknown1;
        uint16_t territoryType;
        uint8_t __padding2;
        uint8_t __padding3;
        uint32_t flags;
        uint32_t finishContentMatchFlags;
        uint64_t startTime;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcFinishContentMatchToClient,
        STRUCT_FIELD(FFXIVIpcFinishContentMatchToClient, classJob),
        STRUCT_FIELD(FFXIVIpcFinishContentMatchToClient, progress),
        STRUCT_FIELD(FFXIVIpcFinishContentMatchToClient, playerNum),
        STRUCT_FIELD(FFXIVIpcFinishContentMatchToClient, unknown1),
        STRUCT_FIELD(FFXIVIpcFinishContentMatchToClient, territoryType),
        STRUCT_FIELD(FFXIVIpcFinishContentMatchToClient, flags),
        STRUCT_FIELD(FFXIVIpcFinishContentMatchToClient, finishContentMatchFlags),
        STRUCT_FIELD(FFXIVIpcFinishContentMatchToClient, startTime)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcContentAttainFlags {
        uint8_t raidAttainFlag[28];
        uint8_t dungeonAttainFlag[18];
        uint8_t guildOrderAttainFlag[10];
        uint8_t bossBattleAttainFlag[6];
        uint8_t colosseumAttainFlag[2];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcContentAttainFlags,
        STRUCT_FIELD(FFXIVIpcContentAttainFlags, raidAttainFlag),
        STRUCT_FIELD(FFXIVIpcContentAttainFlags, dungeonAttainFlag),
        STRUCT_FIELD(FFXIVIpcContentAttainFlags, guildOrderAttainFlag),
        STRUCT_FIELD(FFXIVIpcContentAttainFlags, bossBattleAttainFlag),
        STRUCT_FIELD(FFXIVIpcContentAttainFlags, colosseumAttainFlag)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcContentBonus {
        uint8_t bonusRoles[8];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcContentBonus,
        STRUCT_FIELD(FFXIVIpcContentBonus, bonusRoles)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcResponsePenalties {
        uint8_t penalties[2];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcResponsePenalties,
        STRUCT_FIELD(FFXIVIpcResponsePenalties, penalties)
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

    struct FFXIVIpcEorzeaTimeOffset {
        uint64_t timestamp;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEorzeaTimeOffset,
        STRUCT_FIELD(FFXIVIpcEorzeaTimeOffset, timestamp)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcMount {
        uint32_t id;
    };


#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcMount,
        STRUCT_FIELD(FFXIVIpcMount, id)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcDirectorVars {
        uint32_t directorId;
        uint8_t sequence;
        uint8_t flags;
        uint8_t vars[10];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcDirectorVars,
        STRUCT_FIELD(FFXIVIpcDirectorVars, directorId),
        STRUCT_FIELD(FFXIVIpcDirectorVars, sequence),
        STRUCT_FIELD(FFXIVIpcDirectorVars, flags),
        STRUCT_FIELD(FFXIVIpcDirectorVars, vars)
    );
#endif // DECLARE_PACKET_FIELDS

    // Housing structures
    struct FFXIVIpcHouseList {
        LandIdent LandSetId;
        uint32_t Subdivision;
        uint32_t unknown1;
        House Houses[30];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHouseList,
        STRUCT_FIELD(FFXIVIpcHouseList, LandSetId),
        STRUCT_FIELD(FFXIVIpcHouseList, Subdivision),
        STRUCT_FIELD(FFXIVIpcHouseList, unknown1),
        STRUCT_FIELD(FFXIVIpcHouseList, Houses)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHouse {
        uint16_t Block;
        uint16_t __padding1;
        uint16_t __padding2;
        uint16_t __padding3;
        House House;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHouse,
        STRUCT_FIELD(FFXIVIpcHouse, Block),
        STRUCT_FIELD(FFXIVIpcHouse, House)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcYardObjectList {
        uint8_t PacketIndex;
        uint8_t PacketEnd;
        uint8_t PacketEnd1;
        uint8_t PacketEnd2;
        Furniture YardObjects[400];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcYardObjectList,
        STRUCT_FIELD(FFXIVIpcYardObjectList, PacketIndex),
        STRUCT_FIELD(FFXIVIpcYardObjectList, PacketEnd),
        STRUCT_FIELD(FFXIVIpcYardObjectList, PacketEnd1),
        STRUCT_FIELD(FFXIVIpcYardObjectList, PacketEnd2),
        STRUCT_FIELD(FFXIVIpcYardObjectList, YardObjects)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcYardObject {
        uint8_t PacketIndex;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        Furniture YardObject;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcYardObject,
        STRUCT_FIELD(FFXIVIpcYardObject, PacketIndex),
        STRUCT_FIELD(FFXIVIpcYardObject, YardObject)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcInterior {
        uint16_t Window;
        uint16_t WindowColor;
        uint16_t Door;
        uint16_t DoorColor;
        uint32_t Interior[10];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcInterior,
        STRUCT_FIELD(FFXIVIpcInterior, Window),
        STRUCT_FIELD(FFXIVIpcInterior, WindowColor),
        STRUCT_FIELD(FFXIVIpcInterior, Door),
        STRUCT_FIELD(FFXIVIpcInterior, DoorColor),
        STRUCT_FIELD(FFXIVIpcInterior, Interior)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingAuction {
        uint32_t Price;
        uint32_t Timer;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingAuction,
        STRUCT_FIELD(FFXIVIpcHousingAuction, Price),
        STRUCT_FIELD(FFXIVIpcHousingAuction, Timer)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingProfile {
        LandIdent LandId;
        uint64_t OwnerId;
        uint32_t Like;
        uint8_t Welcome;
        uint8_t Size;
        uint8_t Padding;
        char Name[23];
        char Greeting[193];
        char OwnerName[31];
        char FCTag[7];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingProfile,
        STRUCT_FIELD(FFXIVIpcHousingProfile, LandId),
        STRUCT_FIELD(FFXIVIpcHousingProfile, OwnerId),
        STRUCT_FIELD(FFXIVIpcHousingProfile, Like),
        STRUCT_FIELD(FFXIVIpcHousingProfile, Welcome),
        STRUCT_FIELD(FFXIVIpcHousingProfile, Size),
        STRUCT_FIELD(FFXIVIpcHousingProfile, Name),
        STRUCT_FIELD(FFXIVIpcHousingProfile, Greeting),
        STRUCT_FIELD(FFXIVIpcHousingProfile, OwnerName),
        STRUCT_FIELD(FFXIVIpcHousingProfile, FCTag)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingHouseName {
        LandIdent LandId;
        char Name[23];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingHouseName,
        STRUCT_FIELD(FFXIVIpcHousingHouseName, LandId),
        STRUCT_FIELD(FFXIVIpcHousingHouseName, Name)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingGreeting {
        LandIdent LandId;
        uint8_t Greeting[193];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingGreeting,
        STRUCT_FIELD(FFXIVIpcHousingGreeting, LandId),
        STRUCT_FIELD(FFXIVIpcHousingGreeting, Greeting)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcCharaHousingLandData {
        uint8_t Index;
        uint32_t unknown;
        CharaLandData LandData;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcCharaHousingLandData,
        STRUCT_FIELD(FFXIVIpcCharaHousingLandData, Index),
        STRUCT_FIELD(FFXIVIpcCharaHousingLandData, unknown),
        STRUCT_FIELD(FFXIVIpcCharaHousingLandData, LandData)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcCharaHousing {
        CharaLandData FcLands;
        uint64_t padding;
        CharaLandData CharaLands;
        uint64_t padding1;
        CharaLandData apartment;
        uint64_t padding2;
        CharaLandData sharedHouse[2];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcCharaHousing,
        STRUCT_FIELD(FFXIVIpcCharaHousing, FcLands),
        STRUCT_FIELD(FFXIVIpcCharaHousing, CharaLands),
        STRUCT_FIELD(FFXIVIpcCharaHousing, apartment),
        STRUCT_FIELD(FFXIVIpcCharaHousing, sharedHouse)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingWelcome {
        uint8_t Welcome;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        LandIdent LandId;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingWelcome,
        STRUCT_FIELD(FFXIVIpcHousingWelcome, Welcome),
        STRUCT_FIELD(FFXIVIpcHousingWelcome, LandId)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcFurnitureListS {
        LandIdent LandId;
        int8_t u1;
        uint8_t packetNum;
        uint8_t packetTotal;
        uint8_t u2;
        Furniture Furnitures[100];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcFurnitureListS,
        STRUCT_FIELD(FFXIVIpcFurnitureListS, LandId),
        STRUCT_FIELD(FFXIVIpcFurnitureListS, packetNum),
        STRUCT_FIELD(FFXIVIpcFurnitureListS, packetTotal),
        STRUCT_FIELD(FFXIVIpcFurnitureListS, Furnitures)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcFurnitureListM {
        LandIdent LandId;
        int8_t u1;
        uint8_t packetNum;
        uint8_t packetTotal;
        uint8_t u2;
        Furniture Furnitures[150];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcFurnitureListM,
        STRUCT_FIELD(FFXIVIpcFurnitureListM, LandId),
        STRUCT_FIELD(FFXIVIpcFurnitureListM, packetNum),
        STRUCT_FIELD(FFXIVIpcFurnitureListM, packetTotal),
        STRUCT_FIELD(FFXIVIpcFurnitureListM, Furnitures)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcFurnitureListL {
        LandIdent LandId;
        int8_t u1;
        uint8_t packetNum;
        uint8_t packetTotal;
        uint8_t u2;
        Furniture Furnitures[200];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcFurnitureListL,
        STRUCT_FIELD(FFXIVIpcFurnitureListL, LandId),
        STRUCT_FIELD(FFXIVIpcFurnitureListL, packetNum),
        STRUCT_FIELD(FFXIVIpcFurnitureListL, packetTotal),
        STRUCT_FIELD(FFXIVIpcFurnitureListL, Furnitures)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcFurniture {
        uint16_t StorageId;
        uint8_t ContainerIndex;
        uint8_t __padding1;
        Furniture Furniture;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcFurniture,
        STRUCT_FIELD(FFXIVIpcFurniture, StorageId),
        STRUCT_FIELD(FFXIVIpcFurniture, ContainerIndex),
        STRUCT_FIELD(FFXIVIpcFurniture, Furniture)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingProfileList {
        LandIdent LandSetId;
        SimpleProfile ProfileList[30];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingProfileList,
        STRUCT_FIELD(FFXIVIpcHousingProfileList, LandSetId),
        STRUCT_FIELD(FFXIVIpcHousingProfileList, ProfileList)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingObjectTransform {
        uint16_t Dir;
        uint8_t UserData1;
        uint8_t UserData2;
        uint8_t ContainerIndex;
        uint8_t __padding1;
        uint16_t Pos[3];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingObjectTransform,
        STRUCT_FIELD(FFXIVIpcHousingObjectTransform, Dir),
        STRUCT_FIELD(FFXIVIpcHousingObjectTransform, UserData1),
        STRUCT_FIELD(FFXIVIpcHousingObjectTransform, UserData2),
        STRUCT_FIELD(FFXIVIpcHousingObjectTransform, ContainerIndex),
        STRUCT_FIELD(FFXIVIpcHousingObjectTransform, Pos)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingObjectColor {
        uint8_t Color;
        uint8_t __padding1;
        uint16_t StorageId;
        uint8_t ContainerIndex;
        uint8_t UserData;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingObjectColor,
        STRUCT_FIELD(FFXIVIpcHousingObjectColor, Color),
        STRUCT_FIELD(FFXIVIpcHousingObjectColor, StorageId),
        STRUCT_FIELD(FFXIVIpcHousingObjectColor, ContainerIndex),
        STRUCT_FIELD(FFXIVIpcHousingObjectColor, UserData)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingObjectTransformMulti {
        LandIdent LandId;
        HousingLayout LayoutInfos[10];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingObjectTransformMulti,
        STRUCT_FIELD(FFXIVIpcHousingObjectTransformMulti, LandId),
        STRUCT_FIELD(FFXIVIpcHousingObjectTransformMulti, LayoutInfos)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingGetPersonalRoomProfileListResult {
        uint64_t CharacterID;
        LandIdent HouseLandID;
        uint16_t TopRoomID;
        uint8_t __padding1;
        uint8_t __padding2;
        HousingPersonalRoomProfileData ProfileList[15];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingGetPersonalRoomProfileListResult,
        STRUCT_FIELD(FFXIVIpcHousingGetPersonalRoomProfileListResult, CharacterID),
        STRUCT_FIELD(FFXIVIpcHousingGetPersonalRoomProfileListResult, HouseLandID),
        STRUCT_FIELD(FFXIVIpcHousingGetPersonalRoomProfileListResult, TopRoomID),
        STRUCT_FIELD(FFXIVIpcHousingGetPersonalRoomProfileListResult, ProfileList)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingGetHouseBuddyStableListResult {
        uint64_t CharacterID;
        LandIdent LandID;
        uint8_t Page;
        uint8_t IsMyBuddy;
        uint8_t __padding1;
        uint8_t __padding2;
        HouseBuddyStableData BuddyList[15];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingGetHouseBuddyStableListResult,
        STRUCT_FIELD(FFXIVIpcHousingGetHouseBuddyStableListResult, CharacterID),
        STRUCT_FIELD(FFXIVIpcHousingGetHouseBuddyStableListResult, LandID),
        STRUCT_FIELD(FFXIVIpcHousingGetHouseBuddyStableListResult, Page),
        STRUCT_FIELD(FFXIVIpcHousingGetHouseBuddyStableListResult, IsMyBuddy),
        STRUCT_FIELD(FFXIVIpcHousingGetHouseBuddyStableListResult, BuddyList)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHouseTrainBuddyData {
        uint8_t OwnerRace;
        uint8_t OwnerSex;
        uint8_t Stain;
        uint8_t Equips[3];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHouseTrainBuddyData,
        STRUCT_FIELD(FFXIVIpcHouseTrainBuddyData, OwnerRace),
        STRUCT_FIELD(FFXIVIpcHouseTrainBuddyData, OwnerSex),
        STRUCT_FIELD(FFXIVIpcHouseTrainBuddyData, Stain),
        STRUCT_FIELD(FFXIVIpcHouseTrainBuddyData, Equips)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingObjectTransformMultiResult {
        LandIdent LandId;
        uint8_t Result;
        uint8_t __padding1;
        uint16_t FixIndexes[10];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingObjectTransformMultiResult,
        STRUCT_FIELD(FFXIVIpcHousingObjectTransformMultiResult, LandId),
        STRUCT_FIELD(FFXIVIpcHousingObjectTransformMultiResult, Result),
        STRUCT_FIELD(FFXIVIpcHousingObjectTransformMultiResult, FixIndexes)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingLogWithHouseName {
        uint32_t LogId;
        uint8_t Name[23];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingLogWithHouseName,
        STRUCT_FIELD(FFXIVIpcHousingLogWithHouseName, LogId),
        STRUCT_FIELD(FFXIVIpcHousingLogWithHouseName, Name)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHousingCombinedObjectStatus {
        uint16_t AddressData;
        uint16_t Kind[8];
        uint8_t Step[8];
        uint8_t Status[8];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingCombinedObjectStatus,
        STRUCT_FIELD(FFXIVIpcHousingCombinedObjectStatus, AddressData),
        STRUCT_FIELD(FFXIVIpcHousingCombinedObjectStatus, Kind),
        STRUCT_FIELD(FFXIVIpcHousingCombinedObjectStatus, Step),
        STRUCT_FIELD(FFXIVIpcHousingCombinedObjectStatus, Status)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcHouseBuddyModelData {
        uint16_t AddressData;
        uint8_t BuddyScale;
        uint8_t Stain;
        uint8_t Invisibility;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        uint32_t ModelEquips[3];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHouseBuddyModelData,
        STRUCT_FIELD(FFXIVIpcHouseBuddyModelData, AddressData),
        STRUCT_FIELD(FFXIVIpcHouseBuddyModelData, BuddyScale),
        STRUCT_FIELD(FFXIVIpcHouseBuddyModelData, Stain),
        STRUCT_FIELD(FFXIVIpcHouseBuddyModelData, Invisibility),
        STRUCT_FIELD(FFXIVIpcHouseBuddyModelData, ModelEquips)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcCreateObject {
        uint8_t  Index;
        uint8_t  Kind;
        uint8_t  Flag;
        uint8_t  __padding1;
        uint32_t BaseId;
        uint32_t EntityId;
        uint32_t LayoutId;
        uint32_t ContentId;
        uint32_t OwnerId;
        uint32_t BindLayoutId;
        float    Scale;
        uint16_t SharedGroupTimelineState;
        uint16_t Dir;
        uint16_t FATE;
        uint8_t  PermissionInvisibility;
        uint8_t  Args;
        uint32_t Args2;
        uint32_t Args3;
        FFXIVARR_POSITION3 Pos;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcCreateObject,
        STRUCT_FIELD(FFXIVIpcCreateObject, Index),
        STRUCT_FIELD(FFXIVIpcCreateObject, Kind),
        STRUCT_FIELD(FFXIVIpcCreateObject, Flag),
        STRUCT_FIELD(FFXIVIpcCreateObject, BaseId),
        STRUCT_FIELD(FFXIVIpcCreateObject, EntityId),
        STRUCT_FIELD(FFXIVIpcCreateObject, LayoutId),
        STRUCT_FIELD(FFXIVIpcCreateObject, ContentId),
        STRUCT_FIELD(FFXIVIpcCreateObject, OwnerId),
        STRUCT_FIELD(FFXIVIpcCreateObject, BindLayoutId),
        STRUCT_FIELD(FFXIVIpcCreateObject, Scale),
        STRUCT_FIELD(FFXIVIpcCreateObject, SharedGroupTimelineState),
        STRUCT_FIELD(FFXIVIpcCreateObject, Dir),
        STRUCT_FIELD(FFXIVIpcCreateObject, FATE),
        STRUCT_FIELD(FFXIVIpcCreateObject, PermissionInvisibility),
        STRUCT_FIELD(FFXIVIpcCreateObject, Args),
        STRUCT_FIELD(FFXIVIpcCreateObject, Args2),
        STRUCT_FIELD(FFXIVIpcCreateObject, Args3),
        STRUCT_FIELD(FFXIVIpcCreateObject, Pos)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcDeleteObject {
        uint8_t Index;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcDeleteObject,
        STRUCT_FIELD(FFXIVIpcDeleteObject, Index)
    );
#endif // DECLARE_PACKET_FIELDS

    // Free Company structures
    struct FcInviteCharacter {
        uint64_t CharacterID;
        uint64_t OnlineStatus;
        uint8_t GrandCompanyID;
        uint8_t Region;
        uint8_t SelectRegion;
        uint8_t Identity;
        char CharacterName[32];
        uint8_t GrandCompanyRank[3];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FcInviteCharacter,
        STRUCT_FIELD(FcInviteCharacter, CharacterID),
        STRUCT_FIELD(FcInviteCharacter, OnlineStatus),
        STRUCT_FIELD(FcInviteCharacter, GrandCompanyID),
        STRUCT_FIELD(FcInviteCharacter, Region),
        STRUCT_FIELD(FcInviteCharacter, SelectRegion),
        STRUCT_FIELD(FcInviteCharacter, Identity),
        STRUCT_FIELD(FcInviteCharacter, CharacterName),
        STRUCT_FIELD(FcInviteCharacter, GrandCompanyRank)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetFcInviteListResult {
        uint64_t FreeCompanyID;
        uint64_t CrestID;
        uint32_t CreateDate;
        uint8_t GrandCompanyID;
        char FcTag[7];
        FcInviteCharacter MasterCharacter;
        uint8_t __padding1;
        FcInviteCharacter InviteCharacter[3];
        char FreeCompanyName[22];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetFcInviteListResult,
        STRUCT_FIELD(FFXIVIpcGetFcInviteListResult, FreeCompanyID),
        STRUCT_FIELD(FFXIVIpcGetFcInviteListResult, CrestID),
        STRUCT_FIELD(FFXIVIpcGetFcInviteListResult, CreateDate),
        STRUCT_FIELD(FFXIVIpcGetFcInviteListResult, GrandCompanyID),
        STRUCT_FIELD(FFXIVIpcGetFcInviteListResult, FcTag),
        STRUCT_FIELD(FFXIVIpcGetFcInviteListResult, MasterCharacter),
        STRUCT_FIELD(FFXIVIpcGetFcInviteListResult, InviteCharacter),
        STRUCT_FIELD(FFXIVIpcGetFcInviteListResult, FreeCompanyName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetFcProfileResult {
        uint64_t TargetCharacterID;
        uint64_t FreeCompanyID;
        uint64_t CrestID;
        uint64_t LandID;
        uint32_t TargetEntityID;
        uint32_t CreateDate;
        uint32_t Reputation;
        uint16_t TotalMemberCount;
        uint16_t OnlineMemberCount;
        uint16_t FcActivity;
        uint16_t FcRole;
        uint8_t FcActiveTimeFlag;
        uint8_t FcJoinRequestFlag;
        uint8_t GrandCompanyID;
        uint8_t FcStatus;
        uint8_t FcRank;
        uint8_t JoinRequestCount;
        char FreeCompanyName[22];
        char FcTag[7];
        char MasterCharacterName[32];
        char CompanyMotto[193];
        char HouseName[23];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetFcProfileResult,
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, TargetCharacterID),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, FreeCompanyID),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, CrestID),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, LandID),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, TargetEntityID),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, CreateDate),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, Reputation),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, TotalMemberCount),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, OnlineMemberCount),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, FcActivity),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, FcRole),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, FcActiveTimeFlag),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, FcJoinRequestFlag),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, GrandCompanyID),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, FcStatus),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, FcRank),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, JoinRequestCount),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, FreeCompanyName),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, FcTag),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, MasterCharacterName),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, CompanyMotto),
        STRUCT_FIELD(FFXIVIpcGetFcProfileResult, HouseName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetFcHeaderResult {
        uint64_t FreeCompanyID;
        uint64_t CrestID;
        uint64_t FcPoint;
        uint64_t FcCredit;
        uint32_t Reputation;
        uint32_t NextPoint;
        uint32_t CurrentPoint;
        uint16_t TotalMemberCount;
        uint16_t OnlineMemberCount;
        uint8_t GrandCompanyID;
        uint8_t FcRank;
        char FreeCompanyName[22];
        char FcTag[7];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetFcHeaderResult,
        STRUCT_FIELD(FFXIVIpcGetFcHeaderResult, FreeCompanyID),
        STRUCT_FIELD(FFXIVIpcGetFcHeaderResult, CrestID),
        STRUCT_FIELD(FFXIVIpcGetFcHeaderResult, FcPoint),
        STRUCT_FIELD(FFXIVIpcGetFcHeaderResult, FcCredit),
        STRUCT_FIELD(FFXIVIpcGetFcHeaderResult, Reputation),
        STRUCT_FIELD(FFXIVIpcGetFcHeaderResult, NextPoint),
        STRUCT_FIELD(FFXIVIpcGetFcHeaderResult, CurrentPoint),
        STRUCT_FIELD(FFXIVIpcGetFcHeaderResult, TotalMemberCount),
        STRUCT_FIELD(FFXIVIpcGetFcHeaderResult, OnlineMemberCount),
        STRUCT_FIELD(FFXIVIpcGetFcHeaderResult, GrandCompanyID),
        STRUCT_FIELD(FFXIVIpcGetFcHeaderResult, FcRank),
        STRUCT_FIELD(FFXIVIpcGetFcHeaderResult, FreeCompanyName),
        STRUCT_FIELD(FFXIVIpcGetFcHeaderResult, FcTag)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetCompanyBoardResult {
        uint8_t Type;
        char CompanyBoard[193];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetCompanyBoardResult,
        STRUCT_FIELD(FFXIVIpcGetCompanyBoardResult, Type),
        STRUCT_FIELD(FFXIVIpcGetCompanyBoardResult, CompanyBoard)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FcHierarchy {
        uint64_t AuthorityList;
        uint16_t Count;
        uint8_t SortNo;
        char HierarchyName[46];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FcHierarchy,
        STRUCT_FIELD(FcHierarchy, AuthorityList),
        STRUCT_FIELD(FcHierarchy, Count),
        STRUCT_FIELD(FcHierarchy, SortNo),
        STRUCT_FIELD(FcHierarchy, HierarchyName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetFcHierarchyResult {
        char MasterCharacterName[32];
        FcHierarchy FcHierarchyList[16];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetFcHierarchyResult,
        STRUCT_FIELD(FFXIVIpcGetFcHierarchyResult, MasterCharacterName),
        STRUCT_FIELD(FFXIVIpcGetFcHierarchyResult, FcHierarchyList)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FcActivityList {
        uint64_t ID;
        uint32_t Date;
        uint32_t Param;
        uint16_t Type;
        uint8_t Sex;
        char CharacterName[32];
        char HierarchyName[46];
    };


#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FcActivityList,
        STRUCT_FIELD(FcActivityList, ID),
        STRUCT_FIELD(FcActivityList, Date),
        STRUCT_FIELD(FcActivityList, Param),
        STRUCT_FIELD(FcActivityList, Type),
        STRUCT_FIELD(FcActivityList, Sex),
        STRUCT_FIELD(FcActivityList, CharacterName),
        STRUCT_FIELD(FcActivityList, HierarchyName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetFcActivityListResult {
        uint16_t NextIndex;
        uint8_t Index;
        uint8_t RequestKey;
        FcActivityList ActivityList[5];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetFcActivityListResult,
        STRUCT_FIELD(FFXIVIpcGetFcActivityListResult, NextIndex),
        STRUCT_FIELD(FFXIVIpcGetFcActivityListResult, Index),
        STRUCT_FIELD(FFXIVIpcGetFcActivityListResult, RequestKey),
        STRUCT_FIELD(FFXIVIpcGetFcActivityListResult, ActivityList)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FcHierarchyLite {
        uint64_t AuthorityList;
        uint16_t Count;
        uint8_t SortNo;
    };


#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FcHierarchyLite,
        STRUCT_FIELD(FcHierarchyLite, AuthorityList),
        STRUCT_FIELD(FcHierarchyLite, Count),
        STRUCT_FIELD(FcHierarchyLite, SortNo)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetFcHierarchyLiteResult {
        FcHierarchyLite FcHierarchyList[16];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetFcHierarchyLiteResult,
        STRUCT_FIELD(FFXIVIpcGetFcHierarchyLiteResult, FcHierarchyList)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetCompanyMottoResult {
        uint16_t FcActivity;
        uint16_t FcRole;
        uint8_t Type;
        uint8_t FcActiveTimeFlag;
        uint8_t FcJoinRequestFlag;
        uint8_t JoinRequestCount;
        char CompanyMotto[193];
    };


#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetCompanyMottoResult,
        STRUCT_FIELD(FFXIVIpcGetCompanyMottoResult, FcActivity),
        STRUCT_FIELD(FFXIVIpcGetCompanyMottoResult, FcRole),
        STRUCT_FIELD(FFXIVIpcGetCompanyMottoResult, Type),
        STRUCT_FIELD(FFXIVIpcGetCompanyMottoResult, FcActiveTimeFlag),
        STRUCT_FIELD(FFXIVIpcGetCompanyMottoResult, FcJoinRequestFlag),
        STRUCT_FIELD(FFXIVIpcGetCompanyMottoResult, JoinRequestCount),
        STRUCT_FIELD(FFXIVIpcGetCompanyMottoResult, CompanyMotto)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetFcParamsResult {
        uint64_t CharacterID;
        uint64_t FcPoint;
        uint64_t FcCredit;
        uint64_t FcCreditAccumu;
        uint32_t CreateDate;
        uint32_t NextPoint;
        uint32_t CurrentPoint;
        uint32_t Reputation[3];
        uint8_t FcRank;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetFcParamsResult,
        STRUCT_FIELD(FFXIVIpcGetFcParamsResult, CharacterID),
        STRUCT_FIELD(FFXIVIpcGetFcParamsResult, FcPoint),
        STRUCT_FIELD(FFXIVIpcGetFcParamsResult, FcCredit),
        STRUCT_FIELD(FFXIVIpcGetFcParamsResult, FcCreditAccumu),
        STRUCT_FIELD(FFXIVIpcGetFcParamsResult, CreateDate),
        STRUCT_FIELD(FFXIVIpcGetFcParamsResult, NextPoint),
        STRUCT_FIELD(FFXIVIpcGetFcParamsResult, CurrentPoint),
        STRUCT_FIELD(FFXIVIpcGetFcParamsResult, Reputation),
        STRUCT_FIELD(FFXIVIpcGetFcParamsResult, FcRank)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetFcActionResult {
        uint64_t CharacterID;
        uint32_t ActiveActionList[3];
        uint32_t ActiveActionLeftTime[3];
        uint32_t StockActionList[15];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetFcActionResult,
        STRUCT_FIELD(FFXIVIpcGetFcActionResult, CharacterID),
        STRUCT_FIELD(FFXIVIpcGetFcActionResult, ActiveActionList),
        STRUCT_FIELD(FFXIVIpcGetFcActionResult, ActiveActionLeftTime),
        STRUCT_FIELD(FFXIVIpcGetFcActionResult, StockActionList)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGetFcMemoResult {
        uint64_t CharacterID;
        uint32_t UIParam;
        uint32_t UpdateDate;
        char FcMemo[97];
    };


#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGetFcMemoResult,
        STRUCT_FIELD(FFXIVIpcGetFcMemoResult, CharacterID),
        STRUCT_FIELD(FFXIVIpcGetFcMemoResult, UIParam),
        STRUCT_FIELD(FFXIVIpcGetFcMemoResult, UpdateDate),
        STRUCT_FIELD(FFXIVIpcGetFcMemoResult, FcMemo)
    );
#endif // DECLARE_PACKET_FIELDS


    struct FFXIVIpcFreeCompany {
        uint64_t Crest;
        char Tag[6];
    };


#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcFreeCompany,
        STRUCT_FIELD(FFXIVIpcFreeCompany, Crest),
        STRUCT_FIELD(FFXIVIpcFreeCompany, Tag)
    );
#endif // DECLARE_PACKET_FIELDS

    // Party structures
    struct FFXIVIpcPcPartyResult {
        uint32_t UpPacketNo;
        uint32_t Result;
    };


#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcPcPartyResult,
        STRUCT_FIELD(FFXIVIpcPcPartyResult, UpPacketNo),
        STRUCT_FIELD(FFXIVIpcPcPartyResult, Result)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcPcPartyUpdate {
        uint64_t ExecuteCharacterID;
        uint64_t TargetCharacterID;
        uint8_t ExecuteIdentity;
        uint8_t TargetIdentity;
        uint8_t UpdateStatus;
        uint8_t Count;
        char ExecuteCharacterName[32];
        char TargetCharacterName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcPcPartyUpdate,
        STRUCT_FIELD(FFXIVIpcPcPartyUpdate, ExecuteCharacterID),
        STRUCT_FIELD(FFXIVIpcPcPartyUpdate, TargetCharacterID),
        STRUCT_FIELD(FFXIVIpcPcPartyUpdate, ExecuteIdentity),
        STRUCT_FIELD(FFXIVIpcPcPartyUpdate, TargetIdentity),
        STRUCT_FIELD(FFXIVIpcPcPartyUpdate, UpdateStatus),
        STRUCT_FIELD(FFXIVIpcPcPartyUpdate, Count),
        STRUCT_FIELD(FFXIVIpcPcPartyUpdate, ExecuteCharacterName),
        STRUCT_FIELD(FFXIVIpcPcPartyUpdate, TargetCharacterName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcPartyRecruitResult {
        uint64_t TargetCharacterID;
        uint64_t Param;
        uint32_t Type;
        uint32_t Result;
        uint8_t Identity;
        char TargetName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcPartyRecruitResult,
        STRUCT_FIELD(FFXIVIpcPartyRecruitResult, TargetCharacterID),
        STRUCT_FIELD(FFXIVIpcPartyRecruitResult, Param),
        STRUCT_FIELD(FFXIVIpcPartyRecruitResult, Type),
        STRUCT_FIELD(FFXIVIpcPartyRecruitResult, Result),
        STRUCT_FIELD(FFXIVIpcPartyRecruitResult, Identity),
        STRUCT_FIELD(FFXIVIpcPartyRecruitResult, TargetName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct ZoneProtoDownStatusWork {
        uint16_t Id;
        int16_t SystemParam;
        float Time;
        uint32_t Source;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoDownStatusWork,
        STRUCT_FIELD(ZoneProtoDownStatusWork, Id),
        STRUCT_FIELD(ZoneProtoDownStatusWork, SystemParam),
        STRUCT_FIELD(ZoneProtoDownStatusWork, Time),
        STRUCT_FIELD(ZoneProtoDownStatusWork, Source)
    );
#endif // DECLARE_PACKET_FIELDS

    struct ZoneProtoDownPartyMember {
        char Name[32];
        uint64_t CharaId;
        uint32_t EntityId;
        uint32_t ParentEntityId;
        uint8_t Valid;
        uint8_t ClassJob;
        uint8_t Sex;
        uint8_t Role;
        uint8_t Lv;
        uint8_t LvSync;
        uint8_t ObjType;
        uint8_t BuddyCommand;
        uint32_t Hp;
        uint32_t HpMax;
        uint16_t Mp;
        uint16_t MpMax;
        uint16_t Tp;
        uint16_t TerritoryType;
        uint32_t PetEntityId;
        ZoneProtoDownStatusWork Status[30];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(ZoneProtoDownPartyMember,
        STRUCT_FIELD(ZoneProtoDownPartyMember, Name),
        STRUCT_FIELD(ZoneProtoDownPartyMember, CharaId),
        STRUCT_FIELD(ZoneProtoDownPartyMember, EntityId),
        STRUCT_FIELD(ZoneProtoDownPartyMember, ParentEntityId),
        STRUCT_FIELD(ZoneProtoDownPartyMember, Valid),
        STRUCT_FIELD(ZoneProtoDownPartyMember, ClassJob),
        STRUCT_FIELD(ZoneProtoDownPartyMember, Sex),
        STRUCT_FIELD(ZoneProtoDownPartyMember, Role),
        STRUCT_FIELD(ZoneProtoDownPartyMember, Lv),
        STRUCT_FIELD(ZoneProtoDownPartyMember, LvSync),
        STRUCT_FIELD(ZoneProtoDownPartyMember, ObjType),
        STRUCT_FIELD(ZoneProtoDownPartyMember, BuddyCommand),
        STRUCT_FIELD(ZoneProtoDownPartyMember, Hp),
        STRUCT_FIELD(ZoneProtoDownPartyMember, HpMax),
        STRUCT_FIELD(ZoneProtoDownPartyMember, Mp),
        STRUCT_FIELD(ZoneProtoDownPartyMember, MpMax),
        STRUCT_FIELD(ZoneProtoDownPartyMember, Tp),
        STRUCT_FIELD(ZoneProtoDownPartyMember, TerritoryType),
        STRUCT_FIELD(ZoneProtoDownPartyMember, PetEntityId),
        STRUCT_FIELD(ZoneProtoDownPartyMember, Status)
    );
#endif // DECLARE_PACKET_FIELDS


    struct FFXIVIpcUpdateParty {
        ZoneProtoDownPartyMember Member[8];
        uint64_t PartyID;
        uint64_t PartyLeaderContentID;
        uint8_t AllianceLocalIndex;
        uint8_t AllianceMemberCount;
        uint8_t __padding1;
        uint8_t __padding2;
        uint32_t AllianceFlags;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcUpdateParty,
        STRUCT_FIELD(FFXIVIpcUpdateParty, Member),
        STRUCT_FIELD(FFXIVIpcUpdateParty, PartyID),
        STRUCT_FIELD(FFXIVIpcUpdateParty, PartyLeaderContentID),
        STRUCT_FIELD(FFXIVIpcUpdateParty, AllianceLocalIndex),
        STRUCT_FIELD(FFXIVIpcUpdateParty, AllianceMemberCount),
        STRUCT_FIELD(FFXIVIpcUpdateParty, AllianceFlags)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcPartyPos {
        uint8_t Index;
        uint8_t __padding1;
        uint16_t TerritoryType;
        float X;
        float Y;
        float Z;
        uint32_t EntityId;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcPartyPos,
        STRUCT_FIELD(FFXIVIpcPartyPos, Index),
        STRUCT_FIELD(FFXIVIpcPartyPos, TerritoryType),
        STRUCT_FIELD(FFXIVIpcPartyPos, X),
        STRUCT_FIELD(FFXIVIpcPartyPos, Y),
        STRUCT_FIELD(FFXIVIpcPartyPos, Z),
        STRUCT_FIELD(FFXIVIpcPartyPos, EntityId)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcAlliancePos {
        uint8_t AllianceIndex;
        uint8_t PartyIndex;
        uint16_t TerritoryType;
        float X;
        float Y;
        float Z;
        uint32_t EntityId;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcAlliancePos,
        STRUCT_FIELD(FFXIVIpcAlliancePos, AllianceIndex),
        STRUCT_FIELD(FFXIVIpcAlliancePos, PartyIndex),
        STRUCT_FIELD(FFXIVIpcAlliancePos, TerritoryType),
        STRUCT_FIELD(FFXIVIpcAlliancePos, X),
        STRUCT_FIELD(FFXIVIpcAlliancePos, Y),
        STRUCT_FIELD(FFXIVIpcAlliancePos, Z),
        STRUCT_FIELD(FFXIVIpcAlliancePos, EntityId)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcUpdateAlliance {
        uint32_t AllianceFlags;
        uint8_t AllianceLocalIndex;
        uint8_t AllianceMemberCount;
        uint8_t __padding1;
        uint8_t __padding2;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcUpdateAlliance,
        STRUCT_FIELD(FFXIVIpcUpdateAlliance, AllianceFlags),
        STRUCT_FIELD(FFXIVIpcUpdateAlliance, AllianceLocalIndex),
        STRUCT_FIELD(FFXIVIpcUpdateAlliance, AllianceMemberCount)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGrandCompany {
        uint8_t GrandCompany;
        uint8_t GrandCompanyRank;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGrandCompany,
        STRUCT_FIELD(FFXIVIpcGrandCompany, GrandCompany),
        STRUCT_FIELD(FFXIVIpcGrandCompany, GrandCompanyRank)
    );
#endif // DECLARE_PACKET_FIELDS

    // Market Board structures
    struct FFXIVIpcMarketPriceHeader {
        uint32_t CatalogID;
        uint16_t MinPrice;
        uint16_t MaxPrice;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcMarketPriceHeader,
        STRUCT_FIELD(FFXIVIpcMarketPriceHeader, CatalogID),
        STRUCT_FIELD(FFXIVIpcMarketPriceHeader, MinPrice),
        STRUCT_FIELD(FFXIVIpcMarketPriceHeader, MaxPrice)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcMarketPrice {
        uint32_t CatalogID;
        uint32_t MinPrice;
        uint32_t MaxPrice;
        uint8_t DataCount;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        struct MarketItemListing {
            uint64_t ItemID;
            uint64_t RetainerID;
            uint64_t OwnerID;
            uint32_t UnitPrice;
            uint32_t Stack;
            uint32_t TotalTax;
            uint32_t CityID;
            uint32_t StallID;
            uint8_t Materia[5];
            uint8_t __padding1;
            uint8_t __padding2;
            uint8_t __padding3;
        } Listings[10];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcMarketPrice,
        STRUCT_FIELD(FFXIVIpcMarketPrice, CatalogID),
        STRUCT_FIELD(FFXIVIpcMarketPrice, MinPrice),
        STRUCT_FIELD(FFXIVIpcMarketPrice, MaxPrice),
        STRUCT_FIELD(FFXIVIpcMarketPrice, DataCount),
        STRUCT_FIELD(FFXIVIpcMarketPrice, Listings)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcRetainerList {
        uint64_t RetainerID[10];
        uint8_t RetainerCount;
        char RetainerName[10][32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcRetainerList,
        STRUCT_FIELD(FFXIVIpcRetainerList, RetainerID),
        STRUCT_FIELD(FFXIVIpcRetainerList, RetainerCount),
        STRUCT_FIELD(FFXIVIpcRetainerList, RetainerName)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcRetainerData {
        uint64_t RetainerID;
        uint8_t HireOrder;
        uint8_t ItemCount;
        uint16_t __padding1;
        uint32_t Gil;
        uint8_t SellingCount;
        uint8_t CityID;
        uint8_t ClassJob;
        uint8_t Level;
        uint8_t VentureID;
        uint8_t VentureComplete;
        uint16_t __padding2;
        uint32_t VentureCompleteTime;
        uint32_t VentureStartTime;
        char RetainerName[32];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcRetainerData,
        STRUCT_FIELD(FFXIVIpcRetainerData, RetainerID),
        STRUCT_FIELD(FFXIVIpcRetainerData, HireOrder),
        STRUCT_FIELD(FFXIVIpcRetainerData, ItemCount),
        STRUCT_FIELD(FFXIVIpcRetainerData, Gil),
        STRUCT_FIELD(FFXIVIpcRetainerData, SellingCount),
        STRUCT_FIELD(FFXIVIpcRetainerData, CityID),
        STRUCT_FIELD(FFXIVIpcRetainerData, ClassJob),
        STRUCT_FIELD(FFXIVIpcRetainerData, Level),
        STRUCT_FIELD(FFXIVIpcRetainerData, VentureID),
        STRUCT_FIELD(FFXIVIpcRetainerData, VentureComplete),
        STRUCT_FIELD(FFXIVIpcRetainerData, VentureCompleteTime),
        STRUCT_FIELD(FFXIVIpcRetainerData, VentureStartTime),
        STRUCT_FIELD(FFXIVIpcRetainerData, RetainerName)
    );
#endif // DECLARE_PACKET_FIELDS

    // Trade structures
    struct FFXIVIpcTradeCommand {
        uint32_t TradeID;
        uint8_t Type;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcTradeCommand,
        STRUCT_FIELD(FFXIVIpcTradeCommand, TradeID),
        STRUCT_FIELD(FFXIVIpcTradeCommand, Type)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcItemMessage {
        uint32_t ItemID;
        uint32_t Stack;
        uint8_t Type;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcItemMessage,
        STRUCT_FIELD(FFXIVIpcItemMessage, ItemID),
        STRUCT_FIELD(FFXIVIpcItemMessage, Stack),
        STRUCT_FIELD(FFXIVIpcItemMessage, Type)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcAliasItem {
        uint32_t ItemID;
        uint32_t AliasID;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcAliasItem,
        STRUCT_FIELD(FFXIVIpcAliasItem, ItemID),
        STRUCT_FIELD(FFXIVIpcAliasItem, AliasID)
    );
#endif // DECLARE_PACKET_FIELDS

    // Loot structures
    struct FFXIVIpcOpenTreasure {
        uint32_t ChestID;
        uint32_t ChestType;
        uint32_t Result;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcOpenTreasure,
        STRUCT_FIELD(FFXIVIpcOpenTreasure, ChestID),
        STRUCT_FIELD(FFXIVIpcOpenTreasure, ChestType),
        STRUCT_FIELD(FFXIVIpcOpenTreasure, Result)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcLootRight {
        uint32_t ChestID;
        uint8_t LootMode;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcLootRight,
        STRUCT_FIELD(FFXIVIpcLootRight, ChestID),
        STRUCT_FIELD(FFXIVIpcLootRight, LootMode)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcLootActionResult {
        uint32_t ChestID;
        uint32_t ItemID;
        uint8_t Result;
        uint8_t RolledValue;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcLootActionResult,
        STRUCT_FIELD(FFXIVIpcLootActionResult, ChestID),
        STRUCT_FIELD(FFXIVIpcLootActionResult, ItemID),
        STRUCT_FIELD(FFXIVIpcLootActionResult, Result),
        STRUCT_FIELD(FFXIVIpcLootActionResult, RolledValue)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcGameLog {
        uint32_t MessageID;
        uint32_t Category;
        uint32_t Param1;
        uint32_t Param2;
        uint32_t Param3;
        uint32_t Param4;
        uint32_t Param5;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcGameLog,
        STRUCT_FIELD(FFXIVIpcGameLog, MessageID),
        STRUCT_FIELD(FFXIVIpcGameLog, Category),
        STRUCT_FIELD(FFXIVIpcGameLog, Param1),
        STRUCT_FIELD(FFXIVIpcGameLog, Param2),
        STRUCT_FIELD(FFXIVIpcGameLog, Param3),
        STRUCT_FIELD(FFXIVIpcGameLog, Param4),
        STRUCT_FIELD(FFXIVIpcGameLog, Param5)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcTreasureOpenRight {
        uint32_t ChestID;
        uint8_t Rights[8];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcTreasureOpenRight,
        STRUCT_FIELD(FFXIVIpcTreasureOpenRight, ChestID),
        STRUCT_FIELD(FFXIVIpcTreasureOpenRight, Rights)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcOpenTreasureKeyUi {
        uint32_t ChestID;
        uint8_t RequiresKey;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcOpenTreasureKeyUi,
        STRUCT_FIELD(FFXIVIpcOpenTreasureKeyUi, ChestID),
        STRUCT_FIELD(FFXIVIpcOpenTreasureKeyUi, RequiresKey)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcLootItems {
        uint32_t ChestID;
        struct LootItemInfo {
            uint32_t ItemID;
            uint16_t Stack;
            uint8_t Quality;
            uint8_t __padding1;
        } Items[16];
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcLootItems,
        STRUCT_FIELD(FFXIVIpcLootItems, ChestID),
        STRUCT_FIELD(FFXIVIpcLootItems, Items)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcCreateTreasure {
        uint32_t ChestID;
        uint8_t ChestType;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        FFXIVARR_POSITION3 Position;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcCreateTreasure,
        STRUCT_FIELD(FFXIVIpcCreateTreasure, ChestID),
        STRUCT_FIELD(FFXIVIpcCreateTreasure, ChestType),
        STRUCT_FIELD(FFXIVIpcCreateTreasure, Position)
    );
#endif // DECLARE_PACKET_FIELDS

    struct FFXIVIpcTreasureFadeOut {
        uint32_t ChestID;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcTreasureFadeOut,
        STRUCT_FIELD(FFXIVIpcTreasureFadeOut, ChestID)
    );
#endif // DECLARE_PACKET_FIELDS

    // ============================================================================
    // NEW OPCODES FROM 3.35 GAP ANALYSIS (83 opcodes)
    // Field documentation derived from client handler decompilation analysis
    // ============================================================================

    // ============================================================================
    // Group 1: Content Finder (0x078-0x07C) - 5 opcodes
    // Handler (x64): 0x140E1B130, 0x140E1B160, 0x140E1B190
    // ============================================================================

    /**
     * @brief Notify client of content finder activity (0x078)
     */
    struct FFXIVIpcContentFinderNotify {
        uint32_t contentId;   ///< ContentFinderCondition.exd row ID
        uint32_t param1;      ///< Context-dependent: queue position, time estimate, penalty timer
        uint32_t param2;      ///< Reserved/additional context data
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcContentFinderNotify,
        STRUCT_FIELD(FFXIVIpcContentFinderNotify, contentId),
        STRUCT_FIELD(FFXIVIpcContentFinderNotify, param1),
        STRUCT_FIELD(FFXIVIpcContentFinderNotify, param2)
    );
#endif

    /**
     * @brief Update content finder queue status (0x079)
     */
    struct FFXIVIpcContentFinderUpdate {
        uint32_t contentId;   ///< ContentFinderCondition.exd row ID
        uint32_t status;      ///< Queue status: 0=none, 1=queued, 2=ready, 3=in-progress
        uint32_t param1;      ///< Status-specific data (e.g., wait time in seconds)
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcContentFinderUpdate,
        STRUCT_FIELD(FFXIVIpcContentFinderUpdate, contentId),
        STRUCT_FIELD(FFXIVIpcContentFinderUpdate, status),
        STRUCT_FIELD(FFXIVIpcContentFinderUpdate, param1)
    );
#endif

    /**
     * @brief Content finder queue result (0x07A)
     */
    struct FFXIVIpcContentFinderResult {
        uint32_t contentId;   ///< ContentFinderCondition.exd row ID
        uint32_t result;      ///< Result code: 0=success, 1=cancelled, 2=failed, 3=timeout, 4=disbanded
        uint32_t param1;      ///< Result-specific data
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcContentFinderResult,
        STRUCT_FIELD(FFXIVIpcContentFinderResult, contentId),
        STRUCT_FIELD(FFXIVIpcContentFinderResult, result),
        STRUCT_FIELD(FFXIVIpcContentFinderResult, param1)
    );
#endif

    // 0x07B and 0x07C use vtable callbacks (GameManager idx 244, type 9/11) - no packet struct needed

    // ============================================================================
    // Group 2: Request Item / Ready Check (0x0E4-0x0E7) - 4 opcodes
    // Handler (x64): 0x140CC1080 (0xE4), 0x140D16FF0 (0xE7)
    // ============================================================================

    /**
     * @brief Request high-quality item crafting prompt (0x0E4)
     */
    struct FFXIVIpcRequestHighQuality {
        uint32_t param1;      ///< Item ID or recipe ID
        uint32_t param2;      ///< Quantity or flags
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcRequestHighQuality,
        STRUCT_FIELD(FFXIVIpcRequestHighQuality, param1),
        STRUCT_FIELD(FFXIVIpcRequestHighQuality, param2)
    );
#endif

    /**
     * @brief Ready check notification to party members (0x0E7)
     */
    struct FFXIVIpcReadyCheckNotify {
        uint32_t param1;      ///< Ready check initiator entity ID or 0 for broadcast
        uint32_t param2;      ///< Bitmask of ready members or timeout in seconds
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcReadyCheckNotify,
        STRUCT_FIELD(FFXIVIpcReadyCheckNotify, param1),
        STRUCT_FIELD(FFXIVIpcReadyCheckNotify, param2)
    );
#endif

    // ============================================================================
    // Group 3: Free Company (0x11B-0x11D) - 3 opcodes
    // Handler (x64): 0x140D18560, 0x140D1E170, 0x140D185B0
    // ============================================================================

    /**
     * @brief FC member status update (0x11B)
     */
    struct FFXIVIpcFCMemberUpdate {
        uint64_t fcId;        ///< Free Company ID (from DB)
        uint32_t memberId;    ///< Character ID of the affected member
        uint32_t updateType;  ///< Update type: 0=joined, 1=left, 2=promoted, 3=demoted, 4=kicked
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcFCMemberUpdate,
        STRUCT_FIELD(FFXIVIpcFCMemberUpdate, fcId),
        STRUCT_FIELD(FFXIVIpcFCMemberUpdate, memberId),
        STRUCT_FIELD(FFXIVIpcFCMemberUpdate, updateType)
    );
#endif

    /**
     * @brief FC rank change notification (0x11C)
     */
    struct FFXIVIpcFCRankUpdate {
        uint32_t actorId;     ///< Entity ID of the player whose rank changed
        uint32_t newRank;     ///< New rank index (0=Master, 1-7=custom ranks)
        uint32_t oldRank;     ///< Previous rank index
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcFCRankUpdate,
        STRUCT_FIELD(FFXIVIpcFCRankUpdate, actorId),
        STRUCT_FIELD(FFXIVIpcFCRankUpdate, newRank),
        STRUCT_FIELD(FFXIVIpcFCRankUpdate, oldRank)
    );
#endif

    /**
     * @brief FC permissions update for a rank (0x11D)
     */
    struct FFXIVIpcFCPermissions {
        uint32_t actorId;     ///< Entity ID of the affected player
        uint64_t permissions; ///< Bitmask of permissions (see FcHierarchy.AuthorityList)
        uint32_t rank;        ///< Rank index these permissions apply to (0-7)
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcFCPermissions,
        STRUCT_FIELD(FFXIVIpcFCPermissions, actorId),
        STRUCT_FIELD(FFXIVIpcFCPermissions, permissions),
        STRUCT_FIELD(FFXIVIpcFCPermissions, rank)
    );
#endif

    // ============================================================================
    // Group 4: Quest Tracker UI (0x150-0x15B) - 12 opcodes
    // Handler (x64): 0x140CC2310-0x140CC24B0, 0x140CC0AF0
    // Manages the on-screen quest tracker widget (up to 5 quests visible)
    // ============================================================================

    /**
     * @brief Initialize quest tracker state (0x150)
     * Sent on login to populate the tracker UI
     */
    struct FFXIVIpcQuestTrackerInit {
        uint8_t data[64];     ///< Serialized tracker state: array of (questId:u16, sequence:u8, flags:u8) tuples
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuestTrackerInit,
        STRUCT_FIELD(FFXIVIpcQuestTrackerInit, data)
    );
#endif

    /**
     * @brief Add quest to tracker widget (0x151)
     */
    struct FFXIVIpcQuestTrackerAdd {
        uint16_t questId;     ///< Quest.exd row ID
        uint8_t index;        ///< Slot index in tracker (0-4 for 5 visible slots)
        uint8_t flags;        ///< Display flags: bit0=highlighted, bit1=completed objective blink
        uint32_t param;       ///< Quest sequence number or objective index to highlight
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuestTrackerAdd,
        STRUCT_FIELD(FFXIVIpcQuestTrackerAdd, questId),
        STRUCT_FIELD(FFXIVIpcQuestTrackerAdd, index),
        STRUCT_FIELD(FFXIVIpcQuestTrackerAdd, flags),
        STRUCT_FIELD(FFXIVIpcQuestTrackerAdd, param)
    );
#endif

    /**
     * @brief Remove quest from tracker widget (0x152)
     */
    struct FFXIVIpcQuestTrackerRemove {
        uint8_t index;        ///< Slot index to remove (0-4)
        uint8_t flags;        ///< Removal flags: bit0=animate out, bit1=quest completed
        uint16_t __padding;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuestTrackerRemove,
        STRUCT_FIELD(FFXIVIpcQuestTrackerRemove, index),
        STRUCT_FIELD(FFXIVIpcQuestTrackerRemove, flags)
    );
#endif

    /**
     * @brief Update tracked quest progress (0x153)
     */
    struct FFXIVIpcQuestTrackerUpdate {
        uint16_t questId;     ///< Quest.exd row ID
        uint8_t index;        ///< Slot index (0-4)
        uint8_t flags;        ///< Update flags: bit0=objective changed, bit1=refresh UI
        uint8_t data[32];     ///< Quest progress data: objective counts (8 bytes), todo list completion flags (8 bytes), sequence number, timer values
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuestTrackerUpdate,
        STRUCT_FIELD(FFXIVIpcQuestTrackerUpdate, questId),
        STRUCT_FIELD(FFXIVIpcQuestTrackerUpdate, index),
        STRUCT_FIELD(FFXIVIpcQuestTrackerUpdate, flags),
        STRUCT_FIELD(FFXIVIpcQuestTrackerUpdate, data)
    );
#endif

    /**
     * @brief Update quest objective map positions (0x154)
     * Used to update map markers for tracked quest objectives
     */
    struct FFXIVIpcQuestTrackerPosition {
        uint8_t data[32];     ///< Position data: array of (territoryId:u16, x:u16, y:u16, z:u16) for each objective
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuestTrackerPosition,
        STRUCT_FIELD(FFXIVIpcQuestTrackerPosition, data)
    );
#endif

    /**
     * @brief Mark tracked quest as complete (0x155)
     */
    struct FFXIVIpcQuestTrackerComplete {
        uint8_t index;        ///< Slot index (0-4)
        uint8_t flags;        ///< Completion flags: bit0=play fanfare, bit1=show reward preview
        uint16_t __padding;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuestTrackerComplete,
        STRUCT_FIELD(FFXIVIpcQuestTrackerComplete, index),
        STRUCT_FIELD(FFXIVIpcQuestTrackerComplete, flags)
    );
#endif

    /**
     * @brief Full sync of tracker state (0x156)
     * Sent when tracker needs complete refresh (e.g., after zone change)
     */
    struct FFXIVIpcQuestTrackerSync {
        uint8_t data[64];     ///< Full tracker serialization (same format as Init)
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuestTrackerSync,
        STRUCT_FIELD(FFXIVIpcQuestTrackerSync, data)
    );
#endif

    /**
     * @brief Clear specific tracker entries (0x157)
     */
    struct FFXIVIpcQuestTrackerClear {
        uint8_t data[32];     ///< Bitmask or list of slot indices to clear
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuestTrackerClear,
        STRUCT_FIELD(FFXIVIpcQuestTrackerClear, data)
    );
#endif

    /**
     * @brief Reorder tracked quests (0x158)
     */
    struct FFXIVIpcQuestTrackerReorder {
        uint16_t count;       ///< Number of entries in the order array (max 5)
        uint16_t __padding;
        uint8_t order[16];    ///< New order: order[newIndex] = oldIndex (e.g., [2,0,1,3,4] swaps slots)
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuestTrackerReorder,
        STRUCT_FIELD(FFXIVIpcQuestTrackerReorder, count),
        STRUCT_FIELD(FFXIVIpcQuestTrackerReorder, order)
    );
#endif

    /**
     * @brief Show/expand quest tracker widget (0x159)
     */
    struct FFXIVIpcQuestTrackerShow {
        uint32_t param;       ///< Show mode: 0=normal, 1=expanded, 2=minimized
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuestTrackerShow,
        STRUCT_FIELD(FFXIVIpcQuestTrackerShow, param)
    );
#endif

    /**
     * @brief Hide/collapse quest tracker widget (0x15A)
     */
    struct FFXIVIpcQuestTrackerHide {
        uint32_t param;       ///< Hide mode: 0=collapse, 1=fully hide, 2=fade out
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuestTrackerHide,
        STRUCT_FIELD(FFXIVIpcQuestTrackerHide, param)
    );
#endif

    /**
     * @brief Reset quest tracker to default state (0x15B)
     */
    struct FFXIVIpcQuestTrackerReset {
        uint32_t param;       ///< Reset mode: 0=clear all, 1=restore defaults, 2=hard reset
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcQuestTrackerReset,
        STRUCT_FIELD(FFXIVIpcQuestTrackerReset, param)
    );
#endif

    // ============================================================================
    // Group 5: Director Type 7 / Instance (0x168-0x16A) - 3 opcodes
    // Handler (x64): 0x140CBEE50, 0x140CBEE90, 0x140CC52A0
    // Directors manage instance content state (dungeons, trials, raids)
    // ============================================================================

    /**
     * @brief Initialize instance director (0x168)
     * Sent when entering instanced content to set up the director
     */
    struct FFXIVIpcDirector7Init {
        uint32_t actorId;     ///< Entity ID of the player (or 0 for broadcast)
        uint32_t directorId;  ///< Director ID: (ContentFinderCondition << 16) | instanceId
        uint32_t param1;      ///< Instance-specific: time limit, phase, or content flags
        uint32_t param2;      ///< Instance-specific: objective count, party size, sync level
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcDirector7Init,
        STRUCT_FIELD(FFXIVIpcDirector7Init, actorId),
        STRUCT_FIELD(FFXIVIpcDirector7Init, directorId),
        STRUCT_FIELD(FFXIVIpcDirector7Init, param1),
        STRUCT_FIELD(FFXIVIpcDirector7Init, param2)
    );
#endif

    /**
     * @brief Update instance director state (0x169)
     */
    struct FFXIVIpcDirector7Update {
        uint32_t actorId;     ///< Entity ID of the player (or 0 for broadcast)
        uint32_t directorId;  ///< Director ID
        uint32_t param1;      ///< Update-specific: remaining time, objectives completed, current phase
        uint32_t param2;      ///< Update-specific: phase change, wipe count, checkpoint flags
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcDirector7Update,
        STRUCT_FIELD(FFXIVIpcDirector7Update, actorId),
        STRUCT_FIELD(FFXIVIpcDirector7Update, directorId),
        STRUCT_FIELD(FFXIVIpcDirector7Update, param1),
        STRUCT_FIELD(FFXIVIpcDirector7Update, param2)
    );
#endif

    /**
     * @brief Instance director result/completion (0x16A)
     */
    struct FFXIVIpcDirector7Result {
        uint32_t actorId;     ///< Entity ID of the player (or 0 for broadcast)
        uint32_t result;      ///< Result code: 0=success/clear, 1=failed, 2=time out, 3=abandoned
        uint32_t param1;      ///< Clear time in seconds, or failure reason
        uint32_t param2;      ///< Bonus flags, chest count, or retry count
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcDirector7Result,
        STRUCT_FIELD(FFXIVIpcDirector7Result, actorId),
        STRUCT_FIELD(FFXIVIpcDirector7Result, result),
        STRUCT_FIELD(FFXIVIpcDirector7Result, param1),
        STRUCT_FIELD(FFXIVIpcDirector7Result, param2)
    );
#endif

    // ============================================================================
    // Group 6: Territory/Actor (0x195, 0x197) - 2 opcodes
    // Handler (x64): 0x140CBEE30 (0x195), 0x140CBEED0 (0x197)
    // ============================================================================

    /**
     * @brief Territory setup configuration (0x195)
     * Sent to configure territory-specific behavior
     */
    struct FFXIVIpcTerritorySetup {
        uint32_t actorId;       ///< Entity ID of the player
        uint32_t territoryTypeId; ///< TerritoryType.exd row ID
        uint32_t layerSetId;    ///< Active layer set (for housing/instance phases)
        uint32_t flags;         ///< Territory flags: bit0=pvp, bit1=sanctuary, bit2=no-mount, bit3=no-teleport, bit4=no-return
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcTerritorySetup,
        STRUCT_FIELD(FFXIVIpcTerritorySetup, actorId),
        STRUCT_FIELD(FFXIVIpcTerritorySetup, territoryTypeId),
        STRUCT_FIELD(FFXIVIpcTerritorySetup, layerSetId),
        STRUCT_FIELD(FFXIVIpcTerritorySetup, flags)
    );
#endif

    /**
     * @brief Actor gauge update (0x197)
     * Updates job-specific UI gauges (e.g., BLM Astral Fire, WAR Beast Gauge)
     */
    struct FFXIVIpcActorGauge {
        uint32_t actorId;     ///< Entity ID of the player
        uint8_t gaugeType;    ///< Gauge type ID (job-specific, see ClassJob.exd)
        uint8_t __padding1;
        uint16_t __padding2;
        uint32_t gaugeValue;  ///< Gauge value (stacks, timer, or packed bits)
        uint32_t param;       ///< Secondary gauge data (varies by job)
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcActorGauge,
        STRUCT_FIELD(FFXIVIpcActorGauge, actorId),
        STRUCT_FIELD(FFXIVIpcActorGauge, gaugeType),
        STRUCT_FIELD(FFXIVIpcActorGauge, gaugeValue),
        STRUCT_FIELD(FFXIVIpcActorGauge, param)
    );
#endif

    // ============================================================================
    // Group 7: Event Scene (0x1E0-0x1EA) - 11 opcodes
    // Handler (x64): 0x140CC8D20, 0x140CC7F20, 0x140CC6990, 0x140CC6A90, 0x140CC69E0, 0x140CC6A40
    // Event scenes are cutscenes and scripted NPC interactions
    // ============================================================================

    /**
     * @brief Start event scene/cutscene (0x1E0)
     */
    struct FFXIVIpcEventSceneStart {
        uint32_t sceneId;     ///< Scene ID from quest script or CutScene.exd
        uint32_t flags;       ///< Scene flags: bit0=skippable, bit1=black bars, bit2=hide UI
        uint32_t param1;      ///< Quest ID or event handler ID
        uint32_t param2;      ///< Scene variant or branch index
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEventSceneStart,
        STRUCT_FIELD(FFXIVIpcEventSceneStart, sceneId),
        STRUCT_FIELD(FFXIVIpcEventSceneStart, flags),
        STRUCT_FIELD(FFXIVIpcEventSceneStart, param1),
        STRUCT_FIELD(FFXIVIpcEventSceneStart, param2)
    );
#endif

    /**
     * @brief Play event scene segment (0x1E1)
     * Handler analyzes: +0x00=sceneId, +0x04=params with flags(1,1,1)
     */
    struct FFXIVIpcEventScenePlay {
        uint8_t sceneId;      ///< Scene segment index (0-255)
        uint8_t flags1;       ///< Playback flags: bit0=loop, bit1=reverse
        uint8_t flags2;       ///< Audio flags: bit0=voice, bit1=bgm, bit2=sfx
        uint8_t flags3;       ///< Camera flags: bit0=lock camera, bit1=fade transition
        uint8_t params[64];   ///< Scene parameters: actor positions, animation IDs, camera angles, timing data
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEventScenePlay,
        STRUCT_FIELD(FFXIVIpcEventScenePlay, sceneId),
        STRUCT_FIELD(FFXIVIpcEventScenePlay, flags1),
        STRUCT_FIELD(FFXIVIpcEventScenePlay, flags2),
        STRUCT_FIELD(FFXIVIpcEventScenePlay, flags3),
        STRUCT_FIELD(FFXIVIpcEventScenePlay, params)
    );
#endif

    /**
     * @brief Event scene sequence data (0x1E2)
     * Handler reads 310 bytes of sequence data + 32 bytes extra
     */
    struct FFXIVIpcEventSceneSequence {
        uint8_t sequenceData[310]; ///< Timeline/keyframe data for scene animation
        uint8_t extraData[32];     ///< Additional actor/camera keyframes
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEventSceneSequence,
        STRUCT_FIELD(FFXIVIpcEventSceneSequence, sequenceData),
        STRUCT_FIELD(FFXIVIpcEventSceneSequence, extraData)
    );
#endif

    /**
     * @brief Event scene dialogue choice prompt (0x1E3)
     * Handler: +0x00=u16 choiceId, +0x02=bool, +0x03=bool, +0x04=u8
     */
    struct FFXIVIpcEventSceneChoice {
        uint16_t choiceId;    ///< Dialogue choice index from quest script
        uint8_t flag1;        ///< Choice type: 0=normal, 1=timed, 2=consequence
        uint8_t flag2;        ///< Display mode: 0=list, 1=radial, 2=yes/no
        uint8_t param;        ///< Timeout in seconds (if timed) or default selection
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEventSceneChoice,
        STRUCT_FIELD(FFXIVIpcEventSceneChoice, choiceId),
        STRUCT_FIELD(FFXIVIpcEventSceneChoice, flag1),
        STRUCT_FIELD(FFXIVIpcEventSceneChoice, flag2),
        STRUCT_FIELD(FFXIVIpcEventSceneChoice, param)
    );
#endif

    /**
     * @brief Event scene action triggers (0x1E4)
     * Array of action IDs to execute during scene
     */
    struct FFXIVIpcEventSceneAction {
        int16_t actions[8];   ///< Action IDs: positive=play, negative=stop, 0=skip
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEventSceneAction,
        STRUCT_FIELD(FFXIVIpcEventSceneAction, actions)
    );
#endif

    /**
     * @brief Event scene camera control (0x1E5)
     * Handler: +0x00=cameraId, +0x04=params with flags(1,1)
     */
    struct FFXIVIpcEventSceneCamera {
        uint8_t cameraId;     ///< Camera track index (0-255)
        uint8_t flags1;       ///< Transition: 0=cut, 1=pan, 2=fade, 3=shake
        uint8_t flags2;       ///< FOV mode: 0=normal, 1=wide, 2=closeup
        uint8_t __padding;
        uint8_t params[32];   ///< Camera position/rotation/FOV keyframes
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEventSceneCamera,
        STRUCT_FIELD(FFXIVIpcEventSceneCamera, cameraId),
        STRUCT_FIELD(FFXIVIpcEventSceneCamera, flags1),
        STRUCT_FIELD(FFXIVIpcEventSceneCamera, flags2),
        STRUCT_FIELD(FFXIVIpcEventSceneCamera, params)
    );
#endif

    /**
     * @brief Event scene dialogue text (0x1E6)
     * Handler copies 200 bytes of dialogue data
     */
    struct FFXIVIpcEventSceneDialogue {
        uint8_t dialogueData[200]; ///< UTF-8 dialogue text with FFXIV markup tags
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEventSceneDialogue,
        STRUCT_FIELD(FFXIVIpcEventSceneDialogue, dialogueData)
    );
#endif

    /**
     * @brief End event scene (0x1E7)
     * Handler: +0x00=u16 sceneId, +0x02=bool isComplete
     */
    struct FFXIVIpcEventSceneEnd {
        uint16_t sceneId;     ///< Scene ID that ended
        uint8_t isComplete;   ///< 1=completed normally, 0=skipped/cancelled
        uint8_t __padding;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEventSceneEnd,
        STRUCT_FIELD(FFXIVIpcEventSceneEnd, sceneId),
        STRUCT_FIELD(FFXIVIpcEventSceneEnd, isComplete)
    );
#endif

    /**
     * @brief Event scene parameter update (0x1E8)
     */
    struct FFXIVIpcEventSceneParams {
        uint32_t param1;      ///< Event handler context ID
        uint8_t param2;       ///< Parameter slot index (0-31)
        uint8_t param3;       ///< Parameter type: 0=int, 1=float, 2=string
        uint16_t __padding;
        uint8_t data[32];     ///< Parameter value data
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEventSceneParams,
        STRUCT_FIELD(FFXIVIpcEventSceneParams, param1),
        STRUCT_FIELD(FFXIVIpcEventSceneParams, param2),
        STRUCT_FIELD(FFXIVIpcEventSceneParams, param3),
        STRUCT_FIELD(FFXIVIpcEventSceneParams, data)
    );
#endif

    /**
     * @brief Event scene raw data (0x1E9)
     */
    struct FFXIVIpcEventSceneData {
        uint8_t data[64];     ///< Raw scene data blob (context-dependent)
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEventSceneData,
        STRUCT_FIELD(FFXIVIpcEventSceneData, data)
    );
#endif

    /**
     * @brief Event scene complete callback (0x1EA)
     */
    struct FFXIVIpcEventSceneComplete {
        uint32_t actorId;     ///< Entity ID of the player
        uint32_t sceneId;     ///< Completed scene ID
        uint32_t result;      ///< Completion result: 0=ok, 1=skipped, 2=error
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcEventSceneComplete,
        STRUCT_FIELD(FFXIVIpcEventSceneComplete, actorId),
        STRUCT_FIELD(FFXIVIpcEventSceneComplete, sceneId),
        STRUCT_FIELD(FFXIVIpcEventSceneComplete, result)
    );
#endif

    // ============================================================================
    // Group 8: Housing Buddy/Stable (0x30A-0x310) - 7 opcodes
    // Handler (x64): 0x140CC1050, 0x140CC0ED0, 0x140CC1980, 0x140CC1470, 0x140CC14D0, 0x140CC1530
    // Manages companion chocobos stabled at housing estates
    // ============================================================================

    /**
     * @brief Initialize housing buddy context (0x30A)
     */
    struct FFXIVIpcHousingBuddyInit {
        uint32_t contextId;   ///< Stable interaction context (from NPC event)
        uint32_t param1;      ///< Max stable capacity for this estate size
        uint32_t param2;      ///< Current number of stabled chocobos
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingBuddyInit,
        STRUCT_FIELD(FFXIVIpcHousingBuddyInit, contextId),
        STRUCT_FIELD(FFXIVIpcHousingBuddyInit, param1),
        STRUCT_FIELD(FFXIVIpcHousingBuddyInit, param2)
    );
#endif

    /**
     * @brief Housing buddy list (0x30B)
     * Handler does memcpy of 128 bytes
     */
    struct FFXIVIpcHousingBuddyList {
        uint8_t data[128];    ///< Array of buddy entries: (ownerId:u64, name:char[20], color:u8, rank:u8) × N
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingBuddyList,
        STRUCT_FIELD(FFXIVIpcHousingBuddyList, data)
    );
#endif

    /**
     * @brief Housing buddy status update (0x30C)
     * Handler reads: +0x00=u8 status
     */
    struct FFXIVIpcHousingBuddyStatus {
        uint8_t status;       ///< Status: 0=idle, 1=training, 2=fed, 3=ready for training
        uint8_t flags;        ///< State flags: bit0=fed today, bit1=trained today
        uint16_t __padding;
        uint32_t param;       ///< Time until next action (seconds) or training progress %
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingBuddyStatus,
        STRUCT_FIELD(FFXIVIpcHousingBuddyStatus, status),
        STRUCT_FIELD(FFXIVIpcHousingBuddyStatus, flags),
        STRUCT_FIELD(FFXIVIpcHousingBuddyStatus, param)
    );
#endif

    /**
     * @brief Housing buddy state update (0x30D)
     */
    struct FFXIVIpcHousingBuddyUpdate {
        uint32_t param1;      ///< Buddy index or ID (slot 0-7)
        uint32_t param2;      ///< Update type: 0=color change, 1=name change, 2=stats update
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingBuddyUpdate,
        STRUCT_FIELD(FFXIVIpcHousingBuddyUpdate, param1),
        STRUCT_FIELD(FFXIVIpcHousingBuddyUpdate, param2)
    );
#endif

    /**
     * @brief Housing buddy interaction result (0x30E)
     */
    struct FFXIVIpcHousingBuddyAction {
        uint32_t actionId;    ///< Action type: 0=feed, 1=train, 2=clean, 3=groom
        uint32_t targetId;    ///< Buddy slot index (0-7) or chocobo entity ID
        uint32_t result;      ///< Result: 0=success, 1=failed, 2=not enough feed, 3=already done today
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingBuddyAction,
        STRUCT_FIELD(FFXIVIpcHousingBuddyAction, actionId),
        STRUCT_FIELD(FFXIVIpcHousingBuddyAction, targetId),
        STRUCT_FIELD(FFXIVIpcHousingBuddyAction, result)
    );
#endif

    /**
     * @brief Housing buddy operation result (0x30F)
     */
    struct FFXIVIpcHousingBuddyResult {
        int32_t result;       ///< Result code: negative=error, 0=success, positive=reward/bonus
        uint32_t param1;      ///< Context data: exp gained, gil cost, item consumed, stat increase
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingBuddyResult,
        STRUCT_FIELD(FFXIVIpcHousingBuddyResult, result),
        STRUCT_FIELD(FFXIVIpcHousingBuddyResult, param1)
    );
#endif

    /**
     * @brief Housing buddy session complete (0x310)
     */
    struct FFXIVIpcHousingBuddyComplete {
        uint8_t data[32];     ///< Session summary: exp changes, color changes, ability unlocks, rank progress
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcHousingBuddyComplete,
        STRUCT_FIELD(FFXIVIpcHousingBuddyComplete, data)
    );
#endif

    // ============================================================================
    // Group 9: Chocobo Stable Commands (0x330-0x33A) - 11 opcodes
    // Handler (x64): 0x140CC1110, 0x140CC1150, 0x140CC1250, 0x140CBEDF0, 0x140CBEE50, 0x140CBEEB0
    // Manages chocobo stable UI at estates (different from Housing Buddy)
    // ============================================================================

    /**
     * @brief List of stabled chocobos (0x330)
     */
    struct FFXIVIpcChocoboStableList {
        uint32_t count;       ///< Number of chocobos in stable (0-8 typically)
        uint32_t data[8];     ///< Packed data for each chocobo: (ownerId:u16 << 16) | (color:u8 << 8) | rank:u8
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboStableList,
        STRUCT_FIELD(FFXIVIpcChocoboStableList, count),
        STRUCT_FIELD(FFXIVIpcChocoboStableList, data)
    );
#endif

    /**
     * @brief Select chocobo from stable list (0x331)
     */
    struct FFXIVIpcChocoboStableSelect {
        int32_t selection;    ///< Selected slot index (0-7), -1 for none/cancel
        uint32_t param;       ///< Action to perform: 0=view, 1=train, 2=feed, 3=color
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboStableSelect,
        STRUCT_FIELD(FFXIVIpcChocoboStableSelect, selection),
        STRUCT_FIELD(FFXIVIpcChocoboStableSelect, param)
    );
#endif

    /**
     * @brief Detailed chocobo stable data (0x332)
     */
    struct FFXIVIpcChocoboStableData {
        uint8_t data[64];     ///< Full chocobo data: name[20], stats[12], exp:u32, abilities[8], color:u8, pedigree:u8, rank:u8, reserved[9]
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboStableData,
        STRUCT_FIELD(FFXIVIpcChocoboStableData, data)
    );
#endif

    /**
     * @brief Update stable chocobo state (0x333)
     */
    struct FFXIVIpcChocoboStableUpdate {
        uint32_t param1;      ///< Chocobo slot index (0-7)
        uint32_t param2;      ///< Update flags: bit0=exp, bit1=stats, bit2=color, bit3=abilities
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboStableUpdate,
        STRUCT_FIELD(FFXIVIpcChocoboStableUpdate, param1),
        STRUCT_FIELD(FFXIVIpcChocoboStableUpdate, param2)
    );
#endif

    /**
     * @brief Stable action result (0x334)
     */
    struct FFXIVIpcChocoboStableResult {
        uint32_t result;      ///< Result: 0=success, 1=not enough greens, 2=stable full, 3=cooldown
        uint32_t param;       ///< Context: cooldown time (seconds), required item count, greens consumed
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboStableResult,
        STRUCT_FIELD(FFXIVIpcChocoboStableResult, result),
        STRUCT_FIELD(FFXIVIpcChocoboStableResult, param)
    );
#endif

    /**
     * @brief Stable training action (0x335)
     */
    struct FFXIVIpcChocoboStableAction1 {
        uint32_t actorId;     ///< Entity ID of the player performing action
        uint32_t actionId;    ///< Action: 0=feed, 1=train, 2=dye, 3=rename
        uint32_t param;       ///< Action param: item ID for feed/dye, stat ID for train
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboStableAction1,
        STRUCT_FIELD(FFXIVIpcChocoboStableAction1, actorId),
        STRUCT_FIELD(FFXIVIpcChocoboStableAction1, actionId),
        STRUCT_FIELD(FFXIVIpcChocoboStableAction1, param)
    );
#endif

    /**
     * @brief Extended stable action with multiple params (0x336)
     */
    struct FFXIVIpcChocoboStableAction2 {
        uint32_t actorId;     ///< Entity ID of the player
        uint32_t params[4];   ///< params[0]=action, params[1]=slot, params[2]=item, params[3]=quantity
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboStableAction2,
        STRUCT_FIELD(FFXIVIpcChocoboStableAction2, actorId),
        STRUCT_FIELD(FFXIVIpcChocoboStableAction2, params)
    );
#endif

    /**
     * @brief Overall stable status (0x337)
     */
    struct FFXIVIpcChocoboStableStatus {
        uint32_t param;       ///< Packed status: (maxSlots:u8 << 24) | (usedSlots:u8 << 16) | (cleanliness:u8 << 8) | flags:u8
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboStableStatus,
        STRUCT_FIELD(FFXIVIpcChocoboStableStatus, param)
    );
#endif

    /**
     * @brief Stable feature flags (0x338)
     */
    struct FFXIVIpcChocoboStableFlags {
        uint8_t flags;        ///< Bitmask: bit0=can train, bit1=can feed, bit2=can dye, bit3=breeding unlocked
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboStableFlags,
        STRUCT_FIELD(FFXIVIpcChocoboStableFlags, flags)
    );
#endif

    /**
     * @brief Sync stable state from server (0x339)
     */
    struct FFXIVIpcChocoboStableSync {
        uint8_t syncData[16]; ///< Compact sync: timestamps for last feed/train per slot
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboStableSync,
        STRUCT_FIELD(FFXIVIpcChocoboStableSync, syncData)
    );
#endif

    /**
     * @brief Stable session complete (0x33A)
     */
    struct FFXIVIpcChocoboStableComplete {
        uint8_t result;       ///< Completion: 0=normal close, 1=timeout, 2=error
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboStableComplete,
        STRUCT_FIELD(FFXIVIpcChocoboStableComplete, result)
    );
#endif

    // ============================================================================
    // Group 10: Chocobo Racing (0x34A-0x35E, 0x3B7) - 22 opcodes
    // Handler (x64): 0x140CBEC20, 0x140CBEA80, 0x140CBEA90, 0x140CBEAC0, 0x140CBEB20, 0x140CBEB80
    // Gold Saucer chocobo racing minigame packets
    // ============================================================================

    /**
     * @brief Single racer entry for race initialization
     * 48 bytes per entry, used in FFXIVIpcChocoboRaceInit
     */
    struct ChocoboRaceEntry {
        uint32_t actorId;     ///< Entity ID of the racer (or NPC ID for NPCs)
        uint16_t entryId;     ///< Registration number for this race
        uint16_t __padding;
        uint32_t data1;       ///< Chocobo rank/class (1-5)
        uint32_t data2;       ///< Breeding stats: speed, acceleration, endurance, stamina
        uint32_t data3;       ///< Ability slot data (packed)
        uint8_t extra[28];    ///< Name[20], color:u8, pedigree:u8, traits:u16, reserved:u4
    };

    /**
     * @brief Race configuration/rules (0x34A)
     */
    struct FFXIVIpcChocoboRaceConfig {
        uint8_t config[32];   ///< Race config: trackId:u8, laps:u8, difficulty:u8, weather:u8, rules[28]
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceConfig,
        STRUCT_FIELD(FFXIVIpcChocoboRaceConfig, config)
    );
#endif

    /**
     * @brief Race participant list (0x34B)
     */
    struct FFXIVIpcChocoboRaceParticipants {
        uint8_t data[128];    ///< Compact participant list: (entryId:u8, slot:u8, name[14]) × 8
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceParticipants,
        STRUCT_FIELD(FFXIVIpcChocoboRaceParticipants, data)
    );
#endif

    /**
     * @brief Full race initialization (0x34C)
     * Handler does memcpy of 960 bytes (20 entries × 48 bytes)
     */
    struct FFXIVIpcChocoboRaceInit {
        ChocoboRaceEntry entries[20];  ///< All racers (8 players max + 12 NPC slots)
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceInit,
        STRUCT_FIELD(FFXIVIpcChocoboRaceInit, entries)
    );
#endif

    /**
     * @brief Race state update during race (0x34D)
     */
    struct FFXIVIpcChocoboRaceUpdate {
        uint32_t field1;      ///< Race timer (milliseconds since start)
        uint32_t field2;      ///< Event flags: bit0=item spawned, bit1=obstacle active, bit2=shortcut open, bit3=weather change
        uint32_t field3;      ///< Reserved/future use
        uint8_t currentIndex; ///< Player's current position (0-7, 0=1st place)
        uint8_t __padding[3];
        uint8_t participantData[840]; ///< Per-racer update: (pos[3]:f32, speed:u16, stamina:u16, status:u8) × 8
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceUpdate,
        STRUCT_FIELD(FFXIVIpcChocoboRaceUpdate, field1),
        STRUCT_FIELD(FFXIVIpcChocoboRaceUpdate, field2),
        STRUCT_FIELD(FFXIVIpcChocoboRaceUpdate, field3),
        STRUCT_FIELD(FFXIVIpcChocoboRaceUpdate, currentIndex),
        STRUCT_FIELD(FFXIVIpcChocoboRaceUpdate, participantData)
    );
#endif

    /**
     * @brief Pre-race countdown (0x34E)
     */
    struct FFXIVIpcChocoboRaceCountdown {
        uint8_t data[16];     ///< Countdown state: seconds:u8, phase:u8, ready_flags:u16, camera_id:u32, ...
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceCountdown,
        STRUCT_FIELD(FFXIVIpcChocoboRaceCountdown, data)
    );
#endif

    /**
     * @brief Race start signal (0x34F)
     */
    struct FFXIVIpcChocoboRaceStart {
        uint32_t raceId;      ///< Unique race instance ID (for result matching)
        uint32_t timestamp;   ///< Server timestamp when race started (Unix epoch ms)
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceStart,
        STRUCT_FIELD(FFXIVIpcChocoboRaceStart, raceId),
        STRUCT_FIELD(FFXIVIpcChocoboRaceStart, timestamp)
    );
#endif

    /**
     * @brief Real-time position update (0x350)
     */
    struct FFXIVIpcChocoboRacePosition {
        int32_t positions[8]; ///< Track progress per racer (0-100000 = 0-100% of track)
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRacePosition,
        STRUCT_FIELD(FFXIVIpcChocoboRacePosition, positions)
    );
#endif

    /**
     * @brief Lap completion notification (0x351)
     */
    struct FFXIVIpcChocoboRaceLap {
        uint8_t lapNumber;    ///< Current lap (1-based, e.g., 2 = just completed lap 1)
        uint8_t totalLaps;    ///< Total laps in race (typically 3)
        uint16_t __padding;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceLap,
        STRUCT_FIELD(FFXIVIpcChocoboRaceLap, lapNumber),
        STRUCT_FIELD(FFXIVIpcChocoboRaceLap, totalLaps)
    );
#endif

    /**
     * @brief Checkpoint trigger (0x352)
     */
    struct FFXIVIpcChocoboRaceCheckpoint {
        uint32_t checkpointId; ///< Checkpoint index on track (0-N, varies by track)
        uint32_t timestamp;    ///< Time when checkpoint was crossed (ms since race start)
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceCheckpoint,
        STRUCT_FIELD(FFXIVIpcChocoboRaceCheckpoint, checkpointId),
        STRUCT_FIELD(FFXIVIpcChocoboRaceCheckpoint, timestamp)
    );
#endif

    /**
     * @brief Track obstacle hit (0x353)
     */
    struct FFXIVIpcChocoboRaceObstacle {
        uint8_t obstacleType; ///< Type: 0=rock, 1=puddle, 2=cactuar, 3=bomb, 4=wall, 5=box
        uint8_t severity;     ///< Effect strength: 0=minor, 1=moderate, 2=major slowdown
        uint16_t __padding;
        uint32_t param;       ///< Duration of effect (ms) or stamina loss amount
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceObstacle,
        STRUCT_FIELD(FFXIVIpcChocoboRaceObstacle, obstacleType),
        STRUCT_FIELD(FFXIVIpcChocoboRaceObstacle, severity),
        STRUCT_FIELD(FFXIVIpcChocoboRaceObstacle, param)
    );
#endif

    /**
     * @brief Race commentary/announcement (0x354)
     */
    struct FFXIVIpcChocoboRaceMessage {
        char message[64];     ///< UTF-8 race announcement (e.g., "Player takes the lead!")
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceMessage,
        STRUCT_FIELD(FFXIVIpcChocoboRaceMessage, message)
    );
#endif

    /**
     * @brief Racing ability usage (0x355)
     */
    struct FFXIVIpcChocoboRaceAbility {
        uint32_t abilityId;   ///< RaceChocoboAbility.exd row ID (e.g., Choco Dash, Choco Cure)
        uint32_t targetId;    ///< Target racer slot (0-7) or 0xFF for self
        uint32_t result;      ///< Result: 0=success, 1=blocked, 2=miss, 3=on cooldown
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceAbility,
        STRUCT_FIELD(FFXIVIpcChocoboRaceAbility, abilityId),
        STRUCT_FIELD(FFXIVIpcChocoboRaceAbility, targetId),
        STRUCT_FIELD(FFXIVIpcChocoboRaceAbility, result)
    );
#endif

    /**
     * @brief Item box pickup (0x356)
     */
    struct FFXIVIpcChocoboRaceItem {
        uint32_t itemId;      ///< RaceChocoboItem.exd row ID (speed boost, stamina restore, dash, shield)
        uint32_t slotIndex;   ///< Item slot (0 or 1 for 2-slot inventory during race)
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceItem,
        STRUCT_FIELD(FFXIVIpcChocoboRaceItem, itemId),
        STRUCT_FIELD(FFXIVIpcChocoboRaceItem, slotIndex)
    );
#endif

    /**
     * @brief Racer collision event (0x357)
     */
    struct FFXIVIpcChocoboRaceCollision {
        uint8_t data[16];     ///< Collision data: targetSlot:u8, type:u8, force[3]:u16, result:u16, ...
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceCollision,
        STRUCT_FIELD(FFXIVIpcChocoboRaceCollision, data)
    );
#endif

    /**
     * @brief Speed/stamina gauge update (0x358)
     */
    struct FFXIVIpcChocoboRaceSpeed {
        int32_t speed;        ///< Current speed value (0-1000, scaled to %)
        int32_t maxSpeed;     ///< Max speed based on stats/buffs (0-1000)
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceSpeed,
        STRUCT_FIELD(FFXIVIpcChocoboRaceSpeed, speed),
        STRUCT_FIELD(FFXIVIpcChocoboRaceSpeed, maxSpeed)
    );
#endif

    /**
     * @brief Timer display update (0x359)
     */
    struct FFXIVIpcChocoboRaceTime {
        uint16_t currentTime; ///< Current lap time (centiseconds, divide by 100 for seconds)
        uint16_t bestLapTime; ///< Best lap time this race (centiseconds)
        uint16_t totalTime;   ///< Total race time so far (centiseconds)
        uint16_t __padding;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceTime,
        STRUCT_FIELD(FFXIVIpcChocoboRaceTime, currentTime),
        STRUCT_FIELD(FFXIVIpcChocoboRaceTime, bestLapTime),
        STRUCT_FIELD(FFXIVIpcChocoboRaceTime, totalTime)
    );
#endif

    /**
     * @brief Real-time ranking display (0x35A)
     */
    struct FFXIVIpcChocoboRaceRanking {
        uint8_t rankings[8];  ///< Racer slot in each position: rankings[0]=1st, rankings[1]=2nd, rankings[7]=8th
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceRanking,
        STRUCT_FIELD(FFXIVIpcChocoboRaceRanking, rankings)
    );
#endif

    /**
     * @brief Bonus effect trigger (0x35B)
     */
    struct FFXIVIpcChocoboRaceBonus {
        uint8_t bonusType;    ///< Bonus: 0=speed, 1=stamina, 2=ability reset, 3=invincibility
        uint8_t bonusValue;   ///< Magnitude (1-100 typically)
        uint16_t __padding;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceBonus,
        STRUCT_FIELD(FFXIVIpcChocoboRaceBonus, bonusType),
        STRUCT_FIELD(FFXIVIpcChocoboRaceBonus, bonusValue)
    );
#endif

    /**
     * @brief Penalty applied (0x35C)
     */
    struct FFXIVIpcChocoboRacePenalty {
        uint8_t data[16];     ///< Penalty: type:u8, severity:u8, duration:u16, source:u32, ...
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRacePenalty,
        STRUCT_FIELD(FFXIVIpcChocoboRacePenalty, data)
    );
#endif

    /**
     * @brief Player crossed finish line (0x35D)
     */
    struct FFXIVIpcChocoboRaceFinish {
        uint8_t position;     ///< Final position (1-8)
        uint8_t flags;        ///< Flags: bit0=new record, bit1=perfect run, bit2=no items
        uint16_t __padding;
        uint32_t finalTime;   ///< Total race time (milliseconds)
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceFinish,
        STRUCT_FIELD(FFXIVIpcChocoboRaceFinish, position),
        STRUCT_FIELD(FFXIVIpcChocoboRaceFinish, flags),
        STRUCT_FIELD(FFXIVIpcChocoboRaceFinish, finalTime)
    );
#endif

    /**
     * @brief Race rewards breakdown (0x35E)
     */
    struct FFXIVIpcChocoboRaceReward {
        uint32_t mgpReward;   ///< MGP earned (base + position bonus + streak bonus)
        uint32_t expReward;   ///< Chocobo EXP earned
        uint32_t itemReward;  ///< Item reward ID (0 if none) from RaceChocoboReward.exd
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceReward,
        STRUCT_FIELD(FFXIVIpcChocoboRaceReward, mgpReward),
        STRUCT_FIELD(FFXIVIpcChocoboRaceReward, expReward),
        STRUCT_FIELD(FFXIVIpcChocoboRaceReward, itemReward)
    );
#endif

    /**
     * @brief Full race result summary (0x3B7)
     */
    struct FFXIVIpcChocoboRaceResult {
        uint32_t raceId;      ///< Race instance ID (matches ChocoboRaceStart)
        uint32_t finalPosition; ///< Final position (1-8)
        uint32_t totalTime;   ///< Total race time (milliseconds)
        uint32_t mgpEarned;   ///< Total MGP earned including bonuses
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceResult,
        STRUCT_FIELD(FFXIVIpcChocoboRaceResult, raceId),
        STRUCT_FIELD(FFXIVIpcChocoboRaceResult, finalPosition),
        STRUCT_FIELD(FFXIVIpcChocoboRaceResult, totalTime),
        STRUCT_FIELD(FFXIVIpcChocoboRaceResult, mgpEarned)
    );
#endif

    /**
     * @brief Race session complete (0x35F or related)
     * Handler does: *(float*)(param3), *(float*)(param3+4), *(float*)(param3+8), *(int*)(param3+0xC)
     */
    struct FFXIVIpcChocoboRaceComplete {
        float params[3];      ///< Final position coords (x, y, z) for camera
        uint32_t result;      ///< Completion: 0=normal, 1=disconnected, 2=forfeit
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcChocoboRaceComplete,
        STRUCT_FIELD(FFXIVIpcChocoboRaceComplete, params),
        STRUCT_FIELD(FFXIVIpcChocoboRaceComplete, result)
    );
#endif

    // ============================================================================
    // Group 11: Triple Triad (0x384-0x38A) - 7 opcodes
    // Handler (x64): 0x140CC18E0, 0x140CC1860, 0x140CC18A0, 0x140CC1920, 0x140CC1980, 0x140CC19E0
    // Gold Saucer Triple Triad card game packets
    // ============================================================================

    /**
     * @brief Initialize Triple Triad match (0x384)
     */
    struct FFXIVIpcTriadMatchInit {
        int32_t matchId;      ///< Unique match instance ID
        int32_t opponentId;   ///< Opponent entity ID (NPC ID or player entity ID)
        int32_t ruleFlags;    ///< Bitmask of active rules from TripleTriadRule.exd
                              ///< bit0=All Open, bit1=Three Open, bit2=Same, bit3=Sudden Death
                              ///< bit4=Plus, bit5=Random, bit6=Order, bit7=Chaos, bit8=Reverse
                              ///< bit9=Fallen Ace, bit10=Ascension, bit11=Descension
                              ///< bit12=Swap, bit13=Draft, bit14=Roulette
        int32_t param;        ///< Match variant or tournament round
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcTriadMatchInit,
        STRUCT_FIELD(FFXIVIpcTriadMatchInit, matchId),
        STRUCT_FIELD(FFXIVIpcTriadMatchInit, opponentId),
        STRUCT_FIELD(FFXIVIpcTriadMatchInit, ruleFlags),
        STRUCT_FIELD(FFXIVIpcTriadMatchInit, param)
    );
#endif

    /**
     * @brief Match begins, determine first player (0x385)
     */
    struct FFXIVIpcTriadMatchStart {
        int32_t matchId;      ///< Match instance ID
        int32_t turnPlayer;   ///< Who goes first: 0=player, 1=opponent
        int32_t param1;       ///< Reserved (typically 0)
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcTriadMatchStart,
        STRUCT_FIELD(FFXIVIpcTriadMatchStart, matchId),
        STRUCT_FIELD(FFXIVIpcTriadMatchStart, turnPlayer),
        STRUCT_FIELD(FFXIVIpcTriadMatchStart, param1)
    );
#endif

    /**
     * @brief Turn begins for a player (0x386)
     */
    struct FFXIVIpcTriadTurnStart {
        int32_t turnNumber;   ///< Current turn (1-9)
        int32_t activePlayer; ///< Whose turn: 0=player, 1=opponent
        int32_t timeLimit;    ///< Turn time limit in seconds (0 for NPC matches)
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcTriadTurnStart,
        STRUCT_FIELD(FFXIVIpcTriadTurnStart, turnNumber),
        STRUCT_FIELD(FFXIVIpcTriadTurnStart, activePlayer),
        STRUCT_FIELD(FFXIVIpcTriadTurnStart, timeLimit)
    );
#endif

    /**
     * @brief Card placed on board (0x387)
     */
    struct FFXIVIpcTriadCardPlay {
        int32_t cardId;       ///< TripleTriadCard.exd row ID
        int32_t position;     ///< Board position (0-8, top-left to bottom-right)
                              ///< Layout: 0 1 2
                              ///<         3 4 5
                              ///<         6 7 8
        int32_t playerId;     ///< Who played: 0=player, 1=opponent
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcTriadCardPlay,
        STRUCT_FIELD(FFXIVIpcTriadCardPlay, cardId),
        STRUCT_FIELD(FFXIVIpcTriadCardPlay, position),
        STRUCT_FIELD(FFXIVIpcTriadCardPlay, playerId)
    );
#endif

    /**
     * @brief Card play result and score update (0x388)
     * Sent after a card is placed to show flips and score changes
     */
    struct FFXIVIpcTriadCardResult {
        uint32_t position;      ///< Board position where card was played (0-8)
        uint32_t flippedCards;  ///< Bitmask of positions that flipped (bit0=pos0, bit1=pos1, bit2=pos2, bit3=pos3, bit4=pos4, bit5=pos5, bit6=pos6, bit7=pos7, bit8=pos8)
                                ///< Example: 0x05 means positions 0 and 2 flipped
        uint32_t scorePlayer;   ///< Player's current score (cards owned + 1 if more on board)
        uint32_t scoreOpponent; ///< Opponent's current score
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcTriadCardResult,
        STRUCT_FIELD(FFXIVIpcTriadCardResult, position),
        STRUCT_FIELD(FFXIVIpcTriadCardResult, flippedCards),
        STRUCT_FIELD(FFXIVIpcTriadCardResult, scorePlayer),
        STRUCT_FIELD(FFXIVIpcTriadCardResult, scoreOpponent)
    );
#endif

    /**
     * @brief Match conclusion (0x389)
     */
    struct FFXIVIpcTriadMatchEnd {
        uint32_t winner;        ///< Result: 0=draw, 1=player won, 2=opponent won
        uint32_t scorePlayer;   ///< Final player score (0-9)
        uint32_t scoreOpponent; ///< Final opponent score (0-9)
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcTriadMatchEnd,
        STRUCT_FIELD(FFXIVIpcTriadMatchEnd, winner),
        STRUCT_FIELD(FFXIVIpcTriadMatchEnd, scorePlayer),
        STRUCT_FIELD(FFXIVIpcTriadMatchEnd, scoreOpponent)
    );
#endif

    /**
     * @brief Match rewards (0x38A)
     */
    struct FFXIVIpcTriadReward {
        uint8_t rewardType;   ///< Type: 0=none, 1=MGP only, 2=card won, 3=card + MGP
        uint8_t cardCount;    ///< Number of cards won (0-1 typically, or more with rules)
        uint16_t cardId;      ///< TripleTriadCard.exd row ID of won card (0 if none)
        uint32_t mgpReward;   ///< MGP earned (varies by opponent and win/lose)
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcTriadReward,
        STRUCT_FIELD(FFXIVIpcTriadReward, rewardType),
        STRUCT_FIELD(FFXIVIpcTriadReward, cardCount),
        STRUCT_FIELD(FFXIVIpcTriadReward, cardId),
        STRUCT_FIELD(FFXIVIpcTriadReward, mgpReward)
    );
#endif

    // ============================================================================
    // ContentFinder Notification Packets (0x290-0x294)
    // Handler: sub_140CC6F40 - all 5 opcodes share the same handler
    // Used for duty finder queue state, match pop, ready check, party updates
    // ============================================================================

    /**
     * @brief ContentFinder notification base packet (0x290)
     * Common structure for all CFNotify variants - handler differentiates by category field
     * 
     * Handler signature: sub_140CC6F40(actorId, category, params*, state)
     * - category 8: Queue update (sub_140CC3440)
     * - category 9: Queue operation (sub_140CC37B0)
     * - category 10: Instance content notification
     * - category 11: Instance state change (sub_140538010)
     */
    struct FFXIVIpcCFNotify {
        uint16_t category;    ///< Notification category (8=queue, 9=queueOp, 10=content, 11=state)
        uint8_t state;        ///< State/subtype within category
        uint8_t padding;      ///< Alignment padding
        uint32_t param1;      ///< Category-dependent: contentId, queuePosition, etc.
        uint32_t param2;      ///< Category-dependent: waitTime, flags, etc.
        uint32_t param3;      ///< Additional context data
        uint32_t param4;      ///< Additional context data
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcCFNotify,
        STRUCT_FIELD(FFXIVIpcCFNotify, category),
        STRUCT_FIELD(FFXIVIpcCFNotify, state),
        STRUCT_FIELD(FFXIVIpcCFNotify, padding),
        STRUCT_FIELD(FFXIVIpcCFNotify, param1),
        STRUCT_FIELD(FFXIVIpcCFNotify, param2),
        STRUCT_FIELD(FFXIVIpcCFNotify, param3),
        STRUCT_FIELD(FFXIVIpcCFNotify, param4)
    );
#endif

    /**
     * @brief ContentFinder match pop notification (0x291)
     * Sent when duty finder finds a match and shows the "Duty Ready" dialog
     */
    struct FFXIVIpcCFNotifyPop {
        uint16_t category;      ///< Should be 10 for content notification
        uint8_t state;          ///< Pop state (2+ triggers sub_140CC6570)
        uint8_t padding;
        uint32_t contentId;     ///< ContentFinderCondition.exd row ID
        uint32_t param2;        ///< Additional data
        uint32_t param3;
        uint32_t param4;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcCFNotifyPop,
        STRUCT_FIELD(FFXIVIpcCFNotifyPop, category),
        STRUCT_FIELD(FFXIVIpcCFNotifyPop, state),
        STRUCT_FIELD(FFXIVIpcCFNotifyPop, padding),
        STRUCT_FIELD(FFXIVIpcCFNotifyPop, contentId),
        STRUCT_FIELD(FFXIVIpcCFNotifyPop, param2),
        STRUCT_FIELD(FFXIVIpcCFNotifyPop, param3),
        STRUCT_FIELD(FFXIVIpcCFNotifyPop, param4)
    );
#endif

    /**
     * @brief ContentFinder enter ready notification (0x292)
     * Sent when all players accept and instance is ready to enter
     */
    struct FFXIVIpcCFNotifyEnterReady {
        uint16_t category;
        uint8_t state;
        uint8_t padding;
        uint32_t contentId;     ///< ContentFinderCondition.exd row ID
        uint32_t zoneId;        ///< Target zone/instance ID
        uint32_t param3;
        uint32_t param4;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcCFNotifyEnterReady,
        STRUCT_FIELD(FFXIVIpcCFNotifyEnterReady, category),
        STRUCT_FIELD(FFXIVIpcCFNotifyEnterReady, state),
        STRUCT_FIELD(FFXIVIpcCFNotifyEnterReady, padding),
        STRUCT_FIELD(FFXIVIpcCFNotifyEnterReady, contentId),
        STRUCT_FIELD(FFXIVIpcCFNotifyEnterReady, zoneId),
        STRUCT_FIELD(FFXIVIpcCFNotifyEnterReady, param3),
        STRUCT_FIELD(FFXIVIpcCFNotifyEnterReady, param4)
    );
#endif

    /**
     * @brief ContentFinder party member update (0x293)
     * Sent when party composition changes in queue
     */
    struct FFXIVIpcCFNotifyMemberUpdate {
        uint16_t category;      ///< Should be 11 for state change
        uint8_t state;
        uint8_t padding;
        uint16_t memberFlags;   ///< Bitmask: bit0=tank, bit1=healer, bit2=dps ready
        uint8_t memberState;    ///< Member state byte
        uint8_t reserved;
        uint32_t param2;        ///< Passed to sub_140538010 as param2
        uint32_t param3;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcCFNotifyMemberUpdate,
        STRUCT_FIELD(FFXIVIpcCFNotifyMemberUpdate, category),
        STRUCT_FIELD(FFXIVIpcCFNotifyMemberUpdate, state),
        STRUCT_FIELD(FFXIVIpcCFNotifyMemberUpdate, padding),
        STRUCT_FIELD(FFXIVIpcCFNotifyMemberUpdate, memberFlags),
        STRUCT_FIELD(FFXIVIpcCFNotifyMemberUpdate, memberState),
        STRUCT_FIELD(FFXIVIpcCFNotifyMemberUpdate, reserved),
        STRUCT_FIELD(FFXIVIpcCFNotifyMemberUpdate, param2),
        STRUCT_FIELD(FFXIVIpcCFNotifyMemberUpdate, param3)
    );
#endif

    /**
     * @brief ContentFinder queue/duty status update (0x294)
     * Periodic updates for queue position, wait time, etc.
     */
    struct FFXIVIpcCFNotifyStatus {
        uint16_t category;
        uint8_t state;
        uint8_t padding;
        uint32_t queuePosition; ///< Position in queue (0 = not in queue)
        uint32_t waitTime;      ///< Estimated wait time in seconds
        uint32_t flags;         ///< Status flags
        uint32_t param4;
    };

#ifdef DECLARE_PACKET_FIELDS
    DECLARE_PACKET_FIELDS(FFXIVIpcCFNotifyStatus,
        STRUCT_FIELD(FFXIVIpcCFNotifyStatus, category),
        STRUCT_FIELD(FFXIVIpcCFNotifyStatus, state),
        STRUCT_FIELD(FFXIVIpcCFNotifyStatus, padding),
        STRUCT_FIELD(FFXIVIpcCFNotifyStatus, queuePosition),
        STRUCT_FIELD(FFXIVIpcCFNotifyStatus, waitTime),
        STRUCT_FIELD(FFXIVIpcCFNotifyStatus, flags),
        STRUCT_FIELD(FFXIVIpcCFNotifyStatus, param4)
    );
#endif

} // namespace PacketStructures::Server::Zone