#pragma once
#include <cstdint>
#include "../ProtocolHandlers/CommonTypes.h"

namespace PacketStructures::Server::Zone {

    struct ZoneProtoDownServerPos {
        uint32_t originEntityId;
        float pos[3];
        float dir;
    };

    struct FFXIVIpcSync {
        uint32_t clientTimeValue;
        uint32_t transmissionInterval;
        ZoneProtoDownServerPos position;
    };

    struct FFXIVIpcLogin {
        uint32_t clientTimeValue;
        uint32_t loginTicketId;
        uint32_t playerActorId;
    };

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

    struct FFXIVIpcEnableLogout {
        uint8_t content;
    };

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

    struct ClassJobEntry {
        uint16_t id;
        uint16_t level;
    };

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

    struct FFXIVIpcPcSearchResult {
        int16_t ResultCount;
    };

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

    struct FFXIVIpcInviteResult {
        uint32_t Result;
        uint8_t AuthType;
        uint8_t Identity;
        char TargetName[32];
    };

    struct FFXIVIpcInviteReplyResult {
        uint32_t Result;
        uint8_t AuthType;
        uint8_t Answer;
        uint8_t Identity;
        char InviteCharacterName[32];
    };

    struct FFXIVIpcInviteUpdate {
        uint64_t InviteCharacterID;
        uint32_t InviteTime;
        uint8_t AuthType;
        uint8_t InviteCount;
        uint8_t Result;
        uint8_t Identity;
        char InviteName[32];
    };

    struct FFXIVIpcFriendlistRemoveResult {
        uint64_t RemovedCharacterID;
        uint32_t Result;
        uint8_t Identity;
        char RemovedCharacterName[32];
    };

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

    struct FFXIVIpcSetProfileResult {
        uint64_t OnlineStatus;
        uint64_t SelectClassID;
        uint32_t Result;
        uint8_t CurrentSelectClassID;
        uint8_t Region;
        char SearchComment[193];
    };

    struct FFXIVIpcGetProfileResult {
        uint64_t OnlineStatus;
        uint64_t SelectClassID;
        uint8_t CurrentSelectClassID;
        uint8_t Region;
        char SearchComment[193];
    };

    struct FFXIVIpcGetSearchCommentResult {
        uint32_t TargetEntityID;
        char SearchComment[193];
    };

    struct FFXIVIpcGetCharacterNameResult {
        uint64_t CharacterID;
        char CharacterName[32];
    };

    struct FFXIVIpcSendSystemMessage {
        uint8_t MessageParam;
        char Message[769];
    };

    struct FFXIVIpcSendLoginMessage {
        uint8_t MessageParam;
        char Message[769];
    };

    struct FFXIVIpcSetOnlineStatus {
        uint64_t onlineStatusFlags;
    };

    struct BlacklistCharacter {
        uint64_t CharacterID;
        char CharacterName[32];
    };

    struct FFXIVIpcBlacklistAddResult {
        BlacklistCharacter AddedCharacter;
        uint32_t Result;
        uint8_t Identity;
    };

    struct FFXIVIpcBlacklistRemoveResult {
        BlacklistCharacter RemovedCharacter;
        uint32_t Result;
        uint8_t Identity;
    };

    struct FFXIVIpcGetBlacklistResult {
        BlacklistCharacter Blacklist[20];
        uint8_t NextIndex;
        uint8_t Index;
        uint8_t RequestKey;
    };

    struct ZoneProtoDownLinkshell {
        uint64_t LinkshellID;
        uint64_t ChannelID;
        uint32_t HierarchyID;
        char LinkshellName[32];
    };

    struct FFXIVIpcGetLinkshellListResult {
        ZoneProtoDownLinkshell LinkshellList[8];
    };

    struct FFXIVIpcChatChannelResult {
        uint64_t ChannelID;
        uint64_t CommunityID;
        uint64_t TargetCharacterID;
        uint32_t UpPacketNo;
        uint32_t Result;
    };

    struct FFXIVIpcAchievement {
        uint8_t complete[256];
        uint16_t history[5];
    };

    // Letter/Mail structures
    struct ZoneProtoDownLetterBoxAppendItemBase {
        uint32_t CatalogID;
        uint32_t Stack;
    };

    struct ZoneProtoDownLetterBoxAppendItem {
        ZoneProtoDownLetterBoxAppendItemBase ItemList[5];
        ZoneProtoDownLetterBoxAppendItemBase Gil;
    };

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

    struct FFXIVIpcGetLetterMessageResult {
        ZoneProtoDownLetterMessage LetterMessage[5];
        uint8_t NextIndex;
        uint8_t Index;
        uint8_t RequestKey;
    };

    struct FFXIVIpcGetLetterMessageDetailResult {
        uint64_t SenderCharacterID;
        uint32_t Date;
        char Message[601];
    };

    struct FFXIVIpcLetterResult {
        uint32_t UpPacketNo;
        uint64_t SenderCharacterID;
        uint32_t Date;
        ZoneProtoDownLetterBoxAppendItem AppendItem;
        uint32_t Result;
    };

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

    // Item search structures
    struct FFFXIVIpcItemSearchResult {
        uint32_t CatalogID;
        uint32_t Result;
        uint8_t SubQuality;
        uint8_t MateriaCount;
        uint8_t Count;
    };

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

    struct FFXIVIpcGetItemSearchListResult {
        ZoneProtoDownItemSearchData ItemSearchList[10];
        uint8_t NextIndex;
        uint8_t Index;
        uint8_t RequestKey;
    };

    struct ZoneProtoDownItemHistoryData {
        uint32_t CatalogID;
        uint32_t SellPrice;
        uint32_t BuyRealDate;
        uint32_t Stack;
        uint8_t SubQuality;
        uint8_t MateriaCount;
        char BuyCharacterName[32];
    };

    struct FFXIVIpcGetItemHistoryResult {
        uint32_t CatalogID;
        ZoneProtoDownItemHistoryData ItemHistoryList[20];
    };

    struct ZoneProtoDownCatalogSearchData {
        uint32_t CatalogID;
        uint16_t StockCount;
        uint16_t RequestItemCount;
    };

    struct FFXIVIpcCatalogSearchResult {
        ZoneProtoDownCatalogSearchData CatalogList[20];
        uint32_t NextIndex;
        uint32_t Result;
        uint32_t Index;
        uint8_t RequestKey;
        uint8_t Type;
    };

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

    struct FFXIVIpcActorControl {
        uint16_t category;
        uint16_t padding;
        uint32_t param1;
        uint32_t param2;
        uint32_t param3;
        uint32_t param4;
    };

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

    struct FFXIVIpcActorControlTarget {
        uint16_t category;
        uint16_t padding;
        uint32_t param1;
        uint32_t param2;
        uint32_t param3;
        uint32_t param4;
        uint64_t targetId;
    };

    struct FFXIVIpcResting {
        uint32_t Hp;
        uint16_t Mp;
        uint16_t Tp;
        uint16_t Gp;
        uint32_t Unknown_3_2;
    };

    struct FFXIVIpcRecastGroup {
        float Recast[80];
        float RecastMax[80];
    };

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

    struct FFXIVIpcActorFreeSpawn {
        uint32_t spawnId;
        uint32_t actorId;
    };

    struct FFXIVIpcActorMove {
        uint8_t dir;
        uint8_t dirBeforeSlip;
        uint8_t flag;
        uint8_t flag2;
        uint8_t speed;
        uint8_t __padding1;
        uint16_t pos[3];
    };

    struct FFXIVIpcTransfer {
        uint16_t dir;
        uint8_t padding1;
        uint8_t padding2;
        float duration;
        uint8_t flag;
        uint8_t padding3;
        uint16_t pos[3];
    };

    struct FFXIVIpcWarp {
        uint16_t Dir;
        uint8_t Type;
        uint8_t TypeArg;
        uint32_t LayerSet;
        float x;
        float y;
        float z;
    };

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

    struct ZoneProtoDownHater {
        uint32_t Id;
        uint8_t Rate;
    };

    struct FFXIVIpcHaterList {
        uint8_t Count;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        ZoneProtoDownHater List[32];
    };

    struct ZoneProtoDownHate {
        uint32_t Id;
        uint32_t Value;
    };

    struct FFXIVIpcHateList {
        uint8_t Count;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        ZoneProtoDownHate List[32];
    };

    struct FFXIVIpcTitleList {
        uint8_t TitleFlagsArray[48];
    };

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

    struct FFXIVIpcBaseParam {
        uint32_t Param[50];
        uint32_t OriginalParam[6];
    };

    struct FFXIVIpcFirstAttack {
        uint8_t Type;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        uint64_t Id;
    };

    struct FFXIVIpcCondition {
        uint8_t flags[12];
        uint32_t padding;
    };

    struct FFXIVIpcPlayerStatusUpdate {
        uint8_t ClassJob;
        uint8_t __padding1;
        uint16_t Lv;
        uint16_t Lv1;
        uint16_t LvSync;
        uint32_t Exp;
        uint32_t RestPoint;
    };

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

    struct FFXIVIpcStatus {
        StatusWork effect[30];
    };

    struct FFXIVIpcEquip {
        uint64_t MainWeapon;
        uint64_t SubWeapon;
        uint8_t CrestEnable;
        uint8_t __padding1;
        uint16_t PatternInvalid;
        uint32_t Equipment[10];
    };

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

    struct FFXIVIpcName {
        uint64_t contentId;
        char name[32];
    };

    struct ZoneProtoDownItemStorage {
        uint32_t storageId;
        uint16_t type;
        int16_t index;
        uint32_t containerSize;
    };

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

    struct FFXIVIpcNormalItem {
        uint32_t contextId;
        ZoneProtoDownNormalItem item;
    };

    struct FFXIVIpcUpdateItem {
        uint32_t contextId;
        ZoneProtoDownNormalItem item;
    };

    struct FFXIVIpcItemSize {
        uint32_t contextId;
        int32_t size;
        uint32_t storageId;
    };

    struct FFXIVIpcItemStorage {
        uint32_t contextId;
        ZoneProtoDownItemStorage storage;
    };

    struct FFXIVIpcGilItem {
        uint32_t contextId;
        ZoneProtoDownGilItem item;
    };

    struct FFXIVIpcItemOperationBatch {
        uint32_t contextId;
        uint32_t operationId;
        uint8_t operationType;
        uint8_t errorType;
        uint8_t packetNum;
    };

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

    struct FFXIVIpcEventStart {
        uint64_t targetId;
        uint32_t handlerId;
        uint8_t event;
        uint8_t flags;
        uint8_t __padding1;
        uint8_t __padding2;
        uint32_t eventArg;
    };

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

    struct FFXIVIpcEventFinish {
        uint32_t handlerId;
        uint8_t event;
        uint8_t result;
        uint8_t __padding1;
        uint8_t __padding2;
        uint32_t eventArg;
    };

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

    struct FFXIVIpcQuest {
        uint8_t index;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        QuestData questInfo;
    };

    struct FFXIVIpcQuestCompleteList {
        uint8_t questCompleteMask[310];
        uint8_t unknownCompleteMask[32];
    };

    struct FFXIVIpcLegacyQuestCompleteList {
        uint8_t completeFlagArray[40];
    };

    struct FFXIVIpcQuestFinish {
        uint16_t questId;
        uint8_t flag1;
        uint8_t flag2;
        uint32_t padding;
    };

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

    struct FFXIVIpcWeatherId {
        uint8_t WeatherId;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        float TransitionTime;
    };

    struct FFXIVIpcDiscoveryReply {
        uint32_t mapPartId;
        uint32_t mapId;
    };

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

    struct FFXIVIpcMoveInstance {
        uint64_t characterId;
        uint32_t entityId;
        uint16_t worldId;
        uint16_t worldId1;
        uint64_t unknown1;
        uint64_t unknown2;
    };

    struct FFXIVIpcQuestRepeatFlags {
        uint8_t update;
        uint8_t repeatFlagArray[1];
    };

    struct DailyQuest {
        uint16_t questId;
        uint8_t flags;
    };

    struct FFXIVIpcDailyQuests {
        uint8_t update;
        uint8_t __padding1;
        uint8_t __padding2;
        DailyQuest dailyQuestArray[12];
    };

    struct FFXIVIpcUpdateContent {
        uint16_t territoryType;
        uint16_t padding;
        uint32_t kind;
        uint32_t value1;
        uint32_t value2;
    };

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

    struct FFXIVIpcContentAttainFlags {
        uint8_t raidAttainFlag[28];
        uint8_t dungeonAttainFlag[18];
        uint8_t guildOrderAttainFlag[10];
        uint8_t bossBattleAttainFlag[6];
        uint8_t colosseumAttainFlag[2];
    };

    struct FFXIVIpcContentBonus {
        uint8_t bonusRoles[8];
    };

    struct FFXIVIpcResponsePenalties {
        uint8_t penalties[2];
    };

    struct FFXIVIpcConfig {
        uint16_t flag;
    };

    struct FFXIVIpcEorzeaTimeOffset {
        uint64_t timestamp;
    };

    struct FFXIVIpcMount {
        uint32_t id;
    };

    struct FFXIVIpcDirectorVars {
        uint32_t directorId;
        uint8_t sequence;
        uint8_t flags;
        uint8_t vars[10];
    };

    // Housing structures
    struct FFXIVIpcHouseList {
        LandIdent LandSetId;
        uint32_t Subdivision;
        uint32_t unknown1;
        House Houses[30];
    };

    struct FFXIVIpcHouse {
        uint16_t Block;
        uint16_t __padding1;
        uint16_t __padding2;
        uint16_t __padding3;
        House House;
    };

    struct FFXIVIpcYardObjectList {
        uint8_t PacketIndex;
        uint8_t PacketEnd;
        uint8_t PacketEnd1;
        uint8_t PacketEnd2;
        Furniture YardObjects[400];
    };

    struct FFXIVIpcYardObject {
        uint8_t PacketIndex;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        Furniture YardObject;
    };

    struct FFXIVIpcInterior {
        uint16_t Window;
        uint16_t WindowColor;
        uint16_t Door;
        uint16_t DoorColor;
        uint32_t Interior[10];
    };

    struct FFXIVIpcHousingAuction {
        uint32_t Price;
        uint32_t Timer;
    };

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

    struct FFXIVIpcHousingHouseName {
        LandIdent LandId;
        char Name[23];
    };

    struct FFXIVIpcHousingGreeting {
        LandIdent LandId;
        uint8_t Greeting[193];
    };

    struct FFXIVIpcCharaHousingLandData {
        uint8_t Index;
        uint32_t unknown;
        CharaLandData LandData;
    };

    struct FFXIVIpcCharaHousing {
        CharaLandData FcLands;
        uint64_t padding;
        CharaLandData CharaLands;
        uint64_t padding1;
        CharaLandData apartment;
        uint64_t padding2;
        CharaLandData sharedHouse[2];
    };

    struct FFXIVIpcHousingWelcome {
        uint8_t Welcome;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        LandIdent LandId;
    };

    struct FFXIVIpcFurnitureListS {
        LandIdent LandId;
        int8_t u1;
        uint8_t packetNum;
        uint8_t packetTotal;
        uint8_t u2;
        Furniture Furnitures[100];
    };

    struct FFXIVIpcFurnitureListM {
        LandIdent LandId;
        int8_t u1;
        uint8_t packetNum;
        uint8_t packetTotal;
        uint8_t u2;
        Furniture Furnitures[150];
    };

    struct FFXIVIpcFurnitureListL {
        LandIdent LandId;
        int8_t u1;
        uint8_t packetNum;
        uint8_t packetTotal;
        uint8_t u2;
        Furniture Furnitures[200];
    };

    struct FFXIVIpcFurniture {
        uint16_t StorageId;
        uint8_t ContainerIndex;
        uint8_t __padding1;
        Furniture Furniture;
    };

    struct FFXIVIpcHousingProfileList {
        LandIdent LandSetId;
        SimpleProfile ProfileList[30];
    };

    struct FFXIVIpcHousingObjectTransform {
        uint16_t Dir;
        uint8_t UserData1;
        uint8_t UserData2;
        uint8_t ContainerIndex;
        uint8_t __padding1;
        uint16_t Pos[3];
    };

    struct FFXIVIpcHousingObjectColor {
        uint8_t Color;
        uint8_t __padding1;
        uint16_t StorageId;
        uint8_t ContainerIndex;
        uint8_t UserData;
    };

    struct FFXIVIpcHousingObjectTransformMulti {
        LandIdent LandId;
        HousingLayout LayoutInfos[10];
    };

    struct FFXIVIpcHousingGetPersonalRoomProfileListResult {
        uint64_t CharacterID;
        LandIdent HouseLandID;
        uint16_t TopRoomID;
        uint8_t __padding1;
        uint8_t __padding2;
        HousingPersonalRoomProfileData ProfileList[15];
    };

    struct FFXIVIpcHousingGetHouseBuddyStableListResult {
        uint64_t CharacterID;
        LandIdent LandID;
        uint8_t Page;
        uint8_t IsMyBuddy;
        uint8_t __padding1;
        uint8_t __padding2;
        HouseBuddyStableData BuddyList[15];
    };

    struct FFXIVIpcHouseTrainBuddyData {
        uint8_t OwnerRace;
        uint8_t OwnerSex;
        uint8_t Stain;
        uint8_t Equips[3];
    };

    struct FFXIVIpcHousingObjectTransformMultiResult {
        LandIdent LandId;
        uint8_t Result;
        uint8_t __padding1;
        uint16_t FixIndexes[10];
    };

    struct FFXIVIpcHousingLogWithHouseName {
        uint32_t LogId;
        uint8_t Name[23];
    };

    struct FFXIVIpcHousingCombinedObjectStatus {
        uint16_t AddressData;
        uint16_t Kind[8];
        uint8_t Step[8];
        uint8_t Status[8];
    };

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

    struct FFXIVIpcCreateObject {
        uint8_t Index;
        uint8_t Kind;
        uint8_t Flag;
        uint8_t __padding1;
        uint32_t BaseId;
        uint32_t EntityId;
        uint32_t LayoutId;
        uint32_t ContentId;
        uint32_t OwnerId;
        uint32_t BindLayoutId;
        float Scale;
        uint16_t SharedGroupTimelineState;
        uint16_t Dir;
        uint16_t FATE;
        uint8_t PermissionInvisibility;
        uint8_t Args;
        uint32_t Args2;
        uint32_t Args3;
        FFXIVARR_POSITION3 Pos;
    };

    struct FFXIVIpcDeleteObject {
        uint8_t Index;
    };

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

    struct FFXIVIpcGetCompanyBoardResult {
        uint8_t Type;
        char CompanyBoard[193];
    };

    struct FcHierarchy {
        uint64_t AuthorityList;
        uint16_t Count;
        uint8_t SortNo;
        char HierarchyName[46];
    };

    struct FFXIVIpcGetFcHierarchyResult {
        char MasterCharacterName[32];
        FcHierarchy FcHierarchyList[16];
    };

    struct FcActivityList {
        uint64_t ID;
        uint32_t Date;
        uint32_t Param;
        uint16_t Type;
        uint8_t Sex;
        char CharacterName[32];
        char HierarchyName[46];
    };

    struct FFXIVIpcGetFcActivityListResult {
        uint16_t NextIndex;
        uint8_t Index;
        uint8_t RequestKey;
        FcActivityList ActivityList[5];
    };

    struct FcHierarchyLite {
        uint64_t AuthorityList;
        uint16_t Count;
        uint8_t SortNo;
    };

    struct FFXIVIpcGetFcHierarchyLiteResult {
        FcHierarchyLite FcHierarchyList[16];
    };

    struct FFXIVIpcGetCompanyMottoResult {
        uint16_t FcActivity;
        uint16_t FcRole;
        uint8_t Type;
        uint8_t FcActiveTimeFlag;
        uint8_t FcJoinRequestFlag;
        uint8_t JoinRequestCount;
        char CompanyMotto[193];
    };

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

    struct FFXIVIpcGetFcActionResult {
        uint64_t CharacterID;
        uint32_t ActiveActionList[3];
        uint32_t ActiveActionLeftTime[3];
        uint32_t StockActionList[15];
    };

    struct FFXIVIpcGetFcMemoResult {
        uint64_t CharacterID;
        uint32_t UIParam;
        uint32_t UpdateDate;
        char FcMemo[97];
    };

    struct FFXIVIpcFreeCompany {
        uint64_t Crest;
        char Tag[6];
    };

    // Party structures
    struct FFXIVIpcPcPartyResult {
        uint32_t UpPacketNo;
        uint32_t Result;
    };

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

    struct FFXIVIpcPartyRecruitResult {
        uint64_t TargetCharacterID;
        uint64_t Param;
        uint32_t Type;
        uint32_t Result;
        uint8_t Identity;
        char TargetName[32];
    };

    struct ZoneProtoDownStatusWork {
        uint16_t Id;
        int16_t SystemParam;
        float Time;
        uint32_t Source;
    };

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

    struct FFXIVIpcPartyPos {
        uint8_t Index;
        uint8_t __padding1;
        uint16_t TerritoryType;
        float X;
        float Y;
        float Z;
        uint32_t EntityId;
    };

    struct FFXIVIpcAlliancePos {
        uint8_t AllianceIndex;
        uint8_t PartyIndex;
        uint16_t TerritoryType;
        float X;
        float Y;
        float Z;
        uint32_t EntityId;
    };

    struct FFXIVIpcUpdateAlliance {
        uint32_t AllianceFlags;
        uint8_t AllianceLocalIndex;
        uint8_t AllianceMemberCount;
        uint8_t __padding1;
        uint8_t __padding2;
    };

    struct FFXIVIpcGrandCompany {
        uint8_t GrandCompany;
        uint8_t GrandCompanyRank;
    };

    // Market Board structures
    struct FFXIVIpcMarketPriceHeader {
        uint32_t CatalogID;
        uint16_t MinPrice;
        uint16_t MaxPrice;
    };

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

    struct FFXIVIpcRetainerList {
        uint64_t RetainerID[10];
        uint8_t RetainerCount;
        char RetainerName[10][32];
    };

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

    // Trade structures
    struct FFXIVIpcTradeCommand {
        uint32_t TradeID;
        uint8_t Type;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
    };

    struct FFXIVIpcItemMessage {
        uint32_t ItemID;
        uint32_t Stack;
        uint8_t Type;
    };

    struct FFXIVIpcAliasItem {
        uint32_t ItemID;
        uint32_t AliasID;
    };

    // Loot structures
    struct FFXIVIpcOpenTreasure {
        uint32_t ChestID;
        uint32_t ChestType;
        uint32_t Result;
    };

    struct FFXIVIpcLootRight {
        uint32_t ChestID;
        uint8_t LootMode;
    };

    struct FFXIVIpcLootActionResult {
        uint32_t ChestID;
        uint32_t ItemID;
        uint8_t Result;
        uint8_t RolledValue;
    };

    struct FFXIVIpcGameLog {
        uint32_t MessageID;
        uint32_t Category;
        uint32_t Param1;
        uint32_t Param2;
        uint32_t Param3;
        uint32_t Param4;
        uint32_t Param5;
    };

    struct FFXIVIpcTreasureOpenRight {
        uint32_t ChestID;
        uint8_t Rights[8];
    };

    struct FFXIVIpcOpenTreasureKeyUi {
        uint32_t ChestID;
        uint8_t RequiresKey;
    };

    struct FFXIVIpcLootItems {
        uint32_t ChestID;
        struct LootItemInfo {
            uint32_t ItemID;
            uint16_t Stack;
            uint8_t Quality;
            uint8_t __padding1;
        } Items[16];
    };

    struct FFXIVIpcCreateTreasure {
        uint32_t ChestID;
        uint8_t ChestType;
        uint8_t __padding1;
        uint8_t __padding2;
        uint8_t __padding3;
        FFXIVARR_POSITION3 Position;
    };

    struct FFXIVIpcTreasureFadeOut {
        uint32_t ChestID;
    };

} // namespace PacketStructures::Server::Zone