#pragma once
#include <cstdint>

// ============================================================================
// Game Enumerations - Based on Sapphire Server research
// Used for decoding packet fields to human-readable values
// ============================================================================

namespace GameEnums {

// ============================================================================
// Action/Combat Effect Types (CalcResultType)
// ============================================================================
enum class CalcResultType : uint8_t {
    None = 0x0,
    Miss = 0x1,
    Resist = 0x2,
    DamageHp = 0x3,
    RecoverHp = 0x4,
    CriticalDamageHp = 0x5,
    CriticalRecoverHp = 0x6,
    Guard = 0x7,
    Parry = 0x8,
    Invalid = 0x9,
    Uneffective = 0xA,
    Neglect = 0xB,
    DamageMp = 0xC,
    RecoverMp = 0xD,
    DamageTp = 0xE,
    RecoverTp = 0xF,
    RecoverGp = 0x10,
    SetStatus = 0x11,
    SetStatusMe = 0x12,
    ResetStatus = 0x13,
    ResetStatusMe = 0x14,
    ResetBadStatus = 0x15,
    UneffectiveStatus = 0x16,
    HalfGoodStatus = 0x17,
    HateDirect = 0x18,
    HateIndirection = 0x19,
    HateTop = 0x1A,
    HateAdd = 0x1B,
    HateMult = 0x1C,
    Combo = 0x1D,
    ComboHit = 0x1E,
    Counter = 0x1F,
    Destruct = 0x20,
    Paralysis = 0x21,
    KnockBack = 0x22,
    DrawUpChairs = 0x23,
    Sucked = 0x24,
    CtDrawUpChairs = 0x25,
    LiveCallback = 0x26,
    Mount = 0x27,
    ArcherDot = 0x28,
    MasterDot = 0x29,
    BlessingOfGoddess = 0x2A,
    BadBreath = 0x2B,
    Revival = 0x2C,
    Pet = 0x2D,
    Blow = 0x2E,
    StatusResist = 0x2F,
    ClearPhysical = 0x30,
    BNpcState = 0x31,
    Vfx = 0x32,
    HardCode = 0x33,
    CalcId = 0x34,
    ClearPvpPoint = 0x35,
    CheckBarrier = 0x36,
    Reflect = 0x37,
};

// ============================================================================
// Entity/Object Types (ObjKind)
// ============================================================================
enum class ObjKind : uint8_t {
    None = 0x00,
    Player = 0x01,
    BattleNpc = 0x02,
    EventNpc = 0x03,
    Treasure = 0x04,
    Aetheryte = 0x05,
    GatheringPoint = 0x06,
    EventObj = 0x07,
    MountType = 0x08,
    Companion = 0x09,  // Minion
    Retainer = 0x0A,
    Area = 0x0B,
    Housing = 0x0C,
    Cutscene = 0x0D,
    CardStand = 0x0E,
};

// ============================================================================
// Action Kind (how action is triggered)
// ============================================================================
enum class ActionKind : uint8_t {
    Nothing = 0x0,
    Normal = 0x1,       // Regular ability/spell
    Item = 0x2,         // Consumable item
    EventItem = 0x3,    // Quest/event item
    EventAction = 0x4,  // Event-specific action
    General = 0x5,      // General action (sprint, etc.)
    Buddy = 0x6,        // Chocobo companion
    Command = 0x7,      // System command
    Companion = 0x8,    // Minion action
    Craft = 0x9,        // Crafting action
    Fishing = 0xA,      // Fishing
    Pet = 0xB,          // Pet/summon action
    CompanyAction = 0xC, // FC action
    Mount = 0xD,        // Mount action
    PvpAction = 0xE,    // PvP-specific action
    FieldMarker = 0xF,  // Waymarker placement
};

// ============================================================================
// Warp/Teleport Types
// ============================================================================
enum class WarpType : uint8_t {
    None = 0x0,
    Normal = 0x1,
    NormalPos = 0x2,
    ExitRange = 0x3,
    Telepo = 0x4,
    Reise = 0x5,
    Unknown6 = 0x6,
    Desion = 0x7,
    HomePoint = 0x8,
    RentalChocobo = 0x9,
    ChocoboTaxi = 0xA,
    InstanceContent = 0xB,
    Reject = 0xC,
    ContentEndReturn = 0xD,
    TownTranslate = 0xE,
    GM = 0xF,
    Login = 0x10,
    LayerSet = 0x11,
    Emote = 0x12,
    HousingTelepo = 0x13,
    Debug = 0x14,
};

// ============================================================================
// Actor Status (current state)
// ============================================================================
enum class ActorStatus : uint8_t {
    Idle = 0x01,
    Dead = 0x02,
    Sitting = 0x03,
    Mounted = 0x04,
    Crafting = 0x05,
    Gathering = 0x06,
    Melding = 0x07,
    SMachine = 0x08,
    Carry = 0x09,
    EmoteMode = 0x0B,
};

// ============================================================================
// Player Conditions (flags)
// ============================================================================
enum class PlayerCondition : uint8_t {
    None = 0,
    HideUILockChar = 1,
    EventAction = 21,
    InNpcEvent = 23,
    InCombat = 18,
    Casting = 19,
    BoundByDuty = 26,
    Crafting = 32,
    PreparingToCraft = 33,
    Gathering = 34,
    Fishing = 35,
    BetweenAreas = 37,
    Stealthed = 38,
    AutoRunActive = 41,
    WatchingCutscene = 50,
};

// ============================================================================
// Inventory Container Types
// ============================================================================
enum class InventoryType : uint16_t {
    Bag0 = 0,
    Bag1 = 1,
    Bag2 = 2,
    Bag3 = 3,
    GearSet0 = 1000,
    GearSet1 = 1001,
    Currency = 2000,
    Crystal = 2001,
    KeyItem = 2004,
    HandIn = 2005,
    DamagedGear = 2007,
    ArmoryOff = 3200,
    ArmoryHead = 3201,
    ArmoryBody = 3202,
    ArmoryHand = 3203,
    ArmoryWaist = 3204,
    ArmoryLegs = 3205,
    ArmoryFeet = 3206,
    ArmoryNeck = 3207,
    ArmoryEar = 3208,
    ArmoryWrist = 3209,
    ArmoryRing = 3300,
    ArmorySoulCrystal = 3400,
    ArmoryMain = 3500,
    RetainerBag0 = 10000,
    RetainerBag1 = 10001,
    RetainerBag2 = 10002,
    RetainerBag3 = 10003,
    RetainerBag4 = 10004,
    RetainerBag5 = 10005,
    RetainerBag6 = 10006,
    RetainerEquippedGear = 11000,
    RetainerGil = 12000,
    RetainerCrystal = 12001,
    RetainerMarket = 12002,
    FreeCompanyBag0 = 20000,
    FreeCompanyBag1 = 20001,
    FreeCompanyBag2 = 20002,
    FreeCompanyGil = 22000,
    FreeCompanyCrystal = 22001,
    HousingInteriorAppearance = 25002,
    HousingExteriorAppearance = 25000,
    HousingExteriorPlacedItems = 25001,
    HousingExteriorStoreroom = 27000,
};

// ============================================================================
// Item Operation Types
// ============================================================================
enum class ItemOperationType : uint8_t {
    None = 0x0,
    CreateStorage = 0x1,
    DeleteStorage = 0x2,
    CompactStorage = 0x3,
    ResyncStorage = 0x4,
    CreateItem = 0x5,
    UpdateItem = 0x6,
    DeleteItem = 0x7,
    MoveItem = 0x8,
    SwapItem = 0x9,
    SplitItem = 0xA,
    SplitToMerge = 0xB,
    MergeItem = 0xC,
    RepairItem = 0xD,
    NpcRepairItem = 0xE,
    TradeCommand = 0x18,
    MoveTrade = 0x19,
    SetGilTrade = 0x1A,
    CreateMateria = 0x1D,
    AttachMateria = 0x1E,
    RemoveMateria = 0x1F,
    Gathering = 0x31,
    Craft = 0x32,
    Fishing = 0x33,
    GcSupply = 0x34,
    CabinetTake = 0x35,
    CabinetGive = 0x36,
    ShopBuyback = 0x37,
    Telepo = 0x38,
    VentureStart = 0x39,
    VentureEnd = 0x3A,
    GardeningHarvest = 0x3B,
    SalvageResult = 0x3C,
    TreasurePublic = 0x3D,
    TreasureHunt = 0x41,
    RandomItem = 0x46,
    MateriaSlot = 0x4A,
    AchievementReward = 0x4B,
};

// ============================================================================
// Equipment Slots
// ============================================================================
enum class GearSetSlot : uint8_t {
    MainHand = 0,
    OffHand = 1,
    Head = 2,
    Body = 3,
    Hands = 4,
    Waist = 5,
    Legs = 6,
    Feet = 7,
    Ear = 8,
    Neck = 9,
    Wrist = 10,
    Ring1 = 11,
    Ring2 = 12,
    SoulCrystal = 13,
};

// ============================================================================
// Client Command Types (PacketCommand / ClientTrigger)
// ============================================================================
enum class ClientCommand : uint16_t {
    DrawnSword = 0x01,
    AutoAttack = 0x02,
    TargetDecide = 0x03,
    RequestAction = 0x64,
    CancelMount = 0x65,
    Companion = 0x66,
    CompanionCancel = 0x67,
    RequestStatusReset = 0x68,
    CancelCast = 0x69,
    MountLink = 0x6A,
    UnmountLink = 0x6B,
    BallistaAccess = 0x6C,
    Revive = 0xC8,
    FinishLoading = 0xC9,
    TelepoInquiry = 0xCA,
    TelepoInvitationAnswer = 0xCB,
    TelepoCancel = 0xCC,
    RaiseCancel = 0xCD,
    WarpReply = 0xCE,
    RequestMode = 0xCF,
    PublicInstance = 0xD0,
    NewbieTelepoInquiry = 0xD1,
    Inspect = 0x12C,
    Marking = 0x12D,
    ActiveTitle = 0x12E,
    TitleList = 0x12F,
    BorrowAction = 0x130,
    Random = 0x131,
    Name = 0x132,
    SetHowto = 0x133,
    SetCutscene = 0x134,
    PhysicalBonus = 0x135,
    GroundMarking = 0x136,
    ContentsNoteRequest = 0x137,
    Emote = 0x1F4,
    EmoteWithWarp = 0x1F5,
    EmoteCancel = 0x1F6,
    EmoteModeCancel = 0x1F7,
    EmoteModeCancelWithWarp = 0x1F8,
    PoseEmoteConfig = 0x1F9,
    PoseEmoteWork = 0x1FA,
    PoseEmoteCancel = 0x1FB,
    JumpStart = 0x258,
    JumpLanding = 0x259,
    StartCraft = 0x2BC,
    Fishing = 0x2BD,
    CancelQuest = 0x320,
    DirectorInitReturn = 0x321,
    SyncDirector = 0x327,
    EventHandler = 0x328,
    FateStart = 0x329,
    FateLevelSync = 0x32D,
    AchievementRequestRate = 0x3E8,
    AchievementRequest = 0x3E9,
    HousingLockLandByBuild = 0x44C,
    HousingGetProfile = 0x452,
    HousingGetProfileList = 0x453,
    HousingRelease = 0x454,
    HousingBuild = 0x455,
    HousingBreak = 0x456,
    HousingLoadParts = 0x457,
    HousingLoadRoom = 0x458,
    HousingLoadYard = 0x459,
    HousingUnplace = 0x45A,
    HousingHouseName = 0x45B,
    HousingGreeting = 0x45C,
    HousingLayoutMode = 0x462,
    BuddyAction = 0x6A4,
    BuddyEquip = 0x6A5,
    PetCommand = 0x708,
    ScreenShot = 0x7D0,
};

// ============================================================================
// Grand Company IDs
// ============================================================================
enum class GrandCompany : uint8_t {
    None = 0,
    Maelstrom = 1,
    TwinAdder = 2,
    ImmortalFlames = 3,
};

// ============================================================================
// Housing Types
// ============================================================================
enum class HouseSize : uint8_t {
    Small = 0x0,
    Medium = 0x1,
    Large = 0x2,
    All = 0xFE,
    Invalid = 0xFF,
};

enum class HousingLandStatus : uint8_t {
    NoInit = 0x0,
    None = 0x1,
    BuyLand = 0x2,
    BuildHouse = 0x3,
};

// ============================================================================
// Movement Types
// ============================================================================
enum class MoveType : uint8_t {
    Running = 0x00,
    Walking = 0x02,
    Strafing = 0x04,
    Jumping = 0x10,
};

enum class MoveState : uint8_t {
    None = 0x00,
    LeaveCollision = 0x01,
    EnterCollision = 0x02,
    StartFalling = 0x04,
};

// ============================================================================
// Lookup Functions for Enum Names
// ============================================================================

const char* GetCalcResultTypeName(CalcResultType type) noexcept;
const char* GetObjKindName(ObjKind kind) noexcept;
const char* GetActionKindName(ActionKind kind) noexcept;
const char* GetWarpTypeName(WarpType type) noexcept;
const char* GetActorStatusName(ActorStatus status) noexcept;
const char* GetInventoryTypeName(InventoryType type) noexcept;
const char* GetItemOperationTypeName(ItemOperationType type) noexcept;
const char* GetGearSlotName(GearSetSlot slot) noexcept;
const char* GetClientCommandName(ClientCommand cmd) noexcept;
const char* GetGrandCompanyName(GrandCompany gc) noexcept;
const char* GetHouseSizeName(HouseSize size) noexcept;

} // namespace GameEnums
