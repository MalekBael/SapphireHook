#include "GameEnums.h"

namespace GameEnums {

const char* GetCalcResultTypeName(CalcResultType type) noexcept {
    switch (type) {
        case CalcResultType::None: return "None";
        case CalcResultType::Miss: return "Miss";
        case CalcResultType::Resist: return "Resist";
        case CalcResultType::DamageHp: return "Damage";
        case CalcResultType::RecoverHp: return "Heal";
        case CalcResultType::CriticalDamageHp: return "Critical";
        case CalcResultType::CriticalRecoverHp: return "CritHeal";
        case CalcResultType::Guard: return "Guard";
        case CalcResultType::Parry: return "Parry";
        case CalcResultType::Invalid: return "Invalid";
        case CalcResultType::Uneffective: return "Uneffective";
        case CalcResultType::Neglect: return "Neglect";
        case CalcResultType::DamageMp: return "DamageMp";
        case CalcResultType::RecoverMp: return "RecoverMp";
        case CalcResultType::DamageTp: return "DamageTp";
        case CalcResultType::RecoverTp: return "RecoverTp";
        case CalcResultType::RecoverGp: return "RecoverGp";
        case CalcResultType::SetStatus: return "ApplyStatus";
        case CalcResultType::SetStatusMe: return "ApplyStatusSelf";
        case CalcResultType::ResetStatus: return "RemoveStatus";
        case CalcResultType::ResetStatusMe: return "RemoveStatusSelf";
        case CalcResultType::ResetBadStatus: return "Esuna";
        case CalcResultType::UneffectiveStatus: return "StatusResist";
        case CalcResultType::HalfGoodStatus: return "HalfBuff";
        case CalcResultType::HateDirect: return "Enmity";
        case CalcResultType::HateIndirection: return "EnmityIndirect";
        case CalcResultType::HateTop: return "Provoke";
        case CalcResultType::HateAdd: return "EnmityAdd";
        case CalcResultType::HateMult: return "EnmityMult";
        case CalcResultType::Combo: return "Combo";
        case CalcResultType::ComboHit: return "ComboHit";
        case CalcResultType::Counter: return "Counter";
        case CalcResultType::Destruct: return "Destruct";
        case CalcResultType::Paralysis: return "Paralysis";
        case CalcResultType::KnockBack: return "Knockback";
        case CalcResultType::DrawUpChairs: return "DrawIn";
        case CalcResultType::Sucked: return "Sucked";
        case CalcResultType::CtDrawUpChairs: return "CtDrawIn";
        case CalcResultType::LiveCallback: return "LiveCallback";
        case CalcResultType::Mount: return "Mount";
        case CalcResultType::ArcherDot: return "ArcherDot";
        case CalcResultType::MasterDot: return "MasterDot";
        case CalcResultType::BlessingOfGoddess: return "Blessing";
        case CalcResultType::BadBreath: return "BadBreath";
        case CalcResultType::Revival: return "Raise";
        case CalcResultType::Pet: return "Pet";
        case CalcResultType::Blow: return "Blow";
        case CalcResultType::StatusResist: return "StatusResist";
        case CalcResultType::ClearPhysical: return "ClearPhysical";
        case CalcResultType::BNpcState: return "BNpcState";
        case CalcResultType::Vfx: return "VFX";
        case CalcResultType::HardCode: return "HardCode";
        case CalcResultType::CalcId: return "CalcId";
        case CalcResultType::ClearPvpPoint: return "ClearPvpPoint";
        case CalcResultType::CheckBarrier: return "Barrier";
        case CalcResultType::Reflect: return "Reflect";
        default: return nullptr;
    }
}

const char* GetObjKindName(ObjKind kind) noexcept {
    switch (kind) {
        case ObjKind::None: return "None";
        case ObjKind::Player: return "Player";
        case ObjKind::BattleNpc: return "BattleNpc";
        case ObjKind::EventNpc: return "EventNpc";
        case ObjKind::Treasure: return "Treasure";
        case ObjKind::Aetheryte: return "Aetheryte";
        case ObjKind::GatheringPoint: return "GatheringPoint";
        case ObjKind::EventObj: return "EventObj";
        case ObjKind::MountType: return "Mount";
        case ObjKind::Companion: return "Minion";
        case ObjKind::Retainer: return "Retainer";
        case ObjKind::Area: return "Area";
        case ObjKind::Housing: return "Housing";
        case ObjKind::Cutscene: return "Cutscene";
        case ObjKind::CardStand: return "CardStand";
        default: return nullptr;
    }
}

const char* GetActionKindName(ActionKind kind) noexcept {
    switch (kind) {
        case ActionKind::Nothing: return "None";
        case ActionKind::Normal: return "Normal";
        case ActionKind::Item: return "Item";
        case ActionKind::EventItem: return "EventItem";
        case ActionKind::EventAction: return "EventAction";
        case ActionKind::General: return "General";
        case ActionKind::Buddy: return "Buddy";
        case ActionKind::Command: return "Command";
        case ActionKind::Companion: return "Companion";
        case ActionKind::Craft: return "Craft";
        case ActionKind::Fishing: return "Fishing";
        case ActionKind::Pet: return "Pet";
        case ActionKind::CompanyAction: return "FCAction";
        case ActionKind::Mount: return "Mount";
        case ActionKind::PvpAction: return "PvP";
        case ActionKind::FieldMarker: return "Marker";
        default: return nullptr;
    }
}

const char* GetWarpTypeName(WarpType type) noexcept {
    switch (type) {
        case WarpType::None: return "None";
        case WarpType::Normal: return "Normal";
        case WarpType::NormalPos: return "NormalPos";
        case WarpType::ExitRange: return "ExitRange";
        case WarpType::Telepo: return "Teleport";
        case WarpType::Reise: return "Return";
        case WarpType::Unknown6: return "Unk6";
        case WarpType::Desion: return "Desion";
        case WarpType::HomePoint: return "HomePoint";
        case WarpType::RentalChocobo: return "RentalChocobo";
        case WarpType::ChocoboTaxi: return "ChocoboTaxi";
        case WarpType::InstanceContent: return "Duty";
        case WarpType::Reject: return "Reject";
        case WarpType::ContentEndReturn: return "DutyEnd";
        case WarpType::TownTranslate: return "TownTranslate";
        case WarpType::GM: return "GM";
        case WarpType::Login: return "Login";
        case WarpType::LayerSet: return "LayerSet";
        case WarpType::Emote: return "Emote";
        case WarpType::HousingTelepo: return "Housing";
        case WarpType::Debug: return "Debug";
        default: return nullptr;
    }
}

const char* GetActorStatusName(ActorStatus status) noexcept {
    switch (status) {
        case ActorStatus::Idle: return "Idle";
        case ActorStatus::Dead: return "Dead";
        case ActorStatus::Sitting: return "Sitting";
        case ActorStatus::Mounted: return "Mounted";
        case ActorStatus::Crafting: return "Crafting";
        case ActorStatus::Gathering: return "Gathering";
        case ActorStatus::Melding: return "Melding";
        case ActorStatus::SMachine: return "SMachine";
        case ActorStatus::Carry: return "Carry";
        case ActorStatus::EmoteMode: return "EmoteMode";
        default: return nullptr;
    }
}

const char* GetInventoryTypeName(InventoryType type) noexcept {
    switch (type) {
        case InventoryType::Bag0: return "Bag1";
        case InventoryType::Bag1: return "Bag2";
        case InventoryType::Bag2: return "Bag3";
        case InventoryType::Bag3: return "Bag4";
        case InventoryType::GearSet0: return "Equipped";
        case InventoryType::GearSet1: return "GearSet1";
        case InventoryType::Currency: return "Currency";
        case InventoryType::Crystal: return "Crystal";
        case InventoryType::KeyItem: return "KeyItem";
        case InventoryType::HandIn: return "HandIn";
        case InventoryType::DamagedGear: return "DamagedGear";
        case InventoryType::ArmoryOff: return "ArmoryOff";
        case InventoryType::ArmoryHead: return "ArmoryHead";
        case InventoryType::ArmoryBody: return "ArmoryBody";
        case InventoryType::ArmoryHand: return "ArmoryHand";
        case InventoryType::ArmoryWaist: return "ArmoryWaist";
        case InventoryType::ArmoryLegs: return "ArmoryLegs";
        case InventoryType::ArmoryFeet: return "ArmoryFeet";
        case InventoryType::ArmoryNeck: return "ArmoryNeck";
        case InventoryType::ArmoryEar: return "ArmoryEar";
        case InventoryType::ArmoryWrist: return "ArmoryWrist";
        case InventoryType::ArmoryRing: return "ArmoryRing";
        case InventoryType::ArmorySoulCrystal: return "ArmorySoul";
        case InventoryType::ArmoryMain: return "ArmoryMain";
        case InventoryType::RetainerBag0: return "RetainerBag1";
        case InventoryType::RetainerBag1: return "RetainerBag2";
        case InventoryType::RetainerEquippedGear: return "RetainerEquip";
        case InventoryType::RetainerGil: return "RetainerGil";
        case InventoryType::RetainerCrystal: return "RetainerCrystal";
        case InventoryType::RetainerMarket: return "RetainerMarket";
        case InventoryType::FreeCompanyBag0: return "FCChest1";
        case InventoryType::FreeCompanyBag1: return "FCChest2";
        case InventoryType::FreeCompanyBag2: return "FCChest3";
        case InventoryType::FreeCompanyGil: return "FCGil";
        case InventoryType::FreeCompanyCrystal: return "FCCrystal";
        case InventoryType::HousingExteriorAppearance: return "HousingExt";
        case InventoryType::HousingInteriorAppearance: return "HousingInt";
        case InventoryType::HousingExteriorPlacedItems: return "HousingYard";
        case InventoryType::HousingExteriorStoreroom: return "HousingStore";
        default: return nullptr;
    }
}

const char* GetItemOperationTypeName(ItemOperationType type) noexcept {
    switch (type) {
        case ItemOperationType::None: return "None";
        case ItemOperationType::CreateStorage: return "CreateStorage";
        case ItemOperationType::DeleteStorage: return "DeleteStorage";
        case ItemOperationType::CompactStorage: return "Compact";
        case ItemOperationType::ResyncStorage: return "Resync";
        case ItemOperationType::CreateItem: return "Create";
        case ItemOperationType::UpdateItem: return "Update";
        case ItemOperationType::DeleteItem: return "Delete";
        case ItemOperationType::MoveItem: return "Move";
        case ItemOperationType::SwapItem: return "Swap";
        case ItemOperationType::SplitItem: return "Split";
        case ItemOperationType::SplitToMerge: return "SplitMerge";
        case ItemOperationType::MergeItem: return "Merge";
        case ItemOperationType::RepairItem: return "Repair";
        case ItemOperationType::NpcRepairItem: return "NpcRepair";
        case ItemOperationType::TradeCommand: return "Trade";
        case ItemOperationType::MoveTrade: return "MoveTrade";
        case ItemOperationType::SetGilTrade: return "TradeGil";
        case ItemOperationType::CreateMateria: return "CreateMateria";
        case ItemOperationType::AttachMateria: return "Meld";
        case ItemOperationType::RemoveMateria: return "RemoveMateria";
        case ItemOperationType::Gathering: return "Gather";
        case ItemOperationType::Craft: return "Craft";
        case ItemOperationType::Fishing: return "Fish";
        case ItemOperationType::GcSupply: return "GCSupply";
        case ItemOperationType::CabinetTake: return "CabinetTake";
        case ItemOperationType::CabinetGive: return "CabinetGive";
        case ItemOperationType::ShopBuyback: return "Buyback";
        case ItemOperationType::Telepo: return "Teleport";
        case ItemOperationType::VentureStart: return "VentureStart";
        case ItemOperationType::VentureEnd: return "VentureEnd";
        case ItemOperationType::GardeningHarvest: return "Harvest";
        case ItemOperationType::SalvageResult: return "Desynth";
        case ItemOperationType::TreasurePublic: return "TreasurePublic";
        case ItemOperationType::TreasureHunt: return "TreasureHunt";
        case ItemOperationType::RandomItem: return "Random";
        case ItemOperationType::MateriaSlot: return "MateriaSlot";
        case ItemOperationType::AchievementReward: return "Achievement";
        default: return nullptr;
    }
}

const char* GetGearSlotName(GearSetSlot slot) noexcept {
    switch (slot) {
        case GearSetSlot::MainHand: return "MainHand";
        case GearSetSlot::OffHand: return "OffHand";
        case GearSetSlot::Head: return "Head";
        case GearSetSlot::Body: return "Body";
        case GearSetSlot::Hands: return "Hands";
        case GearSetSlot::Waist: return "Waist";
        case GearSetSlot::Legs: return "Legs";
        case GearSetSlot::Feet: return "Feet";
        case GearSetSlot::Ear: return "Ear";
        case GearSetSlot::Neck: return "Neck";
        case GearSetSlot::Wrist: return "Wrist";
        case GearSetSlot::Ring1: return "Ring1";
        case GearSetSlot::Ring2: return "Ring2";
        case GearSetSlot::SoulCrystal: return "SoulCrystal";
        default: return nullptr;
    }
}

const char* GetClientCommandName(ClientCommand cmd) noexcept {
    switch (cmd) {
        case ClientCommand::DrawnSword: return "ToggleWeapon";
        case ClientCommand::AutoAttack: return "AutoAttack";
        case ClientCommand::TargetDecide: return "Target";
        case ClientCommand::RequestAction: return "Action";
        case ClientCommand::CancelMount: return "Dismount";
        case ClientCommand::Companion: return "SummonMinion";
        case ClientCommand::CompanionCancel: return "DismissMinion";
        case ClientCommand::RequestStatusReset: return "StatusReset";
        case ClientCommand::CancelCast: return "CancelCast";
        case ClientCommand::MountLink: return "Mount";
        case ClientCommand::UnmountLink: return "Unmount";
        case ClientCommand::Revive: return "Revive";
        case ClientCommand::FinishLoading: return "FinishLoading";
        case ClientCommand::TelepoInquiry: return "TeleportInquiry";
        case ClientCommand::TelepoCancel: return "TeleportCancel";
        case ClientCommand::RaiseCancel: return "RaiseCancel";
        case ClientCommand::WarpReply: return "WarpReply";
        case ClientCommand::Inspect: return "Examine";
        case ClientCommand::Marking: return "Mark";
        case ClientCommand::ActiveTitle: return "SetTitle";
        case ClientCommand::TitleList: return "TitleList";
        case ClientCommand::Emote: return "Emote";
        case ClientCommand::EmoteCancel: return "EmoteCancel";
        case ClientCommand::JumpStart: return "JumpStart";
        case ClientCommand::JumpLanding: return "JumpLand";
        case ClientCommand::StartCraft: return "StartCraft";
        case ClientCommand::Fishing: return "Fishing";
        case ClientCommand::CancelQuest: return "AbandonQuest";
        case ClientCommand::DirectorInitReturn: return "DirectorInit";
        case ClientCommand::SyncDirector: return "DirectorSync";
        case ClientCommand::EventHandler: return "Event";
        case ClientCommand::FateStart: return "FateStart";
        case ClientCommand::FateLevelSync: return "FateLevelSync";
        case ClientCommand::AchievementRequest: return "AchievementReq";
        case ClientCommand::HousingGetProfile: return "HousingProfile";
        case ClientCommand::HousingBuild: return "HousingBuild";
        case ClientCommand::HousingLayoutMode: return "HousingLayout";
        case ClientCommand::BuddyAction: return "BuddyAction";
        case ClientCommand::BuddyEquip: return "BuddyEquip";
        case ClientCommand::PetCommand: return "PetCommand";
        case ClientCommand::ScreenShot: return "Screenshot";
        default: return nullptr;
    }
}

const char* GetGrandCompanyName(GrandCompany gc) noexcept {
    switch (gc) {
        case GrandCompany::None: return "None";
        case GrandCompany::Maelstrom: return "Maelstrom";
        case GrandCompany::TwinAdder: return "TwinAdder";
        case GrandCompany::ImmortalFlames: return "ImmortalFlames";
        default: return nullptr;
    }
}

const char* GetHouseSizeName(HouseSize size) noexcept {
    switch (size) {
        case HouseSize::Small: return "Small";
        case HouseSize::Medium: return "Medium";
        case HouseSize::Large: return "Large";
        case HouseSize::All: return "All";
        case HouseSize::Invalid: return "Invalid";
        default: return nullptr;
    }
}

} // namespace GameEnums
