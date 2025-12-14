#include "dynamic_hook_engine.h"
#include "hook_manager.h"
#include "../Logger/Logger.h"

#include <MinHook.h>
#include <array>
#include <atomic>
#include <mutex>

namespace SapphireHook {

    // ---------- Exd_GetById family (uint64_t __fastcall(void*, uint64_t)) ----------
    using Fn_GetById = uint64_t(__fastcall*)(void*, uint64_t);

    static constexpr size_t kMaxSlots = 32;

    struct Slot_GetById {
        std::atomic<bool> used{ false };
        Fn_GetById original{ nullptr };
        std::string name;
        uintptr_t address{ 0 };
    };

    static std::array<Slot_GetById, kMaxSlots> g_slots_getById;
    static std::mutex g_slots_getById_mtx;

    // Generate 32 detour slots without hardcoding per-function bodies.
    // Each slot has its own detour symbol so MinHook can bind a unique target->detour.
#define DEFINE_GETBYID_DETOUR_SLOT(N) \
    static uint64_t __fastcall Detour_GetById_Slot##N(void* rcx, uint64_t id) { \
        auto& slot = g_slots_getById[N]; \
        if (!slot.original) { \
            LogError("Detour_GetById_Slot" #N ": original is null"); \
            return 0; \
        } \
        LogInfo(std::string("[DynHook] Enter ") + slot.name + " this=" + Logger::HexFormat((uint64_t)rcx) + " id=" + std::to_string(id)); \
        const auto ret = slot.original(rcx, id); \
        LogInfo(std::string("[DynHook] Leave ") + slot.name + " -> " + Logger::HexFormat(ret)); \
        return ret; \
    }

    DEFINE_GETBYID_DETOUR_SLOT(0)  DEFINE_GETBYID_DETOUR_SLOT(1)  DEFINE_GETBYID_DETOUR_SLOT(2)  DEFINE_GETBYID_DETOUR_SLOT(3)
        DEFINE_GETBYID_DETOUR_SLOT(4)  DEFINE_GETBYID_DETOUR_SLOT(5)  DEFINE_GETBYID_DETOUR_SLOT(6)  DEFINE_GETBYID_DETOUR_SLOT(7)
        DEFINE_GETBYID_DETOUR_SLOT(8)  DEFINE_GETBYID_DETOUR_SLOT(9)  DEFINE_GETBYID_DETOUR_SLOT(10) DEFINE_GETBYID_DETOUR_SLOT(11)
        DEFINE_GETBYID_DETOUR_SLOT(12) DEFINE_GETBYID_DETOUR_SLOT(13) DEFINE_GETBYID_DETOUR_SLOT(14) DEFINE_GETBYID_DETOUR_SLOT(15)
        DEFINE_GETBYID_DETOUR_SLOT(16) DEFINE_GETBYID_DETOUR_SLOT(17) DEFINE_GETBYID_DETOUR_SLOT(18) DEFINE_GETBYID_DETOUR_SLOT(19)
        DEFINE_GETBYID_DETOUR_SLOT(20) DEFINE_GETBYID_DETOUR_SLOT(21) DEFINE_GETBYID_DETOUR_SLOT(22) DEFINE_GETBYID_DETOUR_SLOT(23)
        DEFINE_GETBYID_DETOUR_SLOT(24) DEFINE_GETBYID_DETOUR_SLOT(25) DEFINE_GETBYID_DETOUR_SLOT(26) DEFINE_GETBYID_DETOUR_SLOT(27)
        DEFINE_GETBYID_DETOUR_SLOT(28) DEFINE_GETBYID_DETOUR_SLOT(29) DEFINE_GETBYID_DETOUR_SLOT(30) DEFINE_GETBYID_DETOUR_SLOT(31)

        // Array of detour entry points matching slots 0..31
        static void* g_getById_detours[kMaxSlots] = {
            (void*)&Detour_GetById_Slot0,  (void*)&Detour_GetById_Slot1,  (void*)&Detour_GetById_Slot2,  (void*)&Detour_GetById_Slot3,
            (void*)&Detour_GetById_Slot4,  (void*)&Detour_GetById_Slot5,  (void*)&Detour_GetById_Slot6,  (void*)&Detour_GetById_Slot7,
            (void*)&Detour_GetById_Slot8,  (void*)&Detour_GetById_Slot9,  (void*)&Detour_GetById_Slot10, (void*)&Detour_GetById_Slot11,
            (void*)&Detour_GetById_Slot12, (void*)&Detour_GetById_Slot13, (void*)&Detour_GetById_Slot14, (void*)&Detour_GetById_Slot15,
            (void*)&Detour_GetById_Slot16, (void*)&Detour_GetById_Slot17, (void*)&Detour_GetById_Slot18, (void*)&Detour_GetById_Slot19,
            (void*)&Detour_GetById_Slot20, (void*)&Detour_GetById_Slot21, (void*)&Detour_GetById_Slot22, (void*)&Detour_GetById_Slot23,
            (void*)&Detour_GetById_Slot24, (void*)&Detour_GetById_Slot25, (void*)&Detour_GetById_Slot26, (void*)&Detour_GetById_Slot27,
            (void*)&Detour_GetById_Slot28, (void*)&Detour_GetById_Slot29, (void*)&Detour_GetById_Slot30, (void*)&Detour_GetById_Slot31
    };

    // ---------- Exd_RowCount family (uint32_t __fastcall(void*)) ----------
    using Fn_RowCount = uint32_t(__fastcall*)(void*);

    struct Slot_RowCount {
        std::atomic<bool> used{ false };
        Fn_RowCount original{ nullptr };
        std::string name;
        uintptr_t address{ 0 };
    };

    static std::array<Slot_RowCount, kMaxSlots> g_slots_rowCount;
    static std::mutex g_slots_rowCount_mtx;

#define DEFINE_ROWCOUNT_DETOUR_SLOT(N) \
    static uint32_t __fastcall Detour_RowCount_Slot##N(void* rcx) { \
        auto& slot = g_slots_rowCount[N]; \
        if (!slot.original) { \
            LogError("Detour_RowCount_Slot" #N ": original is null"); \
            return 0; \
        } \
        LogInfo(std::string("[DynHook] Enter ") + slot.name + " this=" + Logger::HexFormat((uint64_t)rcx)); \
        const auto ret = slot.original(rcx); \
        LogInfo(std::string("[DynHook] Leave ") + slot.name + " -> " + std::to_string(ret)); \
        return ret; \
    }

    DEFINE_ROWCOUNT_DETOUR_SLOT(0)  DEFINE_ROWCOUNT_DETOUR_SLOT(1)  DEFINE_ROWCOUNT_DETOUR_SLOT(2)  DEFINE_ROWCOUNT_DETOUR_SLOT(3)
        DEFINE_ROWCOUNT_DETOUR_SLOT(4)  DEFINE_ROWCOUNT_DETOUR_SLOT(5)  DEFINE_ROWCOUNT_DETOUR_SLOT(6)  DEFINE_ROWCOUNT_DETOUR_SLOT(7)
        DEFINE_ROWCOUNT_DETOUR_SLOT(8)  DEFINE_ROWCOUNT_DETOUR_SLOT(9)  DEFINE_ROWCOUNT_DETOUR_SLOT(10) DEFINE_ROWCOUNT_DETOUR_SLOT(11)
        DEFINE_ROWCOUNT_DETOUR_SLOT(12) DEFINE_ROWCOUNT_DETOUR_SLOT(13) DEFINE_ROWCOUNT_DETOUR_SLOT(14) DEFINE_ROWCOUNT_DETOUR_SLOT(15)
        DEFINE_ROWCOUNT_DETOUR_SLOT(16) DEFINE_ROWCOUNT_DETOUR_SLOT(17) DEFINE_ROWCOUNT_DETOUR_SLOT(18) DEFINE_ROWCOUNT_DETOUR_SLOT(19)
        DEFINE_ROWCOUNT_DETOUR_SLOT(20) DEFINE_ROWCOUNT_DETOUR_SLOT(21) DEFINE_ROWCOUNT_DETOUR_SLOT(22) DEFINE_ROWCOUNT_DETOUR_SLOT(23)
        DEFINE_ROWCOUNT_DETOUR_SLOT(24) DEFINE_ROWCOUNT_DETOUR_SLOT(25) DEFINE_ROWCOUNT_DETOUR_SLOT(26) DEFINE_ROWCOUNT_DETOUR_SLOT(27)
        DEFINE_ROWCOUNT_DETOUR_SLOT(28) DEFINE_ROWCOUNT_DETOUR_SLOT(29) DEFINE_ROWCOUNT_DETOUR_SLOT(30) DEFINE_ROWCOUNT_DETOUR_SLOT(31)

        static void* g_rowCount_detours[kMaxSlots] = {
            (void*)&Detour_RowCount_Slot0,  (void*)&Detour_RowCount_Slot1,  (void*)&Detour_RowCount_Slot2,  (void*)&Detour_RowCount_Slot3,
            (void*)&Detour_RowCount_Slot4,  (void*)&Detour_RowCount_Slot5,  (void*)&Detour_RowCount_Slot6,  (void*)&Detour_RowCount_Slot7,
            (void*)&Detour_RowCount_Slot8,  (void*)&Detour_RowCount_Slot9,  (void*)&Detour_RowCount_Slot10, (void*)&Detour_RowCount_Slot11,
            (void*)&Detour_RowCount_Slot12, (void*)&Detour_RowCount_Slot13, (void*)&Detour_RowCount_Slot14, (void*)&Detour_RowCount_Slot15,
            (void*)&Detour_RowCount_Slot16, (void*)&Detour_RowCount_Slot17, (void*)&Detour_RowCount_Slot18, (void*)&Detour_RowCount_Slot19,
            (void*)&Detour_RowCount_Slot20, (void*)&Detour_RowCount_Slot21, (void*)&Detour_RowCount_Slot22, (void*)&Detour_RowCount_Slot23,
            (void*)&Detour_RowCount_Slot24, (void*)&Detour_RowCount_Slot25, (void*)&Detour_RowCount_Slot26, (void*)&Detour_RowCount_Slot27,
            (void*)&Detour_RowCount_Slot28, (void*)&Detour_RowCount_Slot29, (void*)&Detour_RowCount_Slot30, (void*)&Detour_RowCount_Slot31
    };

    // ---------- Helpers ----------

    static bool CreateEnableHook(uintptr_t address, void* detour, void** outOriginal)
    {
        if (!HookManager::ValidateHookAddress(address))
        {
            LogError("DynamicHook: address validation failed");
            return false;
        }
        void* target = reinterpret_cast<void*>(address);
        if (MH_CreateHook(target, detour, outOriginal) != MH_OK)
        {
            LogError("DynamicHook: MH_CreateHook failed");
            return false;
        }
        if (MH_EnableHook(target) != MH_OK)
        {
            MH_RemoveHook(target);
            LogError("DynamicHook: MH_EnableHook failed");
            return false;
        }
        return true;
    }

    bool InstallDynamicHook(const DynamicHookSpec& spec)
    {
        if (!spec.address)
        {
            LogError("InstallDynamicHook: null address for " + spec.name);
            return false;
        }

        switch (spec.family)
        {
        case HookProtoFamily::Exd_GetById: {
            std::scoped_lock lk(g_slots_getById_mtx);
            for (size_t i = 0; i < kMaxSlots; ++i)
            {
                auto& slot = g_slots_getById[i];
                if (!slot.used.load())
                {
                    void* detour = g_getById_detours[i];
                    void** pOriginal = reinterpret_cast<void**>(&slot.original);
                    if (!CreateEnableHook(spec.address, detour, pOriginal))
                    {
                        return false;
                    }
                    slot.used = true;
                    slot.name = spec.name;
                    slot.address = spec.address;
                    HookManager::RegisterHook(spec.name, spec.address, reinterpret_cast<void*>(slot.original), "ffxiv_dx11.exe");
                    LogInfo("DynamicHook installed [" + spec.name + "] at " + Logger::HexFormat(spec.address) + " (Exd_GetById, slot " + std::to_string(i) + ")");
                    return true;
                }
            }
            LogError("InstallDynamicHook: no free slots for Exd_GetById");
            return false;
        }
        case HookProtoFamily::Exd_RowCount: {
            std::scoped_lock lk(g_slots_rowCount_mtx);
            for (size_t i = 0; i < kMaxSlots; ++i)
            {
                auto& slot = g_slots_rowCount[i];
                if (!slot.used.load())
                {
                    void* detour = g_rowCount_detours[i];
                    void** pOriginal = reinterpret_cast<void**>(&slot.original);
                    if (!CreateEnableHook(spec.address, detour, pOriginal))
                    {
                        return false;
                    }
                    slot.used = true;
                    slot.name = spec.name;
                    slot.address = spec.address;
                    HookManager::RegisterHook(spec.name, spec.address, reinterpret_cast<void*>(slot.original), "ffxiv_dx11.exe");
                    LogInfo("DynamicHook installed [" + spec.name + "] at " + Logger::HexFormat(spec.address) + " (Exd_RowCount, slot " + std::to_string(i) + ")");
                    return true;
                }
            }
            LogError("InstallDynamicHook: no free slots for Exd_RowCount");
            return false;
        }
        default:
            LogError("InstallDynamicHook: unsupported family");
            return false;
        }
    }

    std::optional<HookProtoFamily> InferFamilyFromName(const std::string& name)
    {
        // Heuristics for Client::ExdData::get... functions
        // "Client::ExdData::getX::rowCount" -> RowCount
        // "Client::ExdData::getX" -> GetById
        if (name.rfind("Client::ExdData::get", 0) != std::string::npos)
        {
            if (name.find("::rowCount") != std::string::npos)
                return HookProtoFamily::Exd_RowCount;
            return HookProtoFamily::Exd_GetById;
        }
        return std::nullopt;
    }

} // namespace SapphireHook