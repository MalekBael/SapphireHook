#include "PacketRegistration.h"

#include <unordered_map>
#include <chrono>

// Single definition of the global map
std::unordered_map<uint32_t, std::chrono::system_clock::time_point> g_actionRequestTimes;

// Provide the missing definition to satisfy the declaration in PacketRegistration.h.
// Currently no initialization-specific packet registrations are required.
// Keep this stub for future use (e.g. registering synthetic/internal helper decoders).
namespace PacketDecoding {
    void RegisterInitPackets() {
        // Intentionally empty.
    }
}

// Static initialization helper to ensure all packet decoders are registered exactly once
namespace {
    struct PacketRegistrar {
        PacketRegistrar() {
            PacketDecoding::RegisterAllPackets();
        }
    };

    static PacketRegistrar g_registrar; // Runs at module load
}