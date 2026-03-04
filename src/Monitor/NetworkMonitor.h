#pragma once

#include "../vendor/imgui/imgui.h"
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

inline constexpr size_t SLOT_COUNT = 16384;
inline constexpr size_t SLOT_PAYLOAD_CAP = 8192;
inline constexpr size_t UI_BATCH_CAP =
16384;

struct HookPacket {
	bool outgoing = false;
	uint64_t connection_id = 0;
	std::chrono::system_clock::time_point ts{};
	uint32_t len = 0;
	std::array<uint8_t, SLOT_PAYLOAD_CAP> buf{};
};

enum class SlotState : uint8_t {
	EMPTY = 0,
	WRITING = 1,
	READY = 2,
	READING = 3
};

class PacketCapture {
public:
	struct LastIpcSnapshot {
		bool valid = false;
		bool outgoing = false;
		bool compressed = false;
		uint64_t connection_id = 0;
		uint16_t connType = 0xFFFF;
		uint16_t opcode = 0;
		uint64_t time_epoch_ms = 0;
	};

	static PacketCapture& Instance();

	PacketCapture(const PacketCapture&) = delete;
	PacketCapture& operator=(const PacketCapture&) = delete;

	bool TryEnqueueFromHook(const void* data, size_t len, bool outgoing,
		uint64_t conn_id = 0) noexcept;

	void DrainToVector(std::vector<HookPacket>& out);

	void DrawImGuiSimple();
	void DrawImGuiSimple(bool* p_open);

	void DrawImGuiEmbedded();

	static void DumpHexAscii(const HookPacket& hp);
	static void DumpHexAsciiColored(const HookPacket& hp,
		const std::vector<unsigned int>& colors);

	static bool TryGetSelectedPacket(HookPacket& out);

	static bool TryGetLastIncomingIpcSnapshot(LastIpcSnapshot& out);
	static bool TryGetLastOutgoingIpcSnapshot(LastIpcSnapshot& out);

private:
	PacketCapture();
	~PacketCapture();

	static inline constexpr size_t SLOT_PROBES = 8;

	struct Slot {
		std::atomic<uint8_t> state;
		HookPacket packet;
	};
	alignas(64) Slot slots_[SLOT_COUNT];

	std::atomic<size_t> producer_fetch_{ 0 };
};

using SafeHookLogger = PacketCapture;
