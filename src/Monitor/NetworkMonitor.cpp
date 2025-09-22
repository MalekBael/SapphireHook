#include "NetworkMonitor.h"
#include <cstring>
#include "../vendor/imgui/imgui.h"
#include "../vendor/imgui/imgui_internal.h"
#include <sstream>
#include <cstdio>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <algorithm>
#include "OpcodeNames.h"
#include <vector>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <functional>      
#include <iomanip>
#include "../../vendor/miniz/miniz.h"
#include "../../vendor/ImGuiFD/ImGuiFD.h"

SafeHookLogger& SafeHookLogger::Instance() {
	static SafeHookLogger inst{};
	return inst;
}

namespace { static std::unordered_map<uint64_t, uint16_t> g_connTypeByConnId; }

namespace { struct ActionReqRec { uint64_t connId = 0; std::chrono::system_clock::time_point ts{}; uint8_t actionKind = 0; uint32_t actionKey = 0; uint64_t target = 0; uint16_t dir = 0; uint16_t dirTarget = 0; }; }
namespace { static std::unordered_map<uint32_t, ActionReqRec> g_actionReqById; }

namespace { static bool g_cfgInflateSegments = true; }

namespace { static HookPacket g_lastSelected{}; static bool g_hasSelection = false; }

namespace {
	static int g_hoveredSegmentIndex = -1;
	static uint32_t g_hoveredSegmentOffset = 0;
	static uint32_t g_hoveredSegmentSize = 0;
	static bool g_hasHoveredSegment = false;
}

namespace {
	struct EventSequence {
		uint32_t eventId;
		uint32_t actorId;
		std::chrono::system_clock::time_point startTime;
		std::vector<uint16_t> packets;    
	};
	static std::unordered_map<uint32_t, EventSequence> g_activeEvents;

	struct CombatSequence {
		uint32_t requestId;
		std::chrono::system_clock::time_point startTime;
		uint16_t actionId;
		uint32_t sourceActor;
		uint32_t targetActor;
		std::vector<uint16_t> resultOpcodes;
	};
	static std::unordered_map<uint32_t, CombatSequence> g_combatSequences;

	struct PacketRelationship {
		uint32_t requestOpcode;
		uint32_t responseOpcode;
		std::chrono::milliseconds avgLatency;
		uint32_t count;
	};
	static std::unordered_map<uint64_t, PacketRelationship> g_packetRelations;

	struct FlowSequence {
		std::vector<uint16_t> opcodes;
		std::chrono::system_clock::time_point startTime;
		std::chrono::system_clock::time_point endTime;
		std::string description;
	};
	static std::vector<FlowSequence> g_flowHistory;
	static FlowSequence g_currentFlow;

	struct PacketPattern {
		std::string name;
		std::vector<uint16_t> opcodes;
		std::function<bool(const std::vector<uint16_t>&)> matcher;
		uint32_t matchCount = 0;
	};

	static std::vector<PacketPattern> g_patterns = {
		{"Teleport Sequence", {0x0194, 0x019A}, nullptr}, // Warp -> InitZone (correct)
		{"Combat Round", {0x0196, 0x0146}, nullptr}, // ActionRequest -> ActionResult1 (fixed from 0x0190)
		{"Craft Step", {0x0196, 0x01B4}, nullptr}, // ActionRequest -> TradeCommand (needs verification)
		{"Movement Update", {0x019A, 0x0192}, nullptr}, // Move -> ActorMove
		{"Event Interaction", {0x01C2, 0x1C2}, nullptr}, // StartTalkEvent -> EventPlayHeader
		{"Zone Change", {0x019A, 0x0190}, nullptr}, // InitZone -> Create (spawn actors)
	};

	static void DetectPatterns(const std::vector<uint16_t>& recentOpcodes) {
		for (auto& pattern : g_patterns) {
			if (recentOpcodes.size() >= pattern.opcodes.size()) {
				bool match = true;
				for (size_t i = 0; i < pattern.opcodes.size(); ++i) {
					if (recentOpcodes[recentOpcodes.size() - pattern.opcodes.size() + i] != pattern.opcodes[i]) {
						match = false;
						break;
					}
				}
				if (match) {
					pattern.matchCount++;
				}
			}
		}
	}

	// Replace the existing UpdatePacketCorrelation function (around line 97)
	static void UpdatePacketCorrelation(uint16_t opcode, bool outgoing, const HookPacket& hp) {
		// Track all packets in current flow if one is active
		if (!g_currentFlow.opcodes.empty()) {
			g_currentFlow.opcodes.push_back(opcode);
			// Check if this completes a known flow pattern

			// Combat flows - using correct opcodes from Sapphire
			if (outgoing && opcode == 0x0196) { // ActionRequest (was incorrectly 0x0190)
				g_currentFlow.opcodes.clear();
				g_currentFlow.opcodes.push_back(opcode);
				g_currentFlow.startTime = hp.ts;
				g_currentFlow.description = "Combat Action";
			}
			else if (!outgoing && (opcode == 0x0146 || opcode == 0x0147)) { // ActionResult1/ActionResult - these are correct
				if (!g_currentFlow.opcodes.empty() && g_currentFlow.opcodes[0] == 0x0196) {
					g_currentFlow.endTime = hp.ts;
					if (g_flowHistory.size() >= 100) g_flowHistory.erase(g_flowHistory.begin());
					g_flowHistory.push_back(g_currentFlow);
					g_currentFlow.opcodes.clear();
				}
			}
		}
		else {
			// Start tracking new flows based on common patterns
			if (outgoing) {
				switch (opcode) {
				case 0x0196: // ActionRequest
					g_currentFlow.opcodes.push_back(opcode);
					g_currentFlow.startTime = hp.ts;
					g_currentFlow.description = "Combat Action";
					break;
				case 0x019A: // Move
					g_currentFlow.opcodes.push_back(opcode);
					g_currentFlow.startTime = hp.ts;
					g_currentFlow.description = "Movement";
					break;
				case 0x01C2: // StartTalkEvent
				case 0x01C3: // StartEmoteEvent
				case 0x01C4: // StartWithinRangeEvent
				case 0x01C5: // StartOutsideRangeEvent
					g_currentFlow.opcodes.push_back(opcode);
					g_currentFlow.startTime = hp.ts;
					g_currentFlow.description = "Event Interaction";
					break;
				case 0x01B3: // TradeCommand
					g_currentFlow.opcodes.push_back(opcode);
					g_currentFlow.startTime = hp.ts;
					g_currentFlow.description = "Trade";
					break;
				case 0x0262: // Config
					g_currentFlow.opcodes.push_back(opcode);
					g_currentFlow.startTime = hp.ts;
					g_currentFlow.description = "Configuration Change";
					break;
				}
			}
			else { // Server packets
				switch (opcode) {
				case 0x0194: // Warp
					g_currentFlow.opcodes.push_back(opcode);
					g_currentFlow.startTime = hp.ts;
					g_currentFlow.description = "Teleport/Warp";
					break;
				case 0x019A: // InitZone
					g_currentFlow.opcodes.push_back(opcode);
					g_currentFlow.startTime = hp.ts;
					g_currentFlow.description = "Zone Initialization";
					break;
				case 0x0190: // Create (Actor)
				case 0x0191: // Delete (Actor)
					g_currentFlow.opcodes.push_back(opcode);
					g_currentFlow.startTime = hp.ts;
					g_currentFlow.description = "Actor Spawn/Despawn";
					break;
				}
			}
		}

		// Track packet relationships
		static std::unordered_map<uint64_t, std::pair<uint16_t, std::chrono::system_clock::time_point>> pendingRequests;

		if (outgoing) {
			// Store outgoing packets as potential requests
			pendingRequests[hp.connection_id] = { opcode, hp.ts };
		}
		else if (!pendingRequests.empty()) {
			// Check if this incoming packet could be a response
			auto it = pendingRequests.find(hp.connection_id);
			if (it != pendingRequests.end()) {
				auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(hp.ts - it->second.second);

				// Create relationship key
				uint64_t relKey = (uint64_t(it->second.first) << 32) | opcode;

				// Update or create relationship
				auto& rel = g_packetRelations[relKey];
				if (rel.count == 0) {
					rel.requestOpcode = it->second.first;
					rel.responseOpcode = opcode;
					rel.avgLatency = latency;
					rel.count = 1;
				}
				else {
					// Running average
					rel.avgLatency = (rel.avgLatency * rel.count + latency) / (rel.count + 1);
					rel.count++;
				}

				// Clean up old request
				if (latency.count() < 5000) { // Only correlate if response within 5 seconds
					pendingRequests.erase(it);
				}
			}
		}
	}
}      

SafeHookLogger::SafeHookLogger() {
	for (size_t i = 0; i < SLOT_COUNT; ++i)
		slots_[i].state.store(uint8_t(SlotState::EMPTY));
}

SafeHookLogger::~SafeHookLogger() = default;

bool SafeHookLogger::TryEnqueueFromHook(const void* data, size_t len,
	bool outgoing, uint64_t conn_id) noexcept {
	if (!data || len == 0) return false;
	size_t tocopy = (len > SLOT_PAYLOAD_CAP) ? SLOT_PAYLOAD_CAP : len;

	size_t start = producer_fetch_.fetch_add(1, std::memory_order_relaxed) % SLOT_COUNT;
	for (size_t probe = 0; probe < SLOT_PROBES; ++probe) {
		size_t idx = (start + probe) % SLOT_COUNT;
		uint8_t expected = uint8_t(SlotState::EMPTY);
		if (slots_[idx].state.compare_exchange_strong(expected, uint8_t(SlotState::WRITING),
			std::memory_order_acquire,
			std::memory_order_relaxed)) {
			auto& slot = slots_[idx];
			slot.packet.outgoing = outgoing;
			slot.packet.connection_id = conn_id;
			slot.packet.ts = std::chrono::system_clock::now();
			slot.packet.len = (uint32_t)tocopy;
			std::memcpy(slot.packet.buf.data(), data, tocopy);
			slot.state.store(uint8_t(SlotState::READY), std::memory_order_release);
			return true;
		}
	}
	return false;     
}

void SafeHookLogger::DrainToVector(std::vector<HookPacket>& out) {
	out.clear();
	out.reserve(256);
	for (size_t i = 0; i < SLOT_COUNT && out.size() < UI_BATCH_CAP; ++i) {
		uint8_t expected = uint8_t(SlotState::READY);
		if (slots_[i].state.compare_exchange_strong(expected, uint8_t(SlotState::READING),
			std::memory_order_acquire,
			std::memory_order_relaxed)) {
			out.push_back(slots_[i].packet);
			slots_[i].state.store(uint8_t(SlotState::EMPTY), std::memory_order_release);
		}
	}
}

void SafeHookLogger::DumpHexAscii(const HookPacket& hp) {
	const uint8_t* d = hp.buf.data();
	for (size_t off = 0; off < hp.len; off += 16) {
		size_t len = (hp.len - off < 16) ? hp.len - off : 16;
		char line[256];
		char* p = line;
		p += std::sprintf(p, "%04zx: ", off);
		for (size_t j = 0; j < 16; ++j) {
			if (j < len) p += std::sprintf(p, "%02x ", d[off + j]);
			else p += std::sprintf(p, "   ");
		}
		*p++ = ' ';
		for (size_t j = 0; j < len; ++j) {
			unsigned char c = d[off + j];
			*p++ = (c >= 32 && c < 127) ? (char)c : '.';
		}
		*p = 0;
		ImGui::TextUnformatted(line);
	}
}

void SafeHookLogger::DumpHexAsciiColored(const HookPacket& hp, const std::vector<unsigned int>& colors)
{
	if (colors.size() < hp.len) { DumpHexAscii(hp); return; }

	ImDrawList* dl = ImGui::GetWindowDrawList();
	ImVec2 origin = ImGui::GetCursorScreenPos();
	const ImGuiStyle& style = ImGui::GetStyle();

	const int bytesPerLine = 16;
	const float lineH = ImGui::GetTextLineHeight();
	const float charW = ImGui::CalcTextSize("A").x;
	const float hexCellW = ImGui::CalcTextSize("00 ").x;    
	const float hexStride = hexCellW * 1.5f;                   

	static int s_selStart = -1, s_selEnd = -1;
	static bool s_dragging = false;

	ImVec2 cursor = origin;

	const int totalLines = (int)((hp.len + bytesPerLine - 1) / bytesPerLine);

	const ImVec2 mouse = ImGui::GetIO().MousePos;

	const float offWidth = ImGui::CalcTextSize("0000:").x + style.ItemSpacing.x * 2.0f + 8.0f;
	const float hexWidth = bytesPerLine * hexStride;
	const float asciiWidth = bytesPerLine * charW;
	const float totalWidth = offWidth + hexWidth + style.ItemSpacing.x * 2.0f + asciiWidth;
	const ImVec2 regionSize(totalWidth, totalLines * lineH);
	ImGui::PushID("hex_viewer_overlay");
	ImGui::InvisibleButton("##hex_overlay", regionSize, ImGuiButtonFlags_MouseButtonLeft | ImGuiButtonFlags_MouseButtonRight);
	ImVec2 overlayMin = ImGui::GetItemRectMin();
	ImGui::PopID();

	for (size_t off = 0; off < hp.len; off += bytesPerLine) {
		const float y = cursor.y;
		char offbuf[16]; std::snprintf(offbuf, sizeof(offbuf), "%04zx:", off);
		ImVec2 offPos = ImVec2(cursor.x, y);
		dl->AddText(offPos, ImGui::GetColorU32(ImGuiCol_Text), offbuf);

		const float hexX = cursor.x + ImGui::CalcTextSize("0000:").x + style.ItemSpacing.x * 2.0f + 8.0f;
		const float asciiX = hexX + bytesPerLine * hexStride + style.ItemSpacing.x * 2.0f;

		int hoveredIdx = -1;
		for (int j = 0; j < bytesPerLine; ++j) {
			size_t i = off + j; if (i >= hp.len) break;
			ImRect hexR(ImVec2(hexX + j * hexStride, y), ImVec2(hexX + (j + 1) * hexStride, y + lineH));
			ImRect ascR(ImVec2(asciiX + j * charW, y), ImVec2(asciiX + (j + 1) * charW, y + lineH));
			if (hexR.Contains(mouse) || ascR.Contains(mouse)) { hoveredIdx = (int)i; break; }
		}

		if (hoveredIdx >= 0) {
			if (ImGui::IsMouseClicked(0)) { s_selStart = s_selEnd = hoveredIdx; s_dragging = true; }
		}
		if (s_dragging) {
			if (ImGui::IsMouseDown(0)) { if (hoveredIdx >= 0) s_selEnd = hoveredIdx; }
			else s_dragging = false;
		}
		if (ImGui::IsMouseClicked(1)) { s_selStart = s_selEnd = -1; s_dragging = false; }

		const int selMin = (s_selStart >= 0 && s_selEnd >= 0) ? std::min(s_selStart, s_selEnd) : -1;
		const int selMax = (s_selStart >= 0 && s_selEnd >= 0) ? std::max(s_selStart, s_selEnd) : -1;

		for (int j = 0; j < bytesPerLine; ++j) {
			size_t i = off + j;
			const ImU32 txtCol = (i < hp.len) ? colors[i] : ImGui::GetColorU32(ImGuiCol_Text);
			ImVec2 hpPos = ImVec2(hexX + j * hexStride, y);
			ImVec2 ascPos = ImVec2(asciiX + j * charW, y);
			ImRect hexR(hpPos, ImVec2(hpPos.x + hexStride, y + lineH));
			ImRect ascR(ImVec2(asciiX + j * charW, y), ImVec2(asciiX + (j + 1) * charW, y + lineH));

			if ((int)i >= selMin && (int)i <= selMax && selMin != -1) {
				const ImU32 selCol = IM_COL32(255, 80, 80, 120);
				dl->AddRectFilled(hexR.Min, hexR.Max, selCol, 2.0f);
				dl->AddRectFilled(ascR.Min, ascR.Max, selCol, 2.0f);
			}
			else if ((int)i == hoveredIdx) {
				const ImU32 hovCol = IM_COL32(80, 160, 255, 90);
				dl->AddRectFilled(hexR.Min, hexR.Max, hovCol, 2.0f);
				dl->AddRectFilled(ascR.Min, ascR.Max, hovCol, 2.0f);
			}
			else if (g_hasHoveredSegment &&
				i >= (uint32_t(0x28) + g_hoveredSegmentOffset) &&
				i < (uint32_t(0x28) + g_hoveredSegmentOffset + g_hoveredSegmentSize)) {
				const ImU32 segCol = IM_COL32(255, 255, 120, 80);
				dl->AddRectFilled(hexR.Min, hexR.Max, segCol, 2.0f);
				dl->AddRectFilled(ascR.Min, ascR.Max, segCol, 2.0f);
			}

			char b[4] = { 0 };
			if (i < hp.len) std::snprintf(b, sizeof(b), "%02x", hp.buf[i]); else { b[0] = ' '; b[1] = ' '; }
			dl->AddText(hpPos, txtCol, b);

			char c = (i < hp.len) ? (char)hp.buf[i] : ' ';
			if ((unsigned char)c < 32 || (unsigned char)c >= 127) c = '.';
			char s[2] = { c, 0 };
			dl->AddText(ascPos, txtCol, s);
		}

		cursor.y += lineH;
	}

	ImGui::Dummy(ImVec2(0, totalLines * lineH));
	ImGui::TextDisabled("Hex selection: Left-drag to select bytes. Right-click to clear selection.");
}

bool SafeHookLogger::TryGetSelectedPacket(HookPacket& out)
{
	if (!g_hasSelection) return false;
	out = g_lastSelected;
	return true;
}

namespace {
	inline std::string Vec3f(float x, float y, float z) {
		char b[96]; std::snprintf(b, sizeof(b), "(%.3f, %.3f, %.3f)", x, y, z); return b;
	}
	inline std::string Vec3u16(uint16_t x, uint16_t y, uint16_t z) {
		char b[96]; std::snprintf(b, sizeof(b), "(%u, %u, %u)", (unsigned)x, (unsigned)y, (unsigned)z); return b;
	}

	const char* ActorControlCategoryName(uint16_t cat) {
		switch (cat) {
		case 0x00: return "ToggleWeapon";
		case 0x01: return "AutoAttack";
		case 0x02: return "SetStatus";
		case 0x03: return "CastStart";
		case 0x04: return "SetBattle";
		case 0x05: return "ClassJobChange";
		case 0x06: return "DefeatMsg";
		case 0x07: return "GainExpMsg";
		case 0x0A: return "LevelUpEffect";
		case 0x0C: return "ExpChainMsg";
		case 0x0D: return "HpSetStat";
		case 0x0E: return "DeathAnimation";
		case 0x0F: return "CastInterrupt";
		case 0x11: return "ActionStart";
		case 0x14: return "StatusEffectGain";
		case 0x15: return "StatusEffectLose";
		case 0x17: return "HPFloatingText";
		case 0x1B: return "Flee";
		case 0x22: return "CombatIndicationShow";
		case 0x25: return "SpawnEffect";
		case 0x26: return "ToggleInvisible";
		case 0x27: return "DeadFadeOut";
		case 0x29: return "SetRewardFlag";
		case 0x2B: return "UpdateUiExp";
		case 0x2D: return "SetFallDamage";
		case 0x32: return "SetTarget";
		case 0x36: return "ToggleNameHidden";
		case 0x47: return "LimitbreakStart";
		case 0x48: return "LimitbreakPartyStart";
		case 0x49: return "BubbleText";
		case 0x50: return "DamageEffect";
		case 0x51: return "RaiseAnimation";
		case 0x57: return "TreasureScreenMsg";
		case 0x59: return "SetOwnerId";
		case 0x5C: return "ItemRepairMsg";
		case 0x63: return "BluActionLearn";
		case 0x64: return "DirectorInit";
		case 0x65: return "DirectorClear";
		case 0x66: return "LeveStartAnim";
		case 0x67: return "LeveStartError";
		case 0x6A: return "DirectorEObjMod";
		case 0x6D: return "DirectorUpdate";
		case 0x74: return "SetFateState";
		case 0x75: return "ObtainFateItem";
		case 0x76: return "FateReqFailMsg";
		case 0x7B: return "DutyQuestScreenMsg";
		case 0x82: return "SetContentClearFlag";
		case 0x83: return "SetContentOpenFlag";
		case 0x84: return "ItemObtainIcon";
		case 0x85: return "FateItemFailMsg";
		case 0x86: return "ItemFailMsg";
		case 0x87: return "ActionLearnMsg1";
		case 0x8A: return "FreeEventPos";
		case 0x8E: return "MoveType";
		case 0x90: return "DailyQuestSeed";
		case 0x9B: return "SetFateProgress";
		case 0xA1: return "SetBGM";
		case 0xA4: return "UnlockAetherCurrentMsg";
		case 0xA8: return "RemoveName";
		case 0xAA: return "ScreenFadeOut";
		case 0xC8: return "Appear";
		case 0xC9: return "ZoneInDefaultPos";
		case 0xCB: return "OnExecuteTelepo";
		case 0xCC: return "OnInvitationTelepo";
		case 0xCD: return "OnExecuteTelepoAction";
		case 0xCE: return "TownTranslate";
		case 0xCF: return "WarpStart";
		case 0xD2: return "InstanceSelectDlg";
		case 0xD4: return "ActorDespawnEffect";
		case 0xFD: return "CompanionUnlock";
		case 0xFE: return "ObtainBarding";
		case 0xFF: return "EquipBarding";
		case 0x102: return "CompanionMsg1";
		case 0x103: return "CompanionMsg2";
		case 0x104: return "ShowPetHotbar";
		case 0x109: return "ActionLearnMsg";
		case 0x10A: return "ActorFadeOut";
		case 0x10B: return "ActorFadeIn";
		case 0x10C: return "WithdrawMsg";
		case 0x10D: return "OrderCompanion";
		case 0x10E: return "ToggleCompanion";
		case 0x10F: return "LearnCompanion";
		case 0x110: return "ActorFateOut1";
		case 0x122: return "Emote";
		case 0x123: return "EmoteInterrupt";
		case 0x124: return "EmoteModeInterrupt";
		case 0x125: return "EmoteModeInterruptNonImmediate";
		case 0x127: return "SetPose";
		case 0x12C: return "CraftingUnk";
		case 0x130: return "GatheringSenseMsg";
		case 0x131: return "PartyMsg";
		case 0x132: return "GatheringSenseMsg1";
		case 0x138: return "GatheringSenseMsg2";
		case 0x140: return "FishingMsg";
		case 0x142: return "FishingTotalFishCaught";
		case 0x145: return "FishingBaitMsg";
		case 0x147: return "FishingReachMsg";
		case 0x148: return "FishingFailMsg";
		case 0x15E: return "MateriaConvertMsg";
		case 0x15F: return "MeldSuccessMsg";
		case 0x160: return "MeldFailMsg";
		case 0x161: return "MeldModeToggle";
		case 0x163: return "AetherRestoreMsg";
		case 0x168: return "DyeMsg";
		case 0x16A: return "ToggleCrestMsg";
		case 0x16B: return "ToggleBulkCrestMsg";
		case 0x16C: return "MateriaRemoveMsg";
		case 0x16D: return "GlamourCastMsg";
		case 0x16E: return "GlamourRemoveMsg";
		default: return "?";
		}
	}

	const char* GetStatusEffectName(uint16_t id) {
		switch (id) {
		case 1: return "Weakness";
		case 2: return "Brink of Death";
		case 3: return "Hard Invuln";
		case 4: return "Transcendent";
		case 5: return "Sleep";
		case 6: return "Stun";
		case 7: return "Paralysis";
		case 8: return "Silence";
		case 9: return "Slow";
		case 10: return "Pacification";
		case 11: return "Heavy";
		case 12: return "Bind";
		case 13: return "Damage Up";
		case 14: return "Damage Down";
		case 15: return "Accuracy Up";
		case 16: return "Accuracy Down";
		case 17: return "Attack Speed Up";
		case 18: return "Attack Speed Down";
		case 19: return "HP Boost";
		case 20: return "MP Boost";
		case 21: return "TP Boost";
		case 30: return "Regen";
		case 31: return "Refresh";
		case 32: return "Freecure";
		case 50: return "Protect";
		case 51: return "Shell";
		case 52: return "Haste";
		case 53: return "Bravery";
		case 54: return "Faith";
		case 55: return "Reflect";
		case 56: return "Invisible";
		case 57: return "Sneak";
		case 58: return "Deodorize";
		case 143: return "Aetherflow";
		case 304: return "Energy Drain";
		case 360: return "Swiftcast";
		default: return nullptr;
		}
	}

	const char* GetActionTypeName(uint8_t type) {
		switch (type) {
		case 1: return "Spell";
		case 2: return "Item";
		case 3: return "KeyItem";
		case 4: return "Ability";
		case 5: return "General";
		case 6: return "Companion";
		case 7: return "Weaponskill";
		case 8: return "Trait";
		case 9: return "CompanionOrder";
		case 10: return "PetAction";
		case 11: return "FieldMarker";
		case 13: return "CraftAction";
		case 15: return "Mount";
		case 17: return "PvPAction";
		case 18: return "Waymark";
		case 19: return "ChocoboRaceAbility";
		case 20: return "ChocoboRaceItem";
		case 21: return "DutyAction";
		case 22: return "PerformanceInstrument";
		case 23: return "Fashion";
		case 24: return "LostAction";
		default: return "Unknown";
		}
	}

	const char* WarpTypeName(uint8_t t) {
		switch (t) {
		case 0x0: return "NON";
		case 0x1: return "NORMAL";
		case 0x2: return "NORMAL_POS";
		case 0x3: return "EXIT_RANGE";
		case 0x4: return "TELEPO";
		case 0x5: return "REISE";
		case 0x6: return "_";
		case 0x7: return "DESION";
		case 0x8: return "HOME_POINT";
		case 0x9: return "RENTAL_CHOCOBO";
		case 0xA: return "CHOCOBO_TAXI";
		case 0xB: return "INSTANCE_CONTENT";
		case 0xC: return "REJECT";
		case 0xD: return "CONTENT_END_RETURN";
		case 0xE: return "TOWN_TRANSLATE";
		case 0xF: return "GM";
		case 0x10: return "LOGIN";
		case 0x11: return "LAYER_SET";
		case 0x12: return "EMOTE";
		case 0x13: return "HOUSING_TELEPO";
		case 0x14: return "DEBUG";
		default: return "?";
		}
	}

	inline bool read16(const uint8_t* b, size_t len, size_t off, uint16_t& out) {
		if (!b || off + 2 > len) return false; out = (uint16_t)(b[off] | (b[off + 1] << 8)); return true;
	}
	inline bool read32(const uint8_t* b, size_t len, size_t off, uint32_t& out) {
		if (!b || off + 4 > len) return false; out = (uint32_t)(b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)); return true;
	}
	inline bool read64(const uint8_t* b, size_t len, size_t off, uint64_t& out) {
		if (!b || off + 8 > len) return false; out = 0; for (int i = 0; i < 8; i++) out |= (uint64_t)b[off + i] << (8 * i); return true;
	}

	template<typename T>
	inline T loadLE(const uint8_t* b) {
		T v{}; std::memcpy(&v, b, sizeof(T)); return v;
	}

	struct ParsedPacket {
		bool hdr_ok = false;
		uint64_t magic0 = 0, magic1 = 0, timestamp = 0;   
		uint32_t size = 0; uint16_t connType = 0, segCount = 0; uint8_t unknown20 = 0, isCompressed = 0; uint32_t unknown24 = 0;
		bool seg_ok = false; uint32_t segSize = 0, src = 0, tgt = 0; uint16_t segType = 0, segPad = 0;
		bool ipc_ok = false; uint16_t ipcReserved = 0, opcode = 0, ipcPad = 0, serverId = 0; uint32_t ipcTimestamp = 0, ipcPad1 = 0;
	};

	struct SegmentInfo {
		uint32_t offset;           
		uint32_t size;
		uint32_t source;
		uint32_t target;
		uint16_t type;
		bool hasIpc;
		uint16_t opcode;
		uint16_t serverId;
		uint32_t ipcTimestamp;
	};

	static const char* SegTypeName(uint16_t t) {
		switch (t) {
		case 1: return "SESSIONINIT";
		case 3: return "IPC";
		case 7: return "KEEPALIVE";
		case 9: return "ENCRYPTIONINIT";
		default: return "?";
		}
	}

	struct SegmentView { const uint8_t* data = nullptr; size_t len = 0; bool compressed = false; bool inflated = false; std::vector<uint8_t> storage; };

	static SegmentView GetSegmentView(const HookPacket& hp)
	{
		SegmentView v{};
		if (hp.len < 0x28) return v;  
		const uint8_t* p = hp.buf.data(); const size_t L = hp.len;
		v.data = p + 0x28; v.len = L - 0x28; v.compressed = false; v.inflated = false;
		if (L >= 0x22) {
			uint16_t tmp = 0; std::memcpy(&tmp, p + 0x20, sizeof(tmp));
			v.compressed = (((tmp >> 8) & 0xFF) != 0);
		}
		if (!v.compressed || !g_cfgInflateSegments) return v;
		uint32_t packetSize = 0; std::memcpy(&packetSize, p + 0x18, 4);
		size_t outLen = (packetSize > 0x28) ? (packetSize - 0x28) : 0;
		if (outLen == 0 || outLen > (64u << 20)) return v;  
		v.storage.resize(outLen);
		size_t res = tinfl_decompress_mem_to_mem(v.storage.data(), outLen, v.data, v.len, 0);
		if (res == TINFL_DECOMPRESS_MEM_TO_MEM_FAILED || res != outLen) {
			res = tinfl_decompress_mem_to_mem(v.storage.data(), outLen, v.data, v.len, TINFL_FLAG_PARSE_ZLIB_HEADER);
			if (res == TINFL_DECOMPRESS_MEM_TO_MEM_FAILED || res != outLen) {
				v.storage.clear();
				return v;
			}
		}
		v.data = v.storage.data(); v.len = outLen; v.inflated = true; return v;
	}

	static void ParseAllSegmentsBuffer(const uint8_t* data, size_t len, std::vector<SegmentInfo>& outSegs)
	{
		outSegs.clear(); if (!data || len < 0x10) return;
		size_t pos = 0;
		while (true) {
			if (pos + 0x10 > len) break;
			uint32_t segSize = 0, src = 0, tgt = 0; uint16_t type = 0, pad = 0;
			std::memcpy(&segSize, data + pos + 0x00, 4);
			std::memcpy(&src, data + pos + 0x04, 4);
			std::memcpy(&tgt, data + pos + 0x08, 4);
			std::memcpy(&type, data + pos + 0x0C, 2);
			std::memcpy(&pad, data + pos + 0x0E, 2);
			if (segSize < 0x10 || pos + segSize > len) break;
			SegmentInfo si{}; si.offset = (uint32_t)pos; si.size = segSize; si.source = src; si.target = tgt; si.type = type; si.hasIpc = false; si.opcode = 0; si.serverId = 0; si.ipcTimestamp = 0;
			if (type == 3 && segSize >= 0x20) {
				uint16_t opcode = 0, serverId = 0; uint32_t ts = 0;
				std::memcpy(&opcode, data + pos + 0x12, 2);
				std::memcpy(&serverId, data + pos + 0x16, 2);
				std::memcpy(&ts, data + pos + 0x18, 4);
				si.hasIpc = true; si.opcode = opcode; si.serverId = serverId; si.ipcTimestamp = ts;
			}
			outSegs.push_back(si);
			pos += segSize;
		}
	}

	static ParsedPacket ParsePacket(const HookPacket& hp) {
		ParsedPacket P{};
		const uint8_t* p = hp.buf.data();
		const size_t L = hp.len;
		P.hdr_ok = read64(p, L, 0x00, P.magic0) && read64(p, L, 0x08, P.magic1) && read64(p, L, 0x10, P.timestamp) && read32(p, L, 0x18, P.size) && read16(p, L, 0x1C, P.connType) && read16(p, L, 0x1E, P.segCount);
		if (L >= 0x22) {
			uint16_t tmp = 0;         
			P.hdr_ok = P.hdr_ok && read16(p, L, 0x20, tmp);
			P.unknown20 = (uint8_t)(tmp & 0xFF);
			P.isCompressed = (uint8_t)((tmp >> 8) & 0xFF);
		}
		if (L >= 0x28) { (void)read32(p, L, 0x24, P.unknown24); }
		if (L >= 0x38 && P.isCompressed == 0) {
			P.seg_ok = read32(p, L, 0x28, P.segSize) && read32(p, L, 0x2C, P.src) && read32(p, L, 0x30, P.tgt) && read16(p, L, 0x34, P.segType) && read16(p, L, 0x36, P.segPad);
		}
		if (P.seg_ok && P.segType == 3 && L >= 0x48) {
			P.ipc_ok = read16(p, L, 0x38, P.ipcReserved) && read16(p, L, 0x3A, P.opcode) && read16(p, L, 0x3C, P.ipcPad) && read16(p, L, 0x3E, P.serverId) && read32(p, L, 0x40, P.ipcTimestamp) && read32(p, L, 0x44, P.ipcPad1);
		}
		return P;
	}

	uint16_t ResolveConnType(const HookPacket& hp, const ParsedPacket& P) {
		auto it = g_connTypeByConnId.find(hp.connection_id);
		uint16_t cached = (it != g_connTypeByConnId.end()) ? it->second : 0xFFFF;
		uint16_t header = P.connType;
		if (header != 0 && header != 0xFFFF) {
			if (P.segCount > 0) g_connTypeByConnId[hp.connection_id] = header;
			return header;
		}
		if (cached != 0xFFFF) return cached;
		return 0xFFFF;  
	}

	struct DecodedHeader {
		bool valid = false;        
		uint16_t opcode = 0;
		uint16_t segType = 0;
		uint16_t connType = 0xFFFF;    
		std::vector<uint16_t> opcodes;       
		std::string opcodeSummary;          
	};

	DecodedHeader DecodeForList(const HookPacket& hp) {
		DecodedHeader d{};
		auto P = ParsePacket(hp);
		d.segType = P.seg_ok ? P.segType : 0;
		d.connType = ResolveConnType(hp, P);

		SegmentView v = GetSegmentView(hp);
		std::vector<SegmentInfo> segs;
		ParseAllSegmentsBuffer(v.data, v.len, segs);

		if (segs.empty() && !P.isCompressed && P.ipc_ok) {
			d.valid = true;
			d.opcode = P.opcode;
			d.opcodes.push_back(P.opcode);
		}
		else {
			for (const auto& s : segs) {
				if (!s.hasIpc) continue;
				if (!d.valid) {
					d.valid = true;
					d.opcode = s.opcode;
				}
				d.opcodes.push_back(s.opcode);
			}
		}

		if (!d.opcodes.empty()) {
			std::ostringstream os;
			os.setf(std::ios::uppercase);
			os << std::hex << std::setfill('0');
			int shown = 0;
			for (size_t i = 0; i < d.opcodes.size(); ++i) {
				if (shown >= 12) {
					os << ", ...";
					break;
				}
				uint16_t op = d.opcodes[i];
				if (i > 0) os << ", ";
				os << "0x" << std::setw(4) << op;
				const char* name = LookupOpcodeName(op, hp.outgoing, d.connType);
				if (name && name[0] && name[0] != '?') {
					os << "(" << name << ")";
				}
				++shown;
			}
			d.opcodeSummary = os.str();
		}

		return d;
	}

	static void RenderPayload_KnownAt(uint16_t opcode, bool outgoing, const HookPacket& hp, const uint8_t* payload, size_t payloadLen)
	{
		if (!payload || payloadLen == 0) return;

		auto rowKV = [](const char* k, const std::string& v) {
			ImGui::TableNextRow(); ImGui::TableNextColumn(); ImGui::TextUnformatted(k);
			ImGui::TableNextColumn(); ImGui::TextUnformatted(v.c_str());
			};

		auto Vec3f = [](float x, float y, float z) -> std::string {
			char b[96];
			std::snprintf(b, sizeof(b), "(%.3f, %.3f, %.3f)", x, y, z);
			return b;
			};

		const uint8_t* buf = payload;
		size_t L = payloadLen;

		if (!outgoing && opcode == 0x0140 && L >= 0x14) {
			uint8_t classJob = *(buf + 0x00);
			uint8_t level = *(buf + 0x01);
			uint8_t levelCombined = *(buf + 0x02);
			uint8_t levelSync = *(buf + 0x03);
			uint32_t hp = loadLE<uint32_t>(buf + 0x04);
			uint32_t hpMax = loadLE<uint32_t>(buf + 0x08);
			uint16_t mp = loadLE<uint16_t>(buf + 0x0C);
			uint16_t mpMax = loadLE<uint16_t>(buf + 0x0E);
			uint16_t tp = loadLE<uint16_t>(buf + 0x10);
			uint16_t gpMax = loadLE<uint16_t>(buf + 0x12);

			rowKV("hud.classJob", std::to_string(classJob));
			rowKV("hud.level", std::to_string(level));
			rowKV("hud.levelCombined", std::to_string(levelCombined));
			rowKV("hud.levelSync", std::to_string(levelSync));
			rowKV("hud.hp", std::to_string(hp) + "/" + std::to_string(hpMax));
			rowKV("hud.mp", std::to_string(mp) + "/" + std::to_string(mpMax));
			rowKV("hud.tp", std::to_string(tp));
			rowKV("hud.gpMax", std::to_string(gpMax));

			size_t statusOff = 0x14;
			int activeCount = 0;

			for (int i = 0; i < 30 && statusOff + 12 <= L; ++i) {
				uint16_t id = loadLE<uint16_t>(buf + statusOff + 0);
				int16_t systemParam = loadLE<int16_t>(buf + statusOff + 2);
				float time = loadLE<float>(buf + statusOff + 4);
				uint32_t source = loadLE<uint32_t>(buf + statusOff + 8);

				if (id != 0) {
					activeCount++;
					if (activeCount <= 10) {
						char key[32];
						std::snprintf(key, sizeof(key), "hud.status[%d]", activeCount - 1);
						std::ostringstream os;

						const char* statusName = GetStatusEffectName(id);
						if (statusName) {
							os << statusName << " (id=" << id << ")";
						}
						else {
							os << "id=" << id;
						}

						os << " param=" << systemParam
							<< " time=" << std::fixed << std::setprecision(1) << time
							<< "s src=0x" << std::hex << source;
						rowKV(key, os.str());
					}
				}
				statusOff += 12;
			}

			if (activeCount > 0) {
				rowKV("hud.activeStatusCount", std::to_string(activeCount));
			}
			return;
		}

		if (outgoing && opcode == 0x0196 && L >= 0x20) {
			uint8_t actionKind = *(buf + 0x00);
			uint8_t actionCategory = *(buf + 0x01);
			uint32_t actionKey = loadLE<uint32_t>(buf + 0x04);
			uint64_t targetId = loadLE<uint64_t>(buf + 0x08);
			uint16_t sequence = loadLE<uint16_t>(buf + 0x10);
			uint16_t rotation = loadLE<uint16_t>(buf + 0x12);
			uint16_t targetRotation = loadLE<uint16_t>(buf + 0x14);
			float x = loadLE<float>(buf + 0x18);
			float y = loadLE<float>(buf + 0x1C);

			const char* kindStr = "Unknown";
			switch (actionKind) {
			case 1: kindStr = "Spell"; break;
			case 2: kindStr = "Item"; break;
			case 3: kindStr = "KeyItem"; break;
			case 4: kindStr = "Ability"; break;
			case 7: kindStr = "Weaponskill"; break;
			case 8: kindStr = "Trait"; break;
			case 9: kindStr = "Companion"; break;
			case 13: kindStr = "CraftAction"; break;
			case 15: kindStr = "Mount"; break;
			case 17: kindStr = "PvPAction"; break;
			}

			rowKV("req.actionKind", std::to_string(actionKind) + " (" + kindStr + ")");
			rowKV("req.actionCategory", std::to_string(actionCategory));
			rowKV("req.actionKey", std::to_string(actionKey));
			rowKV("req.targetId", "0x" + std::to_string(targetId));
			rowKV("req.sequence", std::to_string(sequence));
			rowKV("req.rotation", std::to_string(rotation * 360.0f / 65535.0f) + "°");
			rowKV("req.targetRotation", std::to_string(targetRotation * 360.0f / 65535.0f) + "°");
			rowKV("req.position", Vec3f(x, y, 0));

			ActionReqRec rec{ hp.connection_id, hp.ts, actionKind, actionKey, targetId, rotation, targetRotation };
			g_actionReqById[sequence] = rec;

			UpdatePacketCorrelation(opcode, outgoing, hp);
			return;
		}

		if (!outgoing && opcode == 0x0142 && L >= 0x14) {
			uint16_t category = loadLE<uint16_t>(buf + 0x00);
			uint32_t param1 = loadLE<uint32_t>(buf + 0x04);
			uint32_t param2 = loadLE<uint32_t>(buf + 0x08);
			uint32_t param3 = loadLE<uint32_t>(buf + 0x0C);
			uint32_t param4 = loadLE<uint32_t>(buf + 0x10);

			const char* catName = ActorControlCategoryName(category);
			rowKV("actctl.category", std::to_string(category) + " (" + catName + ")");
			rowKV("actctl.param1", std::to_string(param1));
			rowKV("actctl.param2", std::to_string(param2));
			rowKV("actctl.param3", std::to_string(param3));
			rowKV("actctl.param4", std::to_string(param4));

			switch (category) {
			case 0x02:  
			case 0x14:  
			case 0x15:  
				rowKV("  -> statusId", std::to_string(param1));
				rowKV("  -> sourceActorId", std::to_string(param2));
				break;
			case 0x17:  
				rowKV("  -> value", std::to_string(param1));
				rowKV("  -> type", std::to_string(param2));
				break;
			case 0x32:  
				rowKV("  -> targetId", std::to_string(param1));
				break;
			}
			return;
		}

		if (!outgoing && opcode == 0x0143 && L >= 0x1C) {
			uint16_t category = loadLE<uint16_t>(buf + 0x00);
			uint32_t param1 = loadLE<uint32_t>(buf + 0x04);
			uint32_t param2 = loadLE<uint32_t>(buf + 0x08);
			uint32_t param3 = loadLE<uint32_t>(buf + 0x0C);
			uint32_t param4 = loadLE<uint32_t>(buf + 0x10);
			uint32_t param5 = loadLE<uint32_t>(buf + 0x14);
			uint32_t param6 = loadLE<uint32_t>(buf + 0x18);

			const char* catName = ActorControlCategoryName(category);
			rowKV("actctl.category", std::to_string(category) + " (" + catName + ")");
			rowKV("actctl.param1", std::to_string(param1));
			rowKV("actctl.param2", std::to_string(param2));
			rowKV("actctl.param3", std::to_string(param3));
			rowKV("actctl.param4", std::to_string(param4));
			rowKV("actctl.param5", std::to_string(param5));
			rowKV("actctl.param6", std::to_string(param6));
			return;
		}

		if (!outgoing && opcode == 0x0144 && L >= 0x18) {
			uint16_t category = loadLE<uint16_t>(buf + 0x00);
			uint32_t param1 = loadLE<uint32_t>(buf + 0x04);
			uint32_t param2 = loadLE<uint32_t>(buf + 0x08);
			uint32_t param3 = loadLE<uint32_t>(buf + 0x0C);
			uint32_t param4 = loadLE<uint32_t>(buf + 0x10);
			uint64_t targetId = loadLE<uint64_t>(buf + 0x10);     

			const char* catName = ActorControlCategoryName(category);
			rowKV("actctl.category", std::to_string(category) + " (" + catName + ")");
			rowKV("actctl.param1", std::to_string(param1));
			rowKV("actctl.param2", std::to_string(param2));
			rowKV("actctl.param3", std::to_string(param3));
			rowKV("actctl.param4", std::to_string(param4));
			rowKV("actctl.targetId", std::to_string((uint32_t)(targetId & 0xFFFFFFFF)));
			return;
		}

		if (!outgoing && opcode == 0x019A && L >= 0x28) {
			uint16_t zoneId = loadLE<uint16_t>(buf + 0x00);
			uint16_t territoryType = loadLE<uint16_t>(buf + 0x02);
			uint16_t territoryIndex = loadLE<uint16_t>(buf + 0x04);
			uint32_t layerSetId = loadLE<uint32_t>(buf + 0x08);
			uint32_t layoutId = loadLE<uint32_t>(buf + 0x0C);
			uint8_t weatherId = *(buf + 0x10);
			uint8_t flag = *(buf + 0x11);
			float x = loadLE<float>(buf + 0x18);
			float y = loadLE<float>(buf + 0x1C);
			float z = loadLE<float>(buf + 0x20);
			rowKV("init.zoneId", std::to_string(zoneId));
			rowKV("init.territoryType", std::to_string(territoryType));
			rowKV("init.territoryIndex", std::to_string(territoryIndex));
			rowKV("init.layerSetId", std::to_string(layerSetId));
			rowKV("init.layoutId", std::to_string(layoutId));
			rowKV("init.weatherId", std::to_string(weatherId));
			rowKV("init.flag", std::to_string(flag));
			rowKV("init.pos", Vec3f(x, y, z));
			return;
		}

		if (!outgoing && opcode == 0x0140 && L >= 0x14) {
			uint8_t classJob = *(buf + 0x00);
			uint8_t level = *(buf + 0x01);
			uint8_t levelCombined = *(buf + 0x02);
			uint8_t levelSync = *(buf + 0x03);
			uint32_t hp = loadLE<uint32_t>(buf + 0x04);
			uint32_t hpMax = loadLE<uint32_t>(buf + 0x08);
			uint16_t mp = loadLE<uint16_t>(buf + 0x0C);
			uint16_t mpMax = loadLE<uint16_t>(buf + 0x0E);
			uint16_t tp = loadLE<uint16_t>(buf + 0x10);
			uint16_t gpMax = loadLE<uint16_t>(buf + 0x12);

			rowKV("hud.classJob", std::to_string(classJob));
			rowKV("hud.level", std::to_string(level));
			rowKV("hud.levelCombined", std::to_string(levelCombined));
			rowKV("hud.levelSync", std::to_string(levelSync));
			rowKV("hud.hp", std::to_string(hp) + "/" + std::to_string(hpMax));
			rowKV("hud.mp", std::to_string(mp) + "/" + std::to_string(mpMax));
			rowKV("hud.tp", std::to_string(tp));
			rowKV("hud.gpMax", std::to_string(gpMax));

			size_t statusOff = 0x14;
			int activeCount = 0;

			for (int i = 0; i < 30 && statusOff + 12 <= L; ++i) {
				uint16_t id = loadLE<uint16_t>(buf + statusOff + 0);
				int16_t systemParam = loadLE<int16_t>(buf + statusOff + 2);
				float time = loadLE<float>(buf + statusOff + 4);
				uint32_t source = loadLE<uint32_t>(buf + statusOff + 8);

				if (id != 0) {
					activeCount++;
					if (activeCount <= 10) {      
						char key[32];
						std::snprintf(key, sizeof(key), "hud.status[%d]", activeCount - 1);
						std::ostringstream os;
						os << "id=" << id
							<< " param=" << systemParam
							<< " time=" << std::fixed << std::setprecision(1) << time
							<< "s src=0x" << std::hex << source;
						rowKV(key, os.str());
					}
				}
				statusOff += 12;
			}

			if (activeCount > 0) {
				rowKV("hud.activeStatusCount", std::to_string(activeCount));
			}
			return;
		}

		if (!outgoing && (opcode == 0x018E || opcode == 0x0191 || opcode == 0x0192)) {
			if (L >= 0x18) {    
				uint8_t dir = *(buf + 0x00);
				uint8_t dirBeforeSlip = *(buf + 0x01);
				uint8_t flag = *(buf + 0x02);
				uint8_t flag2 = *(buf + 0x03);
				uint8_t speed = *(buf + 0x04);
				uint8_t speedBeforeSlip = *(buf + 0x05);
				float x = loadLE<float>(buf + 0x08);
				float y = loadLE<float>(buf + 0x0C);
				float z = loadLE<float>(buf + 0x10);
				rowKV("move.dir", std::to_string(dir));
				rowKV("move.dirBeforeSlip", std::to_string(dirBeforeSlip));
				rowKV("move.flag", std::to_string(flag));
				rowKV("move.flag2", std::to_string(flag2));
				rowKV("move.speed", std::to_string(speed));
				rowKV("move.speedBeforeSlip", std::to_string(speedBeforeSlip));
				rowKV("move.pos", Vec3f(x, y, z));
			}
			else if (L >= 0x0C) {    
				uint8_t dir = *(buf + 0x00);
				uint8_t dirBeforeSlip = *(buf + 0x01);
				uint8_t flag = *(buf + 0x02);
				uint8_t flag2 = *(buf + 0x03);
				uint8_t speed = *(buf + 0x04);
				uint8_t speedBeforeSlip = *(buf + 0x05);
				uint16_t x = loadLE<uint16_t>(buf + 0x06);
				uint16_t y = loadLE<uint16_t>(buf + 0x08);
				uint16_t z = loadLE<uint16_t>(buf + 0x0A);

				rowKV("move.dir", std::to_string(dir));
				rowKV("move.dirBeforeSlip", std::to_string(dirBeforeSlip));
				rowKV("move.flag", std::to_string(flag));
				rowKV("move.flag2", std::to_string(flag2));
				rowKV("move.speed", std::to_string(speed));
				rowKV("move.speedBeforeSlip", std::to_string(speedBeforeSlip));
				rowKV("move.pos", "(" + std::to_string(x) + ", " + std::to_string(y) + ", " + std::to_string(z) + ")");
			}
			return;
		}

		if (!outgoing && opcode == 0x0194 && L >= 0x14) {
			uint16_t dir = loadLE<uint16_t>(buf + 0x00);
			uint8_t type = *(buf + 0x02);
			uint8_t typeArg = *(buf + 0x03);
			uint32_t layerSet = loadLE<uint32_t>(buf + 0x04);
			float x = loadLE<float>(buf + 0x08);
			float y = loadLE<float>(buf + 0x0C);
			float z = loadLE<float>(buf + 0x10);

			const char* typeName = WarpTypeName(type);
			rowKV("warp.dir", std::to_string(dir));
			rowKV("warp.type", std::to_string((int)type) + " (" + typeName + ")");
			rowKV("warp.typeArg", std::to_string(typeArg));
			rowKV("warp.layerSet", std::to_string(layerSet));
			rowKV("warp.pos", Vec3f(x, y, z));
			return;
		}

		if (!outgoing && (opcode == 0x0146 || opcode == 0x0147) && L >= 0x58) {
			uint64_t mainTarget = loadLE<uint64_t>(buf + 0x00);
			uint16_t action = loadLE<uint16_t>(buf + 0x08);
			uint8_t actionArg = *(buf + 0x0A);
			uint8_t actionKind = *(buf + 0x0B);
			uint32_t actionKey = loadLE<uint32_t>(buf + 0x0C);
			uint32_t requestId = loadLE<uint32_t>(buf + 0x10);
			uint32_t resultId = loadLE<uint32_t>(buf + 0x14);
			float lockTime = loadLE<float>(buf + 0x18);
			rowKV("res.mainTarget", std::to_string((uint32_t)(mainTarget & 0xFFFFFFFF)));
			rowKV("res.action", std::to_string(action));
			rowKV("res.actionArg", std::to_string(actionArg));
			rowKV("res.actionKind", std::to_string(actionKind));
			rowKV("res.actionKey", std::to_string(actionKey));
			rowKV("res.requestId", std::to_string(requestId));
			rowKV("res.resultId", std::to_string(resultId));
			rowKV("res.lockTime", std::to_string(lockTime));
			auto it = g_actionReqById.find(requestId);
			if (it != g_actionReqById.end()) {
				auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(hp.ts - it->second.ts).count();
				rowKV("res.correlatesWith", std::string("ActionRequest ") + std::to_string(requestId) + " (" + std::to_string(dt) + " ms)");
			}

			uint8_t targetCount = *(buf + 0x21);
			rowKV("res.targetCount", std::to_string(targetCount));

			if (L >= 0x58 && targetCount > 0) {
				size_t effectOffset = 0x28;
				for (int i = 0; i < std::min(targetCount, uint8_t(8)); ++i) {
					if (effectOffset + 8 > L) break;

					uint8_t effectType = *(buf + effectOffset);
					uint8_t hitSeverity = *(buf + effectOffset + 1);
					uint8_t param = *(buf + effectOffset + 2);
					uint8_t bonusPercent = *(buf + effectOffset + 3);
					uint16_t value = loadLE<uint16_t>(buf + effectOffset + 4);

					char key[32];
					std::snprintf(key, sizeof(key), "res.effect[%d]", i);
					std::ostringstream os;

					const char* effectStr = "Unknown";
					switch (effectType) {
					case 1: effectStr = "Miss"; break;
					case 2: effectStr = "FullResist"; break;
					case 3: effectStr = "Damage"; break;
					case 4: effectStr = "Heal"; break;
					case 5: effectStr = "BlockedDamage"; break;
					case 6: effectStr = "ParriedDamage"; break;
					case 7: effectStr = "Invulnerable"; break;
					case 8: effectStr = "NoEffectText"; break;
					case 14: effectStr = "StatusNoEffect"; break;
					case 15: effectStr = "StatusGain"; break;
					case 16: effectStr = "StatusLose"; break;
					}

					os << effectStr << " val=" << value;
					if (hitSeverity > 0) {
						os << " (";
						if (hitSeverity & 0x01) os << "Critical ";
						if (hitSeverity & 0x02) os << "DirectHit ";
						os << ")";
					}
					rowKV(key, os.str());

					effectOffset += 8;
				}
			}
			return;
		}

		if (!outgoing && opcode == 0x019B && L >= 0x08) {
			uint8_t count = *(buf + 0x00);
			rowKV("hate.count", std::to_string(count));

			size_t offset = 0x04;
			for (int i = 0; i < std::min(count, uint8_t(8)); ++i) {
				if (offset + 8 > L) break;

				uint32_t actorId = loadLE<uint32_t>(buf + offset);
				uint8_t hatePercent = *(buf + offset + 4);

				char key[32];
				std::snprintf(key, sizeof(key), "hate.entry[%d]", i);
				std::ostringstream os;
				os << "actor=0x" << std::hex << actorId << " hate=" << std::dec << (unsigned)hatePercent << "%";
				rowKV(key, os.str());

				offset += 8;
			}
			return;
		}

		if (!outgoing && opcode == 0x01A2 && L >= 0x08) {
			uint32_t actorId = loadLE<uint32_t>(buf + 0x00);
			uint32_t targetId = loadLE<uint32_t>(buf + 0x04);

			rowKV("firstAttack.actorId", "0x" + std::to_string(actorId));
			rowKV("firstAttack.targetId", "0x" + std::to_string(targetId));
			return;
		}
	}

	static void RenderPayload_Known(uint16_t opcode, bool outgoing, const HookPacket& hp)
	{
		auto view = GetSegmentView(hp);
		if (view.data) {
			std::vector<SegmentInfo> segs; ParseAllSegmentsBuffer(view.data, view.len, segs);
			for (const auto& s : segs) {
				if (s.hasIpc && s.opcode == opcode) {
					const uint8_t* payload = view.data + s.offset + 0x20;
					size_t payloadLen = (s.size > 0x20) ? (s.size - 0x20) : 0;
					RenderPayload_KnownAt(opcode, outgoing, hp, payload, payloadLen);
					return;
				}
			}
		}
		if (hp.len > 0x48) {
			const uint8_t* payload = hp.buf.data() + 0x48;
			size_t payloadLen = hp.len - 0x48;
			RenderPayload_KnownAt(opcode, outgoing, hp, payload, payloadLen);
		}
	}

	static void RenderPayload_Heuristics(const uint8_t* base, size_t len)
	{
		if (!base || len == 0) return;
		if (ImGui::CollapsingHeader("Payload preview (heuristic)", ImGuiTreeNodeFlags_DefaultOpen))
		{
			if (ImGui::BeginTable("pv_u32", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
				ImGui::TableSetupColumn("off"); ImGui::TableSetupColumn("u32 (dec)"); ImGui::TableSetupColumn("u32 (hex)"); ImGui::TableSetupColumn("float");
				for (size_t off = 0; off + 4 <= len; off += 4) {
					uint32_t v = loadLE<uint32_t>(base + off);
					float f; std::memcpy(&f, base + off, sizeof(float));
					char b1[32], b2[32], b3[64];
					std::snprintf(b1, sizeof(b1), "0x%04zx", off);
					std::snprintf(b2, sizeof(b2), "%u", v);
					std::snprintf(b3, sizeof(b3), "0x%08X  (%.4f)", v, f);
					ImGui::TableNextRow();
					ImGui::TableNextColumn(); ImGui::TextUnformatted(b1);
					ImGui::TableNextColumn(); ImGui::TextUnformatted(b2);
					ImGui::TableNextColumn(); ImGui::TextUnformatted(b3);
					ImGui::TableNextColumn(); ImGui::Text("%.6f", f);
				}
				ImGui::EndTable();
			}

			if (ImGui::CollapsingHeader("u16 view", ImGuiTreeNodeFlags_None)) {
				if (ImGui::BeginTable("pv_u16", 8, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
					for (size_t off = 0; off + 2 <= len; off += 16) {
						ImGui::TableNextRow();
						for (int i = 0; i < 8; i++) {
							size_t o2 = off + i * 2; ImGui::TableNextColumn();
							if (o2 + 2 <= len) {
								uint16_t v = loadLE<uint16_t>(base + o2);
								ImGui::Text("%04zx:%5u (0x%04X)", o2, v, v);
							}
							else {
								ImGui::TextUnformatted(" ");
							}
						}
					}
					ImGui::EndTable();
				}
			}
		}
	}
}

namespace {
	struct Filters {
		bool showSend = true;
		bool showRecv = true;
		bool onlyKnown = false;
		char opcodeList[128] = "";  
		char search[128] = "";
		std::string lastParsed;
		std::unordered_set<uint16_t> opcodes;
		void parseOpcodesIfChanged() {
			if (lastParsed == opcodeList) return;
			lastParsed = opcodeList;
			opcodes.clear();
			std::string s = lastParsed; std::string tok;
			auto push = [&](const std::string& t) {
				if (t.empty()) return; char* end = nullptr; unsigned long v = 0;
				if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0) v = strtoul(t.c_str() + 2, &end, 16);
				else v = strtoul(t.c_str(), &end, 10);
				if (end != t.c_str()) opcodes.insert(static_cast<uint16_t>(v & 0xFFFF));
				};
			size_t start = 0; while (start <= s.size()) {
				size_t comma = s.find(',', start); std::string t = s.substr(start, comma == std::string::npos ? std::string::npos : comma - start);  
				t.erase(0, t.find_first_not_of(" \t")); if (!t.empty()) t.erase(t.find_last_not_of(" \t") + 1);
				push(t); if (comma == std::string::npos) break; start = comma + 1;
			}
		}
	};
	Filters& GetFilters() { static Filters f; return f; }

	bool Matches(const HookPacket& hp, const DecodedHeader& dec, const Filters& f) {
		if (hp.outgoing && !f.showSend) return false;
		if (!hp.outgoing && !f.showRecv) return false;
		if (f.onlyKnown && !dec.valid) return false;
		if (!f.opcodes.empty()) {
			if (!dec.valid || f.opcodes.find(dec.opcode) == f.opcodes.end()) return false;
		}
		if (f.search[0] != '\0') {
			std::string q = f.search; std::transform(q.begin(), q.end(), q.begin(), ::tolower);
			const char* nm = dec.valid ? LookupOpcodeName(dec.opcode, hp.outgoing, dec.connType) : "";
			char hexbuf[16]; std::snprintf(hexbuf, sizeof(hexbuf), "%04x", (unsigned)(dec.opcode));
			std::string name = nm; std::transform(name.begin(), name.end(), name.begin(), ::tolower);
			std::string hex = hexbuf;
			if (name.find(q) == std::string::npos && hex.find(q) == std::string::npos) return false;
		}
		return true;
	}
}

static void DrawFilters() {
	auto& f = GetFilters();
	f.parseOpcodesIfChanged();
	ImGui::Checkbox("Send", &f.showSend); ImGui::SameLine();
	ImGui::Checkbox("Recv", &f.showRecv); ImGui::SameLine();
	ImGui::Checkbox("Known only", &f.onlyKnown); ImGui::SameLine();
	ImGui::Checkbox("Inflate compressed", &g_cfgInflateSegments);
	ImGui::SetNextItemWidth(180);
	ImGui::InputTextWithHint("##opcodes", "Opcodes (e.g. 0x67,0x191)", f.opcodeList, sizeof(f.opcodeList));
	ImGui::SameLine();
	ImGui::SetNextItemWidth(180);
	ImGui::InputTextWithHint("##search", "Search name/hex", f.search, sizeof(f.search));
}


namespace {
	// Collapsible header helper with sensible default
	static bool BeginDetailsSection(const char* label, bool defaultOpen = true) {
		ImGui::SetNextItemOpen(defaultOpen, ImGuiCond_Appearing);
		return ImGui::CollapsingHeader(label, ImGuiTreeNodeFlags_SpanAvailWidth);
	}

	// Small RAII table builder for key/value tables
	struct KVTable {
		bool open = false;
		KVTable(const char* id, float keyWidth = 200.0f) {
			ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(8.0f, 6.0f));
			ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8.0f, 6.0f));
			const ImGuiTableFlags flags =
				ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
				ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_PadOuterX |
				ImGuiTableFlags_Resizable;
			open = ImGui::BeginTable(id, 2, flags);
			if (open) {
				ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed, keyWidth);
				ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
				ImGui::TableHeadersRow();
			}
		}
		~KVTable() {
			if (open) ImGui::EndTable();
			ImGui::PopStyleVar(2);
		}
		void Row(const char* k, const std::string& v) {
			if (!open) return;
			ImGui::TableNextRow();
			ImGui::TableNextColumn(); ImGui::TextUnformatted(k);
			ImGui::TableNextColumn(); ImGui::TextUnformatted(v.c_str());
		}
	};

	static void DrawPacketOverview(const HookPacket& hp,
		const ParsedPacket& P,
		const std::vector<SegmentInfo>& segs,
		const DecodedHeader& dec,
		uint16_t resolvedConn)
	{
		KVTable tbl("pkt_overview", 190.0f);
		if (!tbl.open) return;

		// Direction
		tbl.Row("Direction", hp.outgoing ? "SEND" : "RECV");
		// Connection / size
		tbl.Row("Connection Id", std::to_string((unsigned long long)hp.connection_id));
		tbl.Row("Length (bytes)", std::to_string(hp.len));
		// Segments
		tbl.Row("Segments", std::to_string(segs.size()));
		size_t ipcCount = 0; for (const auto& s : segs) if (s.hasIpc) ++ipcCount;
		tbl.Row("IPC segments", std::to_string(ipcCount));
		// Connection type
		tbl.Row("ConnType (header)", std::to_string(P.connType));
		if (resolvedConn != 0xFFFF)
			tbl.Row("ConnType (resolved)", std::to_string(resolvedConn));
		// Compression
		tbl.Row("Compressed", P.isCompressed ? "yes" : "no");

		// Opcodes summary with names (first 6)
		if (dec.valid && !dec.opcodes.empty()) {
			std::ostringstream os;
			os << std::hex << std::setfill('0');
			const size_t limit = std::min<size_t>(dec.opcodes.size(), 6);
			for (size_t i = 0; i < limit; ++i) {
				if (i) os << ", ";
				uint16_t op = dec.opcodes[i];
				os << "0x" << std::setw(4) << op;
				const char* nm = LookupOpcodeName(op, hp.outgoing, resolvedConn);
				if (nm && nm[0] && nm[0] != '?') os << "(" << nm << ")";
			}
			if (dec.opcodes.size() > limit) os << ", ...";
			tbl.Row("Opcodes", os.str());
		}

		// Capture time (human readable)
		auto tt = std::chrono::system_clock::to_time_t(hp.ts);
		char tbuf[64]{};
		std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", std::localtime(&tt));
		tbl.Row("Captured at", tbuf);
	}
}

static void DrawPacketHeaderTable(const ParsedPacket& P, uint16_t resolvedConn) {
	if (!P.hdr_ok) return;
	KVTable tbl("pkt_hdr_main", 190.0f);
	if (!tbl.open) return;

	char b[128];
	std::snprintf(b, sizeof(b), "0x%016llX 0x%016llX", (unsigned long long)P.magic0, (unsigned long long)P.magic1);
	tbl.Row("magic[2]", b);
	std::snprintf(b, sizeof(b), "%llu", (unsigned long long)P.timestamp);
	tbl.Row("timestamp(ms)", b);
	tbl.Row("size", std::to_string(P.size));
	tbl.Row("connectionType (header)", std::to_string(P.connType));
	tbl.Row("segmentCount", std::to_string(P.segCount));
	std::snprintf(b, sizeof(b), "0x%02X", P.unknown20);
	tbl.Row("unknown_20", b);
	tbl.Row("isCompressed", std::to_string((unsigned)P.isCompressed));
	std::snprintf(b, sizeof(b), "0x%08X", P.unknown24);
	tbl.Row("unknown_24", b);
	if (resolvedConn != 0xFFFF)
		tbl.Row("connectionType (resolved)", std::to_string(resolvedConn));
}

static void DrawSegmentHeaderTable(const ParsedPacket& P) {
	if (!P.seg_ok) return;
	KVTable tbl("pkt_hdr_seg", 190.0f);
	if (!tbl.open) return;

	char b[128];
	tbl.Row("size", std::to_string(P.segSize));
	std::snprintf(b, sizeof(b), "0x%08X (%u)", P.src, P.src);
	tbl.Row("source_actor", b);
	std::snprintf(b, sizeof(b), "0x%08X (%u)", P.tgt, P.tgt);
	tbl.Row("target_actor", b);
	std::snprintf(b, sizeof(b), "%u (%s)", P.segType, SegTypeName(P.segType));
	tbl.Row("type", b);
	std::snprintf(b, sizeof(b), "0x%04X", P.segPad);
	tbl.Row("padding", b);
}

static void DrawIPCHeaderTable(const ParsedPacket&, bool outgoing, const HookPacket& hp, uint16_t resolvedConn) {
	SegmentView v = GetSegmentView(hp);
	std::vector<SegmentInfo> segs; ParseAllSegmentsBuffer(v.data, v.len, segs);

	int ipcIndex = 0;
	for (const auto& s : segs) if (s.hasIpc) {
		const char* name = LookupOpcodeName(s.opcode, outgoing, resolvedConn);
		char hdrLabel[160];
		std::snprintf(hdrLabel, sizeof(hdrLabel), "IPC segment #%d  0x%04X (%s)", ipcIndex, s.opcode, name ? name : "?");

		ImGui::SetNextItemOpen(ipcIndex == 0, ImGuiCond_Appearing);
		if (ImGui::CollapsingHeader(hdrLabel, ImGuiTreeNodeFlags_SpanAvailWidth)) {
			// IPC header key/values
			KVTable tbl((std::string("pkt_hdr_ipc_") + std::to_string(ipcIndex)).c_str(), 190.0f);
			if (tbl.open) {
				char b[128];
				std::snprintf(b, sizeof(b), "0x%04X (%s)", s.opcode, name ? name : "?");
				tbl.Row("type (opcode)", b);
				tbl.Row("serverId", std::to_string(s.serverId));
				tbl.Row("timestamp", std::to_string(s.ipcTimestamp));
			}

			// IPC payload details
			const uint8_t* payload = v.data + s.offset + 0x20;
			size_t payloadLen = (s.size > 0x20) ? (s.size - 0x20) : 0;
			ImGui::Indent(8.0f);
			RenderPayload_KnownAt(s.opcode, outgoing, hp, payload, payloadLen);
			ImGui::Unindent(8.0f);
		}
		++ipcIndex;
	}

	if (v.data && v.len) {
		ImGui::Separator();
		RenderPayload_Heuristics(v.data, v.len);
	}
}
static void DrawAllSegmentsTable(const HookPacket& hp, uint16_t resolvedConn)
{
	SegmentView v = GetSegmentView(hp);
	if (!v.data) return;

	std::vector<SegmentInfo> segs; ParseAllSegmentsBuffer(v.data, v.len, segs);

	g_hasHoveredSegment = false;

	if (ImGui::BeginTable("pkt_all_segments", 6, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit)) {
		ImGui::TableSetupColumn("#");
		ImGui::TableSetupColumn("offset");
		ImGui::TableSetupColumn("size");
		ImGui::TableSetupColumn("type");
		ImGui::TableSetupColumn("src->tgt");
		ImGui::TableSetupColumn("opcode");
		ImGui::TableHeadersRow();

		for (size_t i = 0; i < segs.size(); ++i) {
			const auto& s = segs[i];
			ImGui::TableNextRow();

			ImGui::TableNextColumn();
			ImGui::PushID((int)i);
			bool rowHovered = ImGui::Selectable("##row", false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowItemOverlap);
			if (ImGui::IsItemHovered()) {
				g_hasHoveredSegment = true;
				g_hoveredSegmentIndex = (int)i;
				g_hoveredSegmentOffset = s.offset;
				g_hoveredSegmentSize = s.size;
			}
			ImGui::PopID();
			ImGui::SameLine();

			ImGui::Text("%zu", i);
			ImGui::TableNextColumn(); ImGui::Text("0x%04X", s.offset);
			ImGui::TableNextColumn(); ImGui::Text("%u", s.size);
			ImGui::TableNextColumn(); ImGui::Text("%u (%s)", s.type, SegTypeName(s.type));
			ImGui::TableNextColumn(); ImGui::Text("%u -> %u", s.source, s.target);
			ImGui::TableNextColumn();
			if (s.hasIpc) {
				const char* nm = LookupOpcodeName(s.opcode, false    , resolvedConn);
				ImGui::Text("0x%04X (%s)", s.opcode, nm);
			}
			else {
				ImGui::TextUnformatted("-");
			}
		}
		ImGui::EndTable();
	}
}

static void DrawPacketTimeline() {
	if (ImGui::CollapsingHeader("Packet Timeline")) {
		ImDrawList* draw_list = ImGui::GetWindowDrawList();
		ImVec2 canvas_pos = ImGui::GetCursorScreenPos();
		ImVec2 canvas_size = ImGui::GetContentRegionAvail();

		float timeline_height = 100.0f;

		draw_list->AddLine(
			canvas_pos,
			ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y),
			IM_COL32(255, 255, 255, 128)
		);

		for (const auto& flow : g_flowHistory) {
		}

		ImGui::Dummy(ImVec2(canvas_size.x, timeline_height));
	}
}

namespace {
	static std::string Hex(const uint8_t* d, size_t n) {
		static const char* k = "0123456789ABCDEF"; std::string s; s.resize(n * 2);
		for (size_t i = 0; i < n; ++i) { s[2 * i] = k[(d[i] >> 4) & 0xF]; s[2 * i + 1] = k[d[i] & 0xF]; }
		return s;
	}

	static void EnsureExportDir() {
		std::error_code ec; std::filesystem::create_directories("exports", ec);
	}

	static bool ExportToJsonAs(const HookPacket& hp, const std::string& filepath) {
		try {
			std::filesystem::path p(filepath);
			if (p.has_parent_path()) {
				std::error_code ec; std::filesystem::create_directories(p.parent_path(), ec);
			}
			std::ofstream f(p, std::ios::binary);
			if (!f) return false;
			ParsedPacket P = ParsePacket(hp);
			SegmentView v = GetSegmentView(hp);
			std::vector<SegmentInfo> segs; ParseAllSegmentsBuffer(v.data, v.len, segs);
			f << "{\n";
			f << "  \"outgoing\": " << (hp.outgoing ? "true" : "false") << ",\n";
			f << "  \"connectionId\": " << hp.connection_id << ",\n";
			f << "  \"header\": { \"size\": " << P.size << ", \"connType\": " << P.connType << ", \"segCount\": " << P.segCount << ", \"isCompressed\": " << (unsigned)P.isCompressed << " },\n";
			f << "  \"segments\": [\n";
			for (size_t i = 0; i < segs.size(); ++i) {
				const auto& s = segs[i];
				f << "    { \"offset\": " << s.offset << ", \"size\": " << s.size << ", \"type\": " << s.type;
				if (s.hasIpc) f << ", \"opcode\": " << s.opcode;
				f << " }" << (i + 1 < segs.size() ? ",\n" : "\n");
			}
			f << "  ],\n";
			f << "  \"payloadHex\": \"" << Hex(hp.buf.data(), hp.len) << "\"\n";
			f << "}\n";
			return true;
		}
		catch (...) { return false; }
	}

	static bool ExportToPcapAs(const HookPacket& hp, const std::string& filepath) {
		try {
			std::filesystem::path p(filepath);
			if (p.has_parent_path()) {
				std::error_code ec; std::filesystem::create_directories(p.parent_path(), ec);
			}
			auto tp = std::chrono::time_point_cast<std::chrono::microseconds>(hp.ts);
			uint64_t micros = (uint64_t)tp.time_since_epoch().count();
			uint32_t ts_sec = (uint32_t)(micros / 1000000ULL);
			uint32_t ts_usec = (uint32_t)(micros % 1000000ULL);
			std::ofstream f(p, std::ios::binary);
			if (!f) return false;
			struct GH { uint32_t magic; uint16_t vmaj, vmin; int32_t thiszone; uint32_t sigfigs; uint32_t snaplen; uint32_t network; } gh{ 0xA1B2C3D4,2,4,0,0,0x00040000,1 };  
			f.write((const char*)&gh, sizeof(gh));
			const std::vector<uint8_t> payload(hp.buf.begin(), hp.buf.begin() + hp.len);
			const uint16_t udp_payload_len = (uint16_t)payload.size();
			const uint16_t udp_len = 8 + udp_payload_len;
			const uint16_t ip_len = 20 + udp_len;
			std::vector<uint8_t> frame;
			frame.resize(14 + ip_len);
			uint8_t* eth = frame.data();
			uint8_t dst[6] = { 0x02,0,0,0,0,0x02 }; uint8_t src[6] = { 0x02,0,0,0,0,0x01 };
			if (!hp.outgoing) { std::swap_ranges(dst, dst + 6, src); }
			memcpy(eth, dst, 6); memcpy(eth + 6, src, 6); eth[12] = 0x08; eth[13] = 0x00;  
			auto ip_checksum = [](const uint8_t* buf, size_t len) { uint32_t sum = 0; for (size_t i = 0; i + 1 < len; i += 2) sum += (buf[i] << 8) | buf[i + 1]; if (len & 1) sum += (buf[len - 1] << 8); while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16); return (uint16_t)(~sum); };
			uint8_t* ip = eth + 14; memset(ip, 0, 20);
			ip[0] = 0x45;   
			ip[2] = (uint8_t)(ip_len >> 8); ip[3] = (uint8_t)ip_len;
			ip[6] = 0x40;  
			ip[8] = 64;    
			ip[9] = 17;    
			uint8_t saddr[4] = { 10,0,0,1 }; uint8_t daddr[4] = { 10,0,0,2 }; if (!hp.outgoing) { std::swap_ranges(saddr, saddr + 4, daddr); }
			memcpy(ip + 12, saddr, 4); memcpy(ip + 16, daddr, 4);
			uint16_t csum = ip_checksum(ip, 20); ip[10] = (uint8_t)(csum >> 8); ip[11] = (uint8_t)csum;
			uint8_t* udp = ip + 20; uint16_t sport = hp.outgoing ? 55001 : 55002; uint16_t dport = hp.outgoing ? 55002 : 55001;
			udp[0] = (uint8_t)(sport >> 8); udp[1] = (uint8_t)sport; udp[2] = (uint8_t)(dport >> 8); udp[3] = (uint8_t)dport;
			udp[4] = (uint8_t)(udp_len >> 8); udp[5] = (uint8_t)udp_len; udp[6] = udp[7] = 0;   
			memcpy(udp + 8, payload.data(), payload.size());
			struct PH { uint32_t ts_sec, ts_usec, incl_len, orig_len; } ph{ ts_sec, ts_usec, (uint32_t)frame.size(), (uint32_t)frame.size() };
			f.write((const char*)&ph, sizeof(ph));
			f.write((const char*)frame.data(), frame.size());
			return true;
		}
		catch (...) { return false; }
	}

	static bool ExportToJson(const HookPacket& hp) {
		EnsureExportDir();
		auto t = std::chrono::system_clock::to_time_t(hp.ts);
		char fname[256]; std::strftime(fname, sizeof(fname), "exports/packet_%Y%m%d_%H%M%S.json", std::localtime(&t));
		return ExportToJsonAs(hp, fname);
	}

	static bool ExportToPcap(const HookPacket& hp) {
		EnsureExportDir();
		auto t = std::chrono::system_clock::to_time_t(hp.ts);
		char fname[256]; std::strftime(fname, sizeof(fname), "exports/packet_%Y%m%d_%H%M%S.pcap", std::localtime(&t));
		return ExportToPcapAs(hp, fname);
	}
}

static void DrawPacketStatistics(const HookPacket& hp, const std::vector<SegmentInfo>& segs);

static void DrawPacketFlowAnalysis() {
	if (ImGui::CollapsingHeader("Packet Flow Analysis")) {
		static char flowFilter[128] = "";
		ImGui::InputTextWithHint("##flow_filter", "Filter flows...",
			flowFilter, sizeof(flowFilter));

		if (ImGui::BeginTable("flow_sequences", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
			ImGui::TableSetupColumn("Description");
			ImGui::TableSetupColumn("Duration");
			ImGui::TableSetupColumn("Packet Count");
			ImGui::TableSetupColumn("Opcodes");
			ImGui::TableHeadersRow();

			for (const auto& flow : g_flowHistory) {
				if (flowFilter[0] != '\0' &&
					flow.description.find(flowFilter) == std::string::npos) {
					continue;    
				}

				ImGui::TableNextRow();
				ImGui::TableNextColumn();
				ImGui::TextUnformatted(flow.description.c_str());

				ImGui::TableNextColumn();
				auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(flow.endTime - flow.startTime);
				ImGui::Text("%lld ms", duration.count());

				ImGui::TableNextColumn();
				ImGui::Text("%zu", flow.opcodes.size());

				ImGui::TableNextColumn();
				std::ostringstream os;
				os << std::hex << std::setfill('0');
				for (size_t i = 0; i < std::min(flow.opcodes.size(), size_t(5)); ++i) {
					if (i > 0) os << " → ";
					os << "0x" << std::setw(4) << flow.opcodes[i];
				}
				if (flow.opcodes.size() > 5) os << " ...";
				ImGui::TextUnformatted(os.str().c_str());
			}

			ImGui::EndTable();
		}

		if (!g_packetRelations.empty()) {
			ImGui::Separator();
			ImGui::Text("Common Packet Relationships:");
			if (ImGui::BeginTable("relations", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
				ImGui::TableSetupColumn("Request");
				ImGui::TableSetupColumn("Response");
				ImGui::TableSetupColumn("Avg Latency");
				ImGui::TableSetupColumn("Count");
				ImGui::TableHeadersRow();

				for (const auto& [key, rel] : g_packetRelations) {
					ImGui::TableNextRow();
					ImGui::TableNextColumn();
					ImGui::Text("0x%04X", rel.requestOpcode);
					ImGui::TableNextColumn();
					ImGui::Text("0x%04X", rel.responseOpcode);
					ImGui::TableNextColumn();
					ImGui::Text("%lld ms", rel.avgLatency.count());
					ImGui::TableNextColumn();
					ImGui::Text("%u", rel.count);
				}

				ImGui::EndTable();
			}
		}

		if (!g_patterns.empty()) {
			ImGui::Separator();
			ImGui::Text("Detected Patterns:");
			if (ImGui::BeginTable("patterns", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
				ImGui::TableSetupColumn("Pattern");
				ImGui::TableSetupColumn("Sequence");
				ImGui::TableSetupColumn("Match Count");
				ImGui::TableHeadersRow();

				for (const auto& pattern : g_patterns) {
					if (pattern.matchCount > 0) {
						ImGui::TableNextRow();
						ImGui::TableNextColumn();
						ImGui::TextUnformatted(pattern.name.c_str());

						ImGui::TableNextColumn();
						std::ostringstream os;
						os << std::hex << std::setfill('0');
						for (size_t i = 0; i < pattern.opcodes.size(); ++i) {
							if (i > 0) os << " → ";
							os << "0x" << std::setw(4) << pattern.opcodes[i];
						}
						ImGui::TextUnformatted(os.str().c_str());

						ImGui::TableNextColumn();
						ImGui::Text("%u", pattern.matchCount);
					}
				}

				ImGui::EndTable();
			}
		}

		if (!g_flowHistory.empty()) {
			ImGui::Separator();
			ImGui::Text("Flow Statistics:");

			long long totalDuration = 0;
			for (const auto& flow : g_flowHistory) {
				auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
					flow.endTime - flow.startTime
				);
				totalDuration += duration.count();
			}

			ImGui::Text("Average Flow Duration: %lld ms",
				totalDuration / g_flowHistory.size());
			ImGui::Text("Active Flows: %zu", g_flowHistory.size());
		}
	}
}

static void DrawPacketListAndDetails(const std::vector<HookPacket>& display) {
    DrawFilters();
    auto& f = GetFilters();
    f.parseOpcodesIfChanged();

    // Auto-scroll / pause controls
    static bool s_autoScroll = true;
    static bool s_paused = false;
    static std::vector<HookPacket> s_pausedDisplay;

    ImGui::Checkbox("Auto-scroll", &s_autoScroll);
    ImGui::SameLine();
    if (ImGui::Checkbox("Pause", &s_paused)) {
        if (s_paused) s_pausedDisplay = display;
        else s_pausedDisplay.clear();
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        ImGui::SetScrollY(0);
    }

    const std::vector<HookPacket>& activeDisplay = s_paused ? s_pausedDisplay : display;

    // Filtered list
    static std::vector<int> filtered;
    filtered.clear();
    filtered.reserve(activeDisplay.size());
    for (int i = 0; i < (int)activeDisplay.size(); ++i) {
        const HookPacket& hp = activeDisplay[i];
        auto dec = DecodeForList(hp);
        if (Matches(hp, dec, f)) filtered.push_back(i);
    }

    ImGui::Text("Shown: %d / %zu %s", (int)filtered.size(), activeDisplay.size(), s_paused ? "(PAUSED)" : "");

    // Top list
    ImGui::BeginChild("pkt_list", ImVec2(0, 260), true);
    ImGuiListClipper clip;
    clip.Begin((int)filtered.size());
    static int selectedFiltered = -1;

    while (clip.Step()) {
        for (int ri = clip.DisplayStart; ri < clip.DisplayEnd; ++ri) {
            int i = filtered[ri];
            const HookPacket& hp = activeDisplay[i];
            const auto d = DecodeForList(hp);
            const char* name = d.valid ? LookupOpcodeName(d.opcode, hp.outgoing, d.connType) : "?";

            SegmentView v = GetSegmentView(hp);
            std::vector<SegmentInfo> tmp;
            ParseAllSegmentsBuffer(v.data, v.len, tmp);

            char label[300];
            if (d.valid)
                std::snprintf(label, sizeof(label), "%s op=%04x %-20s conn=%llu len=%u %s%zu segs",
                    hp.outgoing ? "SEND" : "RECV",
                    (unsigned)d.opcode, name,
                    (unsigned long long)hp.connection_id, hp.len,
                    (v.inflated ? "(inflated) " : (hp.len >= 0x22 && (hp.buf[0x21] != 0) ? "(compressed) " : "")), tmp.size());
            else
                std::snprintf(label, sizeof(label), "%s seg=%u(%s) conn=%llu len=%u %s%zu segs",
                    hp.outgoing ? "SEND" : "RECV", (unsigned)d.segType, SegTypeName(d.segType),
                    (unsigned long long)hp.connection_id, hp.len,
                    (v.inflated ? "(inflated) " : (hp.len >= 0x22 && (hp.buf[0x21] != 0) ? "(compressed) " : "")), tmp.size());

            ImGui::PushID(i);
            if (ImGui::Selectable(label, selectedFiltered == ri)) {
                selectedFiltered = ri;
                g_lastSelected = hp;
                g_hasSelection = true;
                s_autoScroll = false;
            }
            ImGui::PopID();
        }
    }

    if (s_autoScroll && !s_paused && !filtered.empty()) {
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 20) {
            ImGui::SetScrollHereY(1.0f);
        }
    }

    ImGui::EndChild();

    // Export dialogs state
    static bool s_openJsonDialog = false;
    static bool s_openPcapDialog = false;
    static HookPacket s_pendingJson{};
    static HookPacket s_pendingPcap{};

    // Bottom: details
    ImGui::BeginChild("pkt_details", ImVec2(0, 0), true);
    if (selectedFiltered >= 0 && selectedFiltered < (int)filtered.size()) {
        int selIndex = filtered[selectedFiltered];
        const HookPacket& hp = activeDisplay[selIndex];
        const ParsedPacket P = ParsePacket(hp);
        uint16_t resolvedConn = ResolveConnType(hp, P);

        // Details toolbar (readability)
        static float s_detailsScale = 1.05f;   // slightly larger by default
        static bool  s_compactCells = false;
        ImGui::SeparatorText("Selected Packet Details");
        ImGui::SetNextItemWidth(140.0f);
        ImGui::SliderFloat("Text scale", &s_detailsScale, 0.9f, 1.5f, "%.2fx");
        ImGui::SameLine();
        ImGui::Checkbox("Compact", &s_compactCells);

        ImGui::SetWindowFontScale(s_detailsScale);
        ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, s_compactCells ? ImVec2(4.0f, 2.0f) : ImVec2(8.0f, 6.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, s_compactCells ? ImVec2(6.0f, 3.0f) : ImVec2(10.0f, 6.0f));

        // Precompute segs once (used by multiple sections)
        SegmentView v = GetSegmentView(hp);
        std::vector<SegmentInfo> segs;
        ParseAllSegmentsBuffer(v.data, v.len, segs);
        DecodedHeader dec = DecodeForList(hp);

        // Overview section (new)
        if (BeginDetailsSection("Overview", true)) {
            DrawPacketOverview(hp, P, segs, dec, resolvedConn);
        }

        // Stats and flow
        if (BeginDetailsSection("Statistics & Analysis", true)) {
            DrawPacketStatistics(hp, segs);
            DrawPacketFlowAnalysis();
        }

        // Packet header
        if (BeginDetailsSection("Packet header", true)) {
            DrawPacketHeaderTable(P, resolvedConn);
        }

        // First segment header (raw)
        if (P.seg_ok && BeginDetailsSection("First segment header (raw-only)", false)) {
            DrawSegmentHeaderTable(P);
        }

        // All segments list
        if (BeginDetailsSection("All segments", true)) {
            DrawAllSegmentsTable(hp, resolvedConn);
        }

        // IPC segments (collapsible per item)
        if (BeginDetailsSection("IPC segments", true)) {
            DrawIPCHeaderTable(P, hp.outgoing, hp, resolvedConn);
        }

        ImGui::PopStyleVar(2);
        ImGui::SetWindowFontScale(1.0f);

        ImGui::Separator();
        if (ImGui::Button("Export JSON")) { s_pendingJson = hp; s_openJsonDialog = true; ImGuiFD::OpenDialog("Export JSON", ImGuiFDMode_SaveFile, "exports", "{JSON Files:*.json}, {*.*}"); }
        ImGui::SameLine();
        if (ImGui::Button("Export PCAP")) { s_pendingPcap = hp; s_openPcapDialog = true; ImGuiFD::OpenDialog("Export PCAP", ImGuiFDMode_SaveFile, "exports", "{PCAP Files:*.pcap}, {*.*}"); }
        ImGui::Separator();
    }
    else {
        ImGui::TextDisabled("Select a packet to view headers and hex dump");
    }
    ImGui::EndChild();

    // Save dialogs
    if (ImGuiFD::BeginDialog("Export JSON")) {
        if (ImGuiFD::ActionDone()) {
            if (ImGuiFD::SelectionMade()) {
                const char* selPath = ImGuiFD::GetSelectionPathString(0);
                std::string path = selPath ? std::string(selPath) : std::string();
                if (!path.empty()) {
                    if (path.size() < 5 || path.substr(path.size() - 5) != ".json")
                        path += ".json";
                    (void)ExportToJsonAs(s_pendingJson, path);
                }
            }
            ImGuiFD::CloseCurrentDialog();
            s_openJsonDialog = false;
        }
        ImGuiFD::EndDialog();
    }

    if (ImGuiFD::BeginDialog("Export PCAP")) {
        if (ImGuiFD::ActionDone()) {
            if (ImGuiFD::SelectionMade()) {
                const char* selPath = ImGuiFD::GetSelectionPathString(0);
                std::string path = selPath ? std::string(selPath) : std::string();
                if (!path.empty()) {
                    if (path.size() < 5 || path.substr(path.size() - 5) != ".pcap")
                        path += ".pcap";
                    (void)ExportToPcapAs(s_pendingPcap, path);
                }
            }
            ImGuiFD::CloseCurrentDialog();
            s_openPcapDialog = false;
        }
        ImGuiFD::EndDialog();
    }
}
//DONT REMOVE THIS FUNCTION< IT IS USED BY DrawPacketStatistics
// It is referenced in the ImGui UI to show detailed statistics. 
static void DrawPacketStatistics(const HookPacket& hp, const std::vector<SegmentInfo>& segs) {
	if (ImGui::CollapsingHeader("Packet Statistics", ImGuiTreeNodeFlags_DefaultOpen)) {
		if (ImGui::BeginTable("pkt_stats", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
			auto row = [](const char* k, const std::string& v) {
				ImGui::TableNextRow();
				ImGui::TableNextColumn();
				ImGui::TextUnformatted(k);
				ImGui::TableNextColumn();
				ImGui::TextUnformatted(v.c_str());
				};

			std::unordered_map<uint16_t, int> segTypeCounts;
			std::unordered_map<uint16_t, int> opcodeCounts;
			size_t totalPayloadSize = 0;
			size_t ipcCount = 0;
			size_t compressedSize = hp.len - 0x28;    

			for (const auto& s : segs) {
				segTypeCounts[s.type]++;
				totalPayloadSize += s.size;
				if (s.hasIpc) {
					opcodeCounts[s.opcode]++;
					ipcCount++;
				}
			}

			row("Total Segments", std::to_string(segs.size()));
			row("IPC Segments", std::to_string(ipcCount));
			row("Total Payload Size", std::to_string(totalPayloadSize) + " bytes");

			auto P = ParsePacket(hp);
			if (P.isCompressed && totalPayloadSize > 0) {
				float ratio = (float)compressedSize / (float)totalPayloadSize;
				std::ostringstream os;
				os << std::fixed << std::setprecision(1) << (ratio * 100.0f) << "%";
				row("Compression Ratio", os.str());
			}

			std::ostringstream segTypes;
			for (const auto& [type, count] : segTypeCounts) {
				if (segTypes.tellp() > 0) segTypes << ", ";
				segTypes << SegTypeName(type) << "(" << count << ")";
			}
			row("Segment Types", segTypes.str());

			if (!opcodeCounts.empty()) {
				std::vector<std::pair<uint16_t, int>> sortedOpcodes(opcodeCounts.begin(), opcodeCounts.end());
				std::sort(sortedOpcodes.begin(), sortedOpcodes.end(),
					[](const auto& a, const auto& b) { return a.second > b.second; });

				std::ostringstream opcodes;
				int shown = 0;
				for (const auto& [op, count] : sortedOpcodes) {
					if (shown++ >= 5) {
						opcodes << ", ...";
						break;
					}
					if (opcodes.tellp() > 0) opcodes << ", ";

					uint16_t resolvedConn = ResolveConnType(hp, P);
					const char* name = LookupOpcodeName(op, hp.outgoing, resolvedConn);
					opcodes << "0x" << std::hex << std::setfill('0') << std::setw(4) << op;
					if (name && name[0] && name[0] != '?') {
						opcodes << "(" << name << ")";
					}
					if (count > 1) opcodes << "×" << std::dec << count;
				}
				row("Opcodes", opcodes.str());
			}

			ImGui::EndTable();
		}
	}
}


//DONT REMOVE THIS FUNCTION< IT IS USED BY DrawPacketStatistics
// It is referenced in the ImGui UI to show detailed statistics. 
// Update DrawImGuiEmbedded to better track flows
void SafeHookLogger::DrawImGuiEmbedded() {
	static std::vector<HookPacket> ui_batch;
	DrainToVector(ui_batch);

	static std::vector<HookPacket> display;
	static std::vector<uint16_t> recentOpcodes;

	display.reserve(display.size() + ui_batch.size());
	for (auto& p : ui_batch) {
		// Extract opcodes for pattern detection and flow tracking
		auto dec = DecodeForList(p);
		if (dec.valid) {
			recentOpcodes.push_back(dec.opcode);
			if (recentOpcodes.size() > 100) {
				recentOpcodes.erase(recentOpcodes.begin());
			}
			DetectPatterns(recentOpcodes);

			// Call UpdatePacketCorrelation for ALL valid packets, not just specific ones
			UpdatePacketCorrelation(dec.opcode, p.outgoing, p);

			// Track all opcodes in all flows if we have multiple
			for (const auto& opcode : dec.opcodes) {
				UpdatePacketCorrelation(opcode, p.outgoing, p);
			}
		}

		display.push_back(std::move(p));
	}

	if (display.size() > 100000)
		display.erase(display.begin(), display.begin() + (display.size() - 100000));

	DrawPacketListAndDetails(display);
}

//DONT REMOVE THIS FUNCTION< IT IS USED BY DrawPacketStatistics
// It is referenced in the ImGui UI to show detailed statistics. 
void SafeHookLogger::DrawImGuiSimple() {
	ImGui::Begin("Network Monitor");
	DrawImGuiEmbedded();
	ImGui::End();
}


//DONT REMOVE THIS FUNCTION< IT IS USED BY DrawPacketStatistics
// It is referenced in the ImGui UI to show detailed statistics. 
void SafeHookLogger::DrawImGuiSimple(bool* p_open) {
	if (ImGui::Begin("Network Monitor", p_open)) {
		DrawImGuiEmbedded();
	}
	ImGui::End();
}