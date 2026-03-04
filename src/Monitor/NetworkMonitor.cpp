#define IMGUI_DEFINE_MATH_OPERATORS

#include "NetworkMonitor.h"
#include "../../vendor/ImGuiFD/ImGuiFD.h"
#include "../../vendor/miniz/miniz.h"
#include "../Logger/Logger.h"
#include "../Network/OpcodeNames.h"
#include "../Network/PacketDecoder.h"
#include "../Network/PacketRegistration.h"
#include "../vendor/imgui/imgui.h"
#include "../vendor/imgui/imgui_internal.h"
#include "NetworkMonitorHelper.h"
#include "NetworkMonitorTypes.h"
#include "PacketEvents.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "../../vendor/imgui/TextEditor.h"
#include "../ProtocolHandlers/Zone/ServerZoneDef.h"
#include "../Core/TerritoryScanner.h"
#include "../ProtocolHandlers/Zone/ClientZoneDef.h"
#include "../Modules/CommandInterface.h"
#include <ShlObj.h>
#include <Windows.h>
#include <commdlg.h>

using namespace SapphireHook;

namespace ServerZone = PacketStructures::Server::Zone;

namespace {
	static void ProcessPacketEvents(const HookPacket& hp);
}

namespace {
	static std::string ShowWindowsSaveDialog(const char* title, const char* filter,
		const char* defaultExt) {
		char filename[MAX_PATH] = "";

		OPENFILENAMEA ofn = {};
		ofn.lStructSize = sizeof(ofn);
		ofn.hwndOwner = nullptr;
		ofn.lpstrFilter = filter;
		ofn.lpstrFile = filename;
		ofn.nMaxFile = MAX_PATH;
		ofn.lpstrTitle = title;
		ofn.lpstrDefExt = defaultExt;
		ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

		if (GetSaveFileNameA(&ofn)) {
			return std::string(filename);
		}
		return "";
	}
}

namespace {
	struct UnknownOpcodeInfo {
		uint16_t opcode = 0;
		uint16_t connType = 0;
		bool outgoing = false;
		uint32_t count = 0;
		std::chrono::system_clock::time_point firstSeen{};
		std::chrono::system_clock::time_point lastSeen{};
		std::vector<uint32_t> observedSizes;
	};
	static std::map<uint64_t, UnknownOpcodeInfo>
		g_unknownOpcodes;

	static uint64_t MakeUnknownKey(uint16_t opcode, uint16_t connType,
		bool outgoing) {
		return (uint64_t(connType) << 32) | (uint64_t(outgoing ? 1 : 0) << 16) |
			uint64_t(opcode);
	}

	struct OpcodeCoverageStats {
		uint64_t totalIpcPackets = 0;
		uint64_t knownPackets = 0;
		uint64_t unknownPackets = 0;
		std::map<uint16_t, uint64_t> perConnTypeTotal;
		std::map<uint16_t, uint64_t> perConnTypeKnown;
	};
	static OpcodeCoverageStats g_coverageStats;

	struct OpcodeFrequency {
		uint16_t opcode = 0;
		uint16_t connType = 0;
		bool outgoing = false;
		uint64_t count = 0;
		std::string name;
	};
	static std::map<uint64_t, OpcodeFrequency>
		g_opcodeFrequency;

	struct OpcodeTimelineEntry {
		std::chrono::system_clock::time_point timestamp;
		uint16_t opcode;
		uint16_t connType;
		bool outgoing;
	};
	static std::vector<OpcodeTimelineEntry> g_opcodeTimeline;
	static constexpr size_t MAX_TIMELINE_ENTRIES = 10000;

	struct SizeVarianceEntry {
		uint16_t opcode = 0;
		uint16_t connType = 0;
		bool outgoing = false;
		uint32_t expectedSize = 0;
		uint32_t actualSize = 0;
		uint32_t count = 0;
		std::chrono::system_clock::time_point lastSeen{};
	};
	static std::map<uint64_t, SizeVarianceEntry>
		g_sizeVariance;

	struct SegmentTypeStats {
		uint64_t ipcCount = 0;
		uint64_t keepAliveCount = 0;
		uint64_t responseCount = 0;
		uint64_t encryptionCount = 0;
		uint64_t otherCount = 0;
	};
	static SegmentTypeStats g_segmentStats;

	struct MultiSegmentPacket {
		size_t packetIndex = 0;
		uint32_t segmentCount = 0;
		std::vector<uint16_t> opcodes;
		std::chrono::system_clock::time_point timestamp;
	};
	static std::vector<MultiSegmentPacket> g_multiSegmentPackets;

	static bool IsOpcodeKnown(uint16_t opcode, bool outgoing, uint16_t connType) {
		Net::ConnectionType ct = static_cast<Net::ConnectionType>(connType);
		const char* name = LookupOpcodeName(opcode, outgoing, ct);
		return name && std::strcmp(name, "?") != 0;
	}

	static void UpdateOpcodeAnalytics(const HookPacket& hp, uint16_t opcode,
		uint16_t connType, bool hasIpc,
		uint16_t segType, uint32_t payloadSize) {
		if (!hasIpc) {
			switch (segType) {
			case 1:
				g_segmentStats.keepAliveCount++;
				break;
			case 2:
				g_segmentStats.responseCount++;
				break;
			case 9:
				g_segmentStats.encryptionCount++;
				break;
			default:
				g_segmentStats.otherCount++;
				break;
			}
			return;
		}

		g_segmentStats.ipcCount++;
		g_coverageStats.totalIpcPackets++;
		g_coverageStats.perConnTypeTotal[connType]++;

		bool known = IsOpcodeKnown(opcode, hp.outgoing, connType);

		if (known) {
			g_coverageStats.knownPackets++;
			g_coverageStats.perConnTypeKnown[connType]++;
		}
		else {
			g_coverageStats.unknownPackets++;

			uint64_t key = MakeUnknownKey(opcode, connType, hp.outgoing);
			auto& info = g_unknownOpcodes[key];
			if (info.count == 0) {
				info.opcode = opcode;
				info.connType = connType;
				info.outgoing = hp.outgoing;
				info.firstSeen = hp.ts;
			}
			info.count++;
			info.lastSeen = hp.ts;
			if (std::find(info.observedSizes.begin(), info.observedSizes.end(),
				payloadSize) == info.observedSizes.end()) {
				if (info.observedSizes.size() < 10) {
					info.observedSizes.push_back(payloadSize);
				}
			}
		}

		{
			uint64_t key = MakeUnknownKey(opcode, connType, hp.outgoing);
			auto& freq = g_opcodeFrequency[key];
			if (freq.count == 0) {
				freq.opcode = opcode;
				freq.connType = connType;
				freq.outgoing = hp.outgoing;
				Net::ConnectionType ct = static_cast<Net::ConnectionType>(connType);
				freq.name = LookupOpcodeName(opcode, hp.outgoing, ct);
			}
			freq.count++;
		}

		if (g_opcodeTimeline.size() >= MAX_TIMELINE_ENTRIES) {
			g_opcodeTimeline.erase(g_opcodeTimeline.begin());
		}
		g_opcodeTimeline.push_back({ hp.ts, opcode, connType, hp.outgoing });
	}

	static void ClearOpcodeAnalytics() {
		g_unknownOpcodes.clear();
		g_coverageStats = {};
		g_opcodeFrequency.clear();
		g_opcodeTimeline.clear();
		g_sizeVariance.clear();
		g_segmentStats = {};
		g_multiSegmentPackets.clear();
	}
}

namespace {
	static TextEditor::LanguageDefinition CreateJsonLanguageDefinition() {
		TextEditor::LanguageDefinition langDef;

		langDef.mName = "JSON";
		langDef.mCommentStart = "";
		langDef.mCommentEnd = "";
		langDef.mSingleLineComment = "";
		langDef.mCaseSensitive = true;
		langDef.mAutoIndentation = true;

		langDef.mKeywords.insert("true");
		langDef.mKeywords.insert("false");
		langDef.mKeywords.insert("null");

		langDef.mTokenRegexStrings.push_back(
			std::make_pair<std::string, TextEditor::PaletteIndex>(
				"\"[^\"]*\"\\s*:", TextEditor::PaletteIndex::Identifier));
		langDef.mTokenRegexStrings.push_back(
			std::make_pair<std::string, TextEditor::PaletteIndex>(
				"\"[^\"]*\"", TextEditor::PaletteIndex::String));
		langDef.mTokenRegexStrings.push_back(
			std::make_pair<std::string, TextEditor::PaletteIndex>(
				"[+-]?[0-9]+\\.?[0-9]*([eE][+-]?[0-9]+)?",
				TextEditor::PaletteIndex::Number));
		langDef.mTokenRegexStrings.push_back(
			std::make_pair<std::string, TextEditor::PaletteIndex>(
				"true|false", TextEditor::PaletteIndex::Keyword));
		langDef.mTokenRegexStrings.push_back(
			std::make_pair<std::string, TextEditor::PaletteIndex>(
				"null", TextEditor::PaletteIndex::Keyword));
		langDef.mTokenRegexStrings.push_back(
			std::make_pair<std::string, TextEditor::PaletteIndex>(
				"[\\[\\]{}:,]",
				TextEditor::PaletteIndex::Punctuation));

		return langDef;
	}

	struct JsonViewerState {
		bool isOpen = false;
		TextEditor editor;
		std::string title;
		bool initialized = false;

		void Initialize() {
			if (!initialized) {
				static TextEditor::LanguageDefinition jsonLang =
					CreateJsonLanguageDefinition();
				editor.SetLanguageDefinition(jsonLang);
				editor.SetReadOnly(true);
				editor.SetShowWhitespaces(false);
				initialized = true;
			}
		}

		void Open(const std::string& json, const std::string& windowTitle) {
			Initialize();
			title = windowTitle;
			editor.SetText(json);
			isOpen = true;
		}

		void Render() {
			if (!isOpen)
				return;

			ImGui::SetNextWindowSize(ImVec2(800, 600), ImGuiCond_FirstUseEver);
			if (ImGui::Begin(title.c_str(), &isOpen, ImGuiWindowFlags_MenuBar)) {
				if (ImGui::BeginMenuBar()) {
					if (ImGui::BeginMenu("Edit")) {
						if (ImGui::MenuItem("Copy All", "Ctrl+C")) {
							ImGui::SetClipboardText(editor.GetText().c_str());
						}
						if (ImGui::MenuItem("Select All", "Ctrl+A")) {
							editor.SelectAll();
						}
						ImGui::EndMenu();
					}
					if (ImGui::BeginMenu("View")) {
						bool showLineNumbers = editor.IsShowingWhitespaces();
						if (ImGui::MenuItem("Show Whitespaces", nullptr, &showLineNumbers)) {
							editor.SetShowWhitespaces(showLineNumbers);
						}
						ImGui::EndMenu();
					}
					ImGui::EndMenuBar();
				}

				editor.Render("##json_viewer_editor");

				auto cpos = editor.GetCursorPosition();
				ImGui::Text("Ln %d, Col %d | %zu lines | %zu chars", cpos.mLine + 1,
					cpos.mColumn + 1, editor.GetTotalLines(),
					editor.GetText().size());
			}
			ImGui::End();
		}
	};
	static JsonViewerState g_jsonViewer;

	static std::string GeneratePacketJson(const HookPacket& hp);
}

PacketCapture& PacketCapture::Instance() {
	static PacketCapture inst{};
	return inst;
}

namespace {
	static bool ExportToJsonAs(const HookPacket& hp, const std::string& filepath);
	static bool ExportToPcapAs(const HookPacket& hp, const std::string& filepath);
	static bool ExportFilteredToJsonAs(const std::vector<HookPacket>& packets,
		const std::string& filepath);
	static bool ExportFilteredToPcapAs(const std::vector<HookPacket>& packets,
		const std::string& filepath);
	static bool ExportSessionSummaryAs(const std::vector<HookPacket>& packets,
		const std::string& filepath);
	static bool ExportToFFXIVMonXmlAs(const std::vector<HookPacket>& packets,
		const std::string& filepath);

	struct PcapFlowInfo {
		uint8_t clientIp[4] = { 10, 0, 0, 1 };
		uint8_t serverIp[4] = { 10, 0, 0, 2 };
		uint16_t clientPort = 55001;
		uint16_t serverPort = 55002;
		uint16_t nextIpId = 1;
	};
	static std::unordered_map<uint64_t, PcapFlowInfo> g_pcapFlowByConn;

	static PcapFlowInfo& GetFlow(uint64_t connId) {
		auto it = g_pcapFlowByConn.find(connId);
		if (it != g_pcapFlowByConn.end())
			return it->second;
		PcapFlowInfo f{};
		uint16_t base = static_cast<uint16_t>(50000 + (connId % 10000));
		f.clientPort = base | 1;
		f.serverPort = base | 2;
		auto [ins, _] = g_pcapFlowByConn.emplace(connId, f);
		return ins->second;
	}

	static uint16_t Sum16(const uint8_t* data, size_t len) {
		uint32_t sum = 0;
		while (len > 1) {
			sum += (uint16_t(data[0]) << 8) | uint16_t(data[1]);
			data += 2;
			len -= 2;
		}
		if (len == 1)
			sum += uint16_t(data[0]) << 8;
		while (sum >> 16)
			sum = (sum & 0xFFFF) + (sum >> 16);
		return static_cast<uint16_t>(sum);
	}

	static uint16_t IpHeaderChecksum(const uint8_t* ipHdr, size_t hdrLen) {
		uint32_t sum = Sum16(ipHdr, hdrLen);
		return static_cast<uint16_t>(~sum);
	}

	static uint16_t UdpChecksumIPv4(const uint8_t srcIp[4], const uint8_t dstIp[4],
		const uint8_t* udp, size_t udpLen) {
		uint8_t pseudo[12];
		pseudo[0] = srcIp[0];
		pseudo[1] = srcIp[1];
		pseudo[2] = srcIp[2];
		pseudo[3] = srcIp[3];
		pseudo[4] = dstIp[0];
		pseudo[5] = dstIp[1];
		pseudo[6] = dstIp[2];
		pseudo[7] = dstIp[3];
		pseudo[8] = 0;
		pseudo[9] = 17;

		uint32_t sum = 0;
		sum += Sum16(pseudo, sizeof(pseudo));
		sum += Sum16(udp, udpLen);
		if (udpLen & 1)
			sum += uint16_t(udp[udpLen - 1]) << 8;
		while (sum >> 16)
			sum = (sum & 0xFFFF) + (sum >> 16);
		return static_cast<uint16_t>(~sum);
	}
}

namespace {
	static std::unordered_map<uint64_t, uint16_t> g_connTypeByConnId;
}

namespace {
	struct ActionReqRec {
		uint64_t connId = 0;
		std::chrono::system_clock::time_point ts{};
		uint8_t actionKind = 0;
		uint32_t actionKey = 0;
		uint64_t target = 0;
		uint16_t dir = 0;
		uint16_t dirTarget = 0;
	};
	static std::unordered_map<uint32_t, ActionReqRec> g_actionReqById;
}

namespace {
	static bool g_cfgInflateSegments = true;
}
namespace {
	static HookPacket g_lastSelected{};
	static bool g_hasSelection = false;
}

namespace {
	static std::atomic<uint32_t> g_lastIncomingIpcPacked{ 0 };
	static std::atomic<uint64_t> g_lastIncomingConnId{ 0 };
	static std::atomic<uint64_t> g_lastIncomingEpochMs{ 0 };

	static std::atomic<uint32_t> g_lastOutgoingIpcPacked{ 0 };
	static std::atomic<uint64_t> g_lastOutgoingConnId{ 0 };
	static std::atomic<uint64_t> g_lastOutgoingEpochMs{ 0 };

	static inline uint32_t PackLastIpc(uint16_t opcode, uint16_t connType,
		bool valid, bool compressed) {
		const uint32_t ct8 =
			(connType == 0xFFFF) ? 0xFFu : (uint32_t(connType) & 0xFFu);
		return (uint32_t(opcode) & 0xFFFFu) | (ct8 << 16) |
			(valid ? (1u << 24) : 0u) | (compressed ? (1u << 25) : 0u);
	}

	static inline uint16_t UnpackConnType(uint32_t packed) {
		const uint16_t ct8 = static_cast<uint16_t>((packed >> 16) & 0xFFu);
		return (ct8 == 0xFFu) ? 0xFFFF : ct8;
	}

	static inline bool UnpackValid(uint32_t packed) {
		return ((packed >> 24) & 1u) != 0;
	}
	static inline bool UnpackCompressed(uint32_t packed) {
		return ((packed >> 25) & 1u) != 0;
	}
	static inline uint16_t UnpackOpcode(uint32_t packed) {
		return static_cast<uint16_t>(packed & 0xFFFFu);
	}

	static inline uint64_t EpochMsNow() {
		const auto now = std::chrono::system_clock::now();
		return static_cast<uint64_t>(
			std::chrono::duration_cast<std::chrono::milliseconds>(
				now.time_since_epoch())
			.count());
	}

	static bool TryExtractFirstIpcOpcodeUncompressed(const uint8_t* bytes,
		size_t len,
		uint16_t& outConnType,
		uint16_t& outOpcode,
		bool& outCompressed) {
		outConnType = 0xFFFF;
		outOpcode = 0;
		outCompressed = false;
		if (!bytes || len < 0x28)
			return false;

		std::memcpy(&outConnType, bytes + 0x1C, sizeof(outConnType));

		if (len >= 0x22) {
			uint16_t tmp = 0;
			std::memcpy(&tmp, bytes + 0x20, sizeof(tmp));
			const uint8_t isCompressed = static_cast<uint8_t>((tmp >> 8) & 0xFF);
			if (isCompressed != 0) {
				outCompressed = true;
				return false;
			}
		}

		size_t pos = 0x28;
		while (pos + 0x10 <= len) {
			uint32_t segSize = 0;
			uint16_t segType = 0;
			std::memcpy(&segSize, bytes + pos + 0x00, sizeof(segSize));
			std::memcpy(&segType, bytes + pos + 0x0C, sizeof(segType));
			if (segSize < 0x10 || pos + segSize > len)
				break;
			if (segType == 3 && segSize >= 0x20 && pos + 0x14 <= len) {
				std::memcpy(&outOpcode, bytes + pos + 0x12, sizeof(outOpcode));
				return true;
			}
			pos += segSize;
		}
		return false;
	}
}

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
		{"Teleport Sequence", {0x0194, 0x019A}, nullptr},
		{"Combat Round", {0x0196, 0x0146}, nullptr},
		{"Craft Step", {0x0196, 0x01B4}, nullptr},
		{"Movement Update", {0x019A, 0x0192}, nullptr},
		{"Event Interaction", {0x01C2, 0x01C2}, nullptr},
		{"Zone Change", {0x019A, 0x0190}, nullptr},
	};

	static void DetectPatterns(const std::vector<uint16_t>& recentOpcodes) {
		for (auto& pattern : g_patterns) {
			if (recentOpcodes.size() >= pattern.opcodes.size()) {
				bool match = true;
				for (size_t i = 0; i < pattern.opcodes.size(); ++i) {
					if (recentOpcodes[recentOpcodes.size() - pattern.opcodes.size() + i] !=
						pattern.opcodes[i]) {
						match = false;
						break;
					}
				}
				if (match)
					pattern.matchCount++;
			}
		}
	}

	static void UpdatePacketCorrelation(uint16_t opcode, bool outgoing,
		const HookPacket& hp) {
		if (!g_currentFlow.opcodes.empty()) {
			g_currentFlow.opcodes.push_back(opcode);
			if (outgoing && opcode == 0x0196) {
				g_currentFlow.opcodes.clear();
				g_currentFlow.opcodes.push_back(opcode);
				g_currentFlow.startTime = hp.ts;
				g_currentFlow.description = "Combat Action";
			}
			else if (!outgoing && (opcode == 0x0146 || opcode == 0x0147)) {
				if (!g_currentFlow.opcodes.empty() &&
					g_currentFlow.opcodes[0] == 0x0196) {
					g_currentFlow.endTime = hp.ts;
					if (g_flowHistory.size() >= 100)
						g_flowHistory.erase(g_flowHistory.begin());
					g_flowHistory.push_back(g_currentFlow);
					g_currentFlow.opcodes.clear();
				}
			}
		}
		else {
			if (outgoing) {
				switch (opcode) {
				case 0x0196:
					g_currentFlow.opcodes.push_back(opcode);
					g_currentFlow.startTime = hp.ts;
					g_currentFlow.description = "Combat Action";
					break;
				case 0x019A:
					g_currentFlow.opcodes.push_back(opcode);
					g_currentFlow.startTime = hp.ts;
					g_currentFlow.description = "Movement";
					break;
				case 0x01C2:
				case 0x01C3:
				case 0x01C4:
				case 0x01C5:
					g_currentFlow.opcodes.push_back(opcode);
					g_currentFlow.startTime = hp.ts;
					g_currentFlow.description = "Event Interaction";
					break;
				case 0x01B3:
					g_currentFlow.opcodes.push_back(opcode);
					g_currentFlow.startTime = hp.ts;
					g_currentFlow.description = "Trade";
					break;
				case 0x0262:
					g_currentFlow.opcodes.push_back(opcode);
					g_currentFlow.startTime = hp.ts;
					g_currentFlow.description = "Configuration Change";
					break;
				}
			}
			else {
				switch (opcode) {
				case 0x0194:
					g_currentFlow.opcodes.push_back(opcode);
					g_currentFlow.startTime = hp.ts;
					g_currentFlow.description = "Teleport/Warp";
					break;
				case 0x019A:
					g_currentFlow.opcodes.push_back(opcode);
					g_currentFlow.startTime = hp.ts;
					g_currentFlow.description = "Zone Initialization";
					break;
				case 0x0190:
				case 0x0191:
					g_currentFlow.opcodes.push_back(opcode);
					g_currentFlow.startTime = hp.ts;
					g_currentFlow.description = "Actor Spawn/Despawn";
					break;
				}
			}
		}

		struct PendingRequest {
			uint16_t opcode = 0;
			std::chrono::system_clock::time_point ts{};
			bool timeoutLogged = false;
		};
		static std::unordered_map<uint64_t, PendingRequest> pendingRequests;
		static std::chrono::system_clock::time_point lastSweep = hp.ts;

		if (outgoing) {
			pendingRequests.insert_or_assign(hp.connection_id,
				PendingRequest{ opcode, hp.ts, false });
		}
		else if (!pendingRequests.empty()) {
			auto it = pendingRequests.find(hp.connection_id);
			if (it != pendingRequests.end()) {
				auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(
					hp.ts - it->second.ts);
				uint64_t relKey = (uint64_t(it->second.opcode) << 32) | opcode;
				auto& rel = g_packetRelations[relKey];
				if (rel.count == 0) {
					rel.requestOpcode = it->second.opcode;
					rel.responseOpcode = opcode;
					rel.avgLatency = latency;
					rel.count = 1;
				}
				else {
					rel.avgLatency =
						(rel.avgLatency * rel.count + latency) / (rel.count + 1);
					rel.count++;
				}
				pendingRequests.erase(it);
			}
		}

		auto now = hp.ts;
		if (now - lastSweep >= std::chrono::seconds(5)) {
			for (auto it = pendingRequests.begin(); it != pendingRequests.end();) {
				auto age = now - it->second.ts;
				if (!it->second.timeoutLogged && age > std::chrono::minutes(1)) {
					Logger::Instance().DebugPacketCorrelationTimeout(
						it->second.opcode, it->first,
						std::chrono::duration_cast<std::chrono::milliseconds>(age).count());
					it->second.timeoutLogged = true;
				}
				if (age > std::chrono::minutes(5)) {
					it = pendingRequests.erase(it);
				}
				else {
					++it;
				}
			}
			lastSweep = now;
		}
	}
}

namespace {
	static std::atomic<bool> s_retainerDumpEnabled{ false };
	static std::atomic<bool> s_retainerDumpRotate{ false };
	static std::atomic<bool> s_retainerDumpThreadRun{ false };
	static std::atomic<uint64_t> s_retainerDumpMatched{ 0 };
	static std::atomic<uint64_t> s_retainerDumpEnqueued{ 0 };
	static std::atomic<uint64_t> s_retainerDumpDropped{ 0 };
	static std::atomic<uint64_t> s_retainerDumpSkippedNoRetainer{ 0 };
	static std::atomic<uint64_t> s_retainerDumpWritten{ 0 };
	static std::atomic<uint64_t> s_retainerDumpWriteErrors{ 0 };
	static std::atomic<uint64_t> s_retainerDumpSessions{ 0 };
	static std::mutex s_retainerDumpPathMutex;
	static std::string s_retainerDumpCurrentPath;

	struct RetainerDumpJob {
		HookPacket packet;
		uint16_t firstOpcode = 0;
		uint16_t headerConnType = 0xFFFF;
		bool firstOpcodeOk = false;
		bool compressedFlag = false;
	};

	enum class DumpSlotState : uint8_t {
		EMPTY = 0,
		WRITING = 1,
		READY = 2,
		READING = 3,
	};

	static inline constexpr size_t kDumpSlotCount = 256;
	static inline constexpr size_t kDumpSlotProbes = 8;
	struct DumpSlot {
		std::atomic<uint8_t> state;
		RetainerDumpJob job;
	};
	alignas(64) static DumpSlot s_dumpSlots[kDumpSlotCount];
	static std::atomic<size_t> s_dumpProducerFetch{ 0 };
	static std::thread s_dumpThread;

	static bool IsRetainerRelatedOpcode(uint16_t opcode) noexcept {
		switch (opcode) {
		case 0x0106:
		case 0x010B:
		case 0x01A6:
		case 0x01AA:
		case 0x01AB:
		case 0x01AC:
		case 0x01AD:
		case 0x01EF:
		case 0x01B0:
		case 0x01B3:
			return true;
		default:
			return false;
		}
	}

	static bool TryFindAnyRetainerOpcodeInUncompressedSegments(
		const uint8_t* bytes, size_t len, uint16_t& outFirstMatch) noexcept {
		outFirstMatch = 0;
		if (!bytes || len < 0x28)
			return false;

		if (len >= 0x22) {
			uint16_t tmp = 0;
			std::memcpy(&tmp, bytes + 0x20, sizeof(tmp));
			const uint8_t isCompressed = static_cast<uint8_t>((tmp >> 8) & 0xFF);
			if (isCompressed != 0)
				return false;
		}

		const uint8_t* segBase = bytes + 0x28;
		const size_t segLen = len - 0x28;
		if (segLen < 0x10)
			return false;

		size_t pos = 0;
		for (int segIndex = 0; segIndex < 64; ++segIndex) {
			if (pos + 0x10 > segLen)
				break;
			uint32_t segSize = 0;
			uint16_t segType = 0;
			std::memcpy(&segSize, segBase + pos + 0x00, sizeof(segSize));
			std::memcpy(&segType, segBase + pos + 0x0C, sizeof(segType));
			if (segSize < 0x10)
				break;
			if (pos + segSize > segLen)
				break;

			if (segType == 3 && segSize >= 0x20) {
				uint16_t opcode = 0;
				std::memcpy(&opcode, segBase + pos + 0x12, sizeof(opcode));
				if (IsRetainerRelatedOpcode(opcode)) {
					outFirstMatch = opcode;
					return true;
				}
			}

			pos += segSize;
		}
		return false;
	}

	static std::string
		FormatTimestampUtcMs(const std::chrono::system_clock::time_point& tp) {
		const auto tt = std::chrono::system_clock::to_time_t(tp);
		std::tm tm{};
		gmtime_s(&tm, &tt);
		const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
			tp.time_since_epoch()) %
			1000;
		char buf[64]{};
		std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
			tm.tm_min, tm.tm_sec, (int)ms.count());
		return std::string(buf);
	}

	static void AppendHex(std::ostream& os, const uint8_t* data, size_t len) {
		os.setf(std::ios::uppercase);
		os << std::hex << std::setfill('0');
		for (size_t i = 0; i < len; ++i) {
			os << std::setw(2) << (int)data[i];
		}
		os << std::dec;
	}

	static std::string MakeNewDumpPath() {
		namespace fs = std::filesystem;
		fs::path dir = Logger::GetDefaultTempDir() / "packet_dumps";
		std::error_code ec;
		fs::create_directories(dir, ec);
		auto now = std::chrono::system_clock::now();
		const auto tt = std::chrono::system_clock::to_time_t(now);
		std::tm tm{};
		localtime_s(&tm, &tt);
		char name[96]{};
		std::snprintf(name, sizeof(name),
			"retainer_dump_%04d%02d%02d_%02d%02d%02d_pid%u.jsonl",
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
			tm.tm_min, tm.tm_sec, (unsigned)GetCurrentProcessId());
		fs::path p = dir / name;
		{
			std::lock_guard<std::mutex> lock(s_retainerDumpPathMutex);
			s_retainerDumpCurrentPath = p.string();
		}
		return p.string();
	}

	static bool TryEnqueueRetainerDumpJobFromHook(const void* data, size_t len,
		bool outgoing,
		uint64_t conn_id) noexcept {
		if (!data || len == 0)
			return false;
		if (!s_retainerDumpEnabled.load(std::memory_order_relaxed))
			return false;
		if (outgoing)
			return false;

		const uint8_t* bytes = static_cast<const uint8_t*>(data);
		const size_t tocopy = (len > SLOT_PAYLOAD_CAP) ? SLOT_PAYLOAD_CAP : len;
		uint16_t connType = 0xFFFF;
		uint16_t firstOpcode = 0;
		bool compressed = false;
		const bool firstOk = TryExtractFirstIpcOpcodeUncompressed(
			bytes, tocopy, connType, firstOpcode, compressed);

		bool shouldEnqueue = false;
		uint16_t opcodeHint = 0;

		if (!compressed) {
			uint16_t anyMatchOpcode = 0;
			const bool anyMatch = TryFindAnyRetainerOpcodeInUncompressedSegments(
				bytes, tocopy, anyMatchOpcode);
			shouldEnqueue =
				(firstOk && IsRetainerRelatedOpcode(firstOpcode)) || anyMatch;
			opcodeHint = (firstOk && IsRetainerRelatedOpcode(firstOpcode))
				? firstOpcode
				: anyMatchOpcode;
		}
		else {
			shouldEnqueue = (connType == 1);
			opcodeHint = 0;
		}

		if (!shouldEnqueue)
			return false;
		s_retainerDumpMatched.fetch_add(1, std::memory_order_relaxed);

		RetainerDumpJob job{};
		job.packet.outgoing = outgoing;
		job.packet.connection_id = conn_id;
		job.packet.ts = std::chrono::system_clock::now();
		job.packet.len = (uint32_t)tocopy;
		std::memcpy(job.packet.buf.data(), data, tocopy);
		job.firstOpcode = opcodeHint;
		job.headerConnType = connType;
		job.firstOpcodeOk = firstOk;
		job.compressedFlag = compressed;

		const size_t start =
			s_dumpProducerFetch.fetch_add(1, std::memory_order_relaxed) %
			kDumpSlotCount;
		for (size_t probe = 0; probe < kDumpSlotProbes; ++probe) {
			const size_t idx = (start + probe) % kDumpSlotCount;
			uint8_t expected = uint8_t(DumpSlotState::EMPTY);
			if (s_dumpSlots[idx].state.compare_exchange_strong(
				expected, uint8_t(DumpSlotState::WRITING),
				std::memory_order_acquire, std::memory_order_relaxed)) {
				s_dumpSlots[idx].job = std::move(job);
				s_dumpSlots[idx].state.store(uint8_t(DumpSlotState::READY),
					std::memory_order_release);
				s_retainerDumpEnqueued.fetch_add(1, std::memory_order_relaxed);
				return true;
			}
		}
		s_retainerDumpDropped.fetch_add(1, std::memory_order_relaxed);
		return false;
	}

	static bool TryDequeueRetainerDumpJob(RetainerDumpJob& out) {
		for (size_t i = 0; i < kDumpSlotCount; ++i) {
			uint8_t expected = uint8_t(DumpSlotState::READY);
			if (s_dumpSlots[i].state.compare_exchange_strong(
				expected, uint8_t(DumpSlotState::READING),
				std::memory_order_acquire, std::memory_order_relaxed)) {
				out = std::move(s_dumpSlots[i].job);
				s_dumpSlots[i].state.store(uint8_t(DumpSlotState::EMPTY),
					std::memory_order_release);
				return true;
			}
		}
		return false;
	}

	static void RetainerDumpThreadMain();

	static void InitRetainerDumpOnce() {
		static std::once_flag once;
		std::call_once(once, []() {
			for (size_t i = 0; i < kDumpSlotCount; ++i) {
				s_dumpSlots[i].state.store(uint8_t(DumpSlotState::EMPTY),
					std::memory_order_relaxed);
			}
			s_retainerDumpThreadRun.store(true, std::memory_order_relaxed);
			s_dumpThread = std::thread(RetainerDumpThreadMain);
			});
	}

	static void ShutdownRetainerDump() {
		if (!s_retainerDumpThreadRun.exchange(false, std::memory_order_relaxed))
			return;
		if (s_dumpThread.joinable()) {
			try {
				s_dumpThread.join();
			}
			catch (...) {
			}
		}
	}
}

PacketCapture::PacketCapture() {
	InitRetainerDumpOnce();
	for (size_t i = 0; i < SLOT_COUNT; ++i)
		slots_[i].state.store(uint8_t(SlotState::EMPTY));
}
PacketCapture::~PacketCapture() { ShutdownRetainerDump(); }

bool PacketCapture::TryEnqueueFromHook(const void* data, size_t len,
	bool outgoing,
	uint64_t conn_id) noexcept {
	if (!data || len == 0)
		return false;

	const size_t tocopy = (len > SLOT_PAYLOAD_CAP) ? SLOT_PAYLOAD_CAP : len;
	const size_t start =
		producer_fetch_.fetch_add(1, std::memory_order_relaxed) % SLOT_COUNT;
	for (size_t probe = 0; probe < SLOT_PROBES; ++probe) {
		const size_t idx = (start + probe) % SLOT_COUNT;
		uint8_t expected = uint8_t(SlotState::EMPTY);
		if (!slots_[idx].state.compare_exchange_strong(
			expected, uint8_t(SlotState::WRITING), std::memory_order_acquire,
			std::memory_order_relaxed)) {
			continue;
		}

		auto& slot = slots_[idx];
		slot.packet.outgoing = outgoing;
		slot.packet.connection_id = conn_id;
		slot.packet.ts = std::chrono::system_clock::now();
		slot.packet.len = (uint32_t)tocopy;
		std::memcpy(slot.packet.buf.data(), data, tocopy);

		{
			const uint8_t* bytes = static_cast<const uint8_t*>(data);
			uint16_t connType = 0xFFFF;
			uint16_t opcode = 0;
			bool compressed = false;
			const bool ok = TryExtractFirstIpcOpcodeUncompressed(
				bytes, tocopy, connType, opcode, compressed);
			const uint64_t epochMs = EpochMsNow();
			if (!outgoing) {
				g_lastIncomingConnId.store(conn_id, std::memory_order_relaxed);
				g_lastIncomingEpochMs.store(epochMs, std::memory_order_relaxed);
				g_lastIncomingIpcPacked.store(
					PackLastIpc(opcode, connType, ok, compressed),
					std::memory_order_relaxed);
			}
			else {
				g_lastOutgoingConnId.store(conn_id, std::memory_order_relaxed);
				g_lastOutgoingEpochMs.store(epochMs, std::memory_order_relaxed);
				g_lastOutgoingIpcPacked.store(
					PackLastIpc(opcode, connType, ok, compressed),
					std::memory_order_relaxed);
			}
		}

		(void)TryEnqueueRetainerDumpJobFromHook(data, len, outgoing, conn_id);

		ProcessPacketEvents(slot.packet);

		slot.state.store(uint8_t(SlotState::READY), std::memory_order_release);
		return true;
	}
	return false;
}

void PacketCapture::DrainToVector(std::vector<HookPacket>& out) {
	out.clear();
	out.reserve(256);
	for (size_t i = 0; i < SLOT_COUNT && out.size() < UI_BATCH_CAP; ++i) {
		uint8_t expected = uint8_t(SlotState::READY);
		if (slots_[i].state.compare_exchange_strong(
			expected, uint8_t(SlotState::READING), std::memory_order_acquire,
			std::memory_order_relaxed)) {
			out.push_back(slots_[i].packet);
			slots_[i].state.store(uint8_t(SlotState::EMPTY),
				std::memory_order_release);
		}
	}
}

void PacketCapture::DumpHexAscii(const HookPacket& hp) {
	const uint8_t* d = hp.buf.data();
	constexpr size_t kBytesPerLine = 16;
	constexpr size_t kLineBufSize = 256;
	for (size_t off = 0; off < hp.len; off += kBytesPerLine) {
		size_t len = (hp.len - off < kBytesPerLine) ? hp.len - off : kBytesPerLine;
		char line[kLineBufSize] = {};
		char* p = line;
		size_t remaining = kLineBufSize;

		auto append = [&](const char* fmt, auto... args) {
			if (remaining == 0)
				return;
			const int n = std::snprintf(p, remaining, fmt, args...);
			if (n <= 0)
				return;
			const size_t wrote = static_cast<size_t>(n);
			if (wrote >= remaining) {
				p += (remaining - 1);
				remaining = 1;
				*p = 0;
				return;
			}
			p += wrote;
			remaining -= wrote;
			};

		append("%04zx: ", off);
		for (size_t j = 0; j < kBytesPerLine; ++j) {
			if (j < len)
				append("%02x ", d[off + j]);
			else
				append("   ");
		}
		append(" ");
		for (size_t j = 0; j < len; ++j) {
			if (remaining <= 1)
				break;
			const unsigned char c = d[off + j];
			*p++ = (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
			--remaining;
		}
		if (remaining > 0)
			*p = 0;
		ImGui::TextUnformatted(line);
	}
}

void PacketCapture::DumpHexAsciiColored(
	const HookPacket& hp, const std::vector<unsigned int>& colors) {
	if (colors.size() < hp.len) {
		DumpHexAscii(hp);
		return;
	}

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

	const float offWidth =
		ImGui::CalcTextSize("0000:").x + style.ItemSpacing.x * 2.0f + 8.0f;
	const float hexWidth = bytesPerLine * hexStride;
	const float asciiWidth = bytesPerLine * charW;
	const float totalWidth =
		offWidth + hexWidth + style.ItemSpacing.x * 2.0f + asciiWidth;
	const ImVec2 regionSize(totalWidth, totalLines * lineH);
	ImGui::PushID("hex_viewer_overlay");
	ImGui::InvisibleButton("##hex_overlay", regionSize,
		ImGuiButtonFlags_MouseButtonLeft |
		ImGuiButtonFlags_MouseButtonRight);
	ImGui::PopID();

	for (size_t off = 0; off < hp.len; off += bytesPerLine) {
		const float y = cursor.y;
		char offbuf[16];
		std::snprintf(offbuf, sizeof(offbuf), "%04zx:", off);
		dl->AddText(ImVec2(cursor.x, y), ImGui::GetColorU32(ImGuiCol_Text), offbuf);

		const float hexX = cursor.x + ImGui::CalcTextSize("0000:").x +
			style.ItemSpacing.x * 2.0f + 8.0f;
		const float asciiX =
			hexX + bytesPerLine * hexStride + style.ItemSpacing.x * 2.0f;

		int hoveredIdx = -1;
		for (int j = 0; j < bytesPerLine; ++j) {
			size_t i = off + j;
			if (i >= hp.len)
				break;
			ImRect hexR(ImVec2(hexX + j * hexStride, y),
				ImVec2(hexX + (j + 1) * hexStride, y + lineH));
			ImRect ascR(ImVec2(asciiX + j * charW, y),
				ImVec2(asciiX + (j + 1) * charW,
					y + lineH));
			if (hexR.Contains(mouse) || ascR.Contains(mouse)) {
				hoveredIdx = (int)i;
				break;
			}
		}

		if (hoveredIdx >= 0) {
			if (ImGui::IsMouseClicked(0)) {
				s_selStart = s_selEnd = hoveredIdx;
				s_dragging = true;
			}
		}
		if (s_dragging) {
			if (ImGui::IsMouseDown(0)) {
				if (hoveredIdx >= 0)
					s_selEnd = hoveredIdx;
			}
			else
				s_dragging = false;
		}
		if (ImGui::IsMouseClicked(1)) {
			s_selStart = s_selEnd = -1;
			s_dragging = false;
		}

		const int selMin = (std::min)(s_selStart, s_selEnd);
		const int selMax = (std::max)(s_selStart, s_selEnd);

		for (int j = 0; j < bytesPerLine; ++j) {
			size_t i = off + j;
			ImVec2 hpPos = ImVec2(hexX + j * hexStride, y);
			ImVec2 ascPos = ImVec2(asciiX + j * charW, y);
			ImRect hexR(hpPos, ImVec2(hpPos.x + hexStride, y + lineH));
			ImRect ascR(ascPos,
				ImVec2(ascPos.x + charW,
					y + lineH));

			if (i < hp.len) {
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
					i < (uint32_t(0x28) + g_hoveredSegmentOffset +
						g_hoveredSegmentSize)) {
					const ImU32 segCol = IM_COL32(255, 255, 120, 80);
					dl->AddRectFilled(hexR.Min, hexR.Max, segCol, 2.0f);
					dl->AddRectFilled(ascR.Min, ascR.Max, segCol, 2.0f);
				}
			}

			char b[4] = { 0 };
			if (i < hp.len)
				std::snprintf(b, sizeof(b), "%02x", hp.buf[i]);
			else {
				b[0] = ' ';
				b[1] = ' ';
			}
			dl->AddText(hpPos,
				(i < hp.len) ? colors[i] : ImGui::GetColorU32(ImGuiCol_Text),
				b);

			char c = (i < hp.len) ? (char)hp.buf[i] : ' ';
			if ((unsigned char)c < 32 || (unsigned char)c >= 127)
				c = '.';
			char s[2] = { c, 0 };
			dl->AddText(ascPos,
				(i < hp.len) ? colors[i] : ImGui::GetColorU32(ImGuiCol_Text),
				s);
		}
		cursor.y += lineH;
	}

	ImGui::Dummy(ImVec2(0, totalLines * lineH));
	ImGui::TextDisabled("Hex selection: Left-drag to select bytes. Right-click "
		"to clear selection.");
}

bool PacketCapture::TryGetSelectedPacket(HookPacket& out) {
	if (!g_hasSelection)
		return false;
	out = g_lastSelected;
	return true;
}

bool PacketCapture::TryGetLastIncomingIpcSnapshot(LastIpcSnapshot& out) {
	const uint32_t packed =
		g_lastIncomingIpcPacked.load(std::memory_order_relaxed);
	out = {};
	out.outgoing = false;
	out.connection_id = g_lastIncomingConnId.load(std::memory_order_relaxed);
	out.time_epoch_ms = g_lastIncomingEpochMs.load(std::memory_order_relaxed);
	out.valid = UnpackValid(packed);
	out.compressed = UnpackCompressed(packed);
	out.connType = UnpackConnType(packed);
	out.opcode = UnpackOpcode(packed);
	return out.valid || out.compressed;
}

bool PacketCapture::TryGetLastOutgoingIpcSnapshot(LastIpcSnapshot& out) {
	const uint32_t packed =
		g_lastOutgoingIpcPacked.load(std::memory_order_relaxed);
	out = {};
	out.outgoing = true;
	out.connection_id = g_lastOutgoingConnId.load(std::memory_order_relaxed);
	out.time_epoch_ms = g_lastOutgoingEpochMs.load(std::memory_order_relaxed);
	out.valid = UnpackValid(packed);
	out.compressed = UnpackCompressed(packed);
	out.connType = UnpackConnType(packed);
	out.opcode = UnpackOpcode(packed);
	return out.valid || out.compressed;
}

namespace {
	inline std::string Vec3f(float x, float y, float z) {
		char b[96];
		std::snprintf(b, sizeof(b), "(%.3f, %.3f, %.3f)", x, y, z);
		return b;
	}

	inline bool read16(const uint8_t* b, size_t len, size_t off, uint16_t& out) {
		if (!b || off + 2 > len)
			return false;
		out = (uint16_t)(b[off] | (b[off + 1] << 8));
		return true;
	}
	inline bool read32(const uint8_t* b, size_t len, size_t off, uint32_t& out) {
		if (!b || off + 4 > len)
			return false;
		out = (uint32_t)(b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) |
			(b[off + 3] << 24));
		return true;
	}
	inline bool read64(const uint8_t* b, size_t len, size_t off, uint64_t& out) {
		if (!b || off + 8 > len)
			return false;
		out = 0;
		for (int i = 0; i < 8; i++)
			out |= (uint64_t)b[off + i] << (8 * i);
		return true;
	}

	template <typename T> inline T loadLE(const uint8_t* b) {
		T v{};
		std::memcpy(&v, b, sizeof(T));
		return v;
	}

	static const char* SegTypeName(uint16_t t) {
		switch (t) {
		case 1:
			return "SESSIONINIT";
		case 3:
			return "IPC";
		case 7:
			return "KEEPALIVE";
		case 9:
			return "ENCRYPTIONINIT";
		default:
			return "?";
		}
	}

	static SegmentView GetSegmentView(const HookPacket& hp,
		bool inflateCompressed) {
		SegmentView v{};
		if (hp.len < 0x28)
			return v;
		const uint8_t* p = hp.buf.data();
		const size_t L = hp.len;
		v.data = p + 0x28;
		v.len = L - 0x28;
		v.compressed = false;
		v.inflated = false;
		if (L >= 0x22) {
			uint16_t tmp = 0;
			std::memcpy(&tmp, p + 0x20, sizeof(tmp));
			v.compressed = (((tmp >> 8) & 0xFF) != 0);
		}
		if (!v.compressed || !inflateCompressed)
			return v;
		uint32_t packetSize = 0;
		std::memcpy(&packetSize, p + 0x18, 4);
		size_t outLen = (packetSize > 0x28) ? (packetSize - 0x28) : 0;
		if (outLen == 0 || outLen > (64u << 20))
			return v;
		v.storage.resize(outLen);
		size_t res =
			tinfl_decompress_mem_to_mem(v.storage.data(), outLen, v.data, v.len, 0);
		if (res == TINFL_DECOMPRESS_MEM_TO_MEM_FAILED || res != outLen) {
			res = tinfl_decompress_mem_to_mem(v.storage.data(), outLen, v.data, v.len,
				TINFL_FLAG_PARSE_ZLIB_HEADER);
			if (res == TINFL_DECOMPRESS_MEM_TO_MEM_FAILED || res != outLen) {
				v.storage.clear();
				return v;
			}
		}
		v.data = v.storage.data();
		v.len = outLen;
		v.inflated = true;
		return v;
	}

	static SegmentView GetSegmentView(const HookPacket& hp) {
		return GetSegmentView(hp, g_cfgInflateSegments);
	}

	static void ParseAllSegmentsBuffer(const uint8_t* data, size_t len,
		std::vector<SegmentInfo>& outSegs) {
		outSegs.clear();
		if (!data || len < 0x10)
			return;
		size_t pos = 0;
		while (true) {
			if (pos + 0x10 > len)
				break;
			uint32_t segSize = 0, src = 0, tgt = 0;
			uint16_t type = 0, pad = 0;
			std::memcpy(&segSize, data + pos + 0x00, 4);
			std::memcpy(&src, data + pos + 0x04, 4);
			std::memcpy(&tgt, data + pos + 0x08, 4);
			std::memcpy(&type, data + pos + 0x0C, 2);
			std::memcpy(&pad, data + pos + 0x0E, 2);
			if (segSize < 0x10 || pos + segSize > len)
				break;

			SegmentInfo si{};
			si.offset = (uint32_t)pos;
			si.size = segSize;
			si.source = src;
			si.target = tgt;
			si.type = type;
			si.pad = pad;
			si.hasIpc = false;
			si.opcode = 0;
			si.serverId = 0;
			si.ipcTimestamp = 0;

			if (type == 3 && segSize >= 0x20) {
				uint16_t opcode = 0, serverId = 0;
				uint32_t ts = 0;
				std::memcpy(&opcode, data + pos + 0x12, 2);
				std::memcpy(&serverId, data + pos + 0x16, 2);
				std::memcpy(&ts, data + pos + 0x18, 4);
				si.hasIpc = true;
				si.opcode = opcode;
				si.serverId = serverId;
				si.ipcTimestamp = ts;
			}
			outSegs.push_back(si);
			pos += segSize;
		}
	}

	static ParsedPacket ParsePacket(const HookPacket& hp) {
		ParsedPacket P{};
		const uint8_t* p = hp.buf.data();
		const size_t L = hp.len;
		P.hdr_ok = read64(p, L, 0x00, P.magic0) && read64(p, L, 0x08, P.magic1) &&
			read64(p, L, 0x10, P.timestamp) && read32(p, L, 0x18, P.size) &&
			read16(p, L, 0x1C, P.connType) && read16(p, L, 0x1E, P.segCount);
		if (L >= 0x22) {
			uint16_t tmp = 0;
			P.hdr_ok = P.hdr_ok && read16(p, L, 0x20, tmp);
			P.unknown20 = (uint8_t)(tmp & 0xFF);
			P.isCompressed = (uint8_t)((tmp >> 8) & 0xFF);
		}
		if (L >= 0x28) {
			(void)read32(p, L, 0x24, P.unknown24);
		}
		if (L >= 0x38 && P.isCompressed == 0) {
			P.seg_ok = read32(p, L, 0x28, P.segSize) && read32(p, L, 0x2C, P.src) &&
				read32(p, L, 0x30, P.tgt) && read16(p, L, 0x34, P.segType) &&
				read16(p, L, 0x36, P.segPad);
		}
		if (P.seg_ok && P.segType == 3 && L >= 0x48) {
			P.ipc_ok =
				read16(p, L, 0x38, P.ipcReserved) && read16(p, L, 0x3A, P.opcode) &&
				read16(p, L, 0x3C, P.ipcPad) && read16(p, L, 0x3E, P.serverId) &&
				read32(p, L, 0x40, P.ipcTimestamp) && read32(p, L, 0x44, P.ipcPad1);
		}
		return P;
	}

	static void RetainerDumpThreadMain() {
		std::ofstream f;
		std::string currentPath;
		auto ensureOpen = [&]() {
			if (f.is_open() && !s_retainerDumpRotate.load(std::memory_order_relaxed))
				return;
			s_retainerDumpRotate.store(false, std::memory_order_relaxed);
			try {
				if (f.is_open())
					f.close();
				currentPath = MakeNewDumpPath();
				f.open(currentPath, std::ios::out | std::ios::binary | std::ios::trunc);
				if (!f)
					return;
				f << "{\"type\":\"session_start\",\"time\":\""
					<< FormatTimestampUtcMs(std::chrono::system_clock::now())
					<< "\",\"note\":\"retainer opcode dump\"}\n";
				f.flush();
				s_retainerDumpSessions.fetch_add(1, std::memory_order_relaxed);
			}
			catch (...) {
				s_retainerDumpWriteErrors.fetch_add(1, std::memory_order_relaxed);
			}
			};

		for (;;) {
			if (!s_retainerDumpThreadRun.load(std::memory_order_relaxed))
				break;
			if (!s_retainerDumpEnabled.load(std::memory_order_relaxed)) {
				if (f.is_open()) {
					try {
						f.flush();
						f.close();
					}
					catch (...) {
					}
				}
				Sleep(50);
				continue;
			}

			ensureOpen();
			if (!f.is_open()) {
				Sleep(200);
				continue;
			}

			RetainerDumpJob job{};
			bool wroteAny = false;
			int drained = 0;
			while (drained < 128 && TryDequeueRetainerDumpJob(job)) {
				++drained;
				bool wroteThis = false;
				try {
					ParsedPacket P = ParsePacket(job.packet);
					SegmentView v = GetSegmentView(job.packet, true);
					std::vector<SegmentInfo> segs;
					ParseAllSegmentsBuffer(v.data, v.len, segs);

					bool hasRetainer = false;
					for (const auto& s : segs) {
						if (s.hasIpc && IsRetainerRelatedOpcode(s.opcode)) {
							hasRetainer = true;
							break;
						}
					}
					if (!hasRetainer) {
						s_retainerDumpSkippedNoRetainer.fetch_add(1,
							std::memory_order_relaxed);
						continue;
					}

					f << "{\"type\":\"packet\"";
					f << ",\"time\":\"" << FormatTimestampUtcMs(job.packet.ts) << "\"";
					f << ",\"direction\":\"" << (job.packet.outgoing ? "SEND" : "RECV")
						<< "\"";
					f << ",\"connectionId\":" << job.packet.connection_id;
					f << ",\"length\":" << job.packet.len;
					f << ",\"headerConnType\":" << (uint32_t)P.connType;
					f << ",\"compressed\":" << (v.compressed ? "true" : "false");
					f << ",\"inflated\":" << (v.inflated ? "true" : "false");
					f << ",\"firstOpcodeHint\":\"0x" << std::hex << std::setw(4)
						<< std::setfill('0') << job.firstOpcode << std::dec
						<< std::setfill(' ') << "\"";
					f << ",\"segments\":[";
					bool firstSeg = true;
					for (const auto& s : segs) {
						if (!s.hasIpc)
							continue;
						if (!IsRetainerRelatedOpcode(s.opcode))
							continue;
						const size_t payloadOffset = size_t(s.offset) + 0x20;
						const size_t payloadLen =
							(s.size >= 0x20) ? size_t(s.size - 0x20) : 0;
						if (payloadOffset + payloadLen > v.len)
							continue;
						if (!firstSeg)
							f << ",";
						firstSeg = false;
						f << "{\"opcode\":\"0x" << std::hex << std::setw(4)
							<< std::setfill('0') << s.opcode << std::dec << std::setfill(' ')
							<< "\"";
						f << ",\"serverId\":" << (uint32_t)s.serverId;
						f << ",\"ipcTimestamp\":" << s.ipcTimestamp;
						f << ",\"payloadLen\":" << payloadLen;
						f << ",\"payloadHex\":\"";
						AppendHex(f, v.data + payloadOffset, payloadLen);
						f << "\"";
						f << "}";
					}
					f << "]";
					f << ",\"rawHex\":\"";
					AppendHex(f, job.packet.buf.data(), job.packet.len);
					f << "\"";
					f << "}\n";
					s_retainerDumpWritten.fetch_add(1, std::memory_order_relaxed);
					wroteThis = true;
				}
				catch (...) {
					s_retainerDumpWriteErrors.fetch_add(1, std::memory_order_relaxed);
				}
				wroteAny = wroteAny || wroteThis;
			}
			if (wroteAny) {
				try {
					f.flush();
				}
				catch (...) {
					s_retainerDumpWriteErrors.fetch_add(1, std::memory_order_relaxed);
				}
			}
			Sleep(wroteAny ? 10 : 50);
		}

		if (f.is_open()) {
			try {
				f.flush();
				f.close();
			}
			catch (...) {
				s_retainerDumpWriteErrors.fetch_add(1, std::memory_order_relaxed);
			}
		}
	}

	uint16_t ResolveConnType(const HookPacket& hp, const ParsedPacket& P) {
		auto it = g_connTypeByConnId.find(hp.connection_id);
		uint16_t cached = (it != g_connTypeByConnId.end()) ? it->second : 0xFFFF;
		uint16_t header = P.connType;
		if (header != 0 && header != 0xFFFF) {
			if (P.segCount > 0)
				g_connTypeByConnId[hp.connection_id] =
				header;
			return header;
		}
		if (cached != 0xFFFF)
			return cached;
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
				if (!s.hasIpc)
					continue;
				if (!d.valid) {
					d.valid = true;
					d.opcode = s.opcode;
				}
				d.opcodes.push_back(s.opcode);
			}
		}

		if (!d.valid) {
			uint16_t connGuess =
				(d.connType != 0xFFFF) ? d.connType : 1;
			auto seg = PacketDecoding::TryExtractIpcSegmentKnown(
				hp.buf.data(), hp.len,
				(connGuess == 0xFFFF ? Net::ConnectionType::Unknown
					: static_cast<Net::ConnectionType>(connGuess)));
			if (seg.valid) {
				d.valid = true;
				d.opcode = seg.opcode;
				d.opcodes.push_back(seg.opcode);
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
				if (i > 0)
					os << ", ";
				os << "0x" << std::setw(4) << op;
				const char* name = LookupOpcodeName(op, hp.outgoing, d.connType);
				if (name && name[0] && name[0] != '?')
					os << "(" << name << ")";
				++shown;
			}
			d.opcodeSummary = os.str();
		}
		return d;
	}

	static void
		DispatchActorMoveEvent(uint16_t opcode, bool outgoing, uint32_t sourceActor,
			uint32_t targetActor, const uint8_t* payload,
			size_t payloadLen,
			std::chrono::system_clock::time_point timestamp);

	static void
		DispatchPlayerSpawnEvent(uint16_t opcode, bool outgoing, uint32_t actorId,
			const uint8_t* payload, size_t payloadLen,
			std::chrono::system_clock::time_point timestamp);

	static void ProcessPacketEvents(const HookPacket& hp) {
		if (hp.outgoing)
			return;

		auto P = ParsePacket(hp);
		SegmentView v = GetSegmentView(hp);
		std::vector<SegmentInfo> segs;
		ParseAllSegmentsBuffer(v.data, v.len, segs);

		const uint16_t resolvedConnType = [&]() -> uint16_t {
			const uint16_t ct = ResolveConnType(hp, P);
			if (ct != 0 && ct != 0xFFFF)
				return ct;
			return 1;
			}();

		uint16_t firstIpcOpcode = 0;
		bool foundIpc = false;
		for (const auto& seg : segs) {
			if (!seg.hasIpc)
				continue;
			firstIpcOpcode = seg.opcode;
			foundIpc = true;
			break;
		}
		if (!foundIpc && P.ipc_ok) {
			firstIpcOpcode = P.opcode;
			foundIpc = true;
		}
		if (foundIpc) {
			const uint64_t epochMs = EpochMsNow();
			g_lastIncomingConnId.store(hp.connection_id, std::memory_order_relaxed);
			g_lastIncomingEpochMs.store(epochMs, std::memory_order_relaxed);
			g_lastIncomingIpcPacked.store(
				PackLastIpc(firstIpcOpcode, resolvedConnType, true, v.compressed),
				std::memory_order_relaxed);
		}

		for (const auto& seg : segs) {
			if (!seg.hasIpc)
				continue;

			size_t payloadOffset = seg.offset + 0x20;
			size_t payloadLen = seg.size >= 0x20 ? seg.size - 0x20 : 0;

			if (payloadOffset + payloadLen > v.len)
				continue;
			const uint8_t* payload = v.data + payloadOffset;

			if (seg.opcode == 0x0190 &&
				payloadLen >= sizeof(ServerZone::FFXIVIpcPlayerSpawn)) {
				DispatchPlayerSpawnEvent(seg.opcode, hp.outgoing, seg.source, payload,
					payloadLen, hp.ts);
			}
			else if (seg.opcode == 0x0192 &&
				payloadLen >= sizeof(ServerZone::FFXIVIpcActorMove)) {
				DispatchActorMoveEvent(seg.opcode, hp.outgoing, seg.source, seg.target,
					payload, payloadLen, hp.ts);
			}
			else if (seg.opcode == 0x019A &&
				payloadLen >= sizeof(ServerZone::FFXIVIpcInitZone)) {
				TerritoryScanner::GetInstance().OnInitZonePacket(payload, payloadLen);
			}
			else if (seg.opcode == 0x006A && payloadLen >= 4) {
				TerritoryScanner::GetInstance().OnMoveTerritoryPacket(payload,
					payloadLen);
			}
		}
	}
}

namespace {
	struct RegistryDecodeStats {
		uint64_t attempts = 0;
		uint64_t hits = 0;
		uint64_t misses = 0;
	};
	static RegistryDecodeStats g_regStats;

	inline void EnsurePacketRegistry() {
		static bool done = false;
		if (!done) {
			PacketDecoding::RegisterAllPackets();
			done = true;
		}
	}

	static void AnalyzeForCorrelation(uint16_t opcode, bool outgoing,
		const HookPacket& hp, const uint8_t* payload,
		size_t payloadLen) {
		if (!payload)
			return;
		auto rd16 = [](const uint8_t* p) {
			uint16_t v;
			std::memcpy(&v, p, 2);
			return v;
			};
		auto rd32 = [](const uint8_t* p) {
			uint32_t v;
			std::memcpy(&v, p, 4);
			return v;
			};
		auto rd64 = [](const uint8_t* p) {
			uint64_t v;
			std::memcpy(&v, p, 8);
			return v;
			};

		if (outgoing && opcode == 0x0196 && payloadLen >= 0x18) {
			uint8_t actionKind = payload[1];
			uint32_t actionKey = rd32(payload + 0x04);
			uint32_t requestId = rd32(payload + 0x08);
			uint16_t dir = rd16(payload + 0x0C);
			uint16_t dirTarget = rd16(payload + 0x0E);
			uint64_t target = rd64(payload + 0x10);
			ActionReqRec rec{ hp.connection_id, hp.ts, actionKind, actionKey,
							 target,           dir,   dirTarget };
			g_actionReqById[requestId] = rec;
		}
		else if (!outgoing && (opcode == 0x0146 || opcode == 0x0147) &&
			payloadLen >= 0x18) {
			(void)rd32(payload + 0x10);
		}
	}

	static void
		DispatchActorMoveEvent(uint16_t opcode, bool outgoing, uint32_t sourceActor,
			uint32_t targetActor, const uint8_t* payload,
			size_t payloadLen,
			std::chrono::system_clock::time_point timestamp) {
		if (outgoing || opcode != 0x0192)
			return;
		if (!payload || payloadLen < sizeof(ServerZone::FFXIVIpcActorMove))
			return;

		auto* pkt = reinterpret_cast<const ServerZone::FFXIVIpcActorMove*>(payload);

		DirectX::XMFLOAT3 worldPos =
			PacketEventDispatcher::DecodeActorMovePosition(pkt->pos);

		LogDebug(std::format("ActorMove: actor=0x{:08X} rawPos=({},{},{}) "
			"worldPos=({:.2f},{:.2f},{:.2f}) speed={}",
			sourceActor, pkt->pos[0], pkt->pos[1], pkt->pos[2],
			worldPos.x, worldPos.y, worldPos.z, pkt->speed));

		ActorMoveEvent event{};
		event.sourceActorId = sourceActor;
		event.targetActorId = targetActor;
		event.position = worldPos;
		event.direction = PacketEventDispatcher::DecodeDirection8(pkt->dir);
		event.speed = pkt->speed;
		event.flags = pkt->flag;
		event.timestamp = static_cast<uint64_t>(
			std::chrono::duration_cast<std::chrono::milliseconds>(
				timestamp.time_since_epoch())
			.count());

		PacketEventDispatcher::Instance().DispatchActorMove(event);
	}

	static void
		DispatchPlayerSpawnEvent(uint16_t opcode, bool outgoing, uint32_t actorId,
			const uint8_t* payload, size_t payloadLen,
			std::chrono::system_clock::time_point timestamp) {
		if (outgoing || opcode != 0x0190)
			return;
		if (!payload || payloadLen < sizeof(ServerZone::FFXIVIpcPlayerSpawn))
			return;

		auto* pkt =
			reinterpret_cast<const ServerZone::FFXIVIpcPlayerSpawn*>(payload);

		LogDebug(std::format("PlayerSpawn: actor=0x{:08X} pos=({:.2f},{:.2f},{:.2f}) "
			"objKind={} npcId={}",
			actorId, pkt->Pos[0], pkt->Pos[1], pkt->Pos[2],
			pkt->ObjKind, pkt->NpcId));

		PlayerSpawnEvent event{};
		event.actorId = actorId;
		event.position = { pkt->Pos[0], pkt->Pos[1], pkt->Pos[2] };
		event.direction = PacketEventDispatcher::DecodeDirection16(pkt->Dir);
		event.objKind = pkt->ObjKind;
		event.npcId = pkt->NpcId;
		event.timestamp = static_cast<uint64_t>(
			std::chrono::duration_cast<std::chrono::milliseconds>(
				timestamp.time_since_epoch())
			.count());

		PacketEventDispatcher::Instance().DispatchPlayerSpawn(event);
	}

	static bool DecodeWithRegistry(uint16_t resolvedConnType, bool outgoing,
		uint16_t opcode, const uint8_t* payload,
		size_t payloadLen) {
		if (!payload || payloadLen == 0)
			return false;
		EnsurePacketRegistry();
		auto& reg = PacketDecoding::PacketDecoderRegistry::Instance();

		uint16_t raw[] = { resolvedConnType, 1, 2, 3 };
		std::vector<uint16_t> candidates;
		candidates.reserve(4);
		for (uint16_t c : raw) {
			if (c == 0 || c == 0xFFFF)
				continue;
			if (std::find(candidates.begin(), candidates.end(), c) == candidates.end())
				candidates.push_back(c);
		}
		if (candidates.empty())
			candidates.push_back(1);

		g_regStats.attempts++;
		bool decoded = false;

		ImGui::PushID((int)opcode);
		for (int pass = 0; pass < 2 && !decoded; ++pass) {
			bool dir = (pass == 0) ? outgoing : !outgoing;
			for (uint16_t ct : candidates) {
				bool opened = false;
				bool anyRow = false;
				bool ok = reg.TryDecode(
					ct, dir, opcode, payload, payloadLen,
					[&](const char* k, const std::string& v) {
						if (!opened) {
							ImGui::SeparatorText("Decoded Payload");
							ImGui::BeginTable("decoded_payload_table", 2,
								ImGuiTableFlags_Borders |
								ImGuiTableFlags_RowBg |
								ImGuiTableFlags_SizingFixedFit |
								ImGuiTableFlags_Resizable);
							ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed,
								180.f);
							ImGui::TableSetupColumn("Value",
								ImGuiTableColumnFlags_WidthStretch);
							ImGui::TableHeadersRow();
							opened = true;
						}
						ImGui::TableNextRow();
						ImGui::TableNextColumn();
						ImGui::TextUnformatted(k);
						ImGui::TableNextColumn();
						ImGui::TextUnformatted(v.c_str());
						anyRow = true;
					});

				if (ok && anyRow) {
					if (opened)
						ImGui::EndTable();
					decoded = true;
					g_regStats.hits++;
					break;
				}
				if (opened)
					ImGui::EndTable();
			}
		}
		ImGui::PopID();

		if (!decoded)
			g_regStats.misses++;
		return decoded;
	}

	static void RenderPayload_RawView(const uint8_t* base, size_t len) {
		if (!base || len == 0)
			return;
		ImGui::PushID(base);

		ImGui::TextDisabled("Payload: %zu bytes (no registered decoder)", len);
		ImGui::Spacing();

		if (ImGui::CollapsingHeader("Hex Dump", ImGuiTreeNodeFlags_DefaultOpen)) {
			ImGui::BeginChild("hexdump", ImVec2(0, 200), true);
			for (size_t row = 0; row < len; row += 16) {
				ImGui::Text("%04zX: ", row);
				ImGui::SameLine();
				for (size_t col = 0; col < 16; ++col) {
					if (row + col < len) {
						ImGui::Text("%02X ", base[row + col]);
					}
					else {
						ImGui::Text("   ");
					}
					ImGui::SameLine();
					if (col == 7) {
						ImGui::Text(" ");
						ImGui::SameLine();
					}
				}
				ImGui::Text(" ");
				ImGui::SameLine();
				for (size_t col = 0; col < 16 && row + col < len; ++col) {
					uint8_t c = base[row + col];
					ImGui::Text("%c", (c >= 0x20 && c < 0x7F) ? c : '.');
					ImGui::SameLine();
				}
				ImGui::NewLine();
			}
			ImGui::EndChild();
		}

		if (ImGui::CollapsingHeader("u32 / float View")) {
			if (ImGui::BeginTable("pv_u32", 4,
				ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
				ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 60.f);
				ImGui::TableSetupColumn("u32 (dec)", ImGuiTableColumnFlags_WidthFixed,
					100.f);
				ImGui::TableSetupColumn("u32 (hex)", ImGuiTableColumnFlags_WidthFixed,
					100.f);
				ImGui::TableSetupColumn("float", ImGuiTableColumnFlags_WidthFixed, 100.f);
				ImGui::TableHeadersRow();
				for (size_t off = 0; off + 4 <= len; off += 4) {
					uint32_t v = loadLE<uint32_t>(base + off);
					float f;
					std::memcpy(&f, base + off, sizeof(float));
					ImGui::TableNextRow();
					ImGui::TableNextColumn();
					ImGui::Text("0x%04zX", off);
					ImGui::TableNextColumn();
					ImGui::Text("%u", v);
					ImGui::TableNextColumn();
					ImGui::Text("0x%08X", v);
					ImGui::TableNextColumn();
					ImGui::Text("%.6f", f);
				}
				ImGui::EndTable();
			}
		}

		if (ImGui::CollapsingHeader("u16 View")) {
			if (ImGui::BeginTable("pv_u16", 5,
				ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
				ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 60.f);
				ImGui::TableSetupColumn("u16[0]", ImGuiTableColumnFlags_WidthFixed,
					100.f);
				ImGui::TableSetupColumn("u16[1]", ImGuiTableColumnFlags_WidthFixed,
					100.f);
				ImGui::TableSetupColumn("u16[2]", ImGuiTableColumnFlags_WidthFixed,
					100.f);
				ImGui::TableSetupColumn("u16[3]", ImGuiTableColumnFlags_WidthFixed,
					100.f);
				ImGui::TableHeadersRow();
				for (size_t off = 0; off + 2 <= len; off += 8) {
					ImGui::TableNextRow();
					ImGui::TableNextColumn();
					ImGui::Text("0x%04zX", off);
					for (int i = 0; i < 4; i++) {
						ImGui::TableNextColumn();
						size_t o2 = off + i * 2;
						if (o2 + 2 <= len) {
							uint16_t v = loadLE<uint16_t>(base + o2);
							ImGui::Text("%5u (0x%04X)", v, v);
						}
						else {
							ImGui::TextDisabled("-");
						}
					}
				}
				ImGui::EndTable();
			}
		}

		if (ImGui::CollapsingHeader("u8 View")) {
			if (ImGui::BeginTable("pv_u8", 9,
				ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
				ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 60.f);
				for (int i = 0; i < 8; ++i) {
					char colName[8];
					std::snprintf(colName, sizeof(colName), "+%d", i);
					ImGui::TableSetupColumn(colName, ImGuiTableColumnFlags_WidthFixed,
						50.f);
				}
				ImGui::TableHeadersRow();
				for (size_t off = 0; off < len; off += 8) {
					ImGui::TableNextRow();
					ImGui::TableNextColumn();
					ImGui::Text("0x%04zX", off);
					for (int i = 0; i < 8; ++i) {
						ImGui::TableNextColumn();
						if (off + i < len) {
							ImGui::Text("%3u", base[off + i]);
						}
						else {
							ImGui::TextDisabled("-");
						}
					}
				}
				ImGui::EndTable();
			}
		}

		ImGui::PopID();
	}

	static void RenderPayload_KnownAt(uint16_t opcode, bool outgoing,
		const HookPacket& hp, const uint8_t* payload,
		size_t payloadLen) {
		if (!payload || payloadLen == 0)
			return;
		ParsedPacket P = ParsePacket(hp);
		uint16_t resolvedConn = ResolveConnType(hp, P);

		bool decoded =
			DecodeWithRegistry(resolvedConn, outgoing, opcode, payload, payloadLen);

		AnalyzeForCorrelation(opcode, outgoing, hp, payload, payloadLen);
		UpdatePacketCorrelation(opcode, outgoing, hp);

		if (decoded)
			return;

		if (ImGui::CollapsingHeader("Unknown Packet - Raw Payload",
			ImGuiTreeNodeFlags_DefaultOpen)) {
			RenderPayload_RawView(payload, payloadLen);
		}
	}

	namespace {
		static void RenderOverlayLayersPanel(
			const std::vector<PacketDecoding::OverlayLayer>& layers) {
			if (layers.empty()) {
				ImGui::TextDisabled("No structured layers captured.");
				return;
			}
			for (size_t li = 0; li < layers.size(); ++li) {
				const auto& L = layers[li];
				if (ImGui::TreeNodeEx((void*)(intptr_t)li, ImGuiTreeNodeFlags_DefaultOpen,
					"%s  (globalOff=%zu len=%zu fields=%zu)",
					L.name.c_str(), L.globalOffset, L.length,
					L.fields.size())) {
					if (ImGui::BeginTable(
						("layer_tbl_" + L.name + std::to_string(li)).c_str(), 6,
						ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
						ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_Resizable)) {
						ImGui::TableSetupColumn("Field");
						ImGui::TableSetupColumn("RelOff");
						ImGui::TableSetupColumn("AbsOff");
						ImGui::TableSetupColumn("Size");
						ImGui::TableSetupColumn("Value");
						ImGui::TableSetupColumn("Raw (preview)");
						ImGui::TableHeadersRow();
						for (const auto& F : L.fields) {
							ImGui::TableNextRow();
							ImGui::TableNextColumn();
							ImGui::TextUnformatted(F.name);
							ImGui::TableNextColumn();
							ImGui::Text("%zu", F.offset);
							ImGui::TableNextColumn();
							ImGui::Text("%zu", L.globalOffset + F.offset);
							ImGui::TableNextColumn();
							ImGui::Text("%zu", F.size);
							ImGui::TableNextColumn();
							ImGui::TextUnformatted(F.value.c_str());
							ImGui::TableNextColumn();
							ImGui::TextUnformatted(F.rawPreview.c_str());
						}
						ImGui::EndTable();
					}
					ImGui::TreePop();
				}
			}
		}
	}

	static void DrawIPCHeaderTable(const ParsedPacket& P, bool outgoing,
		const HookPacket& hp, uint16_t resolvedConn) {
		SegmentView v = GetSegmentView(hp);
		std::vector<SegmentInfo> segs;
		ParseAllSegmentsBuffer(v.data, v.len, segs);

		int ipcIndex = 0;
		for (const auto& s : segs) {
			if (!s.hasIpc)
				continue;

			const char* name = LookupOpcodeName(s.opcode, outgoing, resolvedConn);
			char hdrLabel[160];
			std::snprintf(hdrLabel, sizeof(hdrLabel), "IPC segment #%d  0x%04X (%s)",
				ipcIndex, s.opcode, name ? name : "?");

			ImGui::SetNextItemOpen(ipcIndex == 0, ImGuiCond_Appearing);
			if (ImGui::CollapsingHeader(hdrLabel, ImGuiTreeNodeFlags_SpanAvailWidth)) {
				ImGui::PushID(ipcIndex);

				const uint8_t* fullPacket = hp.buf.data();
				const size_t fullLen = hp.len;

				const size_t packetHeaderLen = 0x28;
				const size_t segmentGlobalOff = packetHeaderLen + s.offset;

				const uint8_t* segmentHeader = v.data + s.offset;
				const uint8_t* ipcHeader = segmentHeader + 0x10;
				const uint8_t* payloadPtr = segmentHeader + 0x20;
				size_t payloadLen = (s.size > 0x20) ? (s.size - 0x20) : 0;

				PacketDecoding::BeginOverlayCapture(
					fullPacket, fullLen, fullPacket, packetHeaderLen, segmentHeader, 0x10,
					ipcHeader, 0x10, payloadPtr, payloadLen,
					P.connType ? P.connType : resolvedConn, s.type, true, s.opcode);

				if (ImGui::BeginTable(
					(std::string("ipc_hdr_tbl_") + std::to_string(ipcIndex)).c_str(),
					2,
					ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
					ImGuiTableFlags_SizingFixedFit)) {
					ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed,
						160.f);
					ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
					ImGui::TableHeadersRow();

					auto row = [](const char* k, const std::string& v) {
						ImGui::TableNextRow();
						ImGui::TableNextColumn();
						ImGui::TextUnformatted(k);
						ImGui::TableNextColumn();
						ImGui::TextUnformatted(v.c_str());
						};

					char b[128];
					std::snprintf(b, sizeof(b), "0x%04X (%s)", s.opcode, name ? name : "?");
					row("type (opcode)", b);
					row("serverId", std::to_string(s.serverId));
					row("timestamp", std::to_string(s.ipcTimestamp));
					std::snprintf(b, sizeof(b), "0x%04X (%s)", s.type, SegTypeName(s.type));
					row("segmentType", b);
					row("segmentSize", std::to_string(s.size));
					std::snprintf(b, sizeof(b), "0x%08X (%u)", s.source, s.source);
					row("source_actor", b);
					std::snprintf(b, sizeof(b), "0x%08X (%u)", s.target, s.target);
					row("target_actor", b);
					std::snprintf(b, sizeof(b), "0x%04X", s.pad);
					row("padding", b);
					std::snprintf(b, sizeof(b), "%zu", segmentGlobalOff);
					row("segmentGlobalOffset", b);
					std::snprintf(b, sizeof(b), "0x%04X", s.offset);
					row("segmentLocalOffset", b);

					ImGui::EndTable();
				}

				ImGui::Indent(8.0f);
				RenderPayload_KnownAt(s.opcode, outgoing, hp, payloadPtr, payloadLen);
				ImGui::Unindent(8.0f);

				if (ImGui::CollapsingHeader("Raw Payload View")) {
					RenderPayload_RawView(payloadPtr, payloadLen);
				}

				ImGui::PopID();
			}
			++ipcIndex;
		}
	}
}

namespace {
	static std::unordered_set<uint16_t> g_starredOpcodes;
	static std::mutex g_starredMutex;

	bool IsOpcodeStarred(uint16_t opcode) {
		std::lock_guard<std::mutex> lock(g_starredMutex);
		return g_starredOpcodes.find(opcode) != g_starredOpcodes.end();
	}

	void ToggleOpcodeStarred(uint16_t opcode) {
		std::lock_guard<std::mutex> lock(g_starredMutex);
		if (g_starredOpcodes.find(opcode) != g_starredOpcodes.end())
			g_starredOpcodes.erase(opcode);
		else
			g_starredOpcodes.insert(opcode);
	}

	void ClearStarredOpcodes() {
		std::lock_guard<std::mutex> lock(g_starredMutex);
		g_starredOpcodes.clear();
	}

	std::vector<uint16_t> GetStarredOpcodesList() {
		std::lock_guard<std::mutex> lock(g_starredMutex);
		return std::vector<uint16_t>(g_starredOpcodes.begin(),
			g_starredOpcodes.end());
	}
}

namespace {
	static char g_hexSearchPattern[256] = "";
	static std::vector<int> g_hexSearchResults;
	static bool g_hexSearchActive = false;

	std::vector<uint8_t> ParseHexPattern(const char* pattern) {
		std::vector<uint8_t> bytes;
		std::string s = pattern;
		s.erase(std::remove(s.begin(), s.end(), ' '), s.end());
		if (s.length() % 2 != 0)
			return bytes;
		for (size_t i = 0; i < s.length(); i += 2) {
			char* end = nullptr;
			unsigned long val = strtoul(s.substr(i, 2).c_str(), &end, 16);
			if (end && *end == '\0')
				bytes.push_back(static_cast<uint8_t>(val));
		}
		return bytes;
	}

	bool PacketContainsHexPattern(const HookPacket& hp,
		const std::vector<uint8_t>& pattern) {
		if (pattern.empty() || pattern.size() > hp.len)
			return false;
		for (size_t i = 0; i <= hp.len - pattern.size(); ++i) {
			bool match = true;
			for (size_t j = 0; j < pattern.size(); ++j) {
				if (hp.buf[i + j] != pattern[j]) {
					match = false;
					break;
				}
			}
			if (match)
				return true;
		}
		return false;
	}
}

namespace {
	struct Filters {
		bool showSend = true;
		bool showRecv = true;
		bool onlyKnown = false;
		bool onlyUnknown = false;
		bool onlyStarred = false;
		bool showIpc = true;
		bool showKeepAlive = true;
		bool showResponse = true;
		bool showEncryption = true;
		bool showOtherSeg = true;
		bool onlyMultiSegment =
			false;
		char opcodeList[128] = "";
		char search[128] = "";
		std::string lastParsed;
		std::unordered_set<uint16_t> opcodes;
		void parseOpcodesIfChanged() {
			if (lastParsed == opcodeList)
				return;
			lastParsed = opcodeList;
			opcodes.clear();
			std::string s = lastParsed;
			auto push = [&](const std::string& t) {
				if (t.empty())
					return;
				char* end = nullptr;
				unsigned long v = 0;
				if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0)
					v = strtoul(t.c_str() + 2, &end, 16);
				else
					v = strtoul(t.c_str(), &end, 10);
				if (end != t.c_str())
					opcodes.insert(static_cast<uint16_t>(v & 0xFFFF));
				};
			size_t start = 0;
			while (start <= s.size()) {
				size_t comma = s.find(',', start);
				std::string t =
					s.substr(start, comma == std::string::npos ? std::string::npos
						: comma - start);
				t.erase(0, t.find_first_not_of(" \t"));
				if (!t.empty())
					t.erase(t.find_last_not_of(" \t") + 1);
				push(t);
				if (comma == std::string::npos)
					break;
				start = comma + 1;
			}
		}
	};
	Filters& GetFilters() {
		static Filters f;
		return f;
	}

	bool Matches(const HookPacket& hp, const DecodedHeader& dec, const Filters& f) {
		if (hp.outgoing && !f.showSend)
			return false;
		if (!hp.outgoing && !f.showRecv)
			return false;

		if (f.onlyKnown && !dec.valid)
			return false;

		if (f.onlyUnknown && dec.valid) {
			const bool known = IsOpcodeKnown(dec.opcode, hp.outgoing, dec.connType);
			if (known)
				return false;
		}

		if (f.onlyStarred) {
			if (!dec.valid || !IsOpcodeStarred(dec.opcode))
				return false;
		}

		if (dec.valid) {
			switch (dec.segType) {
			case 3:
				if (!f.showIpc)
					return false;
				break;
			case 1:
				if (!f.showKeepAlive)
					return false;
				break;
			case 2:
				if (!f.showResponse)
					return false;
				break;
			case 9:
				if (!f.showEncryption)
					return false;
				break;
			default:
				if (!f.showOtherSeg)
					return false;
				break;
			}
		}

		const bool needOpcodeScan = (!f.opcodes.empty()) || (f.search[0] != '\0');
		std::vector<uint16_t> packetOpcodes;
		if (needOpcodeScan) {
			ParsedPacket P = ParsePacket(hp);
			SegmentView v = GetSegmentView(hp, true);
			std::vector<SegmentInfo> segs;
			ParseAllSegmentsBuffer(v.data, v.len, segs);
			for (const auto& s : segs) {
				if (s.hasIpc)
					packetOpcodes.push_back(s.opcode);
			}
			if (packetOpcodes.empty() && !P.isCompressed && P.ipc_ok)
				packetOpcodes.push_back(P.opcode);

			std::sort(packetOpcodes.begin(), packetOpcodes.end());
			packetOpcodes.erase(std::unique(packetOpcodes.begin(), packetOpcodes.end()),
				packetOpcodes.end());
		}

		if (!f.opcodes.empty()) {
			bool any = false;
			for (uint16_t op : packetOpcodes) {
				if (f.opcodes.find(op) != f.opcodes.end()) {
					any = true;
					break;
				}
			}
			if (!any)
				return false;
		}

		if (f.search[0] != '\0') {
			std::string q = f.search;
			std::transform(q.begin(), q.end(), q.begin(), ::tolower);

			bool matched = false;
			for (uint16_t op : packetOpcodes) {
				const char* nm = LookupOpcodeName(op, hp.outgoing, dec.connType);
				std::string name = nm ? nm : "";
				std::transform(name.begin(), name.end(), name.begin(), ::tolower);

				char hexbuf[16];
				std::snprintf(hexbuf, sizeof(hexbuf), "%04x", (unsigned)op);
				std::string hex = hexbuf;

				if (name.find(q) != std::string::npos ||
					hex.find(q) != std::string::npos) {
					matched = true;
					break;
				}
			}

			if (!matched)
				return false;
		}

		if (g_hexSearchActive && g_hexSearchPattern[0] != '\0') {
			auto pattern = ParseHexPattern(g_hexSearchPattern);
			if (!pattern.empty() && !PacketContainsHexPattern(hp, pattern))
				return false;
		}

		return true;
	}
}

static void DrawFilters() {
	auto& f = GetFilters();
	f.parseOpcodesIfChanged();

	ImGui::Checkbox("Send", &f.showSend);
	ImGui::SameLine();
	ImGui::Checkbox("Recv", &f.showRecv);
	ImGui::SameLine();
	ImGui::Checkbox("Known only", &f.onlyKnown);
	ImGui::SameLine();
	ImGui::Checkbox("Unknown only", &f.onlyUnknown);
	ImGui::SameLine();
	ImGui::Checkbox("Inflate compressed", &g_cfgInflateSegments);
	ImGui::SameLine();

	{
		auto starred = GetStarredOpcodesList();
		char starLabel[64];
		std::snprintf(starLabel, sizeof(starLabel), "Starred (%zu)",
			starred.size());
		ImGui::Checkbox(starLabel, &f.onlyStarred);
		if (ImGui::IsItemHovered() && !starred.empty()) {
			std::string tooltip = "Starred opcodes: ";
			for (size_t i = 0; i < starred.size() && i < 10; ++i) {
				if (i > 0)
					tooltip += ", ";
				char buf[16];
				std::snprintf(buf, sizeof(buf), "0x%04X", starred[i]);
				tooltip += buf;
			}
			if (starred.size() > 10)
				tooltip += "...";
			ImGui::SetTooltip("%s", tooltip.c_str());
		}
	}

	ImGui::Text("Segments:");
	ImGui::SameLine();
	ImGui::Checkbox("IPC", &f.showIpc);
	ImGui::SameLine();
	ImGui::Checkbox("KeepAlive", &f.showKeepAlive);
	ImGui::SameLine();
	ImGui::Checkbox("Response", &f.showResponse);
	ImGui::SameLine();
	ImGui::Checkbox("Encryption", &f.showEncryption);
	ImGui::SameLine();
	ImGui::Checkbox("Other", &f.showOtherSeg);
	ImGui::SameLine();
	ImGui::Checkbox("Multi-Seg Only", &f.onlyMultiSegment);

	ImGui::SetNextItemWidth(180);
	ImGui::InputTextWithHint("##opcodes", "Opcodes (e.g. 0x67,0x191)",
		f.opcodeList, sizeof(f.opcodeList));
	ImGui::SameLine();
	ImGui::SetNextItemWidth(180);
	ImGui::InputTextWithHint("##search", "Search name/hex", f.search,
		sizeof(f.search));
	ImGui::SameLine();

	ImGui::SetNextItemWidth(200);
	if (ImGui::InputTextWithHint("##hexsearch", "Hex pattern (01 02 03)",
		g_hexSearchPattern,
		sizeof(g_hexSearchPattern))) {
		auto pattern = ParseHexPattern(g_hexSearchPattern);
		g_hexSearchActive = !pattern.empty();
	}
	ImGui::SameLine();
	if (g_hexSearchActive) {
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 1.0f, 0.4f, 1.0f));
		ImGui::Text("(active)");
		ImGui::PopStyleColor();
		ImGui::SameLine();
		if (ImGui::SmallButton("Clear##hexclear")) {
			g_hexSearchPattern[0] = '\0';
			g_hexSearchActive = false;
		}
	}
}

static void DrawAnalyticsDashboard() {
	if (!ImGui::CollapsingHeader("Opcode Analytics Dashboard"))
		return;

	ImGui::Indent(8.0f);

	if (ImGui::TreeNode("Coverage Statistics")) {
		float coveragePercent = g_coverageStats.totalIpcPackets > 0
			? (100.0f * g_coverageStats.knownPackets /
				g_coverageStats.totalIpcPackets)
			: 0.0f;

		ImGui::Text("Overall Coverage:");
		ImGui::SameLine();
		char overlay[64];
		std::snprintf(overlay, sizeof(overlay), "%.1f%% (%llu / %llu)",
			coveragePercent, g_coverageStats.knownPackets,
			g_coverageStats.totalIpcPackets);
		ImGui::ProgressBar(coveragePercent / 100.0f, ImVec2(-1, 0), overlay);

		ImGui::Text("Known: %llu | Unknown: %llu", g_coverageStats.knownPackets,
			g_coverageStats.unknownPackets);

		if (ImGui::BeginTable("coverage_by_conn", 4,
			ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
			ImGui::TableSetupColumn("Connection");
			ImGui::TableSetupColumn("Total");
			ImGui::TableSetupColumn("Known");
			ImGui::TableSetupColumn("Coverage");
			ImGui::TableHeadersRow();

			for (auto& [connType, total] : g_coverageStats.perConnTypeTotal) {
				uint64_t known = g_coverageStats.perConnTypeKnown[connType];
				float pct = total > 0 ? (100.0f * known / total) : 0.0f;
				const char* connName =
					connType == 1
					? "Zone"
					: (connType == 2 ? "Chat"
						: (connType == 3 ? "Lobby" : "Unknown"));

				ImGui::TableNextRow();
				ImGui::TableNextColumn();
				ImGui::Text("%s", connName);
				ImGui::TableNextColumn();
				ImGui::Text("%llu", total);
				ImGui::TableNextColumn();
				ImGui::Text("%llu", known);
				ImGui::TableNextColumn();
				ImGui::Text("%.1f%%", pct);
			}
			ImGui::EndTable();
		}
		ImGui::TreePop();
	}

	if (ImGui::TreeNode("Segment Type Statistics")) {
		if (ImGui::BeginTable("seg_stats", 2,
			ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
			ImGui::TableSetupColumn("Segment Type");
			ImGui::TableSetupColumn("Count");
			ImGui::TableHeadersRow();

			auto row = [](const char* name, uint64_t count) {
				ImGui::TableNextRow();
				ImGui::TableNextColumn();
				ImGui::Text("%s", name);
				ImGui::TableNextColumn();
				ImGui::Text("%llu", count);
				};
			row("IPC (Type 3)", g_segmentStats.ipcCount);
			row("KeepAlive (Type 1)", g_segmentStats.keepAliveCount);
			row("Response (Type 2)", g_segmentStats.responseCount);
			row("Encryption (Type 9)", g_segmentStats.encryptionCount);
			row("Other", g_segmentStats.otherCount);
			ImGui::EndTable();
		}
		ImGui::TreePop();
	}

	if (ImGui::TreeNode("Unknown Opcodes")) {
		ImGui::Text("Tracking %zu unknown opcodes", g_unknownOpcodes.size());

		if (!g_unknownOpcodes.empty()) {
			if (ImGui::BeginTable("unknown_opcodes", 6,
				ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
				ImGuiTableFlags_Sortable |
				ImGuiTableFlags_ScrollY,
				ImVec2(0, 200))) {
				ImGui::TableSetupColumn("Opcode", ImGuiTableColumnFlags_WidthFixed, 80);
				ImGui::TableSetupColumn("Dir", ImGuiTableColumnFlags_WidthFixed, 50);
				ImGui::TableSetupColumn("Conn", ImGuiTableColumnFlags_WidthFixed, 60);
				ImGui::TableSetupColumn("Count", ImGuiTableColumnFlags_WidthFixed, 60);
				ImGui::TableSetupColumn("Sizes", ImGuiTableColumnFlags_WidthStretch);
				ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 40);
				ImGui::TableHeadersRow();

				for (auto& [key, info] : g_unknownOpcodes) {
					ImGui::TableNextRow();
					ImGui::TableNextColumn();
					ImGui::Text("0x%04X", info.opcode);
					ImGui::TableNextColumn();
					ImGui::Text("%s", info.outgoing ? "OUT" : "IN");
					ImGui::TableNextColumn();
					const char* connName =
						info.connType == 1
						? "Zone"
						: (info.connType == 2 ? "Chat"
							: (info.connType == 3 ? "Lobby" : "?"));
					ImGui::Text("%s", connName);
					ImGui::TableNextColumn();
					ImGui::Text("%u", info.count);
					ImGui::TableNextColumn();
					std::string sizes;
					for (size_t i = 0; i < info.observedSizes.size(); ++i) {
						if (i > 0)
							sizes += ", ";
						sizes += std::to_string(info.observedSizes[i]);
					}
					ImGui::TextUnformatted(sizes.c_str());
					ImGui::TableNextColumn();
					char starId[32];
					std::snprintf(starId, sizeof(starId), "*##star%04X", info.opcode);
					if (ImGui::SmallButton(starId)) {
						ToggleOpcodeStarred(info.opcode);
					}
				}
				ImGui::EndTable();
			}
		}
		ImGui::TreePop();
	}

	if (ImGui::TreeNode("Opcode Frequency (Top 20)")) {
		std::vector<std::pair<uint64_t, const OpcodeFrequency*>> sorted;
		for (auto& [key, freq] : g_opcodeFrequency) {
			sorted.push_back({ freq.count, &freq });
		}
		std::sort(sorted.begin(), sorted.end(),
			[](auto& a, auto& b) { return a.first > b.first; });

		uint64_t maxCount = sorted.empty() ? 1 : sorted[0].first;
		size_t shown = (std::min)(sorted.size(), size_t(20));

		for (size_t i = 0; i < shown; ++i) {
			const auto* freq = sorted[i].second;
			char label[128];
			std::snprintf(label, sizeof(label), "0x%04X %s (%s)", freq->opcode,
				freq->name.c_str(), freq->outgoing ? "OUT" : "IN");
			float fraction = float(freq->count) / float(maxCount);
			char overlay[32];
			std::snprintf(overlay, sizeof(overlay), "%llu", freq->count);
			ImGui::ProgressBar(fraction, ImVec2(200, 0), overlay);
			ImGui::SameLine();
			ImGui::TextUnformatted(label);
		}
		ImGui::TreePop();
	}

	if (ImGui::TreeNode("Opcode Timeline (Recent)")) {
		ImGui::Text("Timeline entries: %zu / %zu", g_opcodeTimeline.size(),
			MAX_TIMELINE_ENTRIES);

		if (!g_opcodeTimeline.empty() &&
			ImGui::BeginTable("timeline", 4,
				ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
				ImGuiTableFlags_ScrollY,
				ImVec2(0, 150))) {
			ImGui::TableSetupColumn("Time");
			ImGui::TableSetupColumn("Opcode");
			ImGui::TableSetupColumn("Name");
			ImGui::TableSetupColumn("Dir");
			ImGui::TableHeadersRow();

			size_t start =
				g_opcodeTimeline.size() > 50 ? g_opcodeTimeline.size() - 50 : 0;
			for (size_t i = start; i < g_opcodeTimeline.size(); ++i) {
				auto& entry = g_opcodeTimeline[i];
				auto tt = std::chrono::system_clock::to_time_t(entry.timestamp);
				auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
					entry.timestamp.time_since_epoch()) %
					1000;
				std::tm tm_buf;
				localtime_s(&tm_buf, &tt);

				ImGui::TableNextRow();
				ImGui::TableNextColumn();
				ImGui::Text("%02d:%02d:%02d.%03d", tm_buf.tm_hour, tm_buf.tm_min,
					tm_buf.tm_sec, (int)ms.count());
				ImGui::TableNextColumn();
				ImGui::Text("0x%04X", entry.opcode);
				ImGui::TableNextColumn();
				Net::ConnectionType ct =
					static_cast<Net::ConnectionType>(entry.connType);
				ImGui::Text("%s", LookupOpcodeName(entry.opcode, entry.outgoing, ct));
				ImGui::TableNextColumn();
				ImGui::Text("%s", entry.outgoing ? "OUT" : "IN");
			}
			ImGui::EndTable();
		}
		ImGui::TreePop();
	}

	if (ImGui::TreeNode("Multi-Segment Bundles")) {
		ImGui::Text("Packets with multiple IPC segments: %zu",
			g_multiSegmentPackets.size());

		if (!g_multiSegmentPackets.empty() &&
			ImGui::BeginTable("multiseg", 3,
				ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
				ImGuiTableFlags_ScrollY,
				ImVec2(0, 150))) {
			ImGui::TableSetupColumn("Index");
			ImGui::TableSetupColumn("Segments");
			ImGui::TableSetupColumn("Opcodes");
			ImGui::TableHeadersRow();

			for (auto& ms : g_multiSegmentPackets) {
				ImGui::TableNextRow();
				ImGui::TableNextColumn();
				ImGui::Text("%zu", ms.packetIndex);
				ImGui::TableNextColumn();
				ImGui::Text("%u", ms.segmentCount);
				ImGui::TableNextColumn();
				std::string opcodes;
				for (size_t i = 0; i < ms.opcodes.size(); ++i) {
					if (i > 0)
						opcodes += ", ";
					char buf[16];
					std::snprintf(buf, sizeof(buf), "0x%04X", ms.opcodes[i]);
					opcodes += buf;
				}
				ImGui::TextUnformatted(opcodes.c_str());
			}
			ImGui::EndTable();
		}
		ImGui::TreePop();
	}

	ImGui::Unindent(8.0f);
}

namespace {
	static bool BeginDetailsSection(const char* label, bool defaultOpen = true) {
		ImGui::SetNextItemOpen(defaultOpen, ImGuiCond_Appearing);
		return ImGui::CollapsingHeader(label, ImGuiTreeNodeFlags_SpanAvailWidth);
	}

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
				ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed,
					keyWidth);
				ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
				ImGui::TableHeadersRow();
			}
		}
		~KVTable() {
			if (open)
				ImGui::EndTable();
			ImGui::PopStyleVar(2);
		}
		void Row(const char* k, const std::string& v) {
			if (!open)
				return;
			ImGui::TableNextRow();
			ImGui::TableNextColumn();
			ImGui::TextUnformatted(k);
			ImGui::TableNextColumn();
			ImGui::TextUnformatted(v.c_str());
		}
	};

	static void DrawPacketOverview(const HookPacket& hp, const ParsedPacket& P,
		const std::vector<SegmentInfo>& segs,
		const DecodedHeader& dec,
		uint16_t resolvedConn) {
		KVTable tbl("pkt_overview", 190.0f);
		if (!tbl.open)
			return;

		tbl.Row("Direction", hp.outgoing ? "SEND" : "RECV");
		tbl.Row("Connection Id",
			std::to_string((unsigned long long)hp.connection_id));
		tbl.Row("Length (bytes)", std::to_string(hp.len));
		tbl.Row("Segments", std::to_string(segs.size()));
		size_t ipcCount = 0;
		for (const auto& s : segs)
			if (s.hasIpc)
				++ipcCount;
		tbl.Row("IPC segments", std::to_string(ipcCount));
		tbl.Row("ConnType (header)", std::to_string(P.connType));
		if (resolvedConn != 0xFFFF)
			tbl.Row("ConnType (resolved)", std::to_string(resolvedConn));
		tbl.Row("Compressed", P.isCompressed ? "yes" : "no");

		if (dec.valid && !dec.opcodes.empty()) {
			std::ostringstream os;
			os << std::hex << std::setfill('0');
			int shown = 0;
			for (size_t i = 0; i < dec.opcodes.size(); ++i) {
				if (shown >= 12) {
					os << ", ...";
					break;
				}
				uint16_t op = dec.opcodes[i];
				if (i > 0)
					os << ", ";
				os << "0x" << std::setw(4) << op;
				const char* nm = LookupOpcodeName(op, hp.outgoing, resolvedConn);
				if (nm && nm[0] && nm[0] != '?')
					os << "(" << nm << ")";
				++shown;
			}
			tbl.Row("Opcodes", os.str());
		}

		auto tt = std::chrono::system_clock::to_time_t(hp.ts);
		char tbuf[64]{};
		std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", std::localtime(&tt));
		tbl.Row("Captured at", tbuf);
	}
}

static void DrawPacketHeaderTable(const ParsedPacket& P,
	uint16_t resolvedConn) {
	if (!P.hdr_ok)
		return;
	KVTable tbl("pkt_hdr_main", 190.0f);
	if (!tbl.open)
		return;

	char b[128];
	std::snprintf(b, sizeof(b), "0x%016llX 0x%016llX",
		(unsigned long long)P.magic0, (unsigned long long)P.magic1);
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
	if (!P.seg_ok)
		return;
	KVTable tbl("pkt_hdr_seg", 190.0f);
	if (!tbl.open)
		return;
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

static void DrawAllSegmentsTable(const HookPacket& hp, uint16_t resolvedConn) {
	auto view = GetSegmentView(hp);
	if (!view.data)
		return;
	std::vector<SegmentInfo> segs;
	ParseAllSegmentsBuffer(view.data, view.len, segs);
	g_hasHoveredSegment = false;

	if (ImGui::BeginTable("pkt_all_segments", 6,
		ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
		ImGuiTableFlags_SizingFixedFit)) {
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
			(void)ImGui::Selectable("##row", false,
				ImGuiSelectableFlags_SpanAllColumns |
				ImGuiSelectableFlags_AllowItemOverlap);
			if (ImGui::IsItemHovered()) {
				g_hasHoveredSegment = true;
				g_hoveredSegmentIndex = (int)i;
				g_hoveredSegmentOffset = s.offset;
				g_hoveredSegmentSize = s.size;
			}
			ImGui::PopID();
			ImGui::SameLine();
			ImGui::Text("%zu", i);
			ImGui::TableNextColumn();
			ImGui::Text("0x%04X", s.offset);
			ImGui::TableNextColumn();
			ImGui::Text("%u", s.size);
			ImGui::TableNextColumn();
			ImGui::Text("%u (%s)", s.type, SegTypeName(s.type));
			ImGui::TableNextColumn();
			ImGui::Text("%u -> %u", s.source, s.target);
			ImGui::TableNextColumn();
			if (s.hasIpc) {
				const char* nm = LookupOpcodeName(s.opcode, false, resolvedConn);
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
		draw_list->AddLine(canvas_pos,
			ImVec2(canvas_pos.x + canvas_size.x, canvas_pos.y),
			IM_COL32(255, 255, 255, 128));
		ImGui::Dummy(ImVec2(canvas_size.x, timeline_height));
	}
}

static void DrawPacketFlowAnalysis() {
	if (ImGui::CollapsingHeader("Packet Flow Analysis")) {
		static char flowFilter[128] = "";
		ImGui::InputTextWithHint("##flow_filter", "Filter flows...", flowFilter,
			sizeof(flowFilter));

		if (ImGui::BeginTable("flow_sequences", 4,
			ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
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
				auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
					flow.endTime - flow.startTime);
				ImGui::Text("%lld ms", duration.count());
				ImGui::TableNextColumn();
				ImGui::Text("%zu", flow.opcodes.size());
				ImGui::TableNextColumn();
				std::ostringstream os;
				os << std::hex << std::setfill('0');
				for (size_t i = 0; i < (std::min)(flow.opcodes.size(), size_t(5));
					++i) {
					if (i > 0)
						os << " → ";
					os << "0x" << std::setw(4) << flow.opcodes[i];
				}
				if (flow.opcodes.size() > 5)
					os << " ...";
				ImGui::TextUnformatted(os.str().c_str());
			}
			ImGui::EndTable();
		}

		if (!g_packetRelations.empty()) {
			ImGui::Separator();
			ImGui::Text("Common Packet Relationships:");
			if (ImGui::BeginTable("relations", 4,
				ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
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
			if (ImGui::BeginTable("patterns", 3,
				ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
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
							if (i > 0)
								os << " → ";
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
					flow.endTime - flow.startTime);
				totalDuration += duration.count();
			}
			ImGui::Text("Average Flow Duration: %lld ms",
				totalDuration / g_flowHistory.size());
			ImGui::Text("Active Flows: %zu", g_flowHistory.size());
		}
	}
}

namespace {
	static bool g_clearRequested = false;
}
bool GetClearRequest() {
	if (g_clearRequested) {
		g_clearRequested = false;
		return true;
	}
	return false;
}
void RequestClear() { g_clearRequested = true; }

static void DrawPacketListAndDetails(const std::vector<HookPacket>& display) {
	DrawFilters();
	auto& f = GetFilters();
	f.parseOpcodesIfChanged();

	static bool s_autoScroll = true;
	static bool s_paused = false;
	static std::vector<HookPacket> s_pausedDisplay;
	static int selectedFiltered = -1;

	ImGui::Checkbox("Auto-scroll", &s_autoScroll);
	ImGui::SameLine();
	if (ImGui::Checkbox("Pause", &s_paused)) {
		if (s_paused)
			s_pausedDisplay = display;
		else
			s_pausedDisplay.clear();
	}
	ImGui::SameLine();
	if (ImGui::Button("Clear")) {
		RequestClear();
		selectedFiltered = -1;
		g_hasSelection = false;
		ImGui::SetScrollY(0);
	}

	const std::vector<HookPacket>& activeDisplay =
		s_paused ? s_pausedDisplay : display;

	static std::vector<int> filtered;
	filtered.clear();
	filtered.reserve(activeDisplay.size());
	for (int i = 0; i < (int)activeDisplay.size(); ++i) {
		const HookPacket& hp = activeDisplay[i];
		auto dec = DecodeForList(hp);
		if (Matches(hp, dec, f))
			filtered.push_back(i);
	}

	ImGui::Text("Shown: %d / %zu %s", (int)filtered.size(), activeDisplay.size(),
		s_paused ? "(PAUSED)" : "");

	ImGui::BeginChild("pkt_list", ImVec2(0, 260), true);
	ImGuiListClipper clip;
	clip.Begin((int)filtered.size());
	while (clip.Step()) {
		for (int ri = clip.DisplayStart; ri < clip.DisplayEnd; ++ri) {
			int i = filtered[ri];
			const HookPacket& hp = activeDisplay[i];
			const auto d = DecodeForList(hp);
			const char* name =
				d.valid ? LookupOpcodeName(d.opcode, hp.outgoing, d.connType) : "?";

			ParsedPacket P_list = ParsePacket(hp);
			SegmentView v = GetSegmentView(hp);
			std::vector<SegmentInfo> tmp;
			ParseAllSegmentsBuffer(v.data, v.len, tmp);
			auto status =
				NetworkMonitorHelper::ValidatePacketStructure(hp, P_list, v, tmp);
			const char* statusTag = NetworkMonitorHelper::StatusTag(status.kind);

			char label[360];
			if (d.valid) {
				std::snprintf(label, sizeof(label),
					"%s%s op=%04x %-20s conn=%llu len=%u %s%zu segs",
					statusTag, hp.outgoing ? "SEND" : "RECV",
					(unsigned)d.opcode, name,
					(unsigned long long)hp.connection_id, hp.len,
					(v.inflated ? "(inflated) "
						: (hp.len >= 0x22 && (hp.buf[0x21] != 0)
							? "(compressed) "
							: "")),
					tmp.size());
			}
			else {
				std::snprintf(label, sizeof(label),
					"%s%s seg=%u(%s) conn=%llu len=%u %s%zu segs", statusTag,
					hp.outgoing ? "SEND" : "RECV", (unsigned)d.segType,
					SegTypeName(d.segType),
					(unsigned long long)hp.connection_id, hp.len,
					(v.inflated ? "(inflated) "
						: (hp.len >= 0x22 && (hp.buf[0x21] != 0)
							? "(compressed) "
							: "")),
					tmp.size());
			}

			ImGui::PushID(i);

			if (d.valid) {
				bool starred = IsOpcodeStarred(d.opcode);
				ImGui::PushStyleColor(ImGuiCol_Text,
					starred ? ImVec4(1.0f, 0.9f, 0.2f, 1.0f)
					: ImVec4(0.5f, 0.5f, 0.5f, 1.0f));
				if (ImGui::SmallButton(starred ? "*##star" : " ##star")) {
					ToggleOpcodeStarred(d.opcode);
				}
				ImGui::PopStyleColor();
				if (ImGui::IsItemHovered()) {
					ImGui::SetTooltip(starred ? "Click to unstar opcode 0x%04X"
						: "Click to star opcode 0x%04X",
						d.opcode);
				}
				ImGui::SameLine();
			}

			if (ImGui::Selectable(label, selectedFiltered == ri)) {
				selectedFiltered = ri;
				g_lastSelected = hp;
				g_hasSelection = true;
				s_autoScroll = false;
			}
			if (status.kind != NetworkMonitorHelper::ParseKind::Ok &&
				ImGui::IsItemHovered()) {
				ImGui::SetTooltip("%s", status.reason.c_str());
			}
			ImGui::PopID();
		}
	}
	if (s_autoScroll && !s_paused && !filtered.empty()) {
		if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 20)
			ImGui::SetScrollHereY(1.0f);
	}
	ImGui::EndChild();

	ImGui::BeginChild("pkt_details", ImVec2(0, 0), true);
	if (selectedFiltered >= 0 && selectedFiltered < (int)filtered.size()) {
		int selIndex = filtered[selectedFiltered];
		const HookPacket& hp = activeDisplay[selIndex];
		const ParsedPacket P = ParsePacket(hp);
		uint16_t resolvedConn = ResolveConnType(hp, P);

		static float s_detailsScale = 1.05f;
		static bool s_compactCells = false;
		ImGui::SeparatorText("Selected Packet Details");
		ImGui::SetNextItemWidth(140.0f);
		ImGui::SliderFloat("Text scale", &s_detailsScale, 0.9f, 1.5f, "%.2fx");
		ImGui::SameLine();
		ImGui::Checkbox("Compact", &s_compactCells);

		ImGui::SetWindowFontScale(s_detailsScale);
		ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, s_compactCells
			? ImVec2(4.0f, 2.0f)
			: ImVec2(8.0f, 6.0f));
		ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, s_compactCells
			? ImVec2(6.0f, 3.0f)
			: ImVec2(10.0f, 6.0f));

		SegmentView v = GetSegmentView(hp);
		std::vector<SegmentInfo> segs;
		ParseAllSegmentsBuffer(v.data, v.len, segs);
		DecodedHeader dec = DecodeForList(hp);
		if (segs.empty()) {
			uint16_t connGuess = (resolvedConn != 0xFFFF) ? resolvedConn : 1;
			bool opened = false;
			bool stripHit = PacketDecoding::StripAndDecodeIpcKnown(
				hp.buf.data(), hp.len,
				(connGuess == 0xFFFF ? Net::ConnectionType::Unknown
					: static_cast<Net::ConnectionType>(connGuess)),
				hp.outgoing, [&](const char* k, const std::string& v) {
					if (!opened) {
						ImGui::SeparatorText("Stripped IPC (auto)");
						ImGui::BeginTable("stripped_ipc_table", 2,
							ImGuiTableFlags_Borders |
							ImGuiTableFlags_RowBg |
							ImGuiTableFlags_SizingFixedFit |
							ImGuiTableFlags_Resizable);
						ImGui::TableSetupColumn("Field", ImGuiTableColumnFlags_WidthFixed,
							180.f);
						ImGui::TableSetupColumn("Value",
							ImGuiTableColumnFlags_WidthStretch);
						ImGui::TableHeadersRow();
						opened = true;
					}
					ImGui::TableNextRow();
					ImGui::TableNextColumn();
					ImGui::TextUnformatted(k);
					ImGui::TableNextColumn();
					ImGui::TextUnformatted(v.c_str());
				});
			if (opened)
				ImGui::EndTable();

			if (stripHit) {
				auto layers = PacketDecoding::GetOverlayLayersSnapshot();
				if (!layers.empty()) {
					ImGui::SeparatorText("Stripped Overlay Layers");
					RenderOverlayLayersPanel(layers);
				}
			}
		}

		auto pktStatus =
			NetworkMonitorHelper::ValidatePacketStructure(hp, P, v, segs);
		if (pktStatus.kind != NetworkMonitorHelper::ParseKind::Ok) {
			ImVec4 col =
				(pktStatus.kind == NetworkMonitorHelper::ParseKind::Malformed)
				? ImVec4(1.f, 0.35f, 0.35f, 1.f)
				: ImVec4(1.f, 0.65f, 0.25f, 1.f);
			const char* kindStr =
				(pktStatus.kind == NetworkMonitorHelper::ParseKind::Malformed)
				? "Malformed"
				: "Incomplete";
			ImGui::Spacing();
			ImGui::PushStyleColor(ImGuiCol_Text, col);
			ImGui::Text("%s packet: %s", kindStr, pktStatus.reason.c_str());
			ImGui::PopStyleColor();
			ImGui::Separator();
		}

		if (BeginDetailsSection("Overview", true)) {
			{
				KVTable tbl("pkt_overview", 200.0f);
				if (tbl.open) {
					tbl.Row("Direction", hp.outgoing ? "SEND" : "RECV");
					tbl.Row("Connection Id",
						std::to_string((unsigned long long)hp.connection_id));

					tbl.Row("Length (bytes)", std::to_string(hp.len));

					tbl.Row("Segments", std::to_string(segs.size()));

					size_t ipcCount = 0;
					for (const auto& s : segs)
						if (s.hasIpc)
							++ipcCount;
					tbl.Row("IPC segments", std::to_string(ipcCount));

					tbl.Row("ConnType (header)", std::to_string(P.connType));
					if (resolvedConn != 0xFFFF)
						tbl.Row("ConnType (resolved)", std::to_string(resolvedConn));

					tbl.Row("Compressed", P.isCompressed ? "yes" : "no");

					if (P.hdr_ok) {
						char b[256];
						std::snprintf(b, sizeof(b), "0x%016llX 0x%016llX",
							(unsigned long long)P.magic0,
							(unsigned long long)P.magic1);
						tbl.Row("magic[2]", b);
						std::snprintf(b, sizeof(b), "%llu",
							(unsigned long long)P.timestamp);
						tbl.Row("timestamp(ms)", b);
						std::snprintf(b, sizeof(b), "0x%02X", P.unknown20);
						tbl.Row("unknown_20", b);
						std::snprintf(b, sizeof(b), "0x%08X", P.unknown24);
						tbl.Row("unknown_24", b);
					}

					auto tt = std::chrono::system_clock::to_time_t(hp.ts);
					char tbuf[64]{};
					std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S",
						std::localtime(&tt));
					tbl.Row("Captured at", tbuf);
				}
			}

			g_hasHoveredSegment = false;
			if (!segs.empty()) {
				if (ImGui::BeginTable("pkt_overview_segments", 6,
					ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
					ImGuiTableFlags_SizingFixedFit)) {
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
						(void)ImGui::Selectable("##segrow", false,
							ImGuiSelectableFlags_SpanAllColumns |
							ImGuiSelectableFlags_AllowItemOverlap);
						if (ImGui::IsItemHovered()) {
							g_hasHoveredSegment = true;
							g_hoveredSegmentIndex = (int)i;
							g_hoveredSegmentOffset = s.offset;
							g_hoveredSegmentSize = s.size;
						}
						ImGui::PopID();
						ImGui::SameLine();
						ImGui::Text("%zu", i);
						ImGui::TableNextColumn();
						ImGui::Text("0x%04X", s.offset);
						ImGui::TableNextColumn();
						ImGui::Text("%u", s.size);
						ImGui::TableNextColumn();
						ImGui::Text("%u (%s)", s.type, SegTypeName(s.type));
						ImGui::TableNextColumn();
						ImGui::Text("%u -> %u", s.source, s.target);
						ImGui::TableNextColumn();
						if (s.hasIpc) {
							const char* nm = LookupOpcodeName(s.opcode, false, resolvedConn);
							ImGui::Text("0x%04X (%s)", s.opcode, nm);
						}
						else {
							ImGui::TextUnformatted("-");
						}
					}
					ImGui::EndTable();
				}
			}
		}

		DrawPacketFlowAnalysis();

		if (BeginDetailsSection("IPC segments", true)) {
			DrawIPCHeaderTable(P, hp.outgoing, hp, resolvedConn);
		}

		ImGui::PopStyleVar(2);
		ImGui::SetWindowFontScale(1.0f);

		ImGui::Separator();
		ImGui::Text("Selected Packet:");
		if (ImGui::Button("Export JSON")) {
			std::string path = ShowWindowsSaveDialog(
				"Export Packet to JSON",
				"JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0", "json");
			if (!path.empty()) {
				(void)ExportToJsonAs(hp, path);
			}
		}
		ImGui::SameLine();
		if (ImGui::Button("View JSON")) {
			std::string json = GeneratePacketJson(hp);
			char titleBuf[128];
			std::snprintf(titleBuf, sizeof(titleBuf),
				"Packet JSON (0x%04X)###json_viewer", dec.opcode);
			g_jsonViewer.Open(json, titleBuf);
		}
		if (ImGui::IsItemHovered())
			ImGui::SetTooltip("Open packet as syntax-highlighted JSON");
		ImGui::SameLine();
		if (ImGui::Button("Export PCAP")) {
			std::string path = ShowWindowsSaveDialog(
				"Export Packet to PCAP",
				"PCAP Files (*.pcap)\0*.pcap\0All Files (*.*)\0*.*\0", "pcap");
			if (!path.empty()) {
				(void)ExportToPcapAs(hp, path);
			}
		}
		ImGui::SameLine();

		if (ImGui::Button("Copy Hex")) {
			std::ostringstream hexStream;
			hexStream << std::hex << std::uppercase << std::setfill('0');
			for (size_t i = 0; i < hp.len; ++i) {
				if (i > 0 && i % 16 == 0)
					hexStream << "\n";
				else if (i > 0)
					hexStream << " ";
				hexStream << std::setw(2) << static_cast<int>(hp.buf[i]);
			}
			ImGui::SetClipboardText(hexStream.str().c_str());
		}
		if (ImGui::IsItemHovered())
			ImGui::SetTooltip("Copy packet hex to clipboard");

		ImGui::SameLine();
		if (dec.valid && ImGui::Button("Copy Opcode")) {
			char buf[64];
			const char* name =
				LookupOpcodeName(dec.opcode, hp.outgoing, resolvedConn);
			std::snprintf(buf, sizeof(buf), "0x%04X (%s)", dec.opcode, name);
			ImGui::SetClipboardText(buf);
		}
		if (ImGui::IsItemHovered())
			ImGui::SetTooltip("Copy opcode to clipboard");

		if (hp.outgoing && dec.valid) {
			ImGui::SameLine();
			ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.6f, 0.3f, 0.1f, 1.0f));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered,
				ImVec4(0.8f, 0.4f, 0.2f, 1.0f));
			if (ImGui::Button("Re-inject")) {
				if (hp.len > 0x38) {
					const uint8_t* ipcPayload = hp.buf.data() + 0x38;
					size_t payloadLen = hp.len - 0x38;

					bool success = CommandInterface::SendIpcPacketRaw(
						dec.opcode, ipcPayload, payloadLen,
						resolvedConn != 0xFFFF ? resolvedConn : 1, 0);

					if (success) {
						Logger::Instance().Information(
							"[NetworkMonitor] Re-injected packet opcode 0x" +
							std::to_string(dec.opcode));
					}
					else {
						Logger::Instance().Warning(
							"[NetworkMonitor] Failed to re-inject packet");
					}
				}
			}
			ImGui::PopStyleColor(2);
			if (ImGui::IsItemHovered()) {
				ImGui::SetTooltip("Re-send this packet to the server\n(Only works for "
					"outgoing packets)");
			}
		}

		ImGui::Separator();
	}
	else {
		ImGui::TextDisabled("Select a packet to view headers and hex dump");
	}

	ImGui::Separator();
	ImGui::Text("Bulk Export (%d filtered packets):", (int)filtered.size());

	if (ImGui::Button("Export Filtered JSON")) {
		std::string path = ShowWindowsSaveDialog(
			"Export Filtered Packets to JSON",
			"JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0", "json");
		if (!path.empty()) {
			std::vector<HookPacket> packets;
			for (int idx : filtered)
				packets.push_back(activeDisplay[idx]);
			(void)ExportFilteredToJsonAs(packets, path);
		}
	}
	if (ImGui::IsItemHovered())
		ImGui::SetTooltip("Export all %d filtered packets to JSON",
			(int)filtered.size());

	ImGui::SameLine();
	if (ImGui::Button("Export Filtered PCAP")) {
		std::string path = ShowWindowsSaveDialog(
			"Export Filtered Packets to PCAP",
			"PCAP Files (*.pcap)\0*.pcap\0All Files (*.*)\0*.*\0", "pcap");
		if (!path.empty()) {
			std::vector<HookPacket> packets;
			for (int idx : filtered)
				packets.push_back(activeDisplay[idx]);
			(void)ExportFilteredToPcapAs(packets, path);
		}
	}
	if (ImGui::IsItemHovered())
		ImGui::SetTooltip(
			"Export all %d filtered packets to PCAP (Wireshark compatible)",
			(int)filtered.size());

	ImGui::SameLine();
	if (ImGui::Button("Export Session Summary")) {
		std::string path = ShowWindowsSaveDialog(
			"Export Session Summary",
			"JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0", "json");
		if (!path.empty()) {
			std::vector<HookPacket> packets;
			for (int idx : filtered)
				packets.push_back(activeDisplay[idx]);
			(void)ExportSessionSummaryAs(packets, path);
		}
	}
	if (ImGui::IsItemHovered())
		ImGui::SetTooltip("Export opcode statistics and session summary");

	ImGui::SameLine();
	if (ImGui::Button("Export FFXIVMon XML")) {
		std::string path = ShowWindowsSaveDialog(
			"Export FFXIVMon XML",
			"XML Files (*.xml)\0*.xml\0All Files (*.*)\0*.*\0", "xml");
		if (!path.empty()) {
			std::vector<HookPacket> packets;
			for (int idx : filtered)
				packets.push_back(activeDisplay[idx]);
			(void)ExportToFFXIVMonXmlAs(packets, path);
		}
	}
	if (ImGui::IsItemHovered())
		ImGui::SetTooltip(
			"Export to FFXIVMon compatible XML (SapphireServer/ffxivmon)");

	ImGui::EndChild();
}

void PacketCapture::DrawImGuiEmbedded() {
	static std::vector<HookPacket> ui_batch;
	DrainToVector(ui_batch);

	static std::vector<HookPacket> display;
	static std::vector<uint16_t> recentOpcodes;

	if (GetClearRequest()) {
		display.clear();
		recentOpcodes.clear();
		g_connTypeByConnId.clear();
		g_actionReqById.clear();
		g_activeEvents.clear();
		g_combatSequences.clear();
		g_packetRelations.clear();
		g_flowHistory.clear();
		g_currentFlow.opcodes.clear();
		for (auto& pattern : g_patterns)
			pattern.matchCount = 0;
		g_hasSelection = false;
		ClearOpcodeAnalytics();
	}

	if (ImGui::CollapsingHeader("Retainer Dump",
		ImGuiTreeNodeFlags_DefaultOpen)) {
		bool enabled = s_retainerDumpEnabled.load(std::memory_order_relaxed);
		if (ImGui::Checkbox("Enable retainer IPC dump (incoming only)", &enabled)) {
			s_retainerDumpEnabled.store(enabled, std::memory_order_relaxed);
			if (enabled)
				s_retainerDumpRotate.store(true, std::memory_order_relaxed);
		}
		ImGui::SameLine();
		ImGui::TextDisabled("(opcodes: 0x0106, 0x010B, 0x01AA, 0x01AB, 0x01AC, "
			"0x01AD, 0x01A6, 0x01EF, 0x01B0, 0x01B3)");

		if (ImGui::Button("Start new dump file")) {
			s_retainerDumpRotate.store(true, std::memory_order_relaxed);
		}
		if (ImGui::IsItemHovered()) {
			ImGui::SetTooltip(
				"Closes the current file and starts a new session file");
		}

		std::string path;
		{
			std::lock_guard<std::mutex> lock(s_retainerDumpPathMutex);
			path = s_retainerDumpCurrentPath;
		}
		if (!path.empty()) {
			ImGui::TextWrapped("Writing to: %s", path.c_str());
		}
		else {
			ImGui::TextDisabled("Writing to: (not started yet)");
		}

		const uint64_t matched =
			s_retainerDumpMatched.load(std::memory_order_relaxed);
		const uint64_t enqueued =
			s_retainerDumpEnqueued.load(std::memory_order_relaxed);
		const uint64_t dropped =
			s_retainerDumpDropped.load(std::memory_order_relaxed);
		const uint64_t skipped =
			s_retainerDumpSkippedNoRetainer.load(std::memory_order_relaxed);
		const uint64_t written =
			s_retainerDumpWritten.load(std::memory_order_relaxed);
		const uint64_t errors =
			s_retainerDumpWriteErrors.load(std::memory_order_relaxed);
		const uint64_t sessions =
			s_retainerDumpSessions.load(std::memory_order_relaxed);
		ImGui::Text("Matched: %llu  Enqueued: %llu  Dropped: %llu  Skipped(no "
			"retainer): %llu",
			(unsigned long long)matched, (unsigned long long)enqueued,
			(unsigned long long)dropped, (unsigned long long)skipped);
		ImGui::Text("Written: %llu  Sessions: %llu  WriteErrors: %llu",
			(unsigned long long)written, (unsigned long long)sessions,
			(unsigned long long)errors);
		if (ImGui::Button("Reset counters")) {
			s_retainerDumpMatched.store(0, std::memory_order_relaxed);
			s_retainerDumpEnqueued.store(0, std::memory_order_relaxed);
			s_retainerDumpDropped.store(0, std::memory_order_relaxed);
			s_retainerDumpSkippedNoRetainer.store(0, std::memory_order_relaxed);
			s_retainerDumpWritten.store(0, std::memory_order_relaxed);
			s_retainerDumpWriteErrors.store(0, std::memory_order_relaxed);
			s_retainerDumpSessions.store(0, std::memory_order_relaxed);
		}
		ImGui::TextDisabled("Format: JSONL (one JSON object per line), includes "
			"rawHex and per-segment payloadHex.");
		ImGui::Separator();
	}

	static size_t s_packetIndex = 0;
	display.reserve(display.size() + ui_batch.size());
	for (auto& p : ui_batch) {
		ProcessPacketEvents(p);

		auto dec = DecodeForList(p);

		if (dec.valid) {
			SegmentView v = GetSegmentView(p);
			std::vector<SegmentInfo> segs;
			ParseAllSegmentsBuffer(v.data, v.len, segs);

			size_t ipcCount = 0;
			std::vector<uint16_t> segOpcodes;
			for (const auto& seg : segs) {
				if (seg.hasIpc) {
					ipcCount++;
					segOpcodes.push_back(seg.opcode);
					uint32_t payloadSize = seg.size > 0x20 ? seg.size - 0x20 : 0;
					UpdateOpcodeAnalytics(p, seg.opcode, dec.connType, true, seg.type,
						payloadSize);
				}
				else {
					UpdateOpcodeAnalytics(p, 0, dec.connType, false, seg.type, 0);
				}
			}

			if (ipcCount > 1) {
				MultiSegmentPacket msp;
				msp.packetIndex = s_packetIndex;
				msp.segmentCount = (uint32_t)ipcCount;
				msp.opcodes = segOpcodes;
				msp.timestamp = p.ts;
				if (g_multiSegmentPackets.size() < 1000) {
					g_multiSegmentPackets.push_back(msp);
				}
			}

			recentOpcodes.push_back(dec.opcode);
			if (recentOpcodes.size() > 100)
				recentOpcodes.erase(recentOpcodes.begin());
			DetectPatterns(recentOpcodes);
			UpdatePacketCorrelation(dec.opcode, p.outgoing, p);
			for (const auto& op : dec.opcodes) {
				if (op != dec.opcode)
					UpdatePacketCorrelation(op, p.outgoing, p);
			}
		}

		s_packetIndex++;
		display.push_back(std::move(p));
	}

	if (display.size() > 100000)
		display.erase(display.begin(), display.begin() + (display.size() - 100000));

	DrawAnalyticsDashboard();

	DrawPacketListAndDetails(display);

	if (auto stat = PacketDecoding::GetSizeMismatchStat(); stat.failures) {
		ImGui::TextDisabled("Decode size mismatches: %llu / %llu",
			(unsigned long long)stat.failures,
			(unsigned long long)stat.attempts);
	}
}

void PacketCapture::DrawImGuiSimple() {
	ImGui::Begin("Network Monitor");
	DrawImGuiEmbedded();
	ImGui::End();

	g_jsonViewer.Render();
}

void PacketCapture::DrawImGuiSimple(bool* p_open) {
	if (ImGui::Begin("Network Monitor", p_open)) {
		DrawImGuiEmbedded();
	}
	ImGui::End();

	g_jsonViewer.Render();
}

namespace {
	static std::string Hex(const uint8_t* d, size_t n) {
		static const char* k = "0123456789ABCDEF";
		std::string s;
		s.resize(n * 2);
		for (size_t i = 0; i < n; ++i) {
			s[2 * i] = k[(d[i] >> 4) & 0xF];
			s[2 * i + 1] = k[d[i] & 0xF];
		}
		return s;
	}

	static void EnsureExportDir() {
		std::error_code ec;
		std::filesystem::create_directories("exports", ec);
	}

	static std::string GeneratePacketJson(const HookPacket& hp) {
		ParsedPacket P = ParsePacket(hp);
		uint16_t resolvedConn = ResolveConnType(hp, P);
		SegmentView v = GetSegmentView(hp, true);
		std::vector<SegmentInfo> segs;
		ParseAllSegmentsBuffer(v.data, v.len, segs);

		nlohmann::json root;

		root["connectionId"] = hp.connection_id;
		root["direction"] = hp.outgoing ? "SEND" : "RECV";
		auto tt = std::chrono::system_clock::to_time_t(hp.ts);
		char tbuf[64]{};
		std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", std::localtime(&tt));
		root["captureTime"] = tbuf;

		nlohmann::json header;
		header["magic"] = [&]() {
			std::ostringstream os;
			os << "0x" << std::hex << std::setw(16) << std::setfill('0') << P.magic0
				<< " 0x" << std::setw(16) << P.magic1;
			return os.str();
			}();
		header["size"] = P.size;
		header["timestamp"] = P.timestamp;
		header["connectionType"] = P.connType;
		header["connectionTypeName"] = [&]() -> std::string {
			switch (P.connType) {
			case 0:
				return "Zone";
			case 1:
				return "Chat";
			case 2:
				return "Lobby";
			default:
				return "Unknown";
			}
			}();
		header["segmentCount"] = P.segCount;
		header["isCompressed"] = P.isCompressed != 0;
		header["inflated"] = v.inflated;
		header["unknown20"] = P.unknown20;
		header["unknown24"] = P.unknown24;
		root["header"] = header;

		nlohmann::json segments = nlohmann::json::array();
		EnsurePacketRegistry();
		auto& reg = PacketDecoding::PacketDecoderRegistry::Instance();

		for (size_t i = 0; i < segs.size(); ++i) {
			const auto& s = segs[i];
			nlohmann::json seg;

			seg["index"] = i;
			seg["offset"] = s.offset;
			seg["size"] = s.size;
			seg["type"] = s.type;
			seg["typeName"] = SegTypeName(s.type);
			seg["sourceActor"] = [&]() {
				std::ostringstream os;
				os << "0x" << std::hex << std::setw(8) << std::setfill('0') << s.source
					<< " (" << std::dec << s.source << ")";
				return os.str();
				}();
			seg["targetActor"] = [&]() {
				std::ostringstream os;
				os << "0x" << std::hex << std::setw(8) << std::setfill('0') << s.target
					<< " (" << std::dec << s.target << ")";
				return os.str();
				}();

			if (s.hasIpc) {
				nlohmann::json ipc;
				ipc["opcode"] = [&]() {
					std::ostringstream os;
					os << "0x" << std::hex << std::uppercase << std::setw(4)
						<< std::setfill('0') << s.opcode;
					return os.str();
					}();

				const char* opcodeName =
					LookupOpcodeName(s.opcode, hp.outgoing, resolvedConn);
				ipc["opcodeName"] =
					(opcodeName && opcodeName[0] != '?') ? opcodeName : "Unknown";
				ipc["serverId"] = s.serverId;
				ipc["timestamp"] = s.ipcTimestamp;

				const uint8_t* payloadPtr = v.data + s.offset + 0x20;
				size_t payloadLen = (s.size > 0x20) ? (s.size - 0x20) : 0;

				nlohmann::json decodedPayload;
				bool hasDecoded = false;

				reg.TryDecode(resolvedConn != 0xFFFF ? resolvedConn : 1, hp.outgoing,
					s.opcode, payloadPtr, payloadLen,
					[&](const char* key, const std::string& value) {
						std::string keyStr(key);
						size_t dotPos = keyStr.find('.');
						if (dotPos != std::string::npos) {
							std::string parent = keyStr.substr(0, dotPos);
							std::string child = keyStr.substr(dotPos + 1);
							if (!decodedPayload.contains(parent)) {
								decodedPayload[parent] = nlohmann::json::object();
							}
							decodedPayload[parent][child] = value;
						}
						else {
							decodedPayload[key] = value;
						}
						hasDecoded = true;
					});

				if (hasDecoded) {
					ipc["decodedPayload"] = decodedPayload;
				}

				if (payloadLen > 0) {
					std::ostringstream hexStream;
					hexStream << std::hex << std::uppercase << std::setfill('0');
					for (size_t j = 0; j < payloadLen; ++j) {
						hexStream << std::setw(2) << static_cast<int>(payloadPtr[j]);
					}
					ipc["payloadHex"] = hexStream.str();
					ipc["payloadSize"] = payloadLen;
				}

				seg["ipc"] = ipc;
			}

			segments.push_back(seg);
		}
		root["segments"] = segments;

		root["rawHex"] = Hex(hp.buf.data(), hp.len);
		root["rawLength"] = hp.len;

		return root.dump(2);
	}

	static bool ExportToJsonAs(const HookPacket& hp, const std::string& filepath) {
		try {
			std::filesystem::path p(filepath);
			if (p.has_parent_path()) {
				std::error_code ec;
				std::filesystem::create_directories(p.parent_path(), ec);
			}

			std::string jsonStr = GeneratePacketJson(hp);
			std::ofstream out(filepath);
			if (!out)
				return false;
			out << jsonStr;
			return true;
		}
		catch (const std::exception& e) {
			Logger::Instance().Error("[NetworkMonitor] Export JSON failed: " +
				std::string(e.what()));
			return false;
		}
	}

	static bool ExportToPcapAs(const HookPacket& hp, const std::string& filepath) {
		namespace fs = std::filesystem;
		try {
			fs::path p(filepath);
			if (p.has_parent_path()) {
				std::error_code ec;
				fs::create_directories(p.parent_path(), ec);
			}

			auto& flow = GetFlow(hp.connection_id);

			const std::vector<uint8_t> payload(hp.buf.begin(), hp.buf.begin() + hp.len);
			const uint16_t udp_payload_len = static_cast<uint16_t>(payload.size());
			const uint16_t udp_len = static_cast<uint16_t>(8 + udp_payload_len);
			const uint16_t ip_len = static_cast<uint16_t>(20 + udp_len);

			std::vector<uint8_t> frame;
			frame.resize(14 + ip_len);
			uint8_t* eth = frame.data();
			uint8_t* ip = eth + 14;
			uint8_t* udp = ip + 20;

			const uint8_t macClient[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
			const uint8_t macServer[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
			const bool clientToServer = hp.outgoing;
			const uint8_t* srcMac = clientToServer ? macClient : macServer;
			const uint8_t* dstMac = clientToServer ? macServer : macClient;
			std::memcpy(eth + 0, dstMac, 6);
			std::memcpy(eth + 6, srcMac, 6);
			eth[12] = 0x08;
			eth[13] = 0x00;

			std::memset(ip, 0, 20);
			ip[0] = 0x45;
			ip[1] = 0x00;
			ip[2] = uint8_t(ip_len >> 8);
			ip[3] = uint8_t(ip_len & 0xFF);
			uint16_t ipId = flow.nextIpId++;
			ip[4] = uint8_t(ipId >> 8);
			ip[5] = uint8_t(ipId & 0xFF);
			ip[6] = 0x40;
			ip[7] = 0x00;
			ip[8] = 64;
			ip[9] = 17;

			const uint8_t* srcIp = clientToServer ? flow.clientIp : flow.serverIp;
			const uint8_t* dstIp = clientToServer ? flow.serverIp : flow.clientIp;
			std::memcpy(ip + 12, srcIp, 4);
			std::memcpy(ip + 16, dstIp, 4);

			uint16_t ipCsum = IpHeaderChecksum(ip, 20);
			ip[10] = uint8_t(ipCsum >> 8);
			ip[11] = uint8_t(ipCsum & 0xFF);

			uint16_t srcPort = clientToServer ? flow.clientPort : flow.serverPort;
			uint16_t dstPort = clientToServer ? flow.serverPort : flow.clientPort;
			udp[0] = uint8_t(srcPort >> 8);
			udp[1] = uint8_t(srcPort & 0xFF);
			udp[2] = uint8_t(dstPort >> 8);
			udp[3] = uint8_t(dstPort & 0xFF);
			udp[4] = uint8_t(udp_len >> 8);
			udp[5] = uint8_t(udp_len & 0xFF);
			udp[6] = 0;
			udp[7] = 0;

			if (!payload.empty())
				std::memcpy(udp + 8, payload.data(), payload.size());

			uint16_t udpCsum = UdpChecksumIPv4(srcIp, dstIp, udp, udp_len);
			udp[6] = uint8_t(udpCsum >> 8);
			udp[7] = uint8_t(udpCsum & 0xFF);

			std::ofstream f(p, std::ios::binary);
			if (!f)
				return false;

			struct PcapGlobalHeader {
				uint32_t magic = 0xA1B2C3D4;
				uint16_t vmaj = 2;
				uint16_t vmin = 4;
				int32_t thiszone = 0;
				uint32_t sigfigs = 0;
				uint32_t snaplen = 0x00040000;
				uint32_t network = 1;
			} gh;
			f.write(reinterpret_cast<const char*>(&gh), sizeof(gh));

			auto tp = std::chrono::time_point_cast<std::chrono::microseconds>(hp.ts);
			uint64_t micros = static_cast<uint64_t>(tp.time_since_epoch().count());
			uint32_t ts_sec = static_cast<uint32_t>(micros / 1000000ULL);
			uint32_t ts_usec = static_cast<uint32_t>(micros % 1000000ULL);
			struct PcapPacketHeader {
				uint32_t ts_sec;
				uint32_t ts_usec;
				uint32_t incl_len;
				uint32_t orig_len;
			} ph{ ts_sec, ts_usec, static_cast<uint32_t>(frame.size()),
				 static_cast<uint32_t>(frame.size()) };
			f.write(reinterpret_cast<const char*>(&ph), sizeof(ph));
			f.write(reinterpret_cast<const char*>(frame.data()), frame.size());
			return true;
		}
		catch (...) {
			return false;
		}
	}

	static bool ExportFilteredToPcapAs(const std::vector<HookPacket>& packets,
		const std::string& filepath) {
		namespace fs = std::filesystem;
		if (packets.empty())
			return false;

		try {
			fs::path p(filepath);
			if (p.has_parent_path()) {
				std::error_code ec;
				fs::create_directories(p.parent_path(), ec);
			}

			std::ofstream f(p, std::ios::binary);
			if (!f)
				return false;

			struct PcapGlobalHeader {
				uint32_t magic = 0xA1B2C3D4;
				uint16_t vmaj = 2;
				uint16_t vmin = 4;
				int32_t thiszone = 0;
				uint32_t sigfigs = 0;
				uint32_t snaplen = 0x00040000;
				uint32_t network = 1;
			} gh;
			f.write(reinterpret_cast<const char*>(&gh), sizeof(gh));

			for (const auto& hp : packets) {
				auto& flow = GetFlow(hp.connection_id);

				const std::vector<uint8_t> payload(hp.buf.begin(),
					hp.buf.begin() + hp.len);
				const uint16_t udp_payload_len = static_cast<uint16_t>(payload.size());
				const uint16_t udp_len = static_cast<uint16_t>(8 + udp_payload_len);
				const uint16_t ip_len = static_cast<uint16_t>(20 + udp_len);

				std::vector<uint8_t> frame;
				frame.resize(14 + ip_len);
				uint8_t* eth = frame.data();
				uint8_t* ip = eth + 14;
				uint8_t* udp = ip + 20;

				const uint8_t macClient[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
				const uint8_t macServer[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
				const bool clientToServer = hp.outgoing;
				const uint8_t* srcMac = clientToServer ? macClient : macServer;
				const uint8_t* dstMac = clientToServer ? macServer : macClient;
				std::memcpy(eth + 0, dstMac, 6);
				std::memcpy(eth + 6, srcMac, 6);
				eth[12] = 0x08;
				eth[13] = 0x00;

				std::memset(ip, 0, 20);
				ip[0] = 0x45;
				ip[2] = uint8_t(ip_len >> 8);
				ip[3] = uint8_t(ip_len & 0xFF);
				uint16_t ipId = flow.nextIpId++;
				ip[4] = uint8_t(ipId >> 8);
				ip[5] = uint8_t(ipId & 0xFF);
				ip[6] = 0x40;
				ip[8] = 64;
				ip[9] = 17;

				const uint8_t* srcIp = clientToServer ? flow.clientIp : flow.serverIp;
				const uint8_t* dstIp = clientToServer ? flow.serverIp : flow.clientIp;
				std::memcpy(ip + 12, srcIp, 4);
				std::memcpy(ip + 16, dstIp, 4);

				uint16_t ipCsum = IpHeaderChecksum(ip, 20);
				ip[10] = uint8_t(ipCsum >> 8);
				ip[11] = uint8_t(ipCsum & 0xFF);

				uint16_t srcPort = clientToServer ? flow.clientPort : flow.serverPort;
				uint16_t dstPort = clientToServer ? flow.serverPort : flow.clientPort;
				udp[0] = uint8_t(srcPort >> 8);
				udp[1] = uint8_t(srcPort & 0xFF);
				udp[2] = uint8_t(dstPort >> 8);
				udp[3] = uint8_t(dstPort & 0xFF);
				udp[4] = uint8_t(udp_len >> 8);
				udp[5] = uint8_t(udp_len & 0xFF);
				udp[6] = 0;
				udp[7] = 0;

				if (!payload.empty())
					std::memcpy(udp + 8, payload.data(), payload.size());

				uint16_t udpCsum = UdpChecksumIPv4(srcIp, dstIp, udp, udp_len);
				udp[6] = uint8_t(udpCsum >> 8);
				udp[7] = uint8_t(udpCsum & 0xFF);

				auto tp = std::chrono::time_point_cast<std::chrono::microseconds>(hp.ts);
				uint64_t micros = static_cast<uint64_t>(tp.time_since_epoch().count());
				uint32_t ts_sec = static_cast<uint32_t>(micros / 1000000ULL);
				uint32_t ts_usec = static_cast<uint32_t>(micros % 1000000ULL);
				struct PcapPacketHeader {
					uint32_t ts_sec;
					uint32_t ts_usec;
					uint32_t incl_len;
					uint32_t orig_len;
				} ph{ ts_sec, ts_usec, static_cast<uint32_t>(frame.size()),
					 static_cast<uint32_t>(frame.size()) };
				f.write(reinterpret_cast<const char*>(&ph), sizeof(ph));
				f.write(reinterpret_cast<const char*>(frame.data()), frame.size());
			}
			return true;
		}
		catch (...) {
			return false;
		}
	}

	static bool ExportFilteredToJsonAs(const std::vector<HookPacket>& packets,
		const std::string& filepath) {
		namespace fs = std::filesystem;
		if (packets.empty())
			return false;

		try {
			fs::path p(filepath);
			if (p.has_parent_path()) {
				std::error_code ec;
				fs::create_directories(p.parent_path(), ec);
			}

			nlohmann::json root;
			root["exportType"] = "filtered_packets";
			root["exportTime"] =
				std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
			root["packetCount"] = packets.size();

			nlohmann::json packetsArray = nlohmann::json::array();
			for (const auto& hp : packets) {
				nlohmann::json pkt;
				pkt["direction"] = hp.outgoing ? "SEND" : "RECV";
				pkt["connectionId"] = hp.connection_id;
				pkt["length"] = hp.len;

				auto tt = std::chrono::system_clock::to_time_t(hp.ts);
				char tbuf[64]{};
				std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S",
					std::localtime(&tt));
				pkt["timestamp"] = tbuf;

				ParsedPacket P = ParsePacket(hp);
				SegmentView v = GetSegmentView(hp, true);
				std::vector<SegmentInfo> segs;
				ParseAllSegmentsBuffer(v.data, v.len, segs);

				uint16_t resolvedConn = ResolveConnType(hp, P);
				pkt["connectionType"] = resolvedConn;
				pkt["compressed"] = v.compressed;
				pkt["inflated"] = v.inflated;

				nlohmann::json opcodes = nlohmann::json::array();
				for (const auto& s : segs) {
					if (s.hasIpc) {
						nlohmann::json op;
						op["opcode"] = s.opcode;
						char hexBuf[16];
						std::snprintf(hexBuf, sizeof(hexBuf), "0x%04X", s.opcode);
						op["opcodeHex"] = hexBuf;
						op["name"] = LookupOpcodeName(s.opcode, hp.outgoing, resolvedConn);
						opcodes.push_back(op);
					}
				}
				pkt["opcodes"] = opcodes;

				std::ostringstream hexStream;
				hexStream << std::hex << std::uppercase << std::setfill('0');
				for (size_t i = 0; i < hp.len; ++i) {
					hexStream << std::setw(2) << static_cast<int>(hp.buf[i]);
				}
				pkt["rawHex"] = hexStream.str();

				packetsArray.push_back(pkt);
			}
			root["packets"] = packetsArray;

			std::ofstream f(p, std::ios::binary);
			if (!f)
				return false;
			f << root.dump(2);
			return true;
		}
		catch (const std::exception& e) {
			Logger::Instance().Error("Filtered JSON export failed: " +
				std::string(e.what()));
			return false;
		}
	}

	static bool ExportSessionSummaryAs(const std::vector<HookPacket>& packets,
		const std::string& filepath) {
		namespace fs = std::filesystem;
		if (packets.empty())
			return false;

		try {
			fs::path p(filepath);
			if (p.has_parent_path()) {
				std::error_code ec;
				fs::create_directories(p.parent_path(), ec);
			}

			std::map<uint16_t, int> sendOpcodeCount;
			std::map<uint16_t, int> recvOpcodeCount;
			int totalSend = 0, totalRecv = 0;
			uint64_t totalBytes = 0;
			std::chrono::system_clock::time_point firstTs, lastTs;
			bool firstPacket = true;

			for (const auto& hp : packets) {
				if (firstPacket) {
					firstTs = lastTs = hp.ts;
					firstPacket = false;
				}
				else {
					if (hp.ts < firstTs)
						firstTs = hp.ts;
					if (hp.ts > lastTs)
						lastTs = hp.ts;
				}

				totalBytes += hp.len;
				if (hp.outgoing)
					totalSend++;
				else
					totalRecv++;

				ParsedPacket P = ParsePacket(hp);
				SegmentView v = GetSegmentView(hp, true);
				std::vector<SegmentInfo> segs;
				ParseAllSegmentsBuffer(v.data, v.len, segs);

				for (const auto& s : segs) {
					if (s.hasIpc) {
						if (hp.outgoing)
							sendOpcodeCount[s.opcode]++;
						else
							recvOpcodeCount[s.opcode]++;
					}
				}
			}

			nlohmann::json root;
			root["sessionSummary"] = true;

			auto exportTime = std::chrono::system_clock::now();
			auto tt = std::chrono::system_clock::to_time_t(exportTime);
			char tbuf[64]{};
			std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", std::localtime(&tt));
			root["exportedAt"] = tbuf;

			auto firstTt = std::chrono::system_clock::to_time_t(firstTs);
			auto lastTt = std::chrono::system_clock::to_time_t(lastTs);
			std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S",
				std::localtime(&firstTt));
			root["sessionStart"] = tbuf;
			std::strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S",
				std::localtime(&lastTt));
			root["sessionEnd"] = tbuf;

			auto duration =
				std::chrono::duration_cast<std::chrono::seconds>(lastTs - firstTs)
				.count();
			root["durationSeconds"] = duration;

			nlohmann::json stats;
			stats["totalPackets"] = packets.size();
			stats["sendPackets"] = totalSend;
			stats["recvPackets"] = totalRecv;
			stats["totalBytes"] = totalBytes;
			stats["uniqueSendOpcodes"] = sendOpcodeCount.size();
			stats["uniqueRecvOpcodes"] = recvOpcodeCount.size();
			root["statistics"] = stats;

			auto sortByCount = [](const std::map<uint16_t, int>& m) {
				std::vector<std::pair<uint16_t, int>> v(m.begin(), m.end());
				std::sort(v.begin(), v.end(), [](const auto& a, const auto& b) {
					return a.second > b.second;
					});
				return v;
				};

			nlohmann::json sendOpcodes = nlohmann::json::array();
			for (const auto& [op, cnt] : sortByCount(sendOpcodeCount)) {
				nlohmann::json entry;
				char hexBuf[16];
				std::snprintf(hexBuf, sizeof(hexBuf), "0x%04X", op);
				entry["opcode"] = hexBuf;
				entry["name"] = LookupOpcodeName(op, true, Net::ConnectionType::Zone);
				entry["count"] = cnt;
				sendOpcodes.push_back(entry);
			}
			root["sendOpcodes"] = sendOpcodes;

			nlohmann::json recvOpcodes = nlohmann::json::array();
			for (const auto& [op, cnt] : sortByCount(recvOpcodeCount)) {
				nlohmann::json entry;
				char hexBuf[16];
				std::snprintf(hexBuf, sizeof(hexBuf), "0x%04X", op);
				entry["opcode"] = hexBuf;
				entry["name"] = LookupOpcodeName(op, false, Net::ConnectionType::Zone);
				entry["count"] = cnt;
				recvOpcodes.push_back(entry);
			}
			root["recvOpcodes"] = recvOpcodes;

			auto starred = GetStarredOpcodesList();
			nlohmann::json starredJson = nlohmann::json::array();
			for (uint16_t op : starred) {
				char hexBuf[16];
				std::snprintf(hexBuf, sizeof(hexBuf), "0x%04X", op);
				starredJson.push_back(hexBuf);
			}
			root["starredOpcodes"] = starredJson;

			std::ofstream f(p, std::ios::binary);
			if (!f)
				return false;
			f << root.dump(2);
			return true;
		}
		catch (const std::exception& e) {
			Logger::Instance().Error("Session summary export failed: " +
				std::string(e.what()));
			return false;
		}
	}

	static bool ExportToFFXIVMonXmlAs(const std::vector<HookPacket>& packets,
		const std::string& filepath) {
		if (packets.empty())
			return false;

		try {
			std::filesystem::path p(filepath);
			std::filesystem::create_directories(p.parent_path());

			std::ofstream f(p, std::ios::binary);
			if (!f)
				return false;

			f << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
			f << "<Capture xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
				"xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\n";
			f << "  <UsingSystemTime>true</UsingSystemTime>\n";
			f << "  <Version>-1</Version>\n";
			f << "  <LastSavedAppCommit>SapphireHook</LastSavedAppCommit>\n";
			f << "  <ServerCommitHash></ServerCommitHash>\n";
			f << "  <Packets>\n";

			for (const auto& hp : packets) {
				ParsedPacket parsed;
				if (hp.len >= 28) {
					std::memcpy(&parsed.magic0, hp.buf.data() + 0, 8);
					std::memcpy(&parsed.magic1, hp.buf.data() + 8, 8);
					std::memcpy(&parsed.timestamp, hp.buf.data() + 16, 8);
					std::memcpy(&parsed.size, hp.buf.data() + 24, 4);
					std::memcpy(&parsed.connType, hp.buf.data() + 28, 2);
					std::memcpy(&parsed.segCount, hp.buf.data() + 30, 2);
					parsed.hdr_ok = true;
				}

				uint16_t opcode = 0;
				uint32_t sourceActor = 0;
				uint32_t targetActor = 0;
				{
					SegmentView v = GetSegmentView(hp, true);
					std::vector<SegmentInfo> segs;
					ParseAllSegmentsBuffer(v.data, v.len, segs);
					for (const auto& s : segs) {
						if (!s.hasIpc)
							continue;
						opcode = s.opcode;
						sourceActor = s.source;
						targetActor = s.target;
						break;
					}
				}

				auto tt = std::chrono::system_clock::to_time_t(hp.ts);
				auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
					hp.ts.time_since_epoch())
					.count();
				std::tm tm_buf;
				localtime_s(&tm_buf, &tt);
				char timeBuf[64];
				std::strftime(timeBuf, sizeof(timeBuf), "%m/%d/%Y %H:%M:%S", &tm_buf);

				const char* direction = hp.outgoing ? "C" : "S";

				char opcodeBuf[8];
				std::snprintf(opcodeBuf, sizeof(opcodeBuf), "%04X", opcode);

				std::string dataHex;
				dataHex.reserve(hp.len * 2);
				for (size_t i = 0; i < hp.len; ++i) {
					char hexByte[4];
					std::snprintf(hexByte, sizeof(hexByte), "%02X", hp.buf[i]);
					dataHex += hexByte;
				}

				int connTypeInt = 1;
				if (parsed.hdr_ok) {
					switch (parsed.connType) {
					case 1:
						connTypeInt = 1;
						break;
					case 2:
						connTypeInt = 2;
						break;
					case 3:
						connTypeInt = 0;
						break;
					default:
						connTypeInt = 1;
						break;
					}
				}

				char routeIdBuf[32];
				std::snprintf(routeIdBuf, sizeof(routeIdBuf), "%u",
					hp.outgoing ? targetActor : sourceActor);

				uint32_t unixTime = static_cast<uint32_t>(
					std::chrono::duration_cast<std::chrono::seconds>(
						hp.ts.time_since_epoch())
					.count());
				int64_t systemMsTime = ms;

				f << "    <PacketEntry>\n";
				f << "      <IsDecrypted>true</IsDecrypted>\n";
				f << "      <Direction>" << direction << "</Direction>\n";
				f << "      <Connection>"
					<< (connTypeInt == 0 ? "Lobby" : (connTypeInt == 1 ? "Zone" : "Chat"))
					<< "</Connection>\n";
				f << "      <Category>0</Category>\n";
				f << "      <Message>" << opcodeBuf << "</Message>\n";
				f << "      <Timestamp>" << timeBuf << "</Timestamp>\n";
				f << "      <RouteID>" << routeIdBuf << "</RouteID>\n";
				f << "      <PacketUnixTime>" << unixTime << "</PacketUnixTime>\n";
				f << "      <SystemMsTime>" << systemMsTime << "</SystemMsTime>\n";
				f << "      <HeaderEpoch>" << unixTime << "</HeaderEpoch>\n";
				f << "      <Set>" << connTypeInt << "</Set>\n";
				f << "      <Data />\n";
				f << "      <DataString>" << dataHex << "</DataString>\n";
				f << "    </PacketEntry>\n";
			}

			f << "  </Packets>\n";
			f << "</Capture>\n";

			return true;
		}
		catch (const std::exception& e) {
			Logger::Instance().Error("FFXIVMon XML export failed: " +
				std::string(e.what()));
			return false;
		}
	}
}