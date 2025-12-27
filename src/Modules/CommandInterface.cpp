#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#include "../Analysis/PatternScanner.h"
#include "../Core/PacketInjector.h"
#include "../Logger/Logger.h"

#include "../Modules/CommandInterface.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <thread>
#include <iomanip>
#include <tlhelp32.h>
#include <Psapi.h>
#include <Windows.h>
#include <MinHook.h>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Psapi.lib")

// --- SEH helpers (no C++ objects -> no unwinding) ---
extern "C" __declspec(noinline) uintptr_t SH_SafeReadPtr(uintptr_t addr)
{
	__try { return *reinterpret_cast<uintptr_t*>(addr); }
	__except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

extern "C" __declspec(noinline) bool SH_SafeCall_Send(void* fn, void* thisPtr, uint8_t* data, size_t size)
{
	__try {
		using Fn = bool(__fastcall*)(void*, uint8_t*, size_t);
		return reinterpret_cast<Fn>(fn)(thisPtr, data, size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
}

namespace SapphireHook { uint32_t GetLearnedLocalActorId(); }

namespace {
	struct Position3 {
		float x, y, z;
	};

	static Position3* GetLocalPlayerPosition()
	{
		return nullptr;
	}

	static uint32_t GetLocalEntityId()
	{
		using SapphireHook::Logger;
		uint32_t learned = SapphireHook::GetLearnedLocalActorId();
		if (learned != 0 && learned != 0xFFFFFFFF)
		{
			return learned;
		}
		static uint32_t s_id = 0x200001;
		static bool s_inited = false;
		if (!s_inited)
		{
			s_inited = true;
			if (const char* v = std::getenv("SAPPHIRE_ENTITYID"))
			{
				if (std::strlen(v) > 2 && (v[0] == '0') && (v[1] == 'x' || v[1] == 'X'))
				{
					s_id = static_cast<uint32_t>(std::strtoul(v + 2, nullptr, 16));
				}
				else
				{
					s_id = static_cast<uint32_t>(std::strtoul(v, nullptr, 10));
				}
			}
			Logger::Instance().InformationF("[CommandInterface] LocalEntityId: 0x%X (%u)", s_id, s_id);
		}
		return s_id;
	}

	// Inbound socket observation (recv/WSARecv detours) and retry loop
	static std::unordered_set<UINT_PTR> s_seenSockets;
	static std::mutex s_seenMx;
	static std::atomic<bool> s_hooksInstalled{ false };
	static std::atomic<bool> s_mhInitialized{ false };
	static std::atomic<bool> s_retryActive{ false };
	static std::thread s_retryThread;

	using Recv_t = int (WSAAPI*)(SOCKET, char*, int, int);
	using WSARecv_t = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

	static Recv_t    s_origRecv = nullptr;
	static WSARecv_t s_origWSARecv = nullptr;

	static void RecordSocket(SOCKET s)
	{
		using SapphireHook::Logger;
		const UINT_PTR us = static_cast<UINT_PTR>(s);
		{
			std::lock_guard<std::mutex> lk(s_seenMx);
			s_seenSockets.insert(us);
		}

		const UINT_PTR invalid = static_cast<UINT_PTR>(INVALID_SOCKET);
		if (SapphireHook::PacketInjector::s_zoneSocket == invalid) {
			SapphireHook::PacketInjector::s_zoneSocket = us;
			Logger::Instance().InformationF("[CommandInterface] Learned zone socket via inbound: 0x%llx",
				static_cast<unsigned long long>(us));
		}
		else if (SapphireHook::PacketInjector::s_chatSocket == invalid &&
			SapphireHook::PacketInjector::s_zoneSocket != us) {
			SapphireHook::PacketInjector::s_chatSocket = us;
			Logger::Instance().InformationF("[CommandInterface] Learned chat socket via inbound: 0x%llx",
				static_cast<unsigned long long>(us));
		}
	}

	static int WSAAPI Detour_recv(SOCKET s, char* buf, int len, int flags)
	{
		RecordSocket(s);
		return s_origRecv ? s_origRecv(s, buf, len, flags) : SOCKET_ERROR;
	}

	static int WSAAPI Detour_WSARecv(SOCKET s,
		LPWSABUF lpBuffers,
		DWORD dwBufferCount,
		LPDWORD lpNumberOfBytesRecvd,
		LPDWORD lpFlags,
		LPWSAOVERLAPPED lpOverlapped, // fixed: LPWSAOVERLAPPED (not LPDWSAOVERLAPPED)
		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
	{
		RecordSocket(s);
		return s_origWSARecv
			? s_origWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine)
			: SOCKET_ERROR;
	}

	static void InstallInboundSocketHooks()
	{
		using SapphireHook::Logger;
		if (s_hooksInstalled.load()) return;

		if (!s_mhInitialized.load()) {
			const MH_STATUS st = MH_Initialize();
			if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED) {
				Logger::Instance().ErrorF("[CommandInterface] MinHook init failed: %d", st);
				return;
			}
			s_mhInitialized.store(true);
		}

		HMODULE hWs2 = GetModuleHandleW(L"Ws2_32.dll");
		if (!hWs2) hWs2 = LoadLibraryW(L"Ws2_32.dll");
		if (!hWs2) {
			Logger::Instance().Error("[CommandInterface] Ws2_32.dll not loaded; cannot install inbound hooks");
			return;
		}

		FARPROC pRecv = GetProcAddress(hWs2, "recv");
		FARPROC pWSARecv = GetProcAddress(hWs2, "WSARecv");

		if (pRecv) {
			if (MH_CreateHook(pRecv, reinterpret_cast<LPVOID>(&Detour_recv),
				reinterpret_cast<LPVOID*>(&s_origRecv)) == MH_OK)
			{
				if (MH_EnableHook(pRecv) == MH_OK) {
					Logger::Instance().Information("[CommandInterface] recv() detour installed");
				}
			}
		}
		else {
			Logger::Instance().Error("[CommandInterface] GetProcAddress(recv) failed");
		}

		if (pWSARecv) {
			if (MH_CreateHook(pWSARecv, reinterpret_cast<LPVOID>(&Detour_WSARecv),
				reinterpret_cast<LPVOID*>(&s_origWSARecv)) == MH_OK)
			{
				if (MH_EnableHook(pWSARecv) == MH_OK) {
					Logger::Instance().Information("[CommandInterface] WSARecv() detour installed");
				}
			}
		}
		else {
			Logger::Instance().Error("[CommandInterface] GetProcAddress(WSARecv) failed");
		}

		s_hooksInstalled.store(true);
	}

	static void StartSocketRetryLoop()
	{
		using SapphireHook::Logger;
		if (s_retryActive.exchange(true)) return;

		s_retryThread = std::thread([]() {
			const UINT_PTR invalid = static_cast<UINT_PTR>(INVALID_SOCKET);

			// Single info at start to avoid per-second spam
			Logger::Instance().Information("[CommandInterface] Waiting for sockets (quiet retry loop)...");

			// Track last reported values to log only on change
			UINT_PTR lastZoneLogged = invalid;
			UINT_PTR lastChatLogged = invalid;

			for (int i = 0; i < 15; ++i) { // ~15 seconds total
				Sleep(1000);

				UINT_PTR zone = SapphireHook::PacketInjector::s_zoneSocket;
				UINT_PTR chat = SapphireHook::PacketInjector::s_chatSocket;

				// Log only when the visible state changes (and it’s not the initial invalid state)
				bool stateChanged = (zone != lastZoneLogged) || (chat != lastChatLogged);
				if (stateChanged && (zone != invalid || chat != invalid)) {
					Logger::Instance().InformationF(
						"[CommandInterface] Socket update: zone=0x%llx chat=0x%llx",
						static_cast<unsigned long long>(zone),
						static_cast<unsigned long long>(chat));
					lastZoneLogged = zone;
					lastChatLogged = chat;
				}
				else {
					// Throttle periodic noise to Debug and only every 5 attempts
					if (((i + 1) % 5) == 0) {
						Logger::Instance().DebugF(
							"[CommandInterface] Retry %d: zone=0x%llx chat=0x%llx",
							i + 1,
							static_cast<unsigned long long>(zone),
							static_cast<unsigned long long>(chat));
					}
				}

				if (zone != invalid && chat != invalid && zone != chat) {
					Logger::Instance().Information("[CommandInterface] Sockets learned successfully");
					break;
				}

				// If we have seen inbound sockets, try to assign them
				{
					std::lock_guard<std::mutex> lk(s_seenMx);
					for (auto s : s_seenSockets) {
						if (SapphireHook::PacketInjector::s_zoneSocket == invalid) {
							SapphireHook::PacketInjector::s_zoneSocket = s;
						}
						else if (SapphireHook::PacketInjector::s_chatSocket == invalid &&
							SapphireHook::PacketInjector::s_zoneSocket != s) {
							SapphireHook::PacketInjector::s_chatSocket = s;
						}
					}
				}

				// Re-check success after assignment
				zone = SapphireHook::PacketInjector::s_zoneSocket;
				chat = SapphireHook::PacketInjector::s_chatSocket;
				if (zone != invalid && chat != invalid && zone != chat) {
					Logger::Instance().Information("[CommandInterface] Sockets learned successfully");
					break;
				}
			}

			// Final note if we didn’t fully learn both sockets
			const UINT_PTR z = SapphireHook::PacketInjector::s_zoneSocket;
			const UINT_PTR c = SapphireHook::PacketInjector::s_chatSocket;
			if (z == invalid || c == invalid || z == c) {
				Logger::Instance().Warning("[CommandInterface] Socket learning timed out; inbound hooks will continue silently");
			}

			s_retryActive.store(false);
			});
		s_retryThread.detach();
	}
} // anonymous

namespace SapphireHook {
	struct FFXIVARR_PACKET_HEADER
	{
		uint64_t unknown_0;
		uint64_t unknown_8;
		uint64_t timestamp;
		uint32_t size;
		uint16_t connectionType;
		uint16_t count;
		uint8_t unknown_20;
		uint8_t isCompressed;
		uint32_t unknown_24;
	};

	struct FFXIVARR_PACKET_SEGMENT_HEADER
	{
		uint32_t size;
		uint32_t source_actor;
		uint32_t target_actor;
		uint16_t type;
		uint16_t padding;
	};

	struct FFXIVARR_IPC_HEADER
	{
		uint16_t reserved;
		uint16_t type;
		uint16_t padding;
		uint16_t serverId;
		uint32_t timestamp;
		uint32_t padding1;
	};

	enum GmCommandId : uint32_t
	{
		Pos = 0x0000,
		Lv = 0x0001,
		Race = 0x0002,
		Tribe = 0x0003,
		Sex = 0x0004,
		Time = 0x0005,
		Weather = 0x0006,
		Call = 0x0007,
		Inspect = 0x0008,
		Speed = 0x0009,
		Invis = 0x000D,
		Raise = 0x0010,
		Kill = 0x000E,
		Icon = 0x0012,
		Hp = 0x0064,
		Mp = 0x0065,
		Tp = 0x0066,
		Gp = 0x0067,
		Exp = 0x0068,
		Inv = 0x006A,
		Orchestrion = 0x0074,
		Item = 0x00C8,
		Gil = 0x00C9,
		Collect = 0x00CA,
		QuestAccept = 0x012C,
		QuestCancel = 0x012D,
		QuestComplete = 0x012E,
		QuestIncomplete = 0x012F,
		QuestSequence = 0x0130,
		QuestInspect = 0x0131,
		GC = 0x0154,
		GCRank = 0x0155,
		Aetheryte = 0x015E,
		Wireframe = 0x0226,
		Teri = 0x0258,
		Kick = 0x025C,
		TeriInfo = 0x025D,
		Jump = 0x025E,
		JumpNpc = 0x025F,
	};

	struct GmCommandPacket {
		uint32_t Id;
		uint32_t Arg0;
		uint32_t Arg1;
		uint32_t Arg2;
		uint32_t Arg3;
		uint64_t Target;
	};

	struct CompleteGMPacket {
		FFXIVARR_PACKET_HEADER header;
		FFXIVARR_PACKET_SEGMENT_HEADER segmentHeader;
		FFXIVARR_IPC_HEADER ipcHeader;
		GmCommandPacket gmData;
	};

	struct ChatPacketData {
		uint32_t clientTimeValue;
		uint32_t originEntityId;
		float pos[3];
		float dir;
		uint8_t chatType;
		char message[1024];
	};

	struct CompleteChatPacket {
		FFXIVARR_PACKET_HEADER header;
		FFXIVARR_PACKET_SEGMENT_HEADER segmentHeader;
		FFXIVARR_IPC_HEADER ipcHeader;
		ChatPacketData chatData;
	};

	struct ClientTriggerPacketData {
		uint32_t Id;
		uint32_t Arg0;
		uint32_t Arg1;
		uint32_t Arg2;
		uint32_t Arg3;
		uint64_t Target;
	};

	struct CompleteClientTriggerPacket {
		FFXIVARR_PACKET_HEADER header;
		FFXIVARR_PACKET_SEGMENT_HEADER segmentHeader;
		FFXIVARR_IPC_HEADER ipcHeader;
		ClientTriggerPacketData data;
	};
}

CommandInterface::ChatCommand_t CommandInterface::s_chatCommandFunc = nullptr;
CommandInterface::SendPacket_t CommandInterface::s_sendPacketFunc = nullptr;
CommandInterface::SendPacketMethod_t CommandInterface::s_sendPacketMethod = nullptr;
CommandInterface::GameConnection_t CommandInterface::s_gameConnection = nullptr;
uintptr_t CommandInterface::s_gameConnectionPtr = 0;

bool CommandInterface::Initialize()
{
	using SapphireHook::Logger;

	bool foundCommands = FindCommandFunctions();
	bool foundNetwork = FindNetworkFunctions();
	bool foundConnection = FindGameConnection();

	bool wsaHooked = SapphireHook::PacketInjector::Initialize();

	// Install inbound hooks and start retry loop
	InstallInboundSocketHooks();
	StartSocketRetryLoop();

	if (wsaHooked)
	{
		Logger::Instance().Information("[CommandInterface] WSASend hook installed successfully");

		Logger::Instance().InformationF("[CommandInterface] Initial socket status:");
		Logger::Instance().InformationF("[CommandInterface] - Zone socket: 0x%llx",
			static_cast<unsigned long long>(SapphireHook::PacketInjector::s_zoneSocket));
		Logger::Instance().InformationF("[CommandInterface] - Chat socket: 0x%llx",
			static_cast<unsigned long long>(SapphireHook::PacketInjector::s_chatSocket));

		Sleep(2000);

		Logger::Instance().Information("[CommandInterface] After 2 seconds:");
		Logger::Instance().InformationF("[CommandInterface] - Zone socket: 0x%llx",
			static_cast<unsigned long long>(SapphireHook::PacketInjector::s_zoneSocket));
		Logger::Instance().InformationF("[CommandInterface] - Chat socket: 0x%llx",
			static_cast<unsigned long long>(SapphireHook::PacketInjector::s_chatSocket));
	}

	if (foundNetwork && s_sendPacketFunc != nullptr)
	{
		auto addr = reinterpret_cast<uintptr_t>(s_sendPacketFunc);
		TryResolveNetworkThisFromSend(addr);
	}

	Logger::Instance().InformationF("[CommandInterface] Initialize: Commands=%s, Network=%s, Connection=%s, WSAHook=%s",
		foundCommands ? "OK" : "FAIL",
		foundNetwork ? "OK" : "FAIL",
		foundConnection ? "OK" : "FAIL",
		wsaHooked ? "OK" : "FAIL");

	return foundCommands || foundNetwork || foundConnection || wsaHooked || s_hooksInstalled.load();
}

static inline uintptr_t RipTarget(uintptr_t instr, int relOffset)
{
	int32_t disp = *reinterpret_cast<int32_t*>(instr + relOffset);
	uintptr_t next = instr + relOffset + 4;
	return static_cast<uintptr_t>(next + disp);
}

void CommandInterface::TryResolveNetworkThisFromSend(uintptr_t sendAddr)
{
	using SapphireHook::Logger;

	const uint8_t* p = reinterpret_cast<const uint8_t*>(sendAddr);
	bool logged = false;

	for (int i = 0; i < 64; ++i)
	{
		if (p[i] == 0x48 && p[i + 1] == 0x8B && p[i + 2] == 0x0D)
		{
			uintptr_t tgt = RipTarget(sendAddr + i, 3);
			if (tgt)
			{
				const uintptr_t candidate = SH_SafeReadPtr(tgt);
				if (candidate)
				{
					s_gameConnectionPtr = candidate;
					s_sendPacketMethod = reinterpret_cast<SendPacketMethod_t>(sendAddr);
					Logger::Instance().InformationF("[CommandInterface] Derived network 'this' (mov rcx,[rip+]) at 0x%llx -> 0x%llx",
						static_cast<unsigned long long>(tgt),
						static_cast<unsigned long long>(s_gameConnectionPtr));
					return;
				}
			}
		}
		if (p[i] == 0x48 && p[i + 1] == 0x8D && p[i + 2] == 0x0D)
		{
			uintptr_t tgt = RipTarget(sendAddr + i, 3);
			if (tgt)
			{
				s_gameConnectionPtr = tgt;
				s_sendPacketMethod = reinterpret_cast<SendPacketMethod_t>(sendAddr);
				Logger::Instance().InformationF("[CommandInterface] Derived network 'this' (lea rcx,[rip+]) -> 0x%llx",
					static_cast<unsigned long long>(s_gameConnectionPtr));
				return;
			}
		}
		if (p[i] == 0x48 && p[i + 1] == 0x8B && p[i + 2] == 0x05)
		{
			uintptr_t tgt1 = RipTarget(sendAddr + i, 3);
			const uintptr_t basePtr = SH_SafeReadPtr(tgt1);
			if (basePtr)
			{
				for (int k = i + 7; k < i + 32 && k + 6 < 64; ++k)
				{
					if (p[k] == 0x48 && p[k + 1] == 0x8B && (p[k + 2] & 0xF8) == 0x48 && p[k + 3] == 0x88)
					{
						s_gameConnectionPtr = basePtr;
						s_sendPacketMethod = reinterpret_cast<SendPacketMethod_t>(sendAddr);
						Logger::Instance().InformationF("[CommandInterface] Derived network 'this' (mov rax,[rip+]) base=0x%llx",
							static_cast<unsigned long long>(s_gameConnectionPtr));
						return;
					}
				}
				s_gameConnectionPtr = basePtr;
				s_sendPacketMethod = reinterpret_cast<SendPacketMethod_t>(sendAddr);
				Logger::Instance().InformationF("[CommandInterface] Derived network 'this' (mov rax,[rip+]) base=0x%llx",
					static_cast<unsigned long long>(s_gameConnectionPtr));
				return;
			}
		}
	}

	if (!logged)
		Logger::Instance().Warning("[CommandInterface] Could not derive network 'this' from send function prologue");
}

static void DebugSocketLearning()
{
	using SapphireHook::Logger;
	Logger::Instance().Information("[CommandInterface] === SOCKET LEARNING DEBUG ===");
	Logger::Instance().InformationF("[CommandInterface] Zone socket: 0x%llx (%s)",
		static_cast<unsigned long long>(SapphireHook::PacketInjector::s_zoneSocket),
		(SapphireHook::PacketInjector::s_zoneSocket == static_cast<std::uintptr_t>(INVALID_SOCKET)) ? "INVALID" : "VALID");
	Logger::Instance().InformationF("[CommandInterface] Chat socket: 0x%llx (%s)",
		static_cast<unsigned long long>(SapphireHook::PacketInjector::s_chatSocket),
		(SapphireHook::PacketInjector::s_chatSocket == static_cast<std::uintptr_t>(INVALID_SOCKET)) ? "INVALID" : "VALID");

	Logger::Instance().InformationF("[CommandInterface] INVALID_SOCKET value: 0x%llx",
		static_cast<unsigned long long>(static_cast<std::uintptr_t>(INVALID_SOCKET)));
}

bool CommandInterface::SendRawPacket(const std::vector<uint8_t>& buffer)
{
	using SapphireHook::Logger;

	Logger::Instance().InformationF("[CommandInterface] Attempting to send raw packet of size %zu", buffer.size());

	std::ostringstream dump;
	dump << "[CommandInterface] Packet contents (first 64 bytes):";
	size_t displaySize = (std::min)(buffer.size(), static_cast<size_t>(64));
	for (size_t i = 0; i < displaySize; i++)
	{
		if (i % 16 == 0) dump << "\n" << std::setw(4) << std::setfill('0') << std::hex << i << ": ";
		dump << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(buffer[i]) << " ";
	}
	Logger::Instance().Information(dump.str());

	DebugSocketLearning();

	if (s_sendPacketFunc)
	{
		bool ok = s_sendPacketFunc(const_cast<uint8_t*>(buffer.data()), buffer.size());
		Logger::Instance().InformationF("[CommandInterface] s_sendPacketFunc returned: %s", ok ? "OK" : "FAIL");
		if (ok) return true;
	}

	if (s_sendPacketMethod && s_gameConnectionPtr)
	{
		const bool ok = SH_SafeCall_Send(reinterpret_cast<void*>(s_sendPacketMethod),
			reinterpret_cast<void*>(s_gameConnectionPtr),
			const_cast<uint8_t*>(buffer.data()),
			buffer.size());
		Logger::Instance().InformationF("[CommandInterface] s_sendPacketMethod returned: %s", ok ? "OK" : "FAIL");
		if (ok) return true;
	}

	Logger::Instance().Information("[CommandInterface] Trying PacketInjector::Send...");
	if (SapphireHook::PacketInjector::Send(buffer.data(), buffer.size()))
	{
		Logger::Instance().Information("[CommandInterface] Sent via PacketInjector (WSASend)");
		return true;
	}

	Logger::Instance().Warning("[CommandInterface] PacketInjector::Send failed");
	return false;
}

bool CommandInterface::SetPlayerLevel(uint8_t level, uint64_t targetId)
{
	return SendGMCommand(SapphireHook::GmCommandId::Lv, level, 0, 0, 0, targetId);
}

bool CommandInterface::SetPlayerClass(uint8_t classId, uint64_t targetId)
{
	return SendGMCommand(SapphireHook::GmCommandId::QuestAccept, classId, 0, 0, 0, targetId);
}

bool CommandInterface::GivePlayerItem(uint32_t itemId, uint32_t quantity, uint64_t targetId)
{
	return SendGMCommand(SapphireHook::GmCommandId::Item, itemId, quantity, 0, 0, targetId);
}

bool CommandInterface::GivePlayerGil(uint32_t amount, uint64_t targetId)
{
	return SendGMCommand(SapphireHook::GmCommandId::Gil, amount, 0, 0, 0, targetId);
}

bool CommandInterface::TeleportToZone(uint32_t zoneId, uint64_t targetId)
{
	return SendGMCommand(SapphireHook::GmCommandId::Teri, zoneId, 0, 0, 0, targetId);
}

bool CommandInterface::SetPlayerPosition(float x, float y, float z, uint64_t targetId)
{
	uint32_t pos_x = *reinterpret_cast<uint32_t*>(&x);
	uint32_t pos_y = *reinterpret_cast<uint32_t*>(&y);
	uint32_t pos_z = *reinterpret_cast<uint32_t*>(&z);
	return SendGMCommand(SapphireHook::GmCommandId::Pos, pos_x, pos_y, pos_z, 0, targetId);
}

bool CommandInterface::TryParseAsGMCommand(const char* command)
{
	using SapphireHook::Logger;

	Logger::Instance().InformationF("[CommandInterface] Parsing debug command: %s", command ? command : "");

	std::string cmdStr(command ? command : "");
	for (char& c : cmdStr)
	{
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}

	if (!cmdStr.empty() && cmdStr[0] == '!')
		cmdStr = cmdStr.substr(1);

	std::vector<std::string> parts;
	std::stringstream ss(cmdStr);
	std::string part;
	while (std::getline(ss, part, ' '))
	{
		if (!part.empty())
			parts.push_back(part);
	}

	if (parts.empty())
		return false;

	const std::string& mainCmd = parts[0];
	uint64_t targetId = 0;

	if (mainCmd == "set" && parts.size() >= 3)
	{
		const std::string& subCmd = parts[1];
		if (subCmd == "classjob" || subCmd == "job")
		{
			uint32_t jobId = std::stoul(parts[2]);
			return SendGMCommand(SapphireHook::GmCommandId::Lv, jobId, 0, 0, 0, targetId);
		}
		else if (subCmd == "pos" && parts.size() >= 5)
		{
			float x = std::stof(parts[2]);
			float y = std::stof(parts[3]);
			float z = std::stof(parts[4]);
			return SetPlayerPosition(x, y, z, targetId);
		}
		else if (subCmd == "tele")
		{
			uint32_t zoneId = std::stoul(parts[2]);
			return TeleportToZone(zoneId, targetId);
		}
	}
	else if (mainCmd == "add" && parts.size() >= 3)
	{
		const std::string& subCmd = parts[1];
		if (subCmd == "item")
		{
			uint32_t itemId = std::stoul(parts[2]);
			uint32_t quantity = parts.size() >= 4 ? std::stoul(parts[3]) : 1;
			return GivePlayerItem(itemId, quantity, targetId);
		}
		else if (subCmd == "gil")
		{
			uint32_t amount = std::stoul(parts[2]);
			return GivePlayerGil(amount, targetId);
		}
	}
	else if (mainCmd == "get" && parts.size() >= 2 && parts[1] == "pos")
	{
		return SendGMCommand(SapphireHook::GmCommandId::Pos, 0, 0, 0, 0, targetId);
	}

	Logger::Instance().WarningF("[CommandInterface] Unknown or unsupported debug command: %s", command ? command : "");
	return false;
}

bool CommandInterface::SendDebugCommand(const char* command)
{
	using SapphireHook::Logger;

	Logger::Instance().InformationF("[CommandInterface] Attempting to send debug command: %s", command ? command : "");

	std::string cmd = command ? command : "";
	auto beginsWith = [](const std::string& s, char c) { return !s.empty() && s[0] == c; };
	const std::string chatCommand = (beginsWith(cmd, '!') || beginsWith(cmd, '/')) ? cmd : "!" + cmd;

	if (SendChatMessage(chatCommand.c_str(), 0))
	{
		Logger::Instance().InformationF("[CommandInterface] Sent command via chat path: %s", chatCommand.c_str());
		return true;
	}

	if (TryParseAsGMCommand(command))
	{
		Logger::Instance().InformationF("[CommandInterface] Sent command via GM command parsing: %s", command ? command : "");
		return true;
	}

	Logger::Instance().WarningF("[CommandInterface] All methods failed for: %s", command ? command : "");
	return false;
}

bool CommandInterface::SendDebugCommandPacket(const char* command)
{
	using SapphireHook::Logger;

	if (!command || !*command) return false;
	Logger::Instance().InformationF("[CommandInterface] SendDebugCommandPacket: %s", command);

	std::string cmd = command;
	if (!cmd.empty() && (cmd[0] == '!' || cmd[0] == '/')) cmd.erase(0, 1);
	std::vector<std::string> parts;
	{ std::stringstream ss(cmd); std::string t; while (ss >> t) parts.push_back(t); }

	uint32_t id = 0, a0 = 0, a1 = 0, a2 = 0, a3 = 0;
	if (parts.size() >= 3 && parts[0] == "set" && (parts[1] == "classjob" || parts[1] == "job"))
	{
		id = 0x01BE;
		a0 = 0;
	}

	SapphireHook::CompleteClientTriggerPacket packet{};
	const uint64_t ts = GetTickCount64();
	const uint32_t actorId = GetLocalEntityId();

	packet.header.timestamp = ts;
	packet.header.connectionType = 1;
	packet.header.count = 1;

	const uint32_t dataSize = sizeof(SapphireHook::FFXIVARR_IPC_HEADER) + sizeof(SapphireHook::ClientTriggerPacketData);
	const uint32_t segSize = sizeof(SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER) + dataSize;
	const uint32_t total = sizeof(SapphireHook::FFXIVARR_PACKET_HEADER) + segSize;

	packet.header.size = total;

	packet.segmentHeader.size = segSize;
	packet.segmentHeader.source_actor = actorId;
	packet.segmentHeader.target_actor = 0;
	packet.segmentHeader.type = 3;

	packet.ipcHeader.reserved = 0x14;
	packet.ipcHeader.type = 0x0191;
	packet.ipcHeader.timestamp = static_cast<uint32_t>(ts);

	packet.data.Id = id;
	packet.data.Arg0 = a0; packet.data.Arg1 = a1; packet.data.Arg2 = a2; packet.data.Arg3 = a3;
	packet.data.Target = 0;

	Logger::Instance().InformationF("[CommandInterface] ClientTrigger: Id=0x%X Arg0=%u SourceActor=0x%X", id, a0, actorId);

	std::vector<uint8_t> buffer(sizeof(packet));
	std::memcpy(buffer.data(), &packet, sizeof(packet));
	return SendRawPacket(buffer);
}

bool CommandInterface::SendChatMessage(const char* message, uint8_t chatType)
{
	using SapphireHook::Logger;

	if (!message || !*message)
	{
		Logger::Instance().Warning("[CommandInterface] SendChatMessage: empty message");
		return false;
	}

	if (s_chatCommandFunc)
	{
		try
		{
			s_chatCommandFunc(message);
			Logger::Instance().Information("[CommandInterface] Sent chat via in-process ChatCommand_t");
			return true;
		}
		catch (...)
		{
			Logger::Instance().Warning("[CommandInterface] Exception in ChatCommand_t; falling back to packet");
		}
	}

	if (message && message[0] == '!')
	{
		Logger::Instance().Information("[CommandInterface] Debug command detected, sending ChatHandler then 0x0191");

		if (!SendChatPacket(message, static_cast<uint8_t>(10)))
		{
			Logger::Instance().Error("[CommandInterface] Failed to send ChatHandler packet");
			return false;
		}

		Sleep(50);

		std::string command = message + 1;
		if (!SendDebugCommandPacket(command.c_str()))
		{
			Logger::Instance().Error("[CommandInterface] Failed to send Command packet");
			return false;
		}

		Logger::Instance().Information("[CommandInterface] Successfully sent both Chat (0x0067) and Command (0x0191) packets");
		return true;
	}

	return SendChatPacket(message, chatType);
}

bool CommandInterface::SendChatPacket(const char* message, uint8_t chatType)
{
	using SapphireHook::Logger;

	if (!message || !*message)
	{
		Logger::Instance().Warning("[CommandInterface] SendChatPacket: empty message");
		return false;
	}

	Logger::Instance().InformationF("[CommandInterface] Attempting to send chat packet: %s (type: %u)", message, chatType);

	struct FFXIVIpcChatHandler
	{
		uint32_t clientTimeValue;
		uint32_t originEntityId;
		float pos[3];
		float dir;
		uint16_t chatType;
		char message[1024];
	};

	FFXIVIpcChatHandler chatPacket = {};
	chatPacket.clientTimeValue = static_cast<uint32_t>(GetTickCount64());
	chatPacket.originEntityId = GetLocalEntityId();
	chatPacket.chatType = static_cast<uint16_t>(chatType);
	strncpy_s(chatPacket.message, sizeof(chatPacket.message), message, _TRUNCATE);

	auto pos = GetLocalPlayerPosition();
	if (pos)
	{
		chatPacket.pos[0] = pos->x;
		chatPacket.pos[1] = pos->y;
		chatPacket.pos[2] = pos->z;
		chatPacket.dir = 0.0f;
	}
	else
	{
		chatPacket.pos[0] = 0.0f;
		chatPacket.pos[1] = 0.0f;
		chatPacket.pos[2] = 0.0f;
		chatPacket.dir = 0.0f;
	}

	const size_t chatDataSize = sizeof(FFXIVIpcChatHandler);
	const size_t ipcSize = sizeof(SapphireHook::FFXIVARR_IPC_HEADER) + chatDataSize;
	const size_t segmentSize = sizeof(SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER) + ipcSize;
	const size_t totalSize = sizeof(SapphireHook::FFXIVARR_PACKET_HEADER) + segmentSize;

	std::vector<uint8_t> buffer(totalSize);
	auto* header = reinterpret_cast<SapphireHook::FFXIVARR_PACKET_HEADER*>(buffer.data());
	auto* segment = reinterpret_cast<SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER*>(buffer.data() + sizeof(SapphireHook::FFXIVARR_PACKET_HEADER));
	auto* ipc = reinterpret_cast<SapphireHook::FFXIVARR_IPC_HEADER*>(buffer.data() + sizeof(SapphireHook::FFXIVARR_PACKET_HEADER) + sizeof(SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER));
	auto* data = buffer.data() + sizeof(SapphireHook::FFXIVARR_PACKET_HEADER) + sizeof(SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER) + sizeof(SapphireHook::FFXIVARR_IPC_HEADER);

	header->timestamp = GetTickCount64();
	header->size = static_cast<uint32_t>(totalSize);
	header->connectionType = 0;
	header->count = 1;

	segment->size = static_cast<uint32_t>(segmentSize);
	segment->source_actor = GetLocalEntityId();
	segment->target_actor = 0;
	segment->type = 3;

	ipc->reserved = 0x14;
	ipc->type = 0x0067;
	ipc->timestamp = static_cast<uint32_t>(GetTickCount64());

	memcpy(data, &chatPacket, chatDataSize);

	return SendRawPacket(buffer);
}

bool CommandInterface::SendGMCommand(uint32_t commandId, uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint64_t target)
{
	return SendGMCommandEx(0x0197, commandId, arg0, arg1, arg2, arg3, target);
}

bool CommandInterface::SendGMCommandEx(uint16_t ipcOpcode, uint32_t commandId, uint32_t arg0, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint64_t target)
{
	using SapphireHook::Logger;

	Logger::Instance().InformationF("[CommandInterface] Sending GM Command (EX): OPCODE=0x%X ID=0x%X, Args=(%u,%u,%u,%u), Target=0x%llX",
		ipcOpcode, commandId, arg0, arg1, arg2, arg3, static_cast<unsigned long long>(target));

	SapphireHook::CompleteGMPacket packet = {};
	const uint64_t timestamp = GetTickCount64();

	packet.header.timestamp = timestamp;
	packet.header.connectionType = 1;
	packet.header.count = 1;

	const uint32_t dataSize = sizeof(SapphireHook::FFXIVARR_IPC_HEADER) + sizeof(SapphireHook::GmCommandPacket);
	const uint32_t segmentSize = sizeof(SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER) + dataSize;
	const uint32_t totalSize = sizeof(SapphireHook::FFXIVARR_PACKET_HEADER) + segmentSize;

	packet.header.size = totalSize;
	packet.segmentHeader.size = segmentSize;
	packet.segmentHeader.source_actor = GetLocalEntityId();
	packet.segmentHeader.target_actor = static_cast<uint32_t>(target);
	packet.segmentHeader.type = 3;

	packet.ipcHeader.reserved = 0x14;
	packet.ipcHeader.type = ipcOpcode;
	packet.ipcHeader.timestamp = static_cast<uint32_t>(timestamp);

	packet.gmData.Id = commandId;
	packet.gmData.Arg0 = arg0;
	packet.gmData.Arg1 = arg1;
	packet.gmData.Arg2 = arg2;
	packet.gmData.Arg3 = arg3;
	packet.gmData.Target = target;

	std::vector<uint8_t> buffer(sizeof(packet));
	std::memcpy(buffer.data(), &packet, sizeof(packet));
	return SendRawPacket(buffer);
}

bool CommandInterface::FindCommandFunctions()
{
	using SapphireHook::Logger;
	s_chatCommandFunc = nullptr;
	Logger::Instance().Information("[CommandInterface] FindCommandFunctions: not implemented; using packet path only");
	return false;
}

bool CommandInterface::FindNetworkFunctions()
{
	using SapphireHook::Logger;
	s_sendPacketFunc = nullptr;
	s_sendPacketMethod = nullptr;
	Logger::Instance().Information("[CommandInterface] FindNetworkFunctions: not implemented; using WSASend injector");
	return false;
}

bool CommandInterface::FindGameConnection()
{
	using SapphireHook::Logger;
	s_gameConnection = nullptr;
	s_gameConnectionPtr = 0;
	Logger::Instance().Information("[CommandInterface] FindGameConnection: not implemented; no game connection singleton");
	return false;
}

// === New Wrapper Implementations (added safely; do not alter existing behavior) ===
bool CommandInterface::SetPlayerRace(uint32_t raceId, uint64_t targetId)
{
	return SendGMCommand(SapphireHook::GmCommandId::Race, raceId, 0, 0, 0, targetId);
}

bool CommandInterface::SetPlayerTribe(uint32_t tribeId, uint64_t targetId)
{
	return SendGMCommand(SapphireHook::GmCommandId::Tribe, tribeId, 0, 0, 0, targetId);
}

bool CommandInterface::SetPlayerGender(uint32_t gender, uint64_t targetId)
{
	return SendGMCommand(SapphireHook::GmCommandId::Sex, gender, 0, 0, 0, targetId);
}

bool CommandInterface::SetPlayerHp(uint32_t hp, uint64_t targetId)
{
	return SendGMCommand(SapphireHook::GmCommandId::Hp, hp, 0, 0, 0, targetId);
}

bool CommandInterface::SetPlayerMp(uint32_t mp, uint64_t targetId)
{
	return SendGMCommand(SapphireHook::GmCommandId::Mp, mp, 0, 0, 0, targetId);
}

bool CommandInterface::SetPlayerGp(uint32_t gp, uint64_t targetId)
{
	return SendGMCommand(SapphireHook::GmCommandId::Gp, gp, 0, 0, 0, targetId);
}

bool CommandInterface::AddPlayerExp(uint32_t amount, uint64_t targetId)
{
	// If server treats Exp as additive, this works; otherwise identical to SetPlayerExp.
	return SendGMCommand(SapphireHook::GmCommandId::Exp, amount, 0, 0, 0, targetId);
}

bool CommandInterface::SetPlayerExp(uint32_t amount, uint64_t targetId)
{
	return SendGMCommand(SapphireHook::GmCommandId::Exp, amount, 0, 0, 0, targetId);
}

bool CommandInterface::SetPlayerIcon(uint32_t iconId, uint64_t targetId)
{
	return SendGMCommand(SapphireHook::GmCommandId::Icon, iconId, 0, 0, 0, targetId);
}

bool CommandInterface::SetInvincibility(uint32_t enabled, uint64_t targetId)
{
	// enabled: 1 = on, 0 = off
	return SendGMCommand(SapphireHook::GmCommandId::Inv, enabled, 0, 0, 0, targetId);
}

bool CommandInterface::SetInvisibility(uint32_t visibleFlag)
{
	// visibleFlag: 1 = visible, 0 = invisible (current UI logic in CharacterEdit)
	return SendGMCommand(SapphireHook::GmCommandId::Invis, visibleFlag, 0, 0, 0, 0);
}

bool CommandInterface::SetWireframe(uint32_t enabled)
{
	return SendGMCommand(SapphireHook::GmCommandId::Wireframe, enabled, 0, 0, 0, 0);
}

bool CommandInterface::UnlockOrchestrion(uint32_t songId)
{
	// Arg0=1 per existing usage, Arg1 = songId (0 => all)
	return SendGMCommand(SapphireHook::GmCommandId::Orchestrion, 1, songId, 0, 0, 0);
}

bool CommandInterface::SetGrandCompany(uint32_t companyId, uint64_t targetId)
{
	return SendGMCommand(SapphireHook::GmCommandId::GC, companyId, 0, 0, 0, targetId);
}

bool CommandInterface::SetGrandCompanyRank(uint32_t rank, uint64_t targetId)
{
	return SendGMCommand(SapphireHook::GmCommandId::GCRank, rank, 0, 0, 0, targetId);
}

// === Implementations for previously declared but missing functions ===
bool CommandInterface::SendCommandPacket(uint32_t commandId,
	uint32_t arg0,
	uint32_t arg1,
	uint32_t arg2,
	uint32_t arg3,
	uint64_t target)
{
	// Direct GM1 send; discovery modules may override with SendGMCommandEx.
	return SendGMCommand(commandId, arg0, arg1, arg2, arg3, target);
}

bool CommandInterface::ProcessCommand(const std::string& command)
{
	// Try GM-style parse first, then fallback to chat debug path.
	if (TryParseAsGMCommand(command.c_str()))
		return true;
	return SendDebugCommand(command.c_str());
}

// ============================================================================
// Generic IPC Packet Builder & Sender
// ============================================================================

bool CommandInterface::SendIpcPacketRaw(uint16_t opcode, const void* payloadData, size_t payloadSize,
	uint16_t connectionType, uint32_t targetActorId)
{
	using SapphireHook::Logger;

	Logger::Instance().InformationF("[CommandInterface] SendIpcPacketRaw: opcode=0x%04X, payloadSize=%zu, connType=%u, target=0x%X",
		opcode, payloadSize, connectionType, targetActorId);

	// Build the complete packet structure
	const uint32_t ipcHeaderSize = sizeof(SapphireHook::FFXIVARR_IPC_HEADER);
	const uint32_t dataSize = static_cast<uint32_t>(ipcHeaderSize + payloadSize);
	const uint32_t segmentSize = sizeof(SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER) + dataSize;
	const uint32_t totalSize = sizeof(SapphireHook::FFXIVARR_PACKET_HEADER) + segmentSize;

	std::vector<uint8_t> buffer(totalSize, 0);

	// Packet header
	auto* pktHdr = reinterpret_cast<SapphireHook::FFXIVARR_PACKET_HEADER*>(buffer.data());
	pktHdr->timestamp = GetTickCount64();
	pktHdr->size = totalSize;
	pktHdr->connectionType = connectionType;
	pktHdr->count = 1;
	pktHdr->isCompressed = 0;

	// Segment header
	auto* segHdr = reinterpret_cast<SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER*>(buffer.data() + sizeof(SapphireHook::FFXIVARR_PACKET_HEADER));
	segHdr->size = segmentSize;
	segHdr->source_actor = GetLocalEntityId();
	segHdr->target_actor = targetActorId != 0 ? targetActorId : segHdr->source_actor;
	segHdr->type = 3;  // IPC segment

	// IPC header
	auto* ipcHdr = reinterpret_cast<SapphireHook::FFXIVARR_IPC_HEADER*>(buffer.data() + sizeof(SapphireHook::FFXIVARR_PACKET_HEADER) + sizeof(SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER));
	ipcHdr->reserved = 0x14;
	ipcHdr->type = opcode;
	ipcHdr->timestamp = static_cast<uint32_t>(GetTickCount64());
	ipcHdr->serverId = 0;

	// Copy payload
	if (payloadData && payloadSize > 0) {
		uint8_t* payloadDest = buffer.data() + sizeof(SapphireHook::FFXIVARR_PACKET_HEADER) 
			+ sizeof(SapphireHook::FFXIVARR_PACKET_SEGMENT_HEADER) 
			+ sizeof(SapphireHook::FFXIVARR_IPC_HEADER);
		std::memcpy(payloadDest, payloadData, payloadSize);
	}

	return SendRawPacket(buffer);
}

// Template implementation for typed packets
template<typename T>
bool CommandInterface::SendIpcPacket(uint16_t opcode, const T& payload, uint16_t connectionType, uint32_t targetActorId)
{
	return SendIpcPacketRaw(opcode, &payload, sizeof(T), connectionType, targetActorId);
}

// ============================================================================
// ContentFinder / Duty Finder Packets
// ============================================================================

bool CommandInterface::QueueForDuties(const uint16_t* territoryTypes, uint8_t count, uint32_t flags)
{
	using SapphireHook::Logger;
	(void)flags; // flags not used in Find5Contents - use FindContent (0x01FA) for single duty with flags

	if (!territoryTypes || count == 0 || count > 5) {
		Logger::Instance().Warning("[CommandInterface] QueueForDuties: Invalid parameters");
		return false;
	}

	// Find5Contents packet structure (0x01FD) - matches Sapphire's FFXIVIpcFind5Contents
	// Note: This packet uses TerritoryTypes, NOT ContentFinderCondition IDs!
	// The server looks up InstanceContent by matching the TerritoryType field.
	struct Find5ContentsPayload {
		uint8_t acceptHalfway;      // Allow joining in-progress duties
		uint8_t language;           // Language preference (0 = any, 1 = JP, 2 = EN, 3 = DE, 4 = FR)
		uint16_t territoryTypes[5]; // Territory type IDs (e.g., Sastasha = 1036)
	};

	Find5ContentsPayload payload = {};
	payload.acceptHalfway = 0;  // Don't accept in-progress by default
	payload.language = 0;       // Any language
	for (uint8_t i = 0; i < count && i < 5; ++i) {
		payload.territoryTypes[i] = territoryTypes[i];
	}

	Logger::Instance().InformationF("[CommandInterface] QueueForDuties (Find5Contents): territories=[%u,%u,%u,%u,%u]",
		count > 0 ? territoryTypes[0] : 0,
		count > 1 ? territoryTypes[1] : 0,
		count > 2 ? territoryTypes[2] : 0,
		count > 3 ? territoryTypes[3] : 0,
		count > 4 ? territoryTypes[4] : 0);

	return SendIpcPacketRaw(0x01FD, &payload, sizeof(payload));
}

bool CommandInterface::AcceptDutyPop(uint32_t contentId)
{
	using SapphireHook::Logger;

	// AcceptContent packet structure (0x01FB)
	struct AcceptContentPayload {
		uint32_t contentId;
		uint8_t accepted;  // 1 = accept, 0 = decline
		uint8_t padding[3];
	};

	AcceptContentPayload payload = {};
	payload.contentId = contentId;
	payload.accepted = 1;

	Logger::Instance().InformationF("[CommandInterface] AcceptDutyPop: contentId=%u", contentId);

	return SendIpcPacketRaw(0x01FB, &payload, sizeof(payload));
}

bool CommandInterface::CancelDutyQueue()
{
	using SapphireHook::Logger;

	// CancelFindContent packet structure (0x01FC)
	struct CancelFindContentPayload {
		uint32_t reserved;
	};

	CancelFindContentPayload payload = {};

	Logger::Instance().Information("[CommandInterface] CancelDutyQueue");

	return SendIpcPacketRaw(0x01FC, &payload, sizeof(payload));
}

// ============================================================================
// Quest / Event Packets
// ============================================================================

bool CommandInterface::SendEventTalk(uint32_t eventId, uint32_t actorId)
{
	using SapphireHook::Logger;

	// EventHandlerTalk packet structure (0x01C2)
	// Based on ClientZoneDef.h
	struct EventHandlerTalkPayload {
		uint32_t actorId;
		uint32_t eventId;
		uint32_t unknown1;
		uint32_t unknown2;
	};

	EventHandlerTalkPayload payload = {};
	payload.actorId = actorId;
	payload.eventId = eventId;

	Logger::Instance().InformationF("[CommandInterface] SendEventTalk: eventId=0x%X, actorId=0x%X", eventId, actorId);

	return SendIpcPacketRaw(0x01C2, &payload, sizeof(payload));
}

// Explicit template instantiations for common packet types
// Add more as needed for the packet types you want to send
// Note: Templates are defined in the header, instantiated here for common types
template bool CommandInterface::SendIpcPacket<uint32_t>(uint16_t, const uint32_t&, uint16_t, uint32_t);
template bool CommandInterface::SendIpcPacket<uint64_t>(uint16_t, const uint64_t&, uint16_t, uint32_t);

// Public accessor for local entity ID (wraps anonymous namespace function)
uint32_t CommandInterface::GetLocalEntityId()
{
	// Call the internal anonymous namespace version
	using SapphireHook::Logger;
	uint32_t learned = SapphireHook::GetLearnedLocalActorId();
	if (learned != 0 && learned != 0xFFFFFFFF)
	{
		return learned;
	}
	static uint32_t s_id = 0x200001;
	static bool s_inited = false;
	if (!s_inited)
	{
		s_inited = true;
		if (const char* v = std::getenv("SAPPHIRE_ENTITYID"))
		{
			if (std::strlen(v) > 2 && (v[0] == '0') && (v[1] == 'x' || v[1] == 'X'))
			{
				s_id = static_cast<uint32_t>(std::strtoul(v + 2, nullptr, 16));
			}
			else
			{
				s_id = static_cast<uint32_t>(std::strtoul(v, nullptr, 10));
			}
		}
	}
	return s_id;
}

// (No changes below this point in existing file)