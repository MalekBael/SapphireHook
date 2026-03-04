#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "NetworkHooks.h"
#include "../Analysis/PatternScanner.h"
#include "../Core/SafeMemory.h"
#include "../Logger/Logger.h"


#include <MinHook.h>
#include <Windows.h>
#include <algorithm>


namespace SapphireHook {

NetworkHooks &NetworkHooks::GetInstance() {
  static NetworkHooks instance;
  return instance;
}

NetworkHooks::~NetworkHooks() { Shutdown(); }

bool NetworkHooks::Initialize() {
  if (m_initialized.load()) {
    Logger::Instance().Warning("[NetworkHooks] Already initialized");
    return true;
  }

  Logger::Instance().Information(
      "[NetworkHooks] Initializing high-level network hooks...");

  if (!FindNetworkFunctions()) {
    Logger::Instance().Error(
        "[NetworkHooks] Failed to find network functions via signatures");
    return false;
  }

  MH_STATUS status = MH_Initialize();
  if (status != MH_OK && status != MH_ERROR_ALREADY_INITIALIZED) {
    Logger::Instance().ErrorF("[NetworkHooks] MinHook init failed: %d",
                              static_cast<int>(status));
    return false;
  }

  bool anyHooked = false;

  if (InstallSocketHandlerHook()) {
    anyHooked = true;
    Logger::Instance().InformationF(
        "[NetworkHooks] Socket handler hook installed at 0x%llX",
        static_cast<unsigned long long>(m_addresses.socketHandler));
  }

  if (InstallIPCDispatcherHook()) {
    anyHooked = true;
    Logger::Instance().InformationF(
        "[NetworkHooks] IPC dispatcher hook installed at 0x%llX",
        static_cast<unsigned long long>(m_addresses.ipcDispatcher));
  }

  if (InstallRecvHook()) {
    anyHooked = true;
    Logger::Instance().InformationF(
        "[NetworkHooks] Recv wrapper hook installed at 0x%llX",
        static_cast<unsigned long long>(m_addresses.recvWrapper));
  }

  if (InstallSendHook()) {
    anyHooked = true;
    Logger::Instance().InformationF(
        "[NetworkHooks] Send wrapper hook installed at 0x%llX",
        static_cast<unsigned long long>(m_addresses.sendWrapper));
  }

  if (anyHooked) {
    m_hooked.store(true);
    m_initialized.store(true);
    Logger::Instance().Information(
        "[NetworkHooks] High-level network hooks active");
    return true;
  }

  Logger::Instance().Warning("[NetworkHooks] No hooks could be installed");
  return false;
}

void NetworkHooks::Shutdown() {
  if (!m_initialized.load())
    return;

  Logger::Instance().Information("[NetworkHooks] Shutting down...");

  if (m_addresses.socketHandler && s_origSocketHandler) {
    MH_DisableHook(reinterpret_cast<LPVOID>(m_addresses.socketHandler));
    MH_RemoveHook(reinterpret_cast<LPVOID>(m_addresses.socketHandler));
  }
  if (m_addresses.ipcDispatcher && s_origIPCDispatcher) {
    MH_DisableHook(reinterpret_cast<LPVOID>(m_addresses.ipcDispatcher));
    MH_RemoveHook(reinterpret_cast<LPVOID>(m_addresses.ipcDispatcher));
  }
  if (m_addresses.recvWrapper && s_origRecvWrapper) {
    MH_DisableHook(reinterpret_cast<LPVOID>(m_addresses.recvWrapper));
    MH_RemoveHook(reinterpret_cast<LPVOID>(m_addresses.recvWrapper));
  }
  if (m_addresses.sendWrapper && s_origSendWrapper) {
    MH_DisableHook(reinterpret_cast<LPVOID>(m_addresses.sendWrapper));
    MH_RemoveHook(reinterpret_cast<LPVOID>(m_addresses.sendWrapper));
  }

  s_origSocketHandler = nullptr;
  s_origIPCDispatcher = nullptr;
  s_origRecvWrapper = nullptr;
  s_origSendWrapper = nullptr;

  m_hooked.store(false);
  m_initialized.store(false);

  Logger::Instance().Information("[NetworkHooks] Shutdown complete");
}

bool NetworkHooks::FindNetworkFunctions() {
  bool foundAny = false;

  auto result =
      PatternScanner::ScanMainModule(NetworkSignatures::SocketReceiveHandler);
  if (result) {
    m_addresses.socketHandler = result->address;
    Logger::Instance().InformationF(
        "[NetworkHooks] Found SocketReceiveHandler at 0x%llX",
        static_cast<unsigned long long>(m_addresses.socketHandler));
    foundAny = true;
  } else {
    Logger::Instance().Warning(
        "[NetworkHooks] SocketReceiveHandler signature not found");
  }

  result = PatternScanner::ScanMainModule(NetworkSignatures::IPCDispatcher);
  if (result) {
    m_addresses.ipcDispatcher = result->address;
    Logger::Instance().InformationF(
        "[NetworkHooks] Found IPCDispatcher at 0x%llX",
        static_cast<unsigned long long>(m_addresses.ipcDispatcher));
    foundAny = true;
  } else {
    Logger::Instance().Warning(
        "[NetworkHooks] IPCDispatcher signature not found");
  }

  result = PatternScanner::ScanMainModule(NetworkSignatures::RecvWrapper);
  if (result) {
    m_addresses.recvWrapper = result->address;
    Logger::Instance().InformationF(
        "[NetworkHooks] Found RecvWrapper at 0x%llX",
        static_cast<unsigned long long>(m_addresses.recvWrapper));
    foundAny = true;
  } else {
    Logger::Instance().Warning(
        "[NetworkHooks] RecvWrapper signature not found");
  }

  result = PatternScanner::ScanMainModule(NetworkSignatures::SendWrapper);
  if (result) {
    m_addresses.sendWrapper = result->address;
    Logger::Instance().InformationF(
        "[NetworkHooks] Found SendWrapper at 0x%llX",
        static_cast<unsigned long long>(m_addresses.sendWrapper));
    foundAny = true;
  } else {
    Logger::Instance().Warning(
        "[NetworkHooks] SendWrapper signature not found");
  }

  result =
      PatternScanner::ScanMainModule(NetworkSignatures::PacketQueueHandler);
  if (result) {
    m_addresses.packetQueue = result->address;
    Logger::Instance().InformationF(
        "[NetworkHooks] Found PacketQueueHandler at 0x%llX",
        static_cast<unsigned long long>(m_addresses.packetQueue));
  }

  return foundAny;
}

bool NetworkHooks::InstallRecvHook() {
  if (!m_addresses.recvWrapper)
    return false;

  MH_STATUS status =
      MH_CreateHook(reinterpret_cast<LPVOID>(m_addresses.recvWrapper),
                    reinterpret_cast<LPVOID>(&DetourRecvWrapper),
                    reinterpret_cast<LPVOID *>(&s_origRecvWrapper));

  if (status != MH_OK) {
    Logger::Instance().ErrorF("[NetworkHooks] Failed to create recv hook: %d",
                              static_cast<int>(status));
    return false;
  }

  status = MH_EnableHook(reinterpret_cast<LPVOID>(m_addresses.recvWrapper));
  if (status != MH_OK) {
    Logger::Instance().ErrorF("[NetworkHooks] Failed to enable recv hook: %d",
                              static_cast<int>(status));
    return false;
  }

  return true;
}

bool NetworkHooks::InstallSendHook() {
  if (!m_addresses.sendWrapper)
    return false;

  MH_STATUS status =
      MH_CreateHook(reinterpret_cast<LPVOID>(m_addresses.sendWrapper),
                    reinterpret_cast<LPVOID>(&DetourSendWrapper),
                    reinterpret_cast<LPVOID *>(&s_origSendWrapper));

  if (status != MH_OK) {
    Logger::Instance().ErrorF("[NetworkHooks] Failed to create send hook: %d",
                              static_cast<int>(status));
    return false;
  }

  status = MH_EnableHook(reinterpret_cast<LPVOID>(m_addresses.sendWrapper));
  if (status != MH_OK) {
    Logger::Instance().ErrorF("[NetworkHooks] Failed to enable send hook: %d",
                              static_cast<int>(status));
    return false;
  }

  return true;
}

bool NetworkHooks::InstallSocketHandlerHook() {
  if (!m_addresses.socketHandler)
    return false;

  MH_STATUS status =
      MH_CreateHook(reinterpret_cast<LPVOID>(m_addresses.socketHandler),
                    reinterpret_cast<LPVOID>(&DetourSocketReceiveHandler),
                    reinterpret_cast<LPVOID *>(&s_origSocketHandler));

  if (status != MH_OK) {
    Logger::Instance().ErrorF(
        "[NetworkHooks] Failed to create socket handler hook: %d",
        static_cast<int>(status));
    return false;
  }

  status = MH_EnableHook(reinterpret_cast<LPVOID>(m_addresses.socketHandler));
  if (status != MH_OK) {
    Logger::Instance().ErrorF(
        "[NetworkHooks] Failed to enable socket handler hook: %d",
        static_cast<int>(status));
    return false;
  }

  return true;
}

bool NetworkHooks::InstallIPCDispatcherHook() {
  if (!m_addresses.ipcDispatcher)
    return false;

  MH_STATUS status =
      MH_CreateHook(reinterpret_cast<LPVOID>(m_addresses.ipcDispatcher),
                    reinterpret_cast<LPVOID>(&DetourIPCDispatcher),
                    reinterpret_cast<LPVOID *>(&s_origIPCDispatcher));

  if (status != MH_OK) {
    Logger::Instance().ErrorF(
        "[NetworkHooks] Failed to create IPC dispatcher hook: %d",
        static_cast<int>(status));
    return false;
  }

  status = MH_EnableHook(reinterpret_cast<LPVOID>(m_addresses.ipcDispatcher));
  if (status != MH_OK) {
    Logger::Instance().ErrorF(
        "[NetworkHooks] Failed to enable IPC dispatcher hook: %d",
        static_cast<int>(status));
    return false;
  }

  return true;
}

int __fastcall NetworkHooks::DetourRecvWrapper(void *netObj, char *buffer,
                                               int length) {
  auto &inst = GetInstance();

  int result =
      s_origRecvWrapper ? s_origRecvWrapper(netObj, buffer, length) : -1;

  if (result > 0) {
    inst.m_stats.packetsReceived++;
    inst.m_stats.bytesReceived += result;

    std::lock_guard<std::mutex> lock(inst.m_callbackMutex);
    if (inst.m_recvCallback) {
      auto span = std::span<const uint8_t>(
          reinterpret_cast<const uint8_t *>(buffer), result);
      inst.m_recvCallback(netObj, span);
    }
  }

  return result;
}

int __fastcall NetworkHooks::DetourSendWrapper(void *netObj, char *buffer,
                                               int length) {
  auto &inst = GetInstance();

  inst.m_stats.packetsSent++;
  inst.m_stats.bytesSent += length;

  {
    std::lock_guard<std::mutex> lock(inst.m_callbackMutex);
    if (inst.m_sendCallback) {
      auto span = std::span<const uint8_t>(
          reinterpret_cast<const uint8_t *>(buffer), length);
      if (!inst.m_sendCallback(netObj, span)) {
        return length;     
      }
    }
  }

  return s_origSendWrapper ? s_origSendWrapper(netObj, buffer, length) : -1;
}

int __fastcall NetworkHooks::DetourSocketReceiveHandler(void *connectionObj) {
  auto &inst = GetInstance();

  inst.m_connectionObj = connectionObj;

  if (IsValidMemoryAddress(reinterpret_cast<uintptr_t>(connectionObj), 0x190)) {
    uint32_t bufferSize = *reinterpret_cast<uint32_t *>(
        reinterpret_cast<uintptr_t>(connectionObj) +
        NetworkConnectionOffsets::BufferSize);
    const uint8_t *buffer = *reinterpret_cast<uint8_t **>(
        reinterpret_cast<uintptr_t>(connectionObj) +
        NetworkConnectionOffsets::RecvBuffer);

    if (bufferSize > 0 && buffer &&
        IsValidMemoryAddress(reinterpret_cast<uintptr_t>(buffer), bufferSize)) {
    }
  }

  return s_origSocketHandler ? s_origSocketHandler(connectionObj) : 0;
}

void __fastcall NetworkHooks::DetourIPCDispatcher(void *thisPtr,
                                                  uint32_t actorId,
                                                  void *packetData) {
  auto &inst = GetInstance();

  inst.m_stats.ipcPacketsProcessed++;

  uint16_t opcode = 0;
  if (IsValidMemoryAddress(reinterpret_cast<uintptr_t>(packetData), 16)) {
    opcode = *reinterpret_cast<uint16_t *>(
        reinterpret_cast<uintptr_t>(packetData) + 2);

    std::lock_guard<std::mutex> lock(inst.m_callbackMutex);
    if (inst.m_ipcCallback) {
      const uint8_t *payload =
          reinterpret_cast<const uint8_t *>(packetData) + 16;
      auto span = std::span<const uint8_t>(payload, 512);    

      if (!inst.m_ipcCallback(opcode, actorId, span)) {
        return;
      }
    }
  }

  if (s_origIPCDispatcher) {
    s_origIPCDispatcher(thisPtr, actorId, packetData);
  }
}

void NetworkHooks::SetRawRecvCallback(RawPacketCallback callback) {
  std::lock_guard<std::mutex> lock(m_callbackMutex);
  m_recvCallback = std::move(callback);
}

void NetworkHooks::SetRawSendCallback(RawPacketCallback callback) {
  std::lock_guard<std::mutex> lock(m_callbackMutex);
  m_sendCallback = std::move(callback);
}

void NetworkHooks::SetIPCCallback(IPCPacketCallback callback) {
  std::lock_guard<std::mutex> lock(m_callbackMutex);
  m_ipcCallback = std::move(callback);
}

uintptr_t NetworkHooks::GetSocket() const {
  if (!m_connectionObj)
    return 0;
  if (!IsValidMemoryAddress(reinterpret_cast<uintptr_t>(m_connectionObj), 0x10))
    return 0;
  return *reinterpret_cast<uintptr_t *>(
      reinterpret_cast<uintptr_t>(m_connectionObj) +
      NetworkConnectionOffsets::Socket);
}

uint64_t NetworkHooks::GetBytesReceived() const {
  if (!m_connectionObj)
    return 0;
  if (!IsValidMemoryAddress(reinterpret_cast<uintptr_t>(m_connectionObj), 0xA8))
    return 0;
  return *reinterpret_cast<uint64_t *>(
      reinterpret_cast<uintptr_t>(m_connectionObj) +
      NetworkConnectionOffsets::BytesReceived);
}

const uint8_t *NetworkHooks::GetRecvBuffer() const {
  if (!m_connectionObj)
    return nullptr;
  if (!IsValidMemoryAddress(reinterpret_cast<uintptr_t>(m_connectionObj),
                            0x138))
    return nullptr;
  return *reinterpret_cast<uint8_t **>(
      reinterpret_cast<uintptr_t>(m_connectionObj) +
      NetworkConnectionOffsets::RecvBuffer);
}

uint32_t NetworkHooks::GetBufferSize() const {
  if (!m_connectionObj)
    return 0;
  if (!IsValidMemoryAddress(reinterpret_cast<uintptr_t>(m_connectionObj),
                            0x104))
    return 0;
  return *reinterpret_cast<uint32_t *>(
      reinterpret_cast<uintptr_t>(m_connectionObj) +
      NetworkConnectionOffsets::BufferSize);
}

uint32_t NetworkHooks::GetConnectionState() const {
  if (!m_connectionObj)
    return 0;
  if (!IsValidMemoryAddress(reinterpret_cast<uintptr_t>(m_connectionObj), 0xFC))
    return 0;
  return *reinterpret_cast<uint32_t *>(
      reinterpret_cast<uintptr_t>(m_connectionObj) +
      NetworkConnectionOffsets::ConnectionState);
}

void NetworkHooks::ResetStats() {
  m_stats.packetsReceived.store(0);
  m_stats.packetsSent.store(0);
  m_stats.ipcPacketsProcessed.store(0);
  m_stats.bytesReceived.store(0);
  m_stats.bytesSent.store(0);
}

}   
