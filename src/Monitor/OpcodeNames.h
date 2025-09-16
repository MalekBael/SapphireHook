#pragma once
#include <cstdint>

// Simple opcode name lookup used by the Network Monitor UI.
// Direction hint: outgoing = client->server, incoming = server->client.
// connectionType is taken from packet header and used to disambiguate
// chat vs zone connections (0/2 => chat, otherwise zone). If omitted,
// a best-effort lookup is done.
const char* LookupOpcodeName(uint16_t opcode, bool outgoing, uint16_t connectionType = 0xFFFF) noexcept;
