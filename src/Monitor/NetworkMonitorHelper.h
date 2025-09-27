#pragma once
#include <string>
#include <vector>
#include <cstdint>

#include "NetworkMonitorTypes.h"   // now provides ParsedPacket / SegmentInfo / SegmentView

struct HookPacket;

namespace NetworkMonitorHelper {

    enum class ParseKind { Ok, Incomplete, Malformed };

    struct ParseStatus {
        ParseKind kind = ParseKind::Ok;
        std::string reason;
        bool IsOk() const { return kind == ParseKind::Ok; }
    };

    ParseStatus ValidatePacketStructure(const HookPacket& hp,
        const ParsedPacket& P,
        const SegmentView& view,
        const std::vector<SegmentInfo>& segs);

    inline const char* StatusTag(ParseKind k) {
        switch (k) {
        case ParseKind::Malformed:  return "[M] ";
        case ParseKind::Incomplete: return "[I] ";
        default: return "";
        }
    }
}