#include "NetworkMonitorHelper.h"
#include "NetworkMonitor.h"

using namespace NetworkMonitorHelper;

ParseStatus NetworkMonitorHelper::ValidatePacketStructure(const HookPacket& hp,
                                                          const ParsedPacket& P,
                                                          const SegmentView& v,
                                                          const std::vector<SegmentInfo>& segs)
{
    ParseStatus st;

    if (!P.hdr_ok) {
        if (hp.len < 0x28) {
            st.kind = ParseKind::Incomplete;
            st.reason = "Need >= 0x28 bytes for base header";
        } else {
            st.kind = ParseKind::Malformed;
            st.reason = "Header field parse failed";
        }
        return st;
    }

    if (P.size > (1u << 20)) {
        st.kind = ParseKind::Malformed;
        st.reason = "Packet size exceeds 1MB cap";
        return st;
    }
    if (P.segCount > 255) {
        st.kind = ParseKind::Malformed;
        st.reason = "Segment count > 255";
        return st;
    }

    for (const auto& s : segs) {
        if (s.size > 256u * 1024u) {
            st.kind = ParseKind::Malformed;
            st.reason = "Segment size > 256KB";
            return st;
        }
        if (s.size < 0x10) {
            st.kind = ParseKind::Malformed;
            st.reason = "Segment size < 0x10";
            return st;
        }
    }

    if (P.segCount && !P.isCompressed) {
        if (segs.size() != P.segCount) {
            st.kind = ParseKind::Malformed;
            st.reason = "Parsed segment count (" + std::to_string(segs.size()) +
                        ") != header count (" + std::to_string(P.segCount) + ")";
            return st;
        }
    }

    if (!P.isCompressed && P.size >= 0x28) {
        uint32_t expectedBody = P.size - 0x28;
        uint64_t sum = 0;
        for (auto& s : segs) sum += s.size;
        if (expectedBody != sum) {
            st.kind = ParseKind::Malformed;
            st.reason = "Body size mismatch: header=" + std::to_string(expectedBody) +
                        " sumSegments=" + std::to_string(sum);
            return st;
        }
    }

    if (P.isCompressed && v.compressed && !v.inflated) {
        st.kind = ParseKind::Incomplete;
        st.reason = "Compressed body not inflated (possible partial capture)";
        return st;
    }

    return st;
}