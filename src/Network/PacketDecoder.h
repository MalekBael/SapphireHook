#pragma once
#include <functional>
#include <unordered_map>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <algorithm> // std::min
#include <span>
#include <array>
#include <tuple>
#include <type_traits>

// Defuse Windows min/max macros if <windows.h> was included earlier without NOMINMAX
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

namespace PacketDecoding {
    using RowEmitter = std::function<void(const char*, const std::string&)>;
    using DecoderFunc = std::function<void(const uint8_t* payload, size_t payloadLen,
        std::function<void(const char*, const std::string&)> rowKV)>;

    // Move DumpBytesAsHex BEFORE any use (FieldStringifier / ValueToString)
    inline std::string DumpBytesAsHex(std::span<const uint8_t> bytes, size_t maxLen = 32) {
        std::ostringstream os;
        os << std::hex << std::uppercase << std::setfill('0');
        size_t shown = std::min(bytes.size(), maxLen);
        for (size_t i = 0; i < shown; ++i) {
            if (i) os << ' ';
            os << std::setw(2) << static_cast<int>(bytes[i]);
        }
        if (shown < bytes.size()) os << " ...";
        return os.str();
    }

    class PacketDecoderRegistry {
    public:
        static PacketDecoderRegistry& Instance() {
            static PacketDecoderRegistry instance;
            return instance;
        }
        void RegisterDecoder(uint16_t connType, bool outgoing, uint16_t opcode, DecoderFunc decoder) {
            uint64_t key = MakeKey(connType, outgoing, opcode);
            decoders_[key] = std::move(decoder);
        }
        bool TryDecode(uint16_t connType, bool outgoing, uint16_t opcode,
            const uint8_t* payload, size_t payloadLen,
            std::function<void(const char*, const std::string&)> rowKV) {
            uint64_t key = MakeKey(connType, outgoing, opcode);
            auto it = decoders_.find(key);
            if (it != decoders_.end()) {
                it->second(payload, payloadLen, std::move(rowKV));
                return true;
            }
            return false;
        }
    private:
        [[nodiscard]] static constexpr uint64_t MakeKey(uint16_t connType, bool outgoing, uint16_t opcode) noexcept {
            return (static_cast<uint64_t>(connType & 0xFFFFu) << 32) |
                   (static_cast<uint64_t>(outgoing ? 1u : 0u) << 16) |
                   static_cast<uint64_t>(opcode & 0xFFFFu);
        }
        std::unordered_map<uint64_t, DecoderFunc> decoders_;
    };

    struct FieldStringifier {
        template<typename T>
        static std::string ToString(const T& value) {
            if constexpr (std::is_same_v<T, bool>) {
                return value ? "true" : "false";
            } else if constexpr (std::is_integral_v<T> && !std::is_same_v<T,char> &&
                                 !std::is_same_v<T,signed char> && !std::is_same_v<T,unsigned char>) {
                std::ostringstream os;
                os << value << " (0x" << std::hex << std::uppercase << static_cast<uint64_t>(value) << ")";
                return os.str();
            } else if constexpr (std::is_floating_point_v<T>) {
                std::ostringstream os; os << value; return os.str();
            } else {
                return DumpBytesAsHex(std::span(reinterpret_cast<const uint8_t*>(&value), sizeof(T)));
            }
        }
        template<size_t N>
        static std::string ToString(const char (&value)[N]) {
            size_t len = strnlen(value, N);
            return std::string(value, len);
        }
        template<typename T, size_t N>
        static std::string ToString(const T(&value)[N]) {
            std::ostringstream os;
            os << "[";
            for (size_t i = 0; i < N; ++i) {
                if (i > 0) os << ", ";
                os << ToString(value[i]);
            }
            os << "]";
            return os.str();
        }
        static std::string ToStringRaw(const uint8_t* data, size_t size) {
            return DumpBytesAsHex(std::span(data, size));
        }
    };

    template<typename PacketT>
    struct FieldDescriptor {
        const char* name;
        size_t offset;
        size_t size;
        template<typename MemberT>
        static consteval FieldDescriptor Make(const char* fieldName, MemberT PacketT::*member) {
            return FieldDescriptor{ fieldName, offsetof(PacketT, member), sizeof(MemberT) };
        }
    };

    template<typename PacketT>
    struct StructDecoder {
        template<size_t N>
        static DecoderFunc Create(const std::array<FieldDescriptor<PacketT>, N>& descriptors) {
            return [descriptors](const uint8_t* payload, size_t payloadLen,
                                 std::function<void(const char*, const std::string&)> rowKV) {
                if (payloadLen < sizeof(PacketT)) {
                    std::ostringstream em;
                    em << "payload too small (have " << payloadLen
                       << ", need " << sizeof(PacketT) << ")";
                    rowKV("error", em.str());
                    return;
                }
                const PacketT* pkt = reinterpret_cast<const PacketT*>(payload);
                for (const auto& field : descriptors) {
                    const uint8_t* fieldPtr = reinterpret_cast<const uint8_t*>(pkt) + field.offset;
                    rowKV(field.name, FieldStringifier::ToStringRaw(fieldPtr, field.size));
                }
            };
        }
        template<typename... FieldEmitters>
        static std::enable_if_t<(... && std::is_invocable_v<FieldEmitters, const PacketT*, RowEmitter>), DecoderFunc>
        Create(FieldEmitters... emitters) {
            return [=](const uint8_t* payload, size_t payloadLen, RowEmitter rowKV) {
                if (payloadLen < sizeof(PacketT)) {
                    std::ostringstream em;
                    em << "payload too small (have " << payloadLen
                       << ", need " << sizeof(PacketT) << ")";
                    rowKV("error", em.str());
                    return;
                }
                const PacketT* pkt = reinterpret_cast<const PacketT*>(payload);
                (emitters(pkt, rowKV), ...);
            };
        }
    };

    template<typename T>
    std::string ValueToString(const T& value) {
        if constexpr (std::is_same_v<T,bool>) return value ? "true" : "false";
        else if constexpr (std::is_integral_v<T> && !std::is_same_v<T,char> &&
                 !std::is_same_v<T,signed char> && !std::is_same_v<T,unsigned char>) {
            std::ostringstream os;
            os << value << " (0x" << std::hex << std::uppercase << static_cast<uint64_t>(value) << ")";
            return os.str();
        } else if constexpr (std::is_floating_point_v<T>) {
            std::ostringstream os; os << value; return os.str();
        } else {
            return DumpBytesAsHex(std::span(reinterpret_cast<const uint8_t*>(&value), sizeof(T)));
        }
    }
    template<size_t N>
    std::string ValueToString(const char (&value)[N]) {
        return std::string(value, strnlen(value, N));
    }
    template<typename T, size_t N>
    std::string ValueToString(const T(&value)[N]) {
        std::ostringstream os;
        os << "[";
        for (size_t i = 0; i < N; ++i) {
            if (i > 0) os << ", ";
            os << ValueToString(value[i]);
        }
        os << "]";
        return os.str();
    }

    template<typename PacketT>
    using FieldEmitter = std::function<void(const PacketT*, const RowEmitter&)>;
    template<typename PacketT, typename MemberT>
    FieldEmitter<PacketT> MakeField(const char* name, MemberT PacketT::*member) {
        return [=](const PacketT* pkt, const RowEmitter& emit) {
            emit(name, ValueToString(pkt->*member));
        };
    }

    template<typename PacketT, size_t N>
    DecoderFunc MakeStructDecoder(const std::array<FieldEmitter<PacketT>, N>& emitters) {
        return [emitters](const uint8_t* payload, size_t payloadLen, RowEmitter rowKV) {
            if (payloadLen < sizeof(PacketT)) {
                rowKV("error", "payload too small");
                return;
            }
            const PacketT* pkt = reinterpret_cast<const PacketT*>(payload);
            for (const auto& emit : emitters) emit(pkt, rowKV);
        };
    }

    template<typename T>
    std::string FieldToString(T value) {
        if constexpr (std::is_integral_v<T>) return std::to_string(value);
        else if constexpr (std::is_floating_point_v<T>) {
            std::ostringstream os; os << std::fixed << std::setprecision(3) << value; return os.str();
        } else return "unknown";
    }

    inline std::string FormatHex(uint64_t value) {
        std::ostringstream os; os << "0x" << std::hex << std::uppercase << value; return os.str();
    }
    inline std::string FormatAngle(uint16_t value) {
        float degrees = value * 360.0f / 65535.0f;
        std::ostringstream os; os << std::fixed << std::setprecision(1) << degrees << "\u00B0"; return os.str();
    }
    inline std::string FormatAngle(float radians) {
        float degrees = (radians * 180.0f) / 3.14159265358979323846f;
        std::ostringstream os; os << std::fixed << std::setprecision(1) << degrees << "\u00B0"; return os.str();
    }
    inline std::string FormatPosition(float x, float y, float z) {
        std::ostringstream os; os << "(" << std::fixed << std::setprecision(3) << x << ", " << y << ", " << z << ")"; return os.str();
    }
    inline std::string FormatString(const char* str, size_t maxLen) {
        if (!str) return "";
        return std::string(str, strnlen(str, maxLen));
    }
    inline std::string FormatBool(bool v) { return v ? "true" : "false"; }
    inline std::string FormatPercent(float value) {
        std::ostringstream os; os << std::fixed << std::setprecision(1) << (value * 100.0f) << "%"; return os.str();
    }

    inline const char* GetActionTypeName(uint8_t type);
    inline const char* GetStatusEffectName(uint16_t id);
    inline const char* GetChatTypeName(uint16_t type);
    inline const char* GetWarpTypeName(uint8_t type);

    struct OverlayField {
        const char* name = nullptr;
        size_t offset = 0;
        size_t size = 0;
        std::string value{};
        std::string rawPreview{};
    };
    struct OverlayLayer {
        std::string name;
        size_t globalOffset = 0;
        size_t length = 0;
        std::vector<OverlayField> fields;
    };
    struct PacketOverlayContext {
        const uint8_t* fullPacket = nullptr;
        size_t fullPacketLen = 0;
        const uint8_t* packetHeader = nullptr;
        size_t packetHeaderLen = 0;
        const uint8_t* segmentHeader = nullptr;
        size_t segmentHeaderLen = 0;
        const uint8_t* ipcHeader = nullptr;
        size_t ipcHeaderLen = 0;
        const uint8_t* payload = nullptr;
        size_t payloadLen = 0;
        uint16_t connectionType = 0;
        uint16_t segmentType = 0;
        uint16_t opcode = 0;
        bool isIPC = false;
        std::vector<OverlayLayer> layersBuilt;
        bool finalized = false;
        void Reset() {
            fullPacket = packetHeader = segmentHeader = ipcHeader = payload = nullptr;
            fullPacketLen = packetHeaderLen = segmentHeaderLen = ipcHeaderLen = payloadLen = 0;
            connectionType = segmentType = opcode = 0;
            isIPC = false;
            layersBuilt.clear();
            finalized = false;
        }
    };

    PacketOverlayContext& GetOverlayContext();

    inline void BeginOverlayCapture(const uint8_t* fullPkt, size_t fullLen,
        const uint8_t* pktHdr, size_t pktHdrLen,
        const uint8_t* segHdr, size_t segHdrLen,
        const uint8_t* ipcHdr, size_t ipcHdrLen,
        const uint8_t* payloadPtr, size_t payloadLen,
        uint16_t connType, uint16_t segType, bool isIPC, uint16_t opcode)
    {
        auto& ctx = GetOverlayContext();
        ctx.Reset();
        ctx.fullPacket = fullPkt;
        ctx.fullPacketLen = fullLen;
        ctx.packetHeader = pktHdr;
        ctx.packetHeaderLen = pktHdrLen;
        ctx.segmentHeader = segHdr;
        ctx.segmentHeaderLen = segHdrLen;
        ctx.ipcHeader = ipcHdr;
        ctx.ipcHeaderLen = ipcHdrLen;
        ctx.payload = payloadPtr;
        ctx.payloadLen = payloadLen;
        ctx.connectionType = connType;
        ctx.segmentType = segType;
        ctx.isIPC = isIPC;
        ctx.opcode = opcode;
    }

    inline std::string HexPreview(const uint8_t* p, size_t len, size_t maxBytes = 8) {
        if (!p || len == 0) return "";
        std::ostringstream os;
        os << std::hex << std::uppercase << std::setfill('0');
        size_t show = (std::min)(len, maxBytes);
        for (size_t i = 0; i < show; i++) {
            if (i) os << ' ';
            os << std::setw(2) << (unsigned)p[i];
        }
        if (show < len) os << " ...";
        return os.str();
    }

    inline void PushOverlayLayer(const char* name,
        const uint8_t* /*base*/,
        size_t len,
        size_t globalOffset) {
        auto& ctx = GetOverlayContext();
        OverlayLayer L;
        L.name = name ? name : "Layer";
        L.globalOffset = globalOffset;
        L.length = len;
        ctx.layersBuilt.emplace_back(std::move(L));
    }

    inline void AddOverlayField(const char* name,
        size_t offsetWithinLayer,
        size_t size,
        const std::string& value,
        const uint8_t* layerBase)
    {
        auto& ctx = GetOverlayContext();
        if (ctx.layersBuilt.empty()) return;
        OverlayField f;
        f.name = name;
        f.offset = offsetWithinLayer;
        f.size = size;
        f.value = value;
        if (layerBase && offsetWithinLayer + size <= SIZE_MAX)
            f.rawPreview = HexPreview(layerBase + offsetWithinLayer, size);
        ctx.layersBuilt.back().fields.emplace_back(std::move(f));
    }

    inline std::vector<OverlayLayer> GetOverlayLayersSnapshot() {
        return GetOverlayContext().layersBuilt;
    }

    inline void ForEachOverlayField(const std::function<void(const OverlayLayer&, const OverlayField&)>& cb) {
        auto layers = GetOverlayLayersSnapshot();
        for (auto& L : layers)
            for (auto& F : L.fields)
                cb(L, F);
    }

    template<typename PacketT, typename MemberT, size_t N>
    constexpr auto MakeArrayField(const char* name, MemberT(PacketT::*member)[N]) {
        return [=](const PacketT* pkt, auto rowKV) {
            std::ostringstream os;
            os << "[";
            for (size_t i = 0; i < N; ++i) {
                if (i) os << ", ";
                os << FieldToString((pkt->*member)[i]);
            }
            os << "]";
            rowKV(name, os.str());
        };
    }

    struct SizeMismatchStat { uint64_t attempts=0, failures=0; };
    inline SizeMismatchStat& GetSizeMismatchStat() { static SizeMismatchStat s; return s; }

// ----- Adaptive variant helper (add near bottom of header) -----
    struct AdaptiveVariant {
        size_t size;  // canonical size of this variant
        // return false if decode should be considered failed (e.g. magic mismatch)
        std::function<bool(const uint8_t* payload, size_t len, const RowEmitter&)> decode;
        const char* name;
    };

    inline void RegisterAdaptivePacket(uint16_t connType,
                                       bool outgoing,
                                       uint16_t opcode,
                                       std::vector<AdaptiveVariant> variants,
                                       size_t minRequired = 0)
    {
        // Sort longest->shortest so longest exact match gets first chance on len >= size
        std::sort(variants.begin(), variants.end(),
                  [](auto& a, auto& b){ return a.size > b.size; });

        PacketDecoderRegistry::Instance().RegisterDecoder(
            connType, outgoing, opcode,
            [variants = std::move(variants), minRequired, opcode]
            (const uint8_t* payload, size_t len, RowEmitter emit)
            {
                if (len < minRequired) {
                    std::ostringstream os;
                    os << "payload too small (have " << len << ", need >= " << minRequired << ")";
                    emit("error", os.str());
                    return;
                }

                // Pass 1: exact size match
                for (auto& v : variants) {
                    if (len == v.size) {
                        if (v.decode(payload, len, emit)) return;
                    }
                }
                // Pass 2: largest variant whose declared size <= len
                for (auto& v : variants) {
                    if (len >= v.size) {
                        if (v.decode(payload, len, emit)) {
                            if (len != v.size) {
                                std::ostringstream os;
                                os << "note: extra tail bytes (" << (len - v.size)
                                   << ") beyond variant '" << v.name << "'";
                                emit("_tailInfo", os.str());
                            }
                            return;
                        }
                    }
                }

                std::ostringstream os;
                os << "unhandled size " << len << " for opcode 0x"
                   << std::hex << std::uppercase << opcode;
                emit("error", os.str());
            }
        );
    }

// ============================================================================
// Added helper: auto-strip outer transport/session framing to mirror external
// capture tool (find embedded IPC segment of form: [len][...header(0x10-0x14)])
// ============================================================================

    // Forward declaration so we can validate opcode candidates.
    const char* LookupOpcodeName(uint16_t opcode, bool outgoing, uint16_t connectionType) noexcept;

    struct ExtractedIpcSegment {
        bool   valid = false;
        size_t outerSkip = 0;
        const uint8_t* segmentStart = nullptr;
        size_t segmentLen = 0;
        const uint8_t* ipcHeader = nullptr;
        size_t ipcHeaderLen = 0x14;   // current fixed assumption
        const uint8_t* payload = nullptr;
        size_t payloadLen = 0;
        uint16_t opcode = 0;
        uint16_t connectionTypeGuess = 1; // 1 = zone
    };

    inline uint32_t ReadLE32(const uint8_t* p) {
        return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
    }
    inline uint16_t ReadLE16(const uint8_t* p) {
        return (uint16_t)p[0] | ((uint16_t)p[1]<<8);
    }

    inline bool IsLikelyOpcode(uint16_t opc) {
        // Try both directions (incoming/outgoing) for zone (1) & chat(2)
        if (LookupOpcodeName(opc, false, 1) != "?") return true;
        if (LookupOpcodeName(opc, true, 1)  != "?") return true;
        if (LookupOpcodeName(opc, false, 2) != "?") return true;
        if (LookupOpcodeName(opc, true, 2)  != "?") return true;
        return false;
    }

    inline ExtractedIpcSegment TryExtractIpcSegment(const uint8_t* full, size_t fullLen) {
        ExtractedIpcSegment r;
        if (!full || fullLen < 0x20) return r;

        // Common offsets where the length field has been observed after outer framing.
        static const size_t kCandidateOffsets[] = {
            0, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28
        };

        for (size_t off : kCandidateOffsets) {
            if (off + 4 > fullLen) continue;
            uint32_t segLen = ReadLE32(full + off);
            if (segLen < 0x14) continue;                 // too small
            if (segLen > fullLen - off) continue;        // past end
            // For now require exact remainder match (mirrors external tool)
            if (segLen != fullLen - off) continue;

            // Minimum IPC header we rely on: opcode at offset +0x12 (after two 32-bit + routing shorts pattern)
            if (off + 0x12 + 2 > fullLen) continue;
            uint16_t opc = ReadLE16(full + off + 0x12);
            if (!IsLikelyOpcode(opc)) continue;

            // Assume fixed 0x14 header for now (observed)
            size_t ipcHeaderLen = 0x14;
            if (segLen < ipcHeaderLen) continue;

            r.valid        = true;
            r.outerSkip    = off;
            r.segmentStart = full + off;
            r.segmentLen   = segLen;
            r.ipcHeader    = full + off;
            r.ipcHeaderLen = ipcHeaderLen;
            r.payload      = full + off + ipcHeaderLen;
            r.payloadLen   = segLen - ipcHeaderLen;
            r.opcode       = opc;
            // Guess connection type: if opcode known only in zone table usually 1.
            r.connectionTypeGuess = 1;
            break;
        }
        return r;
    }

    inline bool StripAndDecodeIpc(const uint8_t* full, size_t fullLen,
                                  bool outgoing,
                                  RowEmitter emit,
                                  uint16_t explicitConnType = 0xFFFF)
    {
        auto seg = TryExtractIpcSegment(full, fullLen);
        if (!seg.valid) return false;

        uint16_t connType = (explicitConnType == 0xFFFF) ? seg.connectionTypeGuess : explicitConnType;

        // Overlay capture (outer framing = seg.outerSkip bytes)
        BeginOverlayCapture(full, fullLen,
                            full, seg.outerSkip,     // treat 'packetHeader' as the stripped outer region
                            nullptr, 0,              // segmentHeader unused
                            seg.ipcHeader, seg.ipcHeaderLen,
                            seg.payload, seg.payloadLen,
                            connType, /*segType*/0, true, seg.opcode);

        // Emit a few meta rows (optional)
        emit("_strip.outerSkip", std::to_string(seg.outerSkip));
        emit("_strip.segmentLen", std::to_string(seg.segmentLen));
        emit("_strip.opcode", FormatHex(seg.opcode));

        // Forward to registered decoder
        if (!PacketDecoderRegistry::Instance().TryDecode(connType, outgoing, seg.opcode,
                                                         seg.payload, seg.payloadLen, emit)) {
            emit("decoder", "no registered decoder");
        }
        return true;
    }

// ============================================================================
// ADD near the bottom (just before the closing namespace) – refined strip helpers using known ConnectionType

    // If you have a known connection type (Zone=1, Chat=2, Lobby=3) you can
    // reduce false positives by validating opcodes only against that table.
    inline bool IsLikelyOpcodeForConn(uint16_t opc, uint16_t connType) {
        // Lobby currently shares most with zone table; treat Lobby like Zone.
        uint16_t eff = (connType == 3) ? 1 : connType;
        if (LookupOpcodeName(opc, false, eff) != "?") return true;
        if (LookupOpcodeName(opc, true,  eff) != "?") return true;
        return false;
    }

    struct ExtractedIpcSegmentKnown {
        bool   valid = false;
        size_t outerSkip = 0;
        const uint8_t* segmentStart = nullptr;
        size_t segmentLen = 0;
        const uint8_t* ipcHeader = nullptr;
        size_t ipcHeaderLen = 0x14;   // current fixed assumption
        const uint8_t* payload = nullptr;
        size_t payloadLen = 0;
        uint16_t opcode = 0;
    };

    inline ExtractedIpcSegmentKnown TryExtractIpcSegmentKnown(const uint8_t* full, size_t fullLen, uint16_t connType) {
        ExtractedIpcSegmentKnown r;
        if (!full || fullLen < 0x20) return r;

        // Offsets where the 32-bit segment length has been observed (outer framing sizes).
        static const size_t kCandidateOffsets[] { 0, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28 };

        for (size_t off : kCandidateOffsets) {
            if (off + 4 > fullLen) continue;
            uint32_t segLen = ReadLE32(full + off);
            if (segLen < 0x14) continue;
            if (segLen > fullLen - off) continue;
            if (segLen != fullLen - off) continue; // require exact remainder for now

            if (off + 0x12 + 2 > fullLen) continue;
            uint16_t opc = ReadLE16(full + off + 0x12);
            if (!IsLikelyOpcodeForConn(opc, connType)) continue;

            // Basic header sanity: we often see two repeating 16-bit IDs at +0x04..0x0B; optional future check.
            r.valid        = true;
            r.outerSkip    = off;
            r.segmentStart = full + off;
            r.segmentLen   = segLen;
            r.ipcHeader    = full + off;
            r.payload      = full + off + r.ipcHeaderLen;
            r.payloadLen   = segLen - r.ipcHeaderLen;
            r.opcode       = opc;
            break;
        }
        return r;
    }

    // Public helper: strip outer frame (if present) and dispatch to registered decoder.
    // Returns true if an IPC segment was found & dispatched.
    inline bool StripAndDecodeIpcKnown(const uint8_t* full,
                                       size_t fullLen,
                                       uint16_t connectionType, // 1=Zone,2=Chat,3=Lobby
                                       bool outgoing,
                                       RowEmitter emit)
    {
        auto seg = TryExtractIpcSegmentKnown(full, fullLen, connectionType);
        if (!seg.valid) return false;

        BeginOverlayCapture(full, fullLen,
                            full, seg.outerSkip,
                            nullptr, 0,
                            seg.ipcHeader, seg.ipcHeaderLen,
                            seg.payload, seg.payloadLen,
                            connectionType, 0, true, seg.opcode);

        emit("_strip.outerSkip", std::to_string(seg.outerSkip));
        emit("_strip.segmentLen", std::to_string(seg.segmentLen));
        emit("_strip.opcode", FormatHex(seg.opcode));

        if (!PacketDecoderRegistry::Instance().TryDecode(connectionType, outgoing, seg.opcode,
                                                         seg.payload, seg.payloadLen, emit)) {
            emit("decoder", "no registered decoder");
        }
        return true;
    }
} // namespace PacketDecoding