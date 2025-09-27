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
                if (i > 0) os << ", ";  // Changed from 'if (i)' to 'if (i > 0)'
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
                    rowKV("error", "payload too small");
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
                    rowKV("error", "payload too small");
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
            if (i > 0) os << ", ";  // Changed from 'if (i)' to 'if (i > 0)'
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

} // namespace PacketDecoding