#pragma once
#include <functional>
#include <unordered_map>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <vector>

namespace PacketDecoding {

    // Base decoder interface
    using DecoderFunc = std::function<void(const uint8_t* payload, size_t payloadLen,
        std::function<void(const char*, const std::string&)> rowKV)>;

    // Registry for packet decoders
    class PacketDecoderRegistry {
    public:
        static PacketDecoderRegistry& Instance() {
            static PacketDecoderRegistry instance;
            return instance;
        }

        void RegisterDecoder(uint16_t connType, bool outgoing, uint16_t opcode, DecoderFunc decoder) {
            uint64_t key = MakeKey(connType, outgoing, opcode);
            decoders_[key] = decoder;
        }

        bool TryDecode(uint16_t connType, bool outgoing, uint16_t opcode,
            const uint8_t* payload, size_t payloadLen,
            std::function<void(const char*, const std::string&)> rowKV) {
            uint64_t key = MakeKey(connType, outgoing, opcode);
            auto it = decoders_.find(key);
            if (it != decoders_.end()) {
                it->second(payload, payloadLen, rowKV);
                return true;
            }
            return false;
        }

    private:
        // Key layout (current version):
        // bits 32..47 : connType (16 bits)
        // bit  16     : outgoing (1 bit)
        // bits 0..15  : opcode (16 bits)
        // Other bits are zero. This sparse layout matches the original shifts but is now explicit.
        [[nodiscard]] static constexpr uint64_t MakeKey(uint16_t connType, bool outgoing, uint16_t opcode) noexcept {
            return (static_cast<uint64_t>(connType & 0xFFFFu) << 32) |
                   (static_cast<uint64_t>(outgoing ? 1u : 0u) << 16) |
                   static_cast<uint64_t>(opcode & 0xFFFFu);
        }

        std::unordered_map<uint64_t, DecoderFunc> decoders_;
    };

    // Helper template to create decoders from packet structures
    template<typename PacketT>
    class StructDecoder {
    public:
        using FieldDecoder = std::function<void(const PacketT*, std::function<void(const char*, const std::string&)>)>;

        template<typename... Callables>
        static DecoderFunc Create(Callables&&... callables) {
            std::vector<FieldDecoder> fields;
            fields.reserve(sizeof...(callables));
            (fields.emplace_back([fn = std::forward<Callables>(callables)](const PacketT* pkt,
                                                                          std::function<void(const char*, const std::string&)> rowKV) {
                fn(pkt, rowKV);
            }), ...);

            return [fields = std::move(fields)](const uint8_t* payload, size_t payloadLen,
                std::function<void(const char*, const std::string&)> rowKV) {
                    if (payloadLen < sizeof(PacketT)) return;
                    const PacketT* pkt = reinterpret_cast<const PacketT*>(payload);
                    for (const auto& field : fields) {
                        field(pkt, rowKV);
                    }
                };
        }
    };

    // Field extractors
    template<typename T>
    std::string FieldToString(T value) {
        if constexpr (std::is_integral_v<T>) {
            return std::to_string(value);
        }
        else if constexpr (std::is_floating_point_v<T>) {
            std::ostringstream os;
            os << std::fixed << std::setprecision(3) << value;
            return os.str();
        }
        else {
            return "unknown";
        }
    }

    // Special formatters
    inline std::string FormatHex(uint64_t value) {
        std::ostringstream os;
        os << "0x" << std::hex << std::uppercase << value;
        return os.str();
    }

    inline std::string FormatAngle(uint16_t value) {
        float degrees = value * 360.0f / 65535.0f;
        std::ostringstream os;
        os << std::fixed << std::setprecision(1) << degrees << "\u00B0";
        return os.str();
    }

    inline std::string FormatAngle(float radians) {
        float degrees = (radians * 180.0f) / 3.14159265358979323846f;
        std::ostringstream os;
        os << std::fixed << std::setprecision(1) << degrees << "\u00B0";
        return os.str();
    }

    inline std::string FormatPosition(float x, float y, float z) {
        std::ostringstream os;
        os << "(" << std::fixed << std::setprecision(3)
            << x << ", " << y << ", " << z << ")";
        return os.str();
    }

    inline std::string FormatString(const char* str, size_t maxLen) {
        if (!str) return "";
        return std::string(str, strnlen(str, maxLen));
    }

    inline std::string FormatBool(bool value) {
        return value ? "true" : "false";
    }

    inline std::string FormatPercent(float value) {
        std::ostringstream os;
        os << std::fixed << std::setprecision(1) << (value * 100.0f) << "%";
        return os.str();
    }

    // Helper functions for common packet fields
    inline const char* GetActionTypeName(uint8_t type);
    inline const char* GetStatusEffectName(uint16_t id);
    inline const char* GetChatTypeName(uint16_t type);
    inline const char* GetWarpTypeName(uint8_t type);
}