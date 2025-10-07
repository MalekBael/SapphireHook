#include "PacketDecoder.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include "../Network/OpcodeNames.h"

namespace PacketDecoding {

    using json = nlohmann::json;

    std::string PacketDecoder::ExportToEnhancedJson(const ParsedFFXIVPacket& packet) const {
        json root;

        // Connection metadata
        root["connectionId"] = packet.connectionId;
        root["direction"] = packet.outgoing ? "SEND" : "RECV";
        root["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            packet.captureTime.time_since_epoch()).count();
        root["captureTime"] = FormatTimestamp(packet.captureTime);

        // Full header information
        json header;
        header["magic"] = FormatHex64(packet.header.magic0) + " " + FormatHex64(packet.header.magic1);
        header["size"] = packet.header.size;
        header["timestamp"] = packet.header.timestamp;
        header["connectionType"] = packet.header.connType;
        header["connectionTypeName"] = [&]() -> std::string {
            switch (packet.header.connType) {
                case 0: return "Zone";
                case 1: return "Chat";
                case 2: return "Lobby";
                default: return "Unknown";
            }
        }();
        header["segmentCount"] = packet.header.segCount;
        header["isCompressed"] = packet.header.isCompressed != 0;
        header["unknown20"] = FormatHex8(packet.header.unknown20);
        header["unknown24"] = FormatHex32(packet.header.unknown24);
        root["header"] = header;

        // Process segments with full decoding
        json segments = json::array();
        auto& registry = PacketDecoderRegistry::Instance();

        for (size_t i = 0; i < packet.segments.size(); ++i) {
            const auto& seg = packet.segments[i];
            json segJson;

            // Basic segment information
            segJson["index"] = i;
            segJson["offset"] = seg.header.offset;
            segJson["size"] = seg.header.size;
            segJson["type"] = seg.header.type;
            segJson["typeName"] = GetSegmentTypeName(seg.header.type);
            segJson["sourceActor"] = FormatHex32(seg.header.srcId) + " (" + std::to_string(seg.header.srcId) + ")";
            segJson["targetActor"] = FormatHex32(seg.header.tgtId) + " (" + std::to_string(seg.header.tgtId) + ")";
            segJson["padding"] = FormatHex16(seg.header.pad);

            if (seg.header.type == 3) { // IPC segment
                json ipc;
                ipc["opcode"] = FormatHex16(seg.opcode);
                ipc["opcodeName"] = LookupOpcodeName(seg.opcode, packet.outgoing, packet.header.connType);
                ipc["serverId"] = seg.serverId;
                ipc["timestamp"] = seg.timestamp;
                ipc["reserved"] = FormatHex16(seg.ipcReserved);
                ipc["padding"] = FormatHex16(seg.ipcPad);

                json decodedFields = json::object();
                bool hasDecoded = false;

                RowEmitter jsonEmitter = [&decodedFields, &hasDecoded](const std::string& key, const std::string& value) {
                    size_t dotPos = key.find('.');
                    if (dotPos != std::string::npos) {
                        std::string parent = key.substr(0, dotPos);
                        std::string child = key.substr(dotPos + 1);
                        if (!decodedFields.contains(parent)) {
                            decodedFields[parent] = json::object();
                        }
                        decodedFields[parent][child] = value;
                    } else {
                        decodedFields[key] = value;
                    }
                    hasDecoded = true;
                };

                try {
                    (void)registry.TryDecode(
                        packet.header.connType,
                        packet.outgoing,
                        seg.opcode,
                        seg.data.data(),
                        seg.data.size(),
                        jsonEmitter
                    );
                } catch (const std::exception& e) {
                    segJson["decodeError"] = e.what();
                }

                if (hasDecoded) {
                    ipc["decodedPayload"] = decodedFields;
                }

                ipc["payloadHex"] = BytesToHex(seg.data, 256);
                ipc["payloadSize"] = seg.data.size();

                segJson["ipc"] = ipc;
            } else {
                segJson["dataHex"] = BytesToHex(seg.data, 64);
                segJson["dataSize"] = seg.data.size();
            }

            segments.push_back(segJson);
        }
        root["segments"] = segments;

        // Summary statistics
        json summary;
        summary["totalSize"] = packet.rawData.size();
        summary["segmentCount"] = packet.segments.size();

        int ipcCount = 0;
        json opcodeList = json::array();
        for (const auto& seg : packet.segments) {
            if (seg.header.type == 3) {
                ipcCount++;
                std::ostringstream os;
                os << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << seg.opcode;
                const char* name = LookupOpcodeName(seg.opcode, packet.outgoing, packet.header.connType);
                if (name && name[0] != '?' && name[0] != '\0') {
                    os << " (" << name << ")";
                }
                opcodeList.push_back(os.str());
            }
        }
        summary["ipcSegments"] = ipcCount;
        summary["opcodes"] = opcodeList;
        root["summary"] = summary;

        if (includeRawData_) {
            root["rawDataHex"] = BytesToHex(packet.rawData);
        }

        return root.dump(2);
    }

    std::string PacketDecoder::BytesToHex(const std::vector<uint8_t>& data, size_t maxBytes) const {
        std::ostringstream hexStream;
        hexStream << std::hex << std::uppercase << std::setfill('0');

        size_t len = (maxBytes > 0 && data.size() > maxBytes) ? maxBytes : data.size();
        for (size_t i = 0; i < len; ++i) {
            hexStream << std::setw(2) << static_cast<int>(data[i]);
        }

        if (maxBytes > 0 && data.size() > maxBytes) {
            hexStream << "... (" << std::dec << data.size() << " bytes total)";
        }

        return hexStream.str();
    }

    std::string PacketDecoder::FormatTimestamp(std::chrono::steady_clock::time_point tp) const {
        // Convert steady_clock to system_clock using a safe delta cast
        auto nowSteady = std::chrono::steady_clock::now();
        auto nowSys = std::chrono::system_clock::now();
        auto delta = tp - nowSteady;
        auto sysTp = nowSys + std::chrono::duration_cast<std::chrono::system_clock::duration>(delta);

        std::time_t tt = std::chrono::system_clock::to_time_t(sysTp);
        std::tm tm = *std::localtime(&tt);
        std::ostringstream os;
        os << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");

        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()) % std::chrono::milliseconds(1000);
        os << "." << std::setfill('0') << std::setw(3) << ms.count();

        return os.str();
    }

    const char* PacketDecoder::GetSegmentTypeName(uint16_t type) const {
        switch (type) {
        case 1: return "SessionInit";
        case 2: return "SessionRecv";
        case 3: return "IPC";
        case 7: return "ClientKeepAlive";
        case 8: return "ServerKeepAlive";
        case 9: return "EncryptionInit";
        default: return "Unknown";
        }
    }

    std::string PacketDecoder::FormatHex8(uint8_t value) const {
        std::ostringstream os;
        os << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
            << static_cast<int>(value);
        return os.str();
    }

    std::string PacketDecoder::FormatHex16(uint16_t value) const {
        std::ostringstream os;
        os << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << value;
        return os.str();
    }

    std::string PacketDecoder::FormatHex32(uint32_t value) const {
        std::ostringstream os;
        os << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << value;
        return os.str();
    }

    std::string PacketDecoder::FormatHex64(uint64_t value) const {
        std::ostringstream os;
        os << "0x" << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << value;
        return os.str();
    }

} // namespace PacketDecoding