/**
 * @file PacketDatabase.cpp
 * @brief SQLite-based persistent packet capture storage implementation
 */

#include "PacketDatabase.h"
#include "../Logger/Logger.h"
#include "../Core/LibraryIntegration.h"
#include <sqlite3.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>

namespace SapphireHook {

PacketDatabase& PacketDatabase::Instance() {
    static PacketDatabase instance;
    return instance;
}

PacketDatabase::~PacketDatabase() {
    Shutdown();
}

bool PacketDatabase::Initialize(const std::string& dbPath) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized) {
        LogWarning("[PacketDatabase] Already initialized");
        return true;
    }
    
    // Use default path in temp directory if not specified
    if (dbPath.empty()) {
        auto tempDir = Logger::GetDefaultTempDir();
        std::filesystem::create_directories(tempDir);
        m_dbPath = (tempDir / "packets.db").string();
    } else {
        m_dbPath = dbPath;
    }
    
    LogInfo(fmt::format("[PacketDatabase] Initializing database at: {}", m_dbPath));
    
    // Open database
    int rc = sqlite3_open(m_dbPath.c_str(), &m_db);
    if (rc != SQLITE_OK) {
        LogError(fmt::format("[PacketDatabase] Failed to open database: {}", 
            sqlite3_errmsg(m_db)));
        return false;
    }
    
    // Enable WAL mode for better concurrent access
    sqlite3_exec(m_db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(m_db, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(m_db, "PRAGMA cache_size=-64000;", nullptr, nullptr, nullptr); // 64MB cache
    
    if (!CreateTables()) {
        LogError("[PacketDatabase] Failed to create tables");
        sqlite3_close(m_db);
        m_db = nullptr;
        return false;
    }
    
    if (!PrepareStatements()) {
        LogError("[PacketDatabase] Failed to prepare statements");
        sqlite3_close(m_db);
        m_db = nullptr;
        return false;
    }
    
    m_initialized = true;
    LogInfo("[PacketDatabase] Database initialized successfully");
    
    // Start default session
    StartSession("Default");
    
    return true;
}

void PacketDatabase::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized) return;
    
    FinalizeStatements();
    
    if (m_db) {
        sqlite3_close(m_db);
        m_db = nullptr;
    }
    
    m_initialized = false;
    LogInfo("[PacketDatabase] Database shut down");
}

bool PacketDatabase::CreateTables() {
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            connection_id INTEGER NOT NULL,
            connection_type INTEGER NOT NULL,
            outgoing INTEGER NOT NULL,
            opcode INTEGER NOT NULL,
            opcode_name TEXT,
            payload_size INTEGER NOT NULL,
            raw_data BLOB,
            session_id TEXT,
            notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_packets_opcode ON packets(opcode);
        CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id);
        CREATE INDEX IF NOT EXISTS idx_packets_connection ON packets(connection_type, outgoing);
        
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            name TEXT,
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            ended_at DATETIME,
            packet_count INTEGER DEFAULT 0
        );
        
        CREATE TABLE IF NOT EXISTS opcode_names (
            opcode INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            connection_type INTEGER,
            outgoing INTEGER
        );
    )";
    
    char* errMsg = nullptr;
    int rc = sqlite3_exec(m_db, sql, nullptr, nullptr, &errMsg);
    
    if (rc != SQLITE_OK) {
        LogError(fmt::format("[PacketDatabase] SQL error: {}", errMsg ? errMsg : "unknown"));
        sqlite3_free(errMsg);
        return false;
    }
    
    return true;
}

bool PacketDatabase::PrepareStatements() {
    // Insert packet statement
    const char* insertSql = R"(
        INSERT INTO packets (timestamp, connection_id, connection_type, outgoing, 
                            opcode, opcode_name, payload_size, raw_data, session_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    
    if (sqlite3_prepare_v2(m_db, insertSql, -1, &m_stmtInsert, nullptr) != SQLITE_OK) {
        LogError(fmt::format("[PacketDatabase] Failed to prepare insert statement: {}",
            sqlite3_errmsg(m_db)));
        return false;
    }
    
    // Query by ID
    const char* queryByIdSql = "SELECT * FROM packets WHERE id = ?";
    if (sqlite3_prepare_v2(m_db, queryByIdSql, -1, &m_stmtQueryById, nullptr) != SQLITE_OK) {
        return false;
    }
    
    // Query recent
    const char* queryRecentSql = "SELECT * FROM packets ORDER BY timestamp DESC LIMIT ?";
    if (sqlite3_prepare_v2(m_db, queryRecentSql, -1, &m_stmtQueryRecent, nullptr) != SQLITE_OK) {
        return false;
    }
    
    // Update notes
    const char* updateNotesSql = "UPDATE packets SET notes = ? WHERE id = ?";
    if (sqlite3_prepare_v2(m_db, updateNotesSql, -1, &m_stmtUpdateNotes, nullptr) != SQLITE_OK) {
        return false;
    }
    
    return true;
}

void PacketDatabase::FinalizeStatements() {
    if (m_stmtInsert) { sqlite3_finalize(m_stmtInsert); m_stmtInsert = nullptr; }
    if (m_stmtQueryById) { sqlite3_finalize(m_stmtQueryById); m_stmtQueryById = nullptr; }
    if (m_stmtQueryRecent) { sqlite3_finalize(m_stmtQueryRecent); m_stmtQueryRecent = nullptr; }
    if (m_stmtUpdateNotes) { sqlite3_finalize(m_stmtUpdateNotes); m_stmtUpdateNotes = nullptr; }
}

std::string PacketDatabase::StartSession(const std::string& sessionName) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Generate session ID
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    m_currentSession = fmt::format("{:016X}", dist(gen));
    
    // Insert session record
    const char* sql = "INSERT INTO sessions (id, name) VALUES (?, ?)";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, m_currentSession.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, sessionName.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    
    LogInfo(fmt::format("[PacketDatabase] Started session: {} ({})", 
        sessionName.empty() ? "Unnamed" : sessionName, m_currentSession));
    
    return m_currentSession;
}

int64_t PacketDatabase::StorePacket(int64_t timestamp, uint64_t connectionId, uint16_t connectionType,
                                     bool outgoing, uint16_t opcode, const std::string& opcodeName,
                                     const uint8_t* data, size_t dataLen) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized || !m_stmtInsert) return -1;
    
    sqlite3_reset(m_stmtInsert);
    sqlite3_bind_int64(m_stmtInsert, 1, timestamp);
    sqlite3_bind_int64(m_stmtInsert, 2, static_cast<int64_t>(connectionId));
    sqlite3_bind_int(m_stmtInsert, 3, connectionType);
    sqlite3_bind_int(m_stmtInsert, 4, outgoing ? 1 : 0);
    sqlite3_bind_int(m_stmtInsert, 5, opcode);
    sqlite3_bind_text(m_stmtInsert, 6, opcodeName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(m_stmtInsert, 7, static_cast<int>(dataLen));
    sqlite3_bind_blob(m_stmtInsert, 8, data, static_cast<int>(dataLen), SQLITE_TRANSIENT);
    sqlite3_bind_text(m_stmtInsert, 9, m_currentSession.c_str(), -1, SQLITE_TRANSIENT);
    
    int rc = sqlite3_step(m_stmtInsert);
    if (rc != SQLITE_DONE) {
        LogError(fmt::format("[PacketDatabase] Failed to store packet: {}", sqlite3_errmsg(m_db)));
        return -1;
    }
    
    return sqlite3_last_insert_rowid(m_db);
}

std::vector<StoredPacket> PacketDatabase::QueryPackets(const PacketQuery& query) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<StoredPacket> results;
    
    if (!m_initialized) return results;
    
    // Build dynamic query
    std::string sql = "SELECT * FROM packets WHERE 1=1";
    
    if (query.startTime) sql += fmt::format(" AND timestamp >= {}", *query.startTime);
    if (query.endTime) sql += fmt::format(" AND timestamp <= {}", *query.endTime);
    if (query.opcode) sql += fmt::format(" AND opcode = {}", *query.opcode);
    if (query.outgoing) sql += fmt::format(" AND outgoing = {}", *query.outgoing ? 1 : 0);
    if (query.connectionType) sql += fmt::format(" AND connection_type = {}", *query.connectionType);
    if (query.sessionId) sql += fmt::format(" AND session_id = '{}'", *query.sessionId);
    if (query.search) sql += fmt::format(" AND notes LIKE '%{}%'", *query.search);
    
    sql += query.orderDescending ? " ORDER BY timestamp DESC" : " ORDER BY timestamp ASC";
    sql += fmt::format(" LIMIT {} OFFSET {}", query.limit, query.offset);
    
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        LogError(fmt::format("[PacketDatabase] Query prepare failed: {}", sqlite3_errmsg(m_db)));
        return results;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        StoredPacket pkt;
        pkt.id = sqlite3_column_int64(stmt, 0);
        pkt.timestamp = sqlite3_column_int64(stmt, 1);
        pkt.connectionId = static_cast<uint64_t>(sqlite3_column_int64(stmt, 2));
        pkt.connectionType = static_cast<uint16_t>(sqlite3_column_int(stmt, 3));
        pkt.outgoing = sqlite3_column_int(stmt, 4) != 0;
        pkt.opcode = static_cast<uint16_t>(sqlite3_column_int(stmt, 5));
        
        const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        if (name) pkt.opcodeName = name;
        
        pkt.payloadSize = static_cast<uint32_t>(sqlite3_column_int(stmt, 7));
        
        const void* blob = sqlite3_column_blob(stmt, 8);
        int blobSize = sqlite3_column_bytes(stmt, 8);
        if (blob && blobSize > 0) {
            pkt.rawData.resize(blobSize);
            std::memcpy(pkt.rawData.data(), blob, blobSize);
        }
        
        const char* session = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        if (session) pkt.sessionId = session;
        
        const char* notes = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        if (notes) pkt.notes = notes;
        
        results.push_back(std::move(pkt));
    }
    
    sqlite3_finalize(stmt);
    return results;
}

std::optional<StoredPacket> PacketDatabase::GetPacket(int64_t id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized || !m_stmtQueryById) return std::nullopt;
    
    sqlite3_reset(m_stmtQueryById);
    sqlite3_bind_int64(m_stmtQueryById, 1, id);
    
    if (sqlite3_step(m_stmtQueryById) != SQLITE_ROW) {
        return std::nullopt;
    }
    
    StoredPacket pkt;
    pkt.id = sqlite3_column_int64(m_stmtQueryById, 0);
    pkt.timestamp = sqlite3_column_int64(m_stmtQueryById, 1);
    pkt.connectionId = static_cast<uint64_t>(sqlite3_column_int64(m_stmtQueryById, 2));
    pkt.connectionType = static_cast<uint16_t>(sqlite3_column_int(m_stmtQueryById, 3));
    pkt.outgoing = sqlite3_column_int(m_stmtQueryById, 4) != 0;
    pkt.opcode = static_cast<uint16_t>(sqlite3_column_int(m_stmtQueryById, 5));
    
    const char* name = reinterpret_cast<const char*>(sqlite3_column_text(m_stmtQueryById, 6));
    if (name) pkt.opcodeName = name;
    
    pkt.payloadSize = static_cast<uint32_t>(sqlite3_column_int(m_stmtQueryById, 7));
    
    const void* blob = sqlite3_column_blob(m_stmtQueryById, 8);
    int blobSize = sqlite3_column_bytes(m_stmtQueryById, 8);
    if (blob && blobSize > 0) {
        pkt.rawData.resize(blobSize);
        std::memcpy(pkt.rawData.data(), blob, blobSize);
    }
    
    return pkt;
}

std::vector<StoredPacket> PacketDatabase::GetPacketsByOpcode(uint16_t opcode, size_t limit) {
    PacketQuery query;
    query.opcode = opcode;
    query.limit = limit;
    return QueryPackets(query);
}

std::vector<StoredPacket> PacketDatabase::GetRecentPackets(size_t count) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<StoredPacket> results;
    
    if (!m_initialized || !m_stmtQueryRecent) return results;
    
    sqlite3_reset(m_stmtQueryRecent);
    sqlite3_bind_int(m_stmtQueryRecent, 1, static_cast<int>(count));
    
    while (sqlite3_step(m_stmtQueryRecent) == SQLITE_ROW) {
        StoredPacket pkt;
        pkt.id = sqlite3_column_int64(m_stmtQueryRecent, 0);
        pkt.timestamp = sqlite3_column_int64(m_stmtQueryRecent, 1);
        pkt.connectionId = static_cast<uint64_t>(sqlite3_column_int64(m_stmtQueryRecent, 2));
        pkt.connectionType = static_cast<uint16_t>(sqlite3_column_int(m_stmtQueryRecent, 3));
        pkt.outgoing = sqlite3_column_int(m_stmtQueryRecent, 4) != 0;
        pkt.opcode = static_cast<uint16_t>(sqlite3_column_int(m_stmtQueryRecent, 5));
        pkt.payloadSize = static_cast<uint32_t>(sqlite3_column_int(m_stmtQueryRecent, 7));
        
        results.push_back(std::move(pkt));
    }
    
    return results;
}

std::vector<StoredPacket> PacketDatabase::SearchHexPattern(const std::string& pattern, size_t limit) {
    // Parse hex pattern
    std::vector<uint8_t> bytes;
    std::string cleaned;
    for (char c : pattern) {
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            cleaned += c;
        }
    }
    
    for (size_t i = 0; i + 1 < cleaned.size(); i += 2) {
        char* end = nullptr;
        unsigned long val = strtoul(cleaned.substr(i, 2).c_str(), &end, 16);
        bytes.push_back(static_cast<uint8_t>(val));
    }
    
    if (bytes.empty()) return {};
    
    // Query all packets and filter (inefficient but works for now)
    // Future: use SQLite BLOB pattern matching or custom function
    PacketQuery query;
    query.limit = 10000; // Get more to search through
    auto allPackets = QueryPackets(query);
    
    std::vector<StoredPacket> results;
    for (auto& pkt : allPackets) {
        if (results.size() >= limit) break;
        
        // Search for pattern in raw data
        for (size_t i = 0; i + bytes.size() <= pkt.rawData.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < bytes.size(); ++j) {
                if (pkt.rawData[i + j] != bytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                results.push_back(std::move(pkt));
                break;
            }
        }
    }
    
    return results;
}

bool PacketDatabase::AddPacketNote(int64_t packetId, const std::string& note) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized || !m_stmtUpdateNotes) return false;
    
    sqlite3_reset(m_stmtUpdateNotes);
    sqlite3_bind_text(m_stmtUpdateNotes, 1, note.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(m_stmtUpdateNotes, 2, packetId);
    
    return sqlite3_step(m_stmtUpdateNotes) == SQLITE_DONE;
}

std::string PacketDatabase::GetPacketNotes(int64_t packetId) {
    auto pkt = GetPacket(packetId);
    return pkt ? pkt->notes : "";
}

PacketStats PacketDatabase::GetStats() {
    std::lock_guard<std::mutex> lock(m_mutex);
    PacketStats stats;
    
    if (!m_initialized) return stats;
    
    // Total packets and bytes
    const char* sql1 = "SELECT COUNT(*), SUM(payload_size), COUNT(DISTINCT opcode) FROM packets";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, sql1, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats.totalPackets = sqlite3_column_int64(stmt, 0);
            stats.totalBytes = sqlite3_column_int64(stmt, 1);
            stats.uniqueOpcodes = sqlite3_column_int64(stmt, 2);
        }
        sqlite3_finalize(stmt);
    }
    
    // Direction counts
    const char* sql2 = "SELECT outgoing, COUNT(*) FROM packets GROUP BY outgoing";
    if (sqlite3_prepare_v2(m_db, sql2, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (sqlite3_column_int(stmt, 0) == 0) {
                stats.incomingCount = sqlite3_column_int64(stmt, 1);
            } else {
                stats.outgoingCount = sqlite3_column_int64(stmt, 1);
            }
        }
        sqlite3_finalize(stmt);
    }
    
    // Timestamp range
    const char* sql3 = "SELECT MIN(timestamp), MAX(timestamp) FROM packets";
    if (sqlite3_prepare_v2(m_db, sql3, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats.oldestTimestamp = sqlite3_column_int64(stmt, 0);
            stats.newestTimestamp = sqlite3_column_int64(stmt, 1);
        }
        sqlite3_finalize(stmt);
    }
    
    // Opcode frequency
    stats.opcodeFrequency = GetOpcodeFrequency(50);
    
    return stats;
}

std::vector<std::pair<uint16_t, size_t>> PacketDatabase::GetOpcodeFrequency(size_t limit) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::pair<uint16_t, size_t>> result;
    
    if (!m_initialized) return result;
    
    std::string sql = fmt::format(
        "SELECT opcode, COUNT(*) as cnt FROM packets GROUP BY opcode ORDER BY cnt DESC LIMIT {}",
        limit);
    
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            uint16_t opcode = static_cast<uint16_t>(sqlite3_column_int(stmt, 0));
            size_t count = static_cast<size_t>(sqlite3_column_int64(stmt, 1));
            result.emplace_back(opcode, count);
        }
        sqlite3_finalize(stmt);
    }
    
    return result;
}

size_t PacketDatabase::CountPackets(const PacketQuery& query) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized) return 0;
    
    std::string sql = "SELECT COUNT(*) FROM packets WHERE 1=1";
    
    if (query.startTime) sql += fmt::format(" AND timestamp >= {}", *query.startTime);
    if (query.endTime) sql += fmt::format(" AND timestamp <= {}", *query.endTime);
    if (query.opcode) sql += fmt::format(" AND opcode = {}", *query.opcode);
    if (query.outgoing) sql += fmt::format(" AND outgoing = {}", *query.outgoing ? 1 : 0);
    if (query.connectionType) sql += fmt::format(" AND connection_type = {}", *query.connectionType);
    
    sqlite3_stmt* stmt = nullptr;
    size_t count = 0;
    if (sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = static_cast<size_t>(sqlite3_column_int64(stmt, 0));
        }
        sqlite3_finalize(stmt);
    }
    
    return count;
}

size_t PacketDatabase::PruneOldPackets(int64_t olderThanMs) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized) return 0;
    
    std::string sql = fmt::format("DELETE FROM packets WHERE timestamp < {}", olderThanMs);
    
    char* errMsg = nullptr;
    if (sqlite3_exec(m_db, sql.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
        LogError(fmt::format("[PacketDatabase] Prune failed: {}", errMsg ? errMsg : "unknown"));
        sqlite3_free(errMsg);
        return 0;
    }
    
    return static_cast<size_t>(sqlite3_changes(m_db));
}

size_t PacketDatabase::ClearAllPackets() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized) return 0;
    
    // Get count first
    sqlite3_stmt* stmt = nullptr;
    size_t count = 0;
    if (sqlite3_prepare_v2(m_db, "SELECT COUNT(*) FROM packets", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = static_cast<size_t>(sqlite3_column_int64(stmt, 0));
        }
        sqlite3_finalize(stmt);
    }
    
    sqlite3_exec(m_db, "DELETE FROM packets", nullptr, nullptr, nullptr);
    
    return count;
}

bool PacketDatabase::ExportToJson(const std::string& filePath, const PacketQuery& query) {
    auto packets = QueryPackets(query);
    
    std::ofstream file(filePath);
    if (!file.is_open()) return false;
    
    file << "[\n";
    for (size_t i = 0; i < packets.size(); ++i) {
        const auto& pkt = packets[i];
        file << "  {\n";
        file << fmt::format("    \"id\": {},\n", pkt.id);
        file << fmt::format("    \"timestamp\": {},\n", pkt.timestamp);
        file << fmt::format("    \"connectionId\": {},\n", pkt.connectionId);
        file << fmt::format("    \"connectionType\": {},\n", pkt.connectionType);
        file << fmt::format("    \"outgoing\": {},\n", pkt.outgoing ? "true" : "false");
        file << fmt::format("    \"opcode\": {},\n", pkt.opcode);
        file << fmt::format("    \"opcodeName\": \"{}\",\n", pkt.opcodeName);
        file << fmt::format("    \"payloadSize\": {},\n", pkt.payloadSize);
        
        // Hex encode raw data
        std::string hex;
        for (uint8_t b : pkt.rawData) {
            hex += fmt::format("{:02X}", b);
        }
        file << fmt::format("    \"rawDataHex\": \"{}\"\n", hex);
        file << "  }" << (i + 1 < packets.size() ? "," : "") << "\n";
    }
    file << "]\n";
    
    return true;
}

size_t PacketDatabase::ImportFromJson(const std::string& filePath) {
    // TODO: Implement JSON parsing with nlohmann/json
    LogWarning("[PacketDatabase] ImportFromJson not yet implemented");
    return 0;
}

bool PacketDatabase::Compact() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized) return false;
    
    char* errMsg = nullptr;
    if (sqlite3_exec(m_db, "VACUUM", nullptr, nullptr, &errMsg) != SQLITE_OK) {
        LogError(fmt::format("[PacketDatabase] Compact failed: {}", errMsg ? errMsg : "unknown"));
        sqlite3_free(errMsg);
        return false;
    }
    
    LogInfo("[PacketDatabase] Database compacted");
    return true;
}

size_t PacketDatabase::GetDatabaseSize() const {
    if (m_dbPath.empty()) return 0;
    
    try {
        return static_cast<size_t>(std::filesystem::file_size(m_dbPath));
    } catch (...) {
        return 0;
    }
}

} // namespace SapphireHook
