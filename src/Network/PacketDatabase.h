#pragma once
/**
 * @file PacketDatabase.h
 * @brief SQLite-based persistent packet capture storage
 * 
 * Provides persistent storage for captured network packets with
 * powerful query capabilities for analysis and debugging.
 */

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <chrono>
#include <functional>
#include <mutex>
#include <array>

// Forward declare SQLite types to avoid header exposure
struct sqlite3;
struct sqlite3_stmt;

namespace SapphireHook {

/**
 * @brief Represents a stored packet in the database
 */
struct StoredPacket {
    int64_t id = 0;                         ///< Database row ID
    int64_t timestamp = 0;                  ///< Unix epoch milliseconds
    uint64_t connectionId = 0;              ///< Connection ID
    uint16_t connectionType = 0;            ///< Zone(1), Chat(2), Lobby(3)
    bool outgoing = false;                  ///< Direction
    uint16_t opcode = 0;                    ///< IPC opcode (0 if non-IPC)
    std::string opcodeName;                 ///< Opcode name if known
    uint32_t payloadSize = 0;               ///< Payload size
    std::vector<uint8_t> rawData;           ///< Full raw packet data
    std::string sessionId;                  ///< Session identifier
    std::string notes;                      ///< User notes/annotations
};

/**
 * @brief Query filter for packet searches
 */
struct PacketQuery {
    std::optional<int64_t> startTime;       ///< Start of time range
    std::optional<int64_t> endTime;         ///< End of time range
    std::optional<uint16_t> opcode;         ///< Filter by specific opcode
    std::optional<bool> outgoing;           ///< Filter by direction
    std::optional<uint16_t> connectionType; ///< Filter by connection type
    std::optional<std::string> sessionId;   ///< Filter by session
    std::optional<std::string> search;      ///< Full-text search in notes
    size_t limit = 1000;                    ///< Maximum results
    size_t offset = 0;                      ///< Offset for pagination
    bool orderDescending = true;            ///< Sort by timestamp descending
};

/**
 * @brief Statistics about stored packets
 */
struct PacketStats {
    size_t totalPackets = 0;
    size_t totalBytes = 0;
    size_t uniqueOpcodes = 0;
    size_t outgoingCount = 0;
    size_t incomingCount = 0;
    int64_t oldestTimestamp = 0;
    int64_t newestTimestamp = 0;
    std::vector<std::pair<uint16_t, size_t>> opcodeFrequency; ///< opcode -> count
};

/**
 * @brief SQLite-based packet storage database
 * 
 * Thread-safe persistent storage for network packets with full query support.
 */
class PacketDatabase {
public:
    /**
     * @brief Get singleton instance
     */
    static PacketDatabase& Instance();

    /**
     * @brief Initialize database at the specified path
     * @param dbPath Path to SQLite database file (default: in temp dir)
     * @return True if initialization succeeded
     */
    bool Initialize(const std::string& dbPath = "");

    /**
     * @brief Check if database is initialized
     */
    bool IsInitialized() const { return m_initialized; }

    /**
     * @brief Close database connection
     */
    void Shutdown();

    /**
     * @brief Start a new capture session
     * @param sessionName Optional name for the session
     * @return Session ID
     */
    std::string StartSession(const std::string& sessionName = "");

    /**
     * @brief Get current session ID
     */
    const std::string& GetCurrentSession() const { return m_currentSession; }

    // ========== Packet Storage ==========

    /**
     * @brief Store a captured packet
     * @param timestamp Capture time (milliseconds since epoch)
     * @param connectionId Connection identifier
     * @param connectionType Zone/Chat/Lobby
     * @param outgoing Direction flag
     * @param opcode IPC opcode (0 if non-IPC)
     * @param opcodeName Opcode name (can be empty)
     * @param data Raw packet data
     * @param dataLen Length of data
     * @return Database row ID, or -1 on failure
     */
    int64_t StorePacket(int64_t timestamp, uint64_t connectionId, uint16_t connectionType,
                        bool outgoing, uint16_t opcode, const std::string& opcodeName,
                        const uint8_t* data, size_t dataLen);

    /**
     * @brief Store packet from HookPacket struct (convenience)
     */
    template<typename HookPacketT>
    int64_t StorePacket(const HookPacketT& hp, uint16_t opcode = 0, const std::string& opcodeName = "") {
        auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
            hp.ts.time_since_epoch()).count();
        return StorePacket(ts, hp.connection_id, 1, hp.outgoing, opcode, opcodeName,
                          hp.buf.data(), hp.len);
    }

    // ========== Query ==========

    /**
     * @brief Query packets with filters
     * @param query Query parameters
     * @return Vector of matching packets
     */
    std::vector<StoredPacket> QueryPackets(const PacketQuery& query);

    /**
     * @brief Get a single packet by ID
     */
    std::optional<StoredPacket> GetPacket(int64_t id);

    /**
     * @brief Get packets by opcode
     */
    std::vector<StoredPacket> GetPacketsByOpcode(uint16_t opcode, size_t limit = 100);

    /**
     * @brief Get recent packets
     */
    std::vector<StoredPacket> GetRecentPackets(size_t count = 100);

    /**
     * @brief Search packets containing hex pattern in raw data
     * @param pattern Hex pattern to search (e.g., "01 02 03")
     * @param limit Maximum results
     */
    std::vector<StoredPacket> SearchHexPattern(const std::string& pattern, size_t limit = 100);

    // ========== Annotations ==========

    /**
     * @brief Add notes to a packet
     */
    bool AddPacketNote(int64_t packetId, const std::string& note);

    /**
     * @brief Get all notes for a packet
     */
    std::string GetPacketNotes(int64_t packetId);

    // ========== Statistics ==========

    /**
     * @brief Get statistics about stored packets
     */
    PacketStats GetStats();

    /**
     * @brief Get opcode frequency distribution
     */
    std::vector<std::pair<uint16_t, size_t>> GetOpcodeFrequency(size_t limit = 50);

    /**
     * @brief Count packets matching query
     */
    size_t CountPackets(const PacketQuery& query);

    // ========== Maintenance ==========

    /**
     * @brief Delete packets older than specified time
     * @param olderThanMs Milliseconds since epoch
     * @return Number of deleted packets
     */
    size_t PruneOldPackets(int64_t olderThanMs);

    /**
     * @brief Delete all packets
     * @return Number of deleted packets
     */
    size_t ClearAllPackets();

    /**
     * @brief Export packets to JSON file
     */
    bool ExportToJson(const std::string& filePath, const PacketQuery& query = {});

    /**
     * @brief Import packets from JSON file
     */
    size_t ImportFromJson(const std::string& filePath);

    /**
     * @brief Compact database (VACUUM)
     */
    bool Compact();

    /**
     * @brief Get database file size in bytes
     */
    size_t GetDatabaseSize() const;

    /**
     * @brief Get database path
     */
    const std::string& GetDatabasePath() const { return m_dbPath; }

private:
    PacketDatabase() = default;
    ~PacketDatabase();
    PacketDatabase(const PacketDatabase&) = delete;
    PacketDatabase& operator=(const PacketDatabase&) = delete;

    bool CreateTables();
    bool PrepareStatements();
    void FinalizeStatements();

    sqlite3* m_db = nullptr;
    std::string m_dbPath;
    std::string m_currentSession;
    bool m_initialized = false;
    mutable std::mutex m_mutex;

    // Prepared statements for performance
    sqlite3_stmt* m_stmtInsert = nullptr;
    sqlite3_stmt* m_stmtQueryById = nullptr;
    sqlite3_stmt* m_stmtQueryRecent = nullptr;
    sqlite3_stmt* m_stmtUpdateNotes = nullptr;
};

} // namespace SapphireHook
