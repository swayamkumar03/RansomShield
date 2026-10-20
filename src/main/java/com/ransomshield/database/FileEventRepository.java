package com.ransomshield.database;

import com.ransomshield.model.FileEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Data access operations for FileEvent records in SQLite.
 */
public class FileEventRepository {
    private static final Logger logger = LoggerFactory.getLogger(FileEventRepository.class);

    private final DatabaseManager databaseManager;

    public FileEventRepository(DatabaseManager databaseManager) {
        this.databaseManager = databaseManager;
    }

    public synchronized void save(FileEvent event, String incidentId) {
        if (event == null) return;

        String sql = """
            INSERT OR REPLACE INTO file_events 
            (id, incident_id, file_path, event_type, timestamp, file_size, extension, entropy)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """;

        try (Connection conn = databaseManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, event.getId());
            ps.setString(2, incidentId);
            ps.setString(3, event.getPath() != null ? event.getPath().toString() : "");
            ps.setString(4, event.getEventType());
            ps.setString(5, event.getTimestamp().toString());
            ps.setLong(6, event.getFileSize());
            ps.setString(7, event.getExtension());
            if (event.getEntropy() != null) {
                ps.setDouble(8, event.getEntropy());
            } else {
                ps.setNull(8, java.sql.Types.REAL);
            }

            ps.executeUpdate();

        } catch (SQLException e) {
            logger.error("Failed to save file event {}: {}", event.getId(), e.getMessage());
        }
    }

    public List<FileEvent> findRecent(int limit) {
        String sql = "SELECT * FROM file_events ORDER BY timestamp DESC LIMIT ?;";
        List<FileEvent> list = new ArrayList<>();

        try (Connection conn = databaseManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, Math.max(1, limit));
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String pathStr = rs.getString("file_path");
                    String eventType = rs.getString("event_type");
                    Instant ts = Instant.parse(rs.getString("timestamp"));
                    long size = rs.getLong("file_size");
                    double entropyVal = rs.getDouble("entropy");
                    boolean wasNull = rs.wasNull();

                    FileEvent ev = new FileEvent(Paths.get(pathStr), eventType, ts, size, Paths.get(pathStr).getParent());
                    if (!wasNull) {
                        ev.setEntropy(entropyVal);
                    }
                    list.add(ev);
                }
            }

        } catch (SQLException e) {
            logger.error("Failed to query recent file events: {}", e.getMessage());
        }
        return list;
    }
}
