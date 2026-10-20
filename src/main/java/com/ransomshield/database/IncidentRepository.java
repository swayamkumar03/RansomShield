package com.ransomshield.database;

import com.ransomshield.model.Incident;
import com.ransomshield.model.IncidentStatus;
import com.ransomshield.model.ThreatLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Data access operations for Incident records in SQLite.
 */
public class IncidentRepository {
    private static final Logger logger = LoggerFactory.getLogger(IncidentRepository.class);

    private final DatabaseManager databaseManager;

    public IncidentRepository(DatabaseManager databaseManager) {
        this.databaseManager = databaseManager;
    }

    public synchronized void save(Incident incident) {
        if (incident == null) return;

        String sql = """
            INSERT OR REPLACE INTO incidents 
            (id, timestamp, severity, score, root_directory, files_affected, directories_affected,
             average_entropy, max_entropy, modification_rate, operation_summary, status,
             first_seen, last_seen, affected_paths, response_action, response_result, is_simulated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """;

        try (Connection conn = databaseManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, incident.getId());
            ps.setString(2, incident.getTimestamp().toString());
            ps.setString(3, incident.getSeverity().name());
            ps.setInt(4, incident.getScore());
            ps.setString(5, incident.getRootDirectory());
            ps.setInt(6, incident.getFilesAffected());
            ps.setInt(7, incident.getDirectoriesAffected());
            ps.setDouble(8, incident.getAverageEntropy());
            ps.setDouble(9, incident.getMaxEntropy());
            ps.setDouble(10, incident.getModificationRate());
            ps.setString(11, incident.getOperationSummary());
            ps.setString(12, incident.getStatus().name());
            ps.setString(13, incident.getFirstSeen() != null ? incident.getFirstSeen().toString() : incident.getTimestamp().toString());
            ps.setString(14, incident.getLastSeen() != null ? incident.getLastSeen().toString() : incident.getTimestamp().toString());
            ps.setString(15, String.join("\n", incident.getAffectedPaths()));
            ps.setString(16, incident.getResponseAction());
            ps.setString(17, incident.getResponseResult());
            ps.setInt(18, incident.isSimulated() ? 1 : 0);

            ps.executeUpdate();
            logger.debug("Saved incident {}", incident.getId());

        } catch (SQLException e) {
            logger.error("Failed to save incident {}: {}", incident.getId(), e.getMessage(), e);
        }
    }

    public List<Incident> findAll() {
        String sql = "SELECT * FROM incidents ORDER BY timestamp DESC;";
        List<Incident> list = new ArrayList<>();

        try (Connection conn = databaseManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                list.add(mapRow(rs));
            }

        } catch (SQLException e) {
            logger.error("Failed to query incidents: {}", e.getMessage(), e);
        }
        return list;
    }

    public List<Incident> findBySeverity(ThreatLevel severity) {
        if (severity == null) return findAll();

        String sql = "SELECT * FROM incidents WHERE severity = ? ORDER BY timestamp DESC;";
        List<Incident> list = new ArrayList<>();

        try (Connection conn = databaseManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, severity.name());
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(mapRow(rs));
                }
            }

        } catch (SQLException e) {
            logger.error("Failed to query incidents by severity {}: {}", severity, e.getMessage(), e);
        }
        return list;
    }

    public boolean updateStatus(String incidentId, IncidentStatus newStatus) {
        if (incidentId == null || newStatus == null) return false;

        String sql = "UPDATE incidents SET status = ? WHERE id = ?;";
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, newStatus.name());
            ps.setString(2, incidentId);
            return ps.executeUpdate() > 0;

        } catch (SQLException e) {
            logger.error("Failed to update status for incident {}: {}", incidentId, e.getMessage(), e);
            return false;
        }
    }

    public int count() {
        String sql = "SELECT COUNT(*) FROM incidents;";
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {

            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            logger.error("Failed to count incidents: {}", e.getMessage());
        }
        return 0;
    }

    public int countOpen() {
        String sql = "SELECT COUNT(*) FROM incidents WHERE status IN ('OPEN', 'DETECTED', 'CONTAINMENT_REQUESTED');";
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {

            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            logger.error("Failed to count open incidents: {}", e.getMessage());
        }
        return 0;
    }

    private Incident mapRow(ResultSet rs) throws SQLException {
        String id = rs.getString("id");
        Instant timestamp = Instant.parse(rs.getString("timestamp"));
        ThreatLevel severity = ThreatLevel.valueOf(rs.getString("severity"));
        int score = rs.getInt("score");
        String rootDir = rs.getString("root_directory");
        int files = rs.getInt("files_affected");
        int dirs = rs.getInt("directories_affected");
        double avgEntropy = rs.getDouble("average_entropy");
        double maxEntropy = rs.getDouble("max_entropy");
        double rate = rs.getDouble("modification_rate");
        String summary = rs.getString("operation_summary");
        IncidentStatus status;
        try {
            status = IncidentStatus.valueOf(rs.getString("status"));
        } catch (Exception e) {
            status = IncidentStatus.OPEN;
        }

        List<String> reasons = new ArrayList<>();
        if (summary != null && !summary.isBlank()) {
            reasons.addAll(Arrays.asList(summary.split("; ")));
        }

        Incident incident = new Incident(id, timestamp, severity, score, rootDir, files, dirs, avgEntropy, maxEntropy, rate, summary, status, reasons);

        try {
            String firstSeenStr = rs.getString("first_seen");
            if (firstSeenStr != null) {
                incident.setFirstSeen(Instant.parse(firstSeenStr));
            }
            String lastSeenStr = rs.getString("last_seen");
            if (lastSeenStr != null) {
                incident.setLastSeen(Instant.parse(lastSeenStr));
            }
            String affectedPathsStr = rs.getString("affected_paths");
            if (affectedPathsStr != null && !affectedPathsStr.isBlank()) {
                incident.setAffectedPaths(Arrays.asList(affectedPathsStr.split("\n")));
            }
            String responseAction = rs.getString("response_action");
            if (responseAction != null) {
                incident.setResponseAction(responseAction);
            }
            String responseResult = rs.getString("response_result");
            if (responseResult != null) {
                incident.setResponseResult(responseResult);
            }
            incident.setSimulated(rs.getInt("is_simulated") == 1);
        } catch (SQLException ignored) {
            // Field may not be present in legacy rows
        }

        return incident;
    }
}
