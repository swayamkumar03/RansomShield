package com.ransomshield.defense;

import com.ransomshield.database.DatabaseManager;
import com.ransomshield.util.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.sql.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Opt-in, validated file quarantine service providing sandboxed isolation
 * and reversible file restoration strictly confined within allowed directory boundaries.
 */
public class QuarantineService {
    private static final Logger logger = LoggerFactory.getLogger(QuarantineService.class);

    private final DatabaseManager databaseManager;

    public QuarantineService(DatabaseManager databaseManager) {
        this.databaseManager = databaseManager;
        initializeTable();
    }

    private void initializeTable() {
        String sql = """
            CREATE TABLE IF NOT EXISTS quarantined_files (
                id TEXT PRIMARY KEY,
                incident_id TEXT,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                file_size INTEGER,
                entropy REAL,
                restored INTEGER DEFAULT 0,
                restored_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_quarantined_incident ON quarantined_files(incident_id);
            """;
        try (Connection conn = databaseManager.getConnection();
             Statement stmt = conn.createStatement()) {
            for (String statement : sql.split(";")) {
                String trimmed = statement.trim();
                if (!trimmed.isEmpty()) {
                    stmt.execute(trimmed);
                }
            }
        } catch (SQLException e) {
            logger.warn("Could not verify quarantined_files table: {}", e.getMessage());
        }
    }

    /**
     * Safely isolates a list of files into the sandbox quarantine directory.
     * Enforces path traversal prevention and ensures files are within the allowed root boundary.
     */
    public ResponseResult quarantineFiles(List<String> filePaths, Path allowedScopeRoot, String incidentId) {
        if (filePaths == null || filePaths.isEmpty()) {
            return ResponseResult.failure(ResponseAction.QUARANTINE_FILES, "No files specified for quarantine", "Empty file list");
        }
        if (allowedScopeRoot == null || !Files.exists(allowedScopeRoot)) {
            return ResponseResult.failure(ResponseAction.QUARANTINE_FILES, "Invalid quarantine scope root", "Root directory does not exist");
        }

        Path normalizedScope = allowedScopeRoot.toAbsolutePath().normalize();
        Path quarantineDir = normalizedScope.resolve(".quarantine");

        try {
            if (!Files.exists(quarantineDir)) {
                Files.createDirectories(quarantineDir);
            }
        } catch (IOException e) {
            return ResponseResult.failure(ResponseAction.QUARANTINE_FILES, "Failed to create quarantine sandbox directory", e.getMessage());
        }

        List<String> quarantinedPaths = new ArrayList<>();
        List<String> errors = new ArrayList<>();

        for (String filePathStr : filePaths) {
            try {
                Path targetPath = Paths.get(filePathStr).toAbsolutePath().normalize();

                // 1. Strict Scope / Path Traversal Validation
                if (!targetPath.startsWith(normalizedScope)) {
                    errors.add("Security violation: path outside allowed scope: " + filePathStr);
                    continue;
                }

                // 2. Do not quarantine files inside the quarantine directory itself
                if (targetPath.startsWith(quarantineDir)) {
                    continue;
                }

                // 3. Symbolic link check to prevent escaping sandbox
                if (Files.isSymbolicLink(targetPath)) {
                    errors.add("Refusing to quarantine symbolic link: " + filePathStr);
                    continue;
                }

                if (!Files.exists(targetPath) || !Files.isRegularFile(targetPath)) {
                    continue;
                }

                // 4. Unique destination path in .quarantine
                String originalFilename = targetPath.getFileName().toString();
                String uniqueTargetName = System.currentTimeMillis() + "_" + UUID.randomUUID().toString().substring(0, 6) + "_" + originalFilename;
                Path quarantineFile = quarantineDir.resolve(uniqueTargetName);

                long size = FileUtils.getFileSizeSafely(targetPath);

                // 5. Atomic / standard move
                try {
                    Files.move(targetPath, quarantineFile, StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(targetPath, quarantineFile, StandardCopyOption.REPLACE_EXISTING);
                }

                // Verify move succeeded
                if (!Files.exists(quarantineFile) || Files.exists(targetPath)) {
                    errors.add("Move verification failed for " + filePathStr);
                    continue;
                }

                // 6. Write metadata companion file
                Path metaFile = quarantineDir.resolve(uniqueTargetName + ".meta");
                String metaContent = String.format("ORIGINAL_PATH=%s\nINCIDENT_ID=%s\nTIMESTAMP=%s\nSIZE=%d\n",
                        targetPath, incidentId != null ? incidentId : "manual", Instant.now(), size);
                Files.writeString(metaFile, metaContent, StandardCharsets.UTF_8);

                // 7. Record in SQLite
                String recordId = UUID.randomUUID().toString();
                saveRecord(new QuarantineRecord(
                        recordId,
                        incidentId,
                        targetPath.toString(),
                        quarantineFile.toString(),
                        Instant.now(),
                        size,
                        null,
                        false,
                        null
                ));

                quarantinedPaths.add(targetPath.toString());
                logger.info("Quarantined file successfully: {} -> {}", targetPath, quarantineFile);

            } catch (Exception e) {
                logger.error("Error quarantining file {}: {}", filePathStr, e.getMessage());
                errors.add(filePathStr + ": " + e.getMessage());
            }
        }

        if (quarantinedPaths.isEmpty() && !errors.isEmpty()) {
            return ResponseResult.failure(ResponseAction.QUARANTINE_FILES,
                    "Failed to quarantine files", String.join("; ", errors));
        }

        String msg = String.format("Successfully quarantined %d file(s) into sandbox", quarantinedPaths.size());
        if (!errors.isEmpty()) {
            msg += String.format(" (%d errors encountered)", errors.size());
        }

        return ResponseResult.successReal(ResponseAction.QUARANTINE_FILES, msg, quarantinedPaths);
    }

    /**
     * Restores quarantined files belonging to a specific incident or all quarantined files in scope.
     */
    public ResponseResult restoreQuarantinedFiles(String incidentId, Path allowedScopeRoot) {
        if (allowedScopeRoot == null || !Files.exists(allowedScopeRoot)) {
            return ResponseResult.failure(ResponseAction.RESTORE_FILES, "Invalid scope root", "Root directory does not exist");
        }

        Path normalizedScope = allowedScopeRoot.toAbsolutePath().normalize();
        List<QuarantineRecord> records = findRecords(incidentId, false);

        if (records.isEmpty()) {
            return ResponseResult.failure(ResponseAction.RESTORE_FILES, "No un-restored quarantined files found", "Nothing to restore");
        }

        List<String> restoredPaths = new ArrayList<>();
        List<String> errors = new ArrayList<>();

        for (QuarantineRecord record : records) {
            try {
                Path qPath = Paths.get(record.getQuarantinePath()).toAbsolutePath().normalize();
                Path originalPath = Paths.get(record.getOriginalPath()).toAbsolutePath().normalize();

                // Validate original path is still within scope
                if (!originalPath.startsWith(normalizedScope)) {
                    errors.add("Refusing to restore outside scope: " + originalPath);
                    continue;
                }

                if (!Files.exists(qPath)) {
                    errors.add("Quarantined source file missing on disk: " + qPath);
                    continue;
                }

                // Avoid overwriting if a new file exists at destination: append .restored
                Path destination = originalPath;
                if (Files.exists(destination)) {
                    destination = originalPath.getParent().resolve(originalPath.getFileName().toString() + ".restored");
                }

                if (destination.getParent() != null && !Files.exists(destination.getParent())) {
                    Files.createDirectories(destination.getParent());
                }

                Files.move(qPath, destination, StandardCopyOption.REPLACE_EXISTING);

                // Clean up metadata file if present
                Path metaFile = Paths.get(record.getQuarantinePath() + ".meta");
                try {
                    Files.deleteIfExists(metaFile);
                } catch (IOException ignored) {}

                // Mark record restored
                markRestored(record.getId());
                restoredPaths.add(destination.toString());
                logger.info("Restored quarantined file: {} -> {}", qPath, destination);

            } catch (Exception e) {
                logger.error("Error restoring record {}: {}", record.getId(), e.getMessage());
                errors.add(record.getOriginalPath() + ": " + e.getMessage());
            }
        }

        if (restoredPaths.isEmpty() && !errors.isEmpty()) {
            return ResponseResult.failure(ResponseAction.RESTORE_FILES, "Failed to restore quarantined files", String.join("; ", errors));
        }

        String msg = String.format("Successfully restored %d file(s) to original location", restoredPaths.size());
        return ResponseResult.successReal(ResponseAction.RESTORE_FILES, msg, restoredPaths);
    }

    private void saveRecord(QuarantineRecord record) {
        String sql = """
            INSERT INTO quarantined_files 
            (id, incident_id, original_path, quarantine_path, timestamp, file_size, entropy, restored, restored_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """;
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, record.getId());
            ps.setString(2, record.getIncidentId());
            ps.setString(3, record.getOriginalPath());
            ps.setString(4, record.getQuarantinePath());
            ps.setString(5, record.getTimestamp().toString());
            ps.setLong(6, record.getFileSize());
            if (record.getEntropy() != null) {
                ps.setDouble(7, record.getEntropy());
            } else {
                ps.setNull(7, Types.REAL);
            }
            ps.setInt(8, record.isRestored() ? 1 : 0);
            ps.setString(9, record.getRestoredAt() != null ? record.getRestoredAt().toString() : null);
            ps.executeUpdate();
        } catch (SQLException e) {
            logger.error("Failed to insert quarantine record: {}", e.getMessage());
        }
    }

    private void markRestored(String id) {
        String sql = "UPDATE quarantined_files SET restored = 1, restored_at = ? WHERE id = ?;";
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, Instant.now().toString());
            ps.setString(2, id);
            ps.executeUpdate();
        } catch (SQLException e) {
            logger.error("Failed to mark quarantine record restored: {}", e.getMessage());
        }
    }

    public List<QuarantineRecord> findRecords(String incidentId, boolean includeRestored) {
        List<QuarantineRecord> list = new ArrayList<>();
        String sql = "SELECT * FROM quarantined_files WHERE " +
                (incidentId != null ? "incident_id = ? " : "1=1 ") +
                (!includeRestored ? "AND restored = 0 " : "") +
                "ORDER BY timestamp DESC;";

        try (Connection conn = databaseManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            if (incidentId != null) {
                ps.setString(1, incidentId);
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(new QuarantineRecord(
                            rs.getString("id"),
                            rs.getString("incident_id"),
                            rs.getString("original_path"),
                            rs.getString("quarantine_path"),
                            Instant.parse(rs.getString("timestamp")),
                            rs.getLong("file_size"),
                            rs.getObject("entropy") != null ? rs.getDouble("entropy") : null,
                            rs.getInt("restored") == 1,
                            rs.getString("restored_at") != null ? Instant.parse(rs.getString("restored_at")) : null
                    ));
                }
            }
        } catch (SQLException e) {
            logger.error("Failed to query quarantine records: {}", e.getMessage());
        }
        return list;
    }

    public int countActiveQuarantined() {
        String sql = "SELECT COUNT(*) FROM quarantined_files WHERE restored = 0;";
        try (Connection conn = databaseManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            logger.error("Failed to count quarantined files: {}", e.getMessage());
        }
        return 0;
    }
}
