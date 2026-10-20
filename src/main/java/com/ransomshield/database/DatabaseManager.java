package com.ransomshield.database;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.stream.Collectors;

/**
 * Manages SQLite database connectivity and schema lifecycle via JDBC.
 */
public class DatabaseManager {
    private static final Logger logger = LoggerFactory.getLogger(DatabaseManager.class);

    private final String jdbcUrl;

    public DatabaseManager(String jdbcUrl) {
        this.jdbcUrl = jdbcUrl != null && !jdbcUrl.isBlank() ? jdbcUrl : "jdbc:sqlite:ransomshield.db";
        initializeDatabase();
    }

    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection(jdbcUrl);
    }

    private void initializeDatabase() {
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {

            // Enable WAL mode and foreign keys for SQLite performance & consistency
            stmt.execute("PRAGMA journal_mode=WAL;");
            stmt.execute("PRAGMA foreign_keys=ON;");

            String schemaSql = loadSchemaSql();
            for (String statement : schemaSql.split(";")) {
                String trimmed = statement.trim();
                if (!trimmed.isEmpty()) {
                    stmt.execute(trimmed);
                }
            }

            // Graceful migrations for existing SQLite database files
            String[] migrations = {
                "ALTER TABLE incidents ADD COLUMN first_seen TEXT;",
                "ALTER TABLE incidents ADD COLUMN last_seen TEXT;",
                "ALTER TABLE incidents ADD COLUMN affected_paths TEXT;",
                "ALTER TABLE incidents ADD COLUMN response_action TEXT DEFAULT 'NONE';",
                "ALTER TABLE incidents ADD COLUMN response_result TEXT;",
                "ALTER TABLE incidents ADD COLUMN is_simulated INTEGER DEFAULT 1;"
            };
            for (String mig : migrations) {
                try {
                    stmt.execute(mig);
                } catch (SQLException ignored) {
                    // Column already exists
                }
            }

            logger.info("Database initialized successfully at {}", jdbcUrl);

        } catch (SQLException e) {
            logger.error("Failed to initialize database: {}", e.getMessage(), e);
            throw new RuntimeException("Database initialization failure", e);
        }
    }

    private String loadSchemaSql() {
        try (InputStream in = getClass().getResourceAsStream("/database/schema.sql")) {
            if (in != null) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(in))) {
                    return reader.lines().collect(Collectors.joining("\n"));
                }
            }
        } catch (Exception e) {
            logger.warn("Could not load schema.sql from resources, using fallback schema", e);
        }

        // Inline fallback schema
        return """
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                score INTEGER NOT NULL,
                root_directory TEXT NOT NULL,
                files_affected INTEGER NOT NULL,
                directories_affected INTEGER NOT NULL,
                average_entropy REAL NOT NULL,
                max_entropy REAL NOT NULL,
                modification_rate REAL NOT NULL,
                operation_summary TEXT,
                status TEXT NOT NULL DEFAULT 'DETECTED'
            );
            CREATE TABLE IF NOT EXISTS file_events (
                id TEXT PRIMARY KEY,
                incident_id TEXT,
                file_path TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                file_size INTEGER,
                extension TEXT,
                entropy REAL
            );
            CREATE TABLE IF NOT EXISTS monitored_directories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS application_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """;
    }

    public String getJdbcUrl() {
        return jdbcUrl;
    }

    public void close() {
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute("PRAGMA wal_checkpoint(TRUNCATE);");
            stmt.execute("PRAGMA optimize;");
        } catch (Exception ignored) {}
    }
}
