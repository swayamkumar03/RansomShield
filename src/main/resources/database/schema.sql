-- RansomShield SQLite Schema

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    first_seen TEXT,
    last_seen TEXT,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    root_directory TEXT NOT NULL,
    files_affected INTEGER NOT NULL,
    directories_affected INTEGER NOT NULL,
    average_entropy REAL NOT NULL,
    max_entropy REAL NOT NULL,
    modification_rate REAL NOT NULL,
    operation_summary TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN',
    affected_paths TEXT,
    response_action TEXT DEFAULT 'NONE',
    response_result TEXT,
    is_simulated INTEGER DEFAULT 1
);

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

CREATE TABLE IF NOT EXISTS file_events (
    id TEXT PRIMARY KEY,
    incident_id TEXT,
    file_path TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    file_size INTEGER,
    extension TEXT,
    entropy REAL,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
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

CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_file_events_timestamp ON file_events(timestamp DESC);
