package com.ransomshield.defense;

import java.time.Instant;

/**
 * Metadata record for a file securely isolated in RansomShield's quarantine sandbox.
 */
public class QuarantineRecord {
    private final String id;
    private final String incidentId;
    private final String originalPath;
    private final String quarantinePath;
    private final Instant timestamp;
    private final long fileSize;
    private final Double entropy;
    private boolean restored;
    private Instant restoredAt;

    public QuarantineRecord(String id, String incidentId, String originalPath, String quarantinePath,
                            Instant timestamp, long fileSize, Double entropy, boolean restored, Instant restoredAt) {
        this.id = id;
        this.incidentId = incidentId;
        this.originalPath = originalPath;
        this.quarantinePath = quarantinePath;
        this.timestamp = timestamp != null ? timestamp : Instant.now();
        this.fileSize = fileSize;
        this.entropy = entropy;
        this.restored = restored;
        this.restoredAt = restoredAt;
    }

    public String getId() {
        return id;
    }

    public String getIncidentId() {
        return incidentId;
    }

    public String getOriginalPath() {
        return originalPath;
    }

    public String getQuarantinePath() {
        return quarantinePath;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public long getFileSize() {
        return fileSize;
    }

    public Double getEntropy() {
        return entropy;
    }

    public boolean isRestored() {
        return restored;
    }

    public void setRestored(boolean restored) {
        this.restored = restored;
    }

    public Instant getRestoredAt() {
        return restoredAt;
    }

    public void setRestoredAt(Instant restoredAt) {
        this.restoredAt = restoredAt;
    }
}
