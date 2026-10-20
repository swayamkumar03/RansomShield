package com.ransomshield.model;

import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;

/**
 * Represents a monitored filesystem event captured by Java NIO WatchService.
 */
public class FileEvent {
    private final String id;
    private final Path path;
    private final String eventType; // CREATE, MODIFY, DELETE, RENAME
    private final Instant timestamp;
    private final long fileSize;
    private final String extension;
    private final Path parentDirectory;
    private final Path oldPath; // non-null if RENAME
    private volatile Double entropy; // computed asynchronously

    public FileEvent(Path path, String eventType, Instant timestamp, long fileSize, Path parentDirectory, Path oldPath) {
        this.id = UUID.randomUUID().toString();
        this.path = path;
        this.eventType = eventType;
        this.timestamp = timestamp != null ? timestamp : Instant.now();
        this.fileSize = fileSize;
        this.parentDirectory = parentDirectory;
        this.oldPath = oldPath;
        this.extension = extractExtension(path);
        this.entropy = null;
    }

    public FileEvent(Path path, String eventType, Instant timestamp, long fileSize, Path parentDirectory) {
        this(path, eventType, timestamp, fileSize, parentDirectory, null);
    }

    public static String extractExtension(Path path) {
        if (path == null) return "";
        String fileName = path.getFileName() != null ? path.getFileName().toString() : "";
        int dotIndex = fileName.lastIndexOf('.');
        if (dotIndex > 0 && dotIndex < fileName.length() - 1) {
            return fileName.substring(dotIndex).toLowerCase();
        }
        return "";
    }

    public String getId() {
        return id;
    }

    public Path getPath() {
        return path;
    }

    public String getFileName() {
        return path != null && path.getFileName() != null ? path.getFileName().toString() : "";
    }

    public String getEventType() {
        return eventType;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public long getFileSize() {
        return fileSize;
    }

    public String getExtension() {
        return extension;
    }

    public Path getParentDirectory() {
        return parentDirectory;
    }

    public Path getOldPath() {
        return oldPath;
    }

    public Double getEntropy() {
        return entropy;
    }

    public void setEntropy(Double entropy) {
        this.entropy = entropy;
    }

    public boolean hasEntropy() {
        return entropy != null;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s on %s (size=%d, entropy=%s)",
                eventType, timestamp, path, fileSize, entropy != null ? String.format("%.2f", entropy) : "N/A");
    }
}
