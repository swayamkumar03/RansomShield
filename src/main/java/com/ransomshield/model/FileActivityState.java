package com.ransomshield.model;

import java.nio.file.Path;
import java.time.Instant;

/**
 * Tracks historical activity state for a single file within the sliding analysis window.
 */
public class FileActivityState {
    private final Path path;
    private long initialSize;
    private long latestSize;
    private Instant firstSeen;
    private Instant lastSeen;
    private int modificationCount;
    private String initialExtension;
    private String currentExtension;
    private Double lastEntropy;

    public FileActivityState(Path path, long initialSize, Instant timestamp, String extension) {
        this.path = path;
        this.initialSize = initialSize;
        this.latestSize = initialSize;
        this.firstSeen = timestamp;
        this.lastSeen = timestamp;
        this.modificationCount = 1;
        this.initialExtension = extension;
        this.currentExtension = extension;
        this.lastEntropy = null;
    }

    public synchronized void recordEvent(String eventType, long size, Instant timestamp, String extension, Double entropy) {
        this.latestSize = size;
        this.lastSeen = timestamp;
        this.modificationCount++;
        this.currentExtension = extension;
        if (entropy != null) {
            this.lastEntropy = entropy;
        }
    }

    public Path getPath() {
        return path;
    }

    public synchronized long getInitialSize() {
        return initialSize;
    }

    public synchronized long getLatestSize() {
        return latestSize;
    }

    public synchronized Instant getFirstSeen() {
        return firstSeen;
    }

    public synchronized Instant getLastSeen() {
        return lastSeen;
    }

    public synchronized int getModificationCount() {
        return modificationCount;
    }

    public synchronized String getInitialExtension() {
        return initialExtension;
    }

    public synchronized String getCurrentExtension() {
        return currentExtension;
    }

    public synchronized Double getLastEntropy() {
        return lastEntropy;
    }

    public synchronized boolean hasExtensionChanged() {
        return initialExtension != null && currentExtension != null && !initialExtension.equalsIgnoreCase(currentExtension);
    }
}
