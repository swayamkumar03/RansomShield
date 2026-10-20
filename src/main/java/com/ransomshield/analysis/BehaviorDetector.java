package com.ransomshield.analysis;

import com.ransomshield.model.FileActivityState;
import com.ransomshield.model.FileEvent;
import com.ransomshield.model.MonitoringConfig;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * Tracks and analyzes filesystem events over a configurable sliding time window.
 */
public class BehaviorDetector {
    private final MonitoringConfig config;
    private final Deque<FileEvent> eventWindow = new ConcurrentLinkedDeque<>();
    private final Map<Path, FileActivityState> fileStates = new ConcurrentHashMap<>();

    public BehaviorDetector(MonitoringConfig config) {
        this.config = config;
    }

    /**
     * Records a newly analyzed filesystem event and updates the sliding window.
     */
    public synchronized void recordEvent(FileEvent event) {
        if (event == null) return;

        eventWindow.addLast(event);

        // Update file state tracking
        if (event.getPath() != null) {
            fileStates.compute(event.getPath(), (path, state) -> {
                if (state == null) {
                    return new FileActivityState(path, event.getFileSize(), event.getTimestamp(), event.getExtension());
                } else {
                    state.recordEvent(event.getEventType(), event.getFileSize(), event.getTimestamp(), event.getExtension(), event.getEntropy());
                    return state;
                }
            });
        }

        pruneWindow(Instant.now());
    }

    /**
     * Prunes events that fall outside the configured sliding window.
     */
    public synchronized void pruneWindow(Instant now) {
        double windowSeconds = config.getAnalysisWindowSeconds();
        Instant cutoff = now.minusMillis((long) (windowSeconds * 1000));

        while (!eventWindow.isEmpty()) {
            FileEvent oldest = eventWindow.peekFirst();
            if (oldest != null && oldest.getTimestamp().isBefore(cutoff)) {
                eventWindow.pollFirst();
            } else {
                break;
            }
        }

        // Clean up stale file states older than 2x window
        Instant stateCutoff = now.minusMillis((long) (windowSeconds * 2000));
        fileStates.entrySet().removeIf(entry -> entry.getValue().getLastSeen().isBefore(stateCutoff));
    }

    /**
     * Calculates a point-in-time behavioral snapshot from the sliding window.
     */
    public synchronized BehaviorSnapshot getSnapshot() {
        Instant now = Instant.now();
        pruneWindow(now);

        List<FileEvent> events = new ArrayList<>(eventWindow);
        if (events.isEmpty()) {
            return BehaviorSnapshot.empty(config.getAnalysisWindowSeconds());
        }

        int modifiedCount = 0;
        int createdCount = 0;
        int deletedCount = 0;
        int renameCount = 0;
        int suspiciousRenames = 0;

        Set<Path> uniqueFiles = new HashSet<>();
        Set<Path> uniqueDirectories = new HashSet<>();
        Set<String> suspiciousExtensionsFound = new HashSet<>();

        double entropySum = 0.0;
        double maxEntropy = 0.0;
        int entropySampleCount = 0;

        Instant earliest = now;
        Instant latest = Instant.EPOCH;

        for (FileEvent ev : events) {
            if (ev.getTimestamp().isBefore(earliest)) earliest = ev.getTimestamp();
            if (ev.getTimestamp().isAfter(latest)) latest = ev.getTimestamp();

            if (ev.getPath() != null) {
                uniqueFiles.add(ev.getPath());
            }
            if (ev.getParentDirectory() != null) {
                uniqueDirectories.add(ev.getParentDirectory());
            }

            String type = ev.getEventType();
            if ("MODIFY".equalsIgnoreCase(type)) {
                modifiedCount++;
            } else if ("CREATE".equalsIgnoreCase(type)) {
                createdCount++;
            } else if ("DELETE".equalsIgnoreCase(type)) {
                deletedCount++;
            } else if ("RENAME".equalsIgnoreCase(type)) {
                renameCount++;
            }

            // Check suspicious extension
            String ext = ev.getExtension();
            if (config.isSuspiciousExtension(ext)) {
                suspiciousRenames++;
                suspiciousExtensionsFound.add(ext);
            }

            if (ev.hasEntropy()) {
                double e = ev.getEntropy();
                entropySum += e;
                if (e > maxEntropy) {
                    maxEntropy = e;
                }
                entropySampleCount++;
            }
        }

        // Calculate rate over the actual active time span in seconds (min 1.0s to avoid instant burst inflation)
        double durationSeconds = Math.max(1.0, Duration.between(earliest, latest).toMillis() / 1000.0);
        // Modification rate focuses on modifications + renames
        double modificationRate = (modifiedCount + renameCount) / durationSeconds;

        double avgEntropy = entropySampleCount > 0 ? (entropySum / entropySampleCount) : 0.0;

        return new BehaviorSnapshot(
                config.getAnalysisWindowSeconds(),
                events.size(),
                modifiedCount,
                createdCount,
                deletedCount,
                renameCount,
                uniqueFiles.size(),
                uniqueDirectories.size(),
                modificationRate,
                avgEntropy,
                maxEntropy,
                suspiciousRenames,
                suspiciousExtensionsFound,
                events
        );
    }

    /**
     * Clears all buffered events and tracked file states.
     */
    public synchronized void reset() {
        eventWindow.clear();
        fileStates.clear();
    }

    /**
     * Snapshot record of behavioral statistics.
     */
    public static class BehaviorSnapshot {
        private final double windowSeconds;
        private final int totalEvents;
        private final int modifiedCount;
        private final int createdCount;
        private final int deletedCount;
        private final int renameCount;
        private final int uniqueFilesCount;
        private final int uniqueDirectoriesCount;
        private final double modificationRate;
        private final double averageEntropy;
        private final double maxEntropy;
        private final int suspiciousRenamesCount;
        private final Set<String> suspiciousExtensionsFound;
        private final List<FileEvent> recentEvents;

        public BehaviorSnapshot(double windowSeconds, int totalEvents, int modifiedCount, int createdCount,
                                int deletedCount, int renameCount, int uniqueFilesCount, int uniqueDirectoriesCount,
                                double modificationRate, double averageEntropy, double maxEntropy,
                                int suspiciousRenamesCount, Set<String> suspiciousExtensionsFound,
                                List<FileEvent> recentEvents) {
            this.windowSeconds = windowSeconds;
            this.totalEvents = totalEvents;
            this.modifiedCount = modifiedCount;
            this.createdCount = createdCount;
            this.deletedCount = deletedCount;
            this.renameCount = renameCount;
            this.uniqueFilesCount = uniqueFilesCount;
            this.uniqueDirectoriesCount = uniqueDirectoriesCount;
            this.modificationRate = modificationRate;
            this.averageEntropy = averageEntropy;
            this.maxEntropy = maxEntropy;
            this.suspiciousRenamesCount = suspiciousRenamesCount;
            this.suspiciousExtensionsFound = Collections.unmodifiableSet(new HashSet<>(suspiciousExtensionsFound));
            this.recentEvents = Collections.unmodifiableList(new ArrayList<>(recentEvents));
        }

        public static BehaviorSnapshot empty(double windowSeconds) {
            return new BehaviorSnapshot(
                    windowSeconds, 0, 0, 0, 0, 0, 0, 0,
                    0.0, 0.0, 0.0, 0, Collections.emptySet(), Collections.emptyList()
            );
        }

        public double getWindowSeconds() { return windowSeconds; }
        public int getTotalEvents() { return totalEvents; }
        public int getModifiedCount() { return modifiedCount; }
        public int getCreatedCount() { return createdCount; }
        public int getDeletedCount() { return deletedCount; }
        public int getRenameCount() { return renameCount; }
        public int getUniqueFilesCount() { return uniqueFilesCount; }
        public int getUniqueDirectoriesCount() { return uniqueDirectoriesCount; }
        public double getModificationRate() { return modificationRate; }
        public double getAverageEntropy() { return averageEntropy; }
        public double getMaxEntropy() { return maxEntropy; }
        public int getSuspiciousRenamesCount() { return suspiciousRenamesCount; }
        public Set<String> getSuspiciousExtensionsFound() { return suspiciousExtensionsFound; }
        public List<FileEvent> getRecentEvents() { return recentEvents; }
    }
}
