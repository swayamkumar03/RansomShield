package com.ransomshield.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Result of behavioral risk evaluation produced by the ThreatScoreEngine.
 */
public class ThreatAssessment {
    private final int score;
    private final ThreatLevel threatLevel;
    private final List<String> reasons;
    private final Instant timestamp;
    private final int affectedFiles;
    private final int affectedDirectories;
    private final double averageEntropy;
    private final double maxEntropy;
    private final double modificationRate;

    // Component score breakdown
    private final int entropyScore;
    private final int rateScore;
    private final int filesScore;
    private final int directoryScore;
    private final int operationScore;

    public ThreatAssessment(int score, ThreatLevel threatLevel, List<String> reasons, Instant timestamp,
                            int affectedFiles, int affectedDirectories, double averageEntropy, double maxEntropy,
                            double modificationRate, int entropyScore, int rateScore, int filesScore,
                            int directoryScore, int operationScore) {
        this.score = Math.max(0, Math.min(100, score));
        this.threatLevel = threatLevel;
        this.reasons = reasons != null ? Collections.unmodifiableList(new ArrayList<>(reasons)) : Collections.emptyList();
        this.timestamp = timestamp != null ? timestamp : Instant.now();
        this.affectedFiles = affectedFiles;
        this.affectedDirectories = affectedDirectories;
        this.averageEntropy = averageEntropy;
        this.maxEntropy = maxEntropy;
        this.modificationRate = modificationRate;
        this.entropyScore = entropyScore;
        this.rateScore = rateScore;
        this.filesScore = filesScore;
        this.directoryScore = directoryScore;
        this.operationScore = operationScore;
    }

    public static ThreatAssessment createNormal() {
        return new ThreatAssessment(
                0,
                ThreatLevel.NORMAL,
                Collections.emptyList(),
                Instant.now(),
                0,
                0,
                0.0,
                0.0,
                0.0,
                0, 0, 0, 0, 0
        );
    }

    public int getScore() {
        return score;
    }

    public ThreatLevel getThreatLevel() {
        return threatLevel;
    }

    public List<String> getReasons() {
        return reasons;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public int getAffectedFiles() {
        return affectedFiles;
    }

    public int getAffectedDirectories() {
        return affectedDirectories;
    }

    public double getAverageEntropy() {
        return averageEntropy;
    }

    public double getMaxEntropy() {
        return maxEntropy;
    }

    public double getModificationRate() {
        return modificationRate;
    }

    public int getEntropyScore() {
        return entropyScore;
    }

    public int getRateScore() {
        return rateScore;
    }

    public int getFilesScore() {
        return filesScore;
    }

    public int getDirectoryScore() {
        return directoryScore;
    }

    public int getOperationScore() {
        return operationScore;
    }

    @Override
    public String toString() {
        return String.format("ThreatAssessment [score=%d, level=%s, files=%d, dirs=%d, rate=%.1f/s, avgEntropy=%.2f, reasons=%s]",
                score, threatLevel, affectedFiles, affectedDirectories, modificationRate, averageEntropy, reasons);
    }
}
