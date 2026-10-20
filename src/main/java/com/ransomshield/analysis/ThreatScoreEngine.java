package com.ransomshield.analysis;

import com.ransomshield.model.MonitoringConfig;
import com.ransomshield.model.ThreatAssessment;
import com.ransomshield.model.ThreatLevel;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Multi-factor threat scoring engine combining Shannon entropy, modification rate,
 * affected file counts, directory span, and operational patterns into a 0-100 score.
 */
public class ThreatScoreEngine {
    private final MonitoringConfig config;

    public ThreatScoreEngine(MonitoringConfig config) {
        this.config = config;
    }

    /**
     * Evaluates a behavioral snapshot and produces a structured threat assessment.
     */
    public ThreatAssessment assess(BehaviorDetector.BehaviorSnapshot snapshot) {
        if (snapshot == null || snapshot.getTotalEvents() == 0) {
            return ThreatAssessment.createNormal();
        }

        List<String> reasons = new ArrayList<>();

        // 1. ENTROPY SCORE (0 - 20 pts)
        // Uses the higher of average or max entropy with weighting
        double evaluatedEntropy = snapshot.getMaxEntropy() > 0 ? snapshot.getMaxEntropy() : snapshot.getAverageEntropy();
        int entropyScore = 0;
        if (evaluatedEntropy >= config.getEntropyHigh()) { // >= 7.5
            entropyScore = 20;
            reasons.add(String.format("Very high Shannon entropy (max %.2f bits/byte)", evaluatedEntropy));
        } else if (evaluatedEntropy >= config.getEntropyMedium()) { // >= 7.0
            entropyScore = 10;
            reasons.add(String.format("High Shannon entropy (max %.2f bits/byte)", evaluatedEntropy));
        } else if (evaluatedEntropy >= config.getEntropyLow()) { // >= 6.0
            entropyScore = 5;
            reasons.add(String.format("Moderate entropy elevation (max %.2f bits/byte)", evaluatedEntropy));
        }

        // 2. MODIFICATION RATE SCORE (0 - 20 pts)
        double rate = snapshot.getModificationRate();
        int rateScore = 0;
        if (rate > config.getRateHigh()) { // > 15 files/sec
            rateScore = 20;
            reasons.add(String.format("Rapid modification burst (%.1f files/sec)", rate));
        } else if (rate >= config.getRateMedium()) { // 5 - 15 files/sec
            rateScore = 10;
            reasons.add(String.format("Elevated modification rate (%.1f files/sec)", rate));
        } else if (rate >= config.getRateLow()) { // 2 - 5 files/sec
            rateScore = 5;
            reasons.add(String.format("Noticeable file activity rate (%.1f files/sec)", rate));
        }

        // 3. NUMBER OF FILES MODIFIED SCORE (0 - 20 pts)
        int filesCount = snapshot.getUniqueFilesCount();
        int filesScore = 0;
        if (filesCount > config.getFilesHigh()) { // > 100
            filesScore = 20;
            reasons.add(String.format("Massive file volume (%d unique files touched)", filesCount));
        } else if (filesCount >= config.getFilesMedium()) { // 21 - 100
            filesScore = 10;
            reasons.add(String.format("Substantial file modification volume (%d files)", filesCount));
        } else if (filesCount > config.getFilesLow()) { // 6 - 20
            filesScore = 5;
            reasons.add(String.format("Moderate file count touched (%d files)", filesCount));
        }

        // 4. DIRECTORIES AFFECTED SCORE (0 - 10 pts)
        int dirCount = snapshot.getUniqueDirectoriesCount();
        int directoryScore = 0;
        if (dirCount >= config.getDirectoriesCritical()) { // 5+
            directoryScore = 10;
            reasons.add(String.format("Widespread traversal across %d distinct directories", dirCount));
        } else if (dirCount >= config.getDirectoriesHigh()) { // 3 - 4
            directoryScore = 7;
            reasons.add(String.format("Multi-directory activity (%d directories)", dirCount));
        } else if (dirCount >= config.getDirectoriesMedium()) { // 2
            directoryScore = 3;
            reasons.add(String.format("Multiple directories touched (%d directories)", dirCount));
        }

        // 5. OPERATION PATTERN SCORE (0 - 20 pts)
        int operationScore = 0;
        int suspRenames = snapshot.getSuspiciousRenamesCount();
        int totalRenames = snapshot.getRenameCount();
        int totalDeleted = snapshot.getDeletedCount();

        if (suspRenames > 0 && filesCount >= 10) {
            // Suspicious extension change + mass operations
            operationScore = 20;
            reasons.add(String.format("Known ransomware extension pattern detected (%d files, %s)",
                    suspRenames, snapshot.getSuspiciousExtensionsFound()));
        } else if (suspRenames > 0) {
            operationScore = 10;
            reasons.add(String.format("Suspicious file rename to ransomware extension (%d files)", suspRenames));
        } else if (totalRenames >= 10 || totalDeleted >= 10) {
            // Mass rename/delete
            operationScore = 7;
            reasons.add(String.format("Mass file rename/deletion pattern (%d renames, %d deletes)", totalRenames, totalDeleted));
        } else if (snapshot.getTotalEvents() > 20 && snapshot.getModifiedCount() > 10) {
            // Repeated create/modify
            operationScore = 3;
            reasons.add("Repeated create/modify cycle detected");
        }

        // TOTAL RAW SCORE (0 - 100)
        int totalScore = entropyScore + rateScore + filesScore + directoryScore + operationScore;
        totalScore = Math.min(100, Math.max(0, totalScore));

        // Determine ThreatLevel according to thresholds
        ThreatLevel level = ThreatLevel.fromScore(
                totalScore,
                config.getScoreSuspicious(),
                config.getScoreHigh(),
                config.getScoreCritical()
        );

        return new ThreatAssessment(
                totalScore,
                level,
                reasons,
                Instant.now(),
                snapshot.getUniqueFilesCount(),
                snapshot.getUniqueDirectoriesCount(),
                snapshot.getAverageEntropy(),
                snapshot.getMaxEntropy(),
                snapshot.getModificationRate(),
                entropyScore,
                rateScore,
                filesScore,
                directoryScore,
                operationScore
        );
    }
}
