package com.ransomshield;

import com.ransomshield.analysis.BehaviorDetector;
import com.ransomshield.analysis.ThreatScoreEngine;
import com.ransomshield.model.FileEvent;
import com.ransomshield.model.MonitoringConfig;
import com.ransomshield.model.ThreatAssessment;
import com.ransomshield.model.ThreatLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Paths;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class ThreatScoreEngineTest {

    private MonitoringConfig config;
    private ThreatScoreEngine engine;

    @BeforeEach
    public void setUp() {
        config = new MonitoringConfig();
        engine = new ThreatScoreEngine(config);
    }

    @Test
    public void testEmptySnapshotProducesNormal() {
        BehaviorDetector.BehaviorSnapshot empty = BehaviorDetector.BehaviorSnapshot.empty(5.0);
        ThreatAssessment assessment = engine.assess(empty);

        assertEquals(0, assessment.getScore());
        assertEquals(ThreatLevel.NORMAL, assessment.getThreatLevel());
        assertTrue(assessment.getReasons().isEmpty());
    }

    @Test
    public void testFalsePositiveDefense_SingleHighEntropyFileDoesNotTriggerCritical() {
        // SCENARIO: A user modifies or creates a single encrypted ZIP / compressed file.
        // Entropy = 7.85 bits/byte (High)
        // Files modified = 1
        // Rate = 0.5 files/sec (Low)
        // Directories = 1
        // Renames = 0

        BehaviorDetector.BehaviorSnapshot snapshot = new BehaviorDetector.BehaviorSnapshot(
                5.0,
                1,          // total events
                1,          // modified
                0,          // created
                0,          // deleted
                0,          // renames
                1,          // unique files
                1,          // unique dirs
                0.5,        // rate (low)
                7.85,       // average entropy (high)
                7.85,       // max entropy (high)
                0,          // suspicious renames
                Collections.emptySet(),
                List.of(new FileEvent(Paths.get("data.zip"), "MODIFY", Instant.now(), 5000, Paths.get(".")))
        );

        ThreatAssessment assessment = engine.assess(snapshot);

        // Entropy gives 20 pts, all other signals give 0 pts. Total = 20 pts.
        assertEquals(20, assessment.getScore());
        assertEquals(ThreatLevel.NORMAL, assessment.getThreatLevel(),
                "CRITICAL REQUIREMENT: High entropy on a single file must NOT cause high or critical alarm!");
    }

    @Test
    public void testRansomwareLikeActivityTriggersCritical() {
        // SCENARIO: Rapid burst modifying 105 files across 5 directories with 7.85 entropy and .encrypted renames
        BehaviorDetector.BehaviorSnapshot snapshot = new BehaviorDetector.BehaviorSnapshot(
                5.0,
                150,        // total events
                105,        // modified
                0,          // created
                0,          // deleted
                50,         // renames
                105,        // unique files (> 100 -> 20 pts)
                5,          // unique directories (5+ -> 10 pts)
                25.0,       // rate (25 files/sec > 15/s -> 20 pts)
                7.85,       // avg entropy (>= 7.5 -> 20 pts)
                7.92,       // max entropy
                50,         // suspicious renames (-> 20 pts)
                Set.of(".encrypted"),
                Collections.emptyList()
        );

        ThreatAssessment assessment = engine.assess(snapshot);

        assertTrue(assessment.getScore() >= 80, "Combined ransomware activity should score >= 80, was: " + assessment.getScore());
        assertEquals(ThreatLevel.CRITICAL, assessment.getThreatLevel());
        assertFalse(assessment.getReasons().isEmpty());
    }

    @Test
    public void testHighThreatActivityClassification() {
        // SCENARIO: Rapid burst with 75 files and 4 directories -> Score = 77 (HIGH, 60-79)
        BehaviorDetector.BehaviorSnapshot snapshot = new BehaviorDetector.BehaviorSnapshot(
                5.0,
                100, 75, 0, 0, 40,
                75, 4, 20.0,
                7.80, 7.85, 30,
                Set.of(".encrypted"),
                Collections.emptyList()
        );

        ThreatAssessment assessment = engine.assess(snapshot);
        assertEquals(77, assessment.getScore());
        assertEquals(ThreatLevel.HIGH, assessment.getThreatLevel());
    }

    @Test
    public void testModerateActivityProducesSuspicious() {
        // SCENARIO: Moderate burst of 15 files touched in 1 dir, moderate rate ~4 files/sec, normal text entropy ~4.0
        BehaviorDetector.BehaviorSnapshot snapshot = new BehaviorDetector.BehaviorSnapshot(
                5.0,
                15, 15, 0, 0, 0,
                15, 1, 4.0,
                4.1, 4.2, 0,
                Collections.emptySet(),
                Collections.emptyList()
        );

        ThreatAssessment assessment = engine.assess(snapshot);
        // filesScore: 5 pts, rateScore: 5 pts -> score = 10 pts (NORMAL)
        assertEquals(ThreatLevel.NORMAL, assessment.getThreatLevel());
    }
}
