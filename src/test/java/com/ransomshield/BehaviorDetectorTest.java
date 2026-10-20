package com.ransomshield;

import com.ransomshield.analysis.BehaviorDetector;
import com.ransomshield.model.FileEvent;
import com.ransomshield.model.MonitoringConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

public class BehaviorDetectorTest {

    private MonitoringConfig config;
    private BehaviorDetector detector;

    @BeforeEach
    public void setUp() {
        config = new MonitoringConfig();
        config.setAnalysisWindowSeconds(2.0); // short window for test
        detector = new BehaviorDetector(config);
    }

    @Test
    public void testRecordAndCountEvents() {
        Path dir1 = Paths.get("test-data/Documents");
        Path dir2 = Paths.get("test-data/Images");

        Instant now = Instant.now();

        FileEvent ev1 = new FileEvent(dir1.resolve("doc1.txt"), "CREATE", now, 100, dir1);
        FileEvent ev2 = new FileEvent(dir1.resolve("doc1.txt"), "MODIFY", now.plusMillis(50), 200, dir1);
        ev2.setEntropy(4.5);

        FileEvent ev3 = new FileEvent(dir2.resolve("img1.jpg"), "MODIFY", now.plusMillis(100), 500, dir2);
        ev3.setEntropy(5.2);

        detector.recordEvent(ev1);
        detector.recordEvent(ev2);
        detector.recordEvent(ev3);

        BehaviorDetector.BehaviorSnapshot snapshot = detector.getSnapshot();

        assertEquals(3, snapshot.getTotalEvents());
        assertEquals(2, snapshot.getModifiedCount());
        assertEquals(1, snapshot.getCreatedCount());
        assertEquals(2, snapshot.getUniqueFilesCount());
        assertEquals(2, snapshot.getUniqueDirectoriesCount());
        assertEquals(4.85, snapshot.getAverageEntropy(), 0.01);
    }

    @Test
    public void testSuspiciousExtensionDetection() {
        Path dir = Paths.get("test-data/Documents");
        Instant now = Instant.now();

        FileEvent ev = new FileEvent(dir.resolve("document.txt.encrypted"), "RENAME", now, 1024, dir);
        detector.recordEvent(ev);

        BehaviorDetector.BehaviorSnapshot snapshot = detector.getSnapshot();

        assertEquals(1, snapshot.getSuspiciousRenamesCount());
        assertTrue(snapshot.getSuspiciousExtensionsFound().contains(".encrypted"));
    }

    @Test
    public void testSlidingWindowPruning() {
        Path dir = Paths.get("test-data/Documents");
        Instant oldTime = Instant.now().minusSeconds(10); // outside 2.0s window
        Instant freshTime = Instant.now();

        FileEvent oldEv = new FileEvent(dir.resolve("old.txt"), "MODIFY", oldTime, 100, dir);
        FileEvent freshEv = new FileEvent(dir.resolve("fresh.txt"), "MODIFY", freshTime, 100, dir);

        detector.recordEvent(oldEv);
        detector.recordEvent(freshEv);

        BehaviorDetector.BehaviorSnapshot snapshot = detector.getSnapshot();

        // The old event should have been pruned out of the active window
        assertEquals(1, snapshot.getTotalEvents());
        assertEquals(1, snapshot.getUniqueFilesCount());
    }
}
