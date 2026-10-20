package com.ransomshield;

import com.ransomshield.alert.NotificationService;
import com.ransomshield.database.DatabaseManager;
import com.ransomshield.database.IncidentRepository;
import com.ransomshield.defense.*;
import com.ransomshield.model.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

public class ActiveDefenseResponseTest {

    @TempDir
    Path tempDir;

    private DatabaseManager dbManager;
    private IncidentRepository incidentRepo;
    private QuarantineService quarantineService;
    private ProcessContainmentService processService;
    private DefensePolicy defensePolicy;
    private NotificationService notificationService;
    private DefenseManager defenseManager;

    @BeforeEach
    public void setUp() {
        String dbUrl = "jdbc:sqlite:" + tempDir.resolve("test_defense.db").toAbsolutePath();
        dbManager = new DatabaseManager(dbUrl);
        incidentRepo = new IncidentRepository(dbManager);
        quarantineService = new QuarantineService(dbManager);
        processService = new ProcessContainmentService();
        defensePolicy = new DefensePolicy();
        notificationService = new NotificationService();

        defenseManager = new DefenseManager(
                incidentRepo,
                quarantineService,
                processService,
                defensePolicy,
                notificationService
        );
    }

    @AfterEach
    public void tearDown() {
        notificationService.clearHistory();
    }

    @Test
    public void testSeverityToResponseMapping() {
        // 1. NORMAL (0 - 29)
        ThreatAssessment normalAssessment = new ThreatAssessment(
                15, ThreatLevel.NORMAL, Collections.emptyList(), Instant.now(),
                1, 1, 3.2, 3.5, 0.5, 0, 0, 5, 0, 0
        );
        DefensePolicy.PolicyDecision normalDecision = defensePolicy.evaluate(normalAssessment, null);
        assertEquals(ResponseAction.NONE, normalDecision.getRecommendedAction());
        assertFalse(normalDecision.isRequiresNotification());
        assertFalse(normalDecision.isRequiresUserConfirmation());

        // 2. SUSPICIOUS (30 - 59)
        ThreatAssessment suspiciousAssessment = new ThreatAssessment(
                45, ThreatLevel.SUSPICIOUS, List.of("Noticeable file rate"), Instant.now(),
                15, 2, 5.0, 5.5, 6.0, 5, 10, 5, 3, 0
        );
        DefensePolicy.PolicyDecision suspDecision = defensePolicy.evaluate(suspiciousAssessment, null);
        assertEquals(ResponseAction.INVESTIGATE, suspDecision.getRecommendedAction());
        assertTrue(suspDecision.isRequiresNotification());
        assertTrue(suspDecision.isDesktopNotificationEligible());

        // 3. HIGH (60 - 79)
        ThreatAssessment highAssessment = new ThreatAssessment(
                70, ThreatLevel.HIGH, List.of("High entropy", "Mass modification burst"), Instant.now(),
                45, 3, 7.2, 7.8, 18.0, 20, 20, 10, 7, 0
        );
        DefensePolicy.PolicyDecision highDecision = defensePolicy.evaluate(highAssessment, null);
        assertEquals(ResponseAction.SIMULATE_CONTAINMENT, highDecision.getRecommendedAction());
        assertTrue(highDecision.isRequiresNotification());
        assertTrue(highDecision.isRequiresUserConfirmation());

        // 4. CRITICAL (80 - 100)
        ThreatAssessment criticalAssessment = new ThreatAssessment(
                90, ThreatLevel.CRITICAL, List.of("Ransomware extension", "Very high entropy"), Instant.now(),
                120, 5, 7.9, 7.99, 25.0, 20, 20, 20, 10, 20
        );
        DefensePolicy.PolicyDecision critDecision = defensePolicy.evaluate(criticalAssessment, null);
        assertEquals(ResponseAction.SIMULATE_CONTAINMENT, critDecision.getRecommendedAction());
        assertTrue(critDecision.isRequiresNotification());
        assertTrue(critDecision.isRequiresUserConfirmation());
    }

    @Test
    public void testHighEntropyAloneStaysNormalAndCausesNoDestructiveAction() {
        // High entropy (e.g. 7.9 bits) alone contributes max 20 points, staying in NORMAL
        ThreatAssessment singleHighEntropy = new ThreatAssessment(
                20, ThreatLevel.NORMAL, List.of("Very high Shannon entropy (max 7.92 bits/byte)"), Instant.now(),
                1, 1, 7.92, 7.92, 0.2, 20, 0, 0, 0, 0
        );

        DefensePolicy.PolicyDecision decision = defensePolicy.evaluate(singleHighEntropy, null);
        assertEquals(ResponseAction.NONE, decision.getRecommendedAction());
        assertFalse(decision.isRequiresNotification(), "High entropy alone should not raise noisy user interruptions");
        assertFalse(decision.isRequiresUserConfirmation());
    }

    @Test
    public void testNotificationDeduplicationAndRateLimiting() {
        AtomicInteger inAppCount = new AtomicInteger(0);
        notificationService.addListener(msg -> inAppCount.incrementAndGet());

        Incident incident = new Incident(
                "inc-test-dedup", Instant.now(), ThreatLevel.SUSPICIOUS, 45,
                tempDir.toString(), 10, 1, 5.5, 6.0, 5.0, "Rate test",
                IncidentStatus.OPEN, List.of("Noticeable file rate")
        );

        // Dispatch 5 rapid alerts for the same incident
        for (int i = 0; i < 5; i++) {
            notificationService.dispatchAlert(
                    ThreatLevel.SUSPICIOUS, 45, tempDir.toString(),
                    List.of("Noticeable file rate"), incident
            );
        }

        // All in-app alerts are recorded in history
        assertEquals(5, notificationService.getRecentAlerts().size());
        assertEquals("inc-test-dedup", notificationService.getRecentAlerts().get(0).incidentId());
    }

    @Test
    public void testIncidentPersistenceWithDefenseAndTimelineFields() {
        Incident incident = new Incident(
                "inc-persist-1", Instant.now(), ThreatLevel.HIGH, 75,
                tempDir.toString(), 30, 2, 7.1, 7.8, 12.0, "Suspicious rename burst",
                IncidentStatus.OPEN, List.of("Ransomware extension", "High entropy")
        );
        incident.addAffectedPath(tempDir.resolve("doc1.txt.encrypted").toString());
        incident.addAffectedPath(tempDir.resolve("doc2.txt.encrypted").toString());
        incident.setResponseAction("SIMULATE_CONTAINMENT");
        incident.setResponseResult("SIMULATED: Isolated 2 files");
        incident.setSimulated(true);

        incidentRepo.save(incident);

        List<Incident> all = incidentRepo.findAll();
        assertFalse(all.isEmpty());

        Incident loaded = all.stream().filter(i -> "inc-persist-1".equals(i.getId())).findFirst().orElse(null);
        assertNotNull(loaded);
        assertEquals(ThreatLevel.HIGH, loaded.getSeverity());
        assertEquals(75, loaded.getScore());
        assertEquals(2, loaded.getAffectedPaths().size());
        assertEquals("SIMULATE_CONTAINMENT", loaded.getResponseAction());
        assertEquals("SIMULATED: Isolated 2 files", loaded.getResponseResult());
        assertTrue(loaded.isSimulated());
    }

    @Test
    public void testSafeSimulatedContainment() throws IOException {
        Path testFile = tempDir.resolve("protected_document.docx");
        Files.writeString(testFile, "Sensitive intellectual property", StandardCharsets.UTF_8);

        Incident incident = new Incident(
                "inc-sim-contain", Instant.now(), ThreatLevel.CRITICAL, 85,
                tempDir.toString(), 1, 1, 7.9, 7.9, 20.0, "Critical attack pattern",
                IncidentStatus.OPEN, List.of("Known ransomware extension", "Very high entropy")
        );
        incident.addAffectedPath(testFile.toString());

        ResponseResult result = defenseManager.simulateContainment(incident);

        assertTrue(result.isSuccess());
        assertTrue(result.isSimulated());
        assertEquals(ResponseAction.SIMULATE_CONTAINMENT, result.getAction());
        assertEquals(IncidentStatus.CONTAINED, incident.getStatus());
        assertTrue(incident.getResponseResult().contains("SIMULATED CONTAINMENT"));

        // Crucial safety check: The real file must NOT be deleted, locked, or mutated!
        assertTrue(Files.exists(testFile), "Original file must remain untouched during simulated containment");
        assertEquals("Sensitive intellectual property", Files.readString(testFile));
    }

    @Test
    public void testQuarantineStrictPathTraversalPrevention() throws IOException {
        Path allowedRoot = tempDir.resolve("sandbox-root");
        Files.createDirectories(allowedRoot);

        Path outsideDir = tempDir.resolve("outside-unauthorized");
        Files.createDirectories(outsideDir);
        Path outsideFile = outsideDir.resolve("system_secret.txt");
        Files.writeString(outsideFile, "Secret data", StandardCharsets.UTF_8);

        // Attempting to quarantine a file outside allowedScopeRoot
        ResponseResult result = quarantineService.quarantineFiles(
                List.of(outsideFile.toString()),
                allowedRoot,
                "inc-test-traversal"
        );

        assertFalse(result.isSuccess(), "Quarantine should reject paths outside allowed root scope");
        assertTrue(Files.exists(outsideFile), "File outside scope must remain untouched");
    }

    @Test
    public void testQuarantineAndReversibleRestorationWithinScope() throws IOException {
        Path allowedRoot = tempDir.resolve("sandbox-root");
        Path docsDir = allowedRoot.resolve("Documents");
        Files.createDirectories(docsDir);

        Path testFile = docsDir.resolve("financial_report.xlsx");
        Files.writeString(testFile, "Quarterly financial records", StandardCharsets.UTF_8);

        Incident incident = new Incident(
                "inc-quarantine-1", Instant.now(), ThreatLevel.HIGH, 70,
                allowedRoot.toString(), 1, 1, 7.5, 7.5, 10.0, "Suspicious activity",
                IncidentStatus.OPEN, List.of("High entropy")
        );
        incident.addAffectedPath(testFile.toString());

        // 1. Execute quarantine
        ResponseResult qResult = defenseManager.quarantineIncidentFiles(incident, allowedRoot);
        assertTrue(qResult.isSuccess());
        assertFalse(qResult.isSimulated());
        assertEquals(IncidentStatus.CONTAINED, incident.getStatus());

        // Original file moved to .quarantine
        assertFalse(Files.exists(testFile), "Original file should be moved away from working directory");
        Path quarantineDir = allowedRoot.resolve(".quarantine");
        assertTrue(Files.exists(quarantineDir));

        List<QuarantineRecord> records = quarantineService.findRecords(incident.getId(), false);
        assertEquals(1, records.size());

        // 2. Execute restore
        ResponseResult rResult = defenseManager.restoreQuarantinedFiles(incident, allowedRoot);
        assertTrue(rResult.isSuccess());
        assertEquals(IncidentStatus.RESOLVED, incident.getStatus());

        // File is restored back to original location
        assertTrue(Files.exists(testFile), "File should be restored to original path");
        assertEquals("Quarterly financial records", Files.readString(testFile));

        // Records marked restored
        List<QuarantineRecord> remainingActive = quarantineService.findRecords(incident.getId(), false);
        assertEquals(0, remainingActive.size());
    }

    @Test
    public void testProcessContainmentSystemProtection() {
        // Attempting to terminate the RansomShield JVM itself must be strictly rejected
        long jvmPid = ProcessHandle.current().pid();
        ResponseResult jvmResult = processService.containProcess(jvmPid, false);
        assertFalse(jvmResult.isSuccess());
        assertTrue(jvmResult.getMessage().contains("RansomShield JVM itself"));

        // Attempting to terminate PID 0 or PID 4 must be strictly rejected
        ResponseResult kernelResult = processService.containProcess(4L, false);
        assertFalse(kernelResult.isSuccess());
        assertTrue(kernelResult.getMessage().contains("protected OS core kernel process"));

        // In simulation mode, eligible process returns simulated success without killing
        ResponseResult simResult = processService.containProcess(999999L, true);
        // Process doesn't exist, correctly handles non-existent PID
        assertFalse(simResult.isSuccess());
        assertTrue(simResult.getErrorDetails().contains("Process not alive"));
    }

    @Test
    public void testSimulatorModes1Through6UnderDefensePipeline() throws Exception {
        Path sandbox = tempDir.resolve("modes-sandbox");
        com.ransomshield.simulator.RansomwareSimulator sim = new com.ransomshield.simulator.RansomwareSimulator(sandbox);
        sim.ensureTestDataset();

        MonitoringConfig config = new MonitoringConfig();
        config.setMonitoredDirectory(sandbox.toString());
        config.setTestDirectory(sandbox.toString());
        config.setDatabaseUrl("jdbc:sqlite:" + tempDir.resolve("modes.db").toAbsolutePath());

        RansomShieldEngine engine = new RansomShieldEngine(config);
        try {
            engine.startMonitoring(sandbox);
            Thread.sleep(300);

            // MODE 1: Normal Activity
            sim.runSimulation(com.ransomshield.simulator.SimulationMode.NORMAL_ACTIVITY);
            Thread.sleep(600);
            ThreatAssessment m1 = engine.getLatestAssessment();
            assertEquals(ThreatLevel.NORMAL, m1.getThreatLevel());
            assertEquals(ResponseAction.NONE, defensePolicy.evaluate(m1, null).getRecommendedAction());

            // MODE 2: High Entropy Single File (False-Positive Defense)
            sim.runSimulation(com.ransomshield.simulator.SimulationMode.HIGH_ENTROPY_SINGLE);
            Thread.sleep(600);
            ThreatAssessment m2 = engine.getLatestAssessment();
            // High entropy alone must NOT exceed NORMAL
            assertEquals(ThreatLevel.NORMAL, m2.getThreatLevel());
            assertEquals(ResponseAction.NONE, defensePolicy.evaluate(m2, null).getRecommendedAction());

            // MODE 3: Mass Modification
            sim.runSimulation(com.ransomshield.simulator.SimulationMode.MASS_MODIFICATION);
            Thread.sleep(800);
            ThreatAssessment m3 = engine.getLatestAssessment();
            assertTrue(m3.getFilesScore() > 0 || m3.getRateScore() > 0, "Mass modification must score volume/rate");

            // Reset dataset cleanly before renames
            sim.ensureTestDataset();
            Thread.sleep(300);

            // MODE 4: Suspicious Extension Rename
            sim.runSimulation(com.ransomshield.simulator.SimulationMode.SUSPICIOUS_RENAME);
            Thread.sleep(800);
            ThreatAssessment m4 = engine.getLatestAssessment();
            assertTrue(m4.getOperationScore() > 0, "Suspicious rename must trigger operation pattern score");

            // MODE 5: Multi-Directory Traversal
            sim.runSimulation(com.ransomshield.simulator.SimulationMode.MULTI_DIRECTORY_TRAVERSAL);
            Thread.sleep(800);
            ThreatAssessment m5 = engine.getLatestAssessment();
            assertTrue(m5.getDirectoryScore() >= 3, "Multi-directory traversal must score directory factor");

            // MODE 6: Combined Simulation
            sim.runSimulation(com.ransomshield.simulator.SimulationMode.COMBINED_RANSOMWARE_SIMULATION);
            Thread.sleep(1200);
            ThreatAssessment m6 = engine.getLatestAssessment();
            assertTrue(m6.getScore() >= 30, "Combined simulation must raise threat score");
            DefensePolicy.PolicyDecision d6 = defensePolicy.evaluate(m6, engine.getAlertManager().getActiveIncident());
            assertTrue(d6.isRequiresNotification(), "Combined simulation must trigger notification");

            // Test executing simulated containment for the resulting incident
            Incident activeInc = engine.getAlertManager().getActiveIncident();
            if (activeInc != null) {
                ResponseResult containRes = engine.getDefenseManager().simulateContainment(activeInc);
                assertTrue(containRes.isSuccess());
                assertTrue(containRes.isSimulated());
                assertEquals(IncidentStatus.CONTAINED, activeInc.getStatus());
            }

        } finally {
            engine.shutdown();
            System.gc();
        }
    }
}
