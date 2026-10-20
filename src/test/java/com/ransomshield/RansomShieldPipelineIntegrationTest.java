package com.ransomshield;

import com.ransomshield.model.Incident;
import com.ransomshield.model.MonitoringConfig;
import com.ransomshield.model.ThreatAssessment;
import com.ransomshield.model.ThreatLevel;
import com.ransomshield.simulator.RansomwareSimulator;
import com.ransomshield.simulator.SimulationMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

public class RansomShieldPipelineIntegrationTest {

    private RansomShieldEngine engine;
    private RansomwareSimulator simulator;
    private Path testDir;

    @BeforeEach
    public void setUp(@TempDir Path tempDir) throws Exception {
        testDir = tempDir.resolve("sandbox-test-data");
        Files.createDirectories(testDir);

        MonitoringConfig config = new MonitoringConfig();
        config.setMonitoredDirectory(testDir.toString());
        config.setTestDirectory(testDir.toString());
        config.setDatabaseUrl("jdbc:sqlite:" + tempDir.resolve("integration.db").toAbsolutePath());
        config.setAnalysisWindowSeconds(5.0);

        engine = new RansomShieldEngine(config);
        simulator = new RansomwareSimulator(testDir);
        simulator.ensureTestDataset();
        Thread.sleep(400); // let initial file generation settle

        engine.startMonitoring(testDir);
        Thread.sleep(400); // let WatchService initial registration settle
        engine.getBehaviorDetector().reset();
        engine.getEventQueue().clear();
    }

    @AfterEach
    public void tearDown() {
        if (engine != null) {
            engine.shutdown();
        }
        System.gc();
    }

    @Test
    public void testFullPipeline_NormalActivityRemainsNormal() throws Exception {
        AtomicReference<ThreatAssessment> peakAssessment = new AtomicReference<>(ThreatAssessment.createNormal());
        engine.getAlertManager().addListener(new com.ransomshield.alert.AlertListener() {
            @Override
            public void onThreatAssessed(ThreatAssessment assessment) {
                if (assessment.getScore() > peakAssessment.get().getScore()) {
                    peakAssessment.set(assessment);
                }
            }
            @Override public void onIncidentRaised(Incident incident) {}
            @Override public void onEventProcessed(com.ransomshield.model.FileEvent event) {}
        });

        simulator.runSimulation(SimulationMode.NORMAL_ACTIVITY);
        Thread.sleep(1500); // allow event queue and worker to consume

        ThreatAssessment peak = peakAssessment.get();
        assertEquals(ThreatLevel.NORMAL, peak.getThreatLevel(),
                "Normal slow activity should never trigger elevated threat alarms: score was " + peak.getScore());
    }

    @Test
    public void testFullPipeline_SingleHighEntropyFileDoesNotTriggerCritical() throws Exception {
        AtomicReference<ThreatAssessment> peakAssessment = new AtomicReference<>(ThreatAssessment.createNormal());
        engine.getAlertManager().addListener(new com.ransomshield.alert.AlertListener() {
            @Override
            public void onThreatAssessed(ThreatAssessment assessment) {
                if (assessment.getScore() > peakAssessment.get().getScore()) {
                    peakAssessment.set(assessment);
                }
            }
            @Override public void onIncidentRaised(Incident incident) {}
            @Override public void onEventProcessed(com.ransomshield.model.FileEvent event) {}
        });

        simulator.runSimulation(SimulationMode.HIGH_ENTROPY_SINGLE);
        Thread.sleep(1500);

        ThreatAssessment peak = peakAssessment.get();
        assertNotEquals(ThreatLevel.CRITICAL, peak.getThreatLevel(),
                "False-positive check: Single high-entropy file must NOT produce CRITICAL alert");
        assertTrue(peak.getScore() <= 30,
                "Score should stay low (<= 30) for a single file, was: " + peak.getScore());
    }

    @Test
    public void testFullPipeline_CombinedSimulationSpikesThreatAndLogsIncident() throws Exception {
        AtomicReference<ThreatAssessment> peakAssessment = new AtomicReference<>(ThreatAssessment.createNormal());
        engine.getAlertManager().addListener(new com.ransomshield.alert.AlertListener() {
            @Override
            public void onThreatAssessed(ThreatAssessment assessment) {
                if (assessment.getScore() > peakAssessment.get().getScore()) {
                    peakAssessment.set(assessment);
                }
            }
            @Override public void onIncidentRaised(Incident incident) {}
            @Override public void onEventProcessed(com.ransomshield.model.FileEvent event) {}
        });

        // Run combined attack mode
        simulator.runSimulation(SimulationMode.COMBINED_RANSOMWARE_SIMULATION);
        Thread.sleep(2500); // allow WatchService and workers to digest rapid events

        ThreatAssessment peak = peakAssessment.get();
        assertTrue(peak.getScore() >= 60, "Peak threat score should reach HIGH or CRITICAL, was: " + peak.getScore());
        assertTrue(peak.getThreatLevel() == ThreatLevel.HIGH || peak.getThreatLevel() == ThreatLevel.CRITICAL);

        // Verify incident persisted in database
        List<Incident> incidents = engine.getIncidentRepository().findAll();
        assertFalse(incidents.isEmpty(), "An incident must be persisted in SQLite during elevated attack simulation");
        Incident logged = incidents.get(0);
        assertTrue(logged.getScore() >= 60);
        assertTrue(logged.getFilesAffected() > 10);
    }
}
