package com.ransomshield;

import com.ransomshield.model.FileEvent;
import com.ransomshield.model.MonitoringConfig;
import com.ransomshield.simulator.RansomwareSimulator;
import com.ransomshield.simulator.SimulationMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ModeDebugTraceTest {

    private RansomShieldEngine engine;
    private RansomwareSimulator simulator;
    private Path testDir;
    private final List<FileEvent> eventsReceived = Collections.synchronizedList(new ArrayList<>());

    @BeforeEach
    public void setUp(@TempDir Path tempDir) throws Exception {
        testDir = tempDir.resolve("trace-test-data");
        Files.createDirectories(testDir);

        MonitoringConfig config = new MonitoringConfig();
        config.setMonitoredDirectory(testDir.toString());
        config.setTestDirectory(testDir.toString());
        config.setDatabaseUrl("jdbc:sqlite:" + tempDir.resolve("trace.db").toAbsolutePath());

        engine = new RansomShieldEngine(config);
        simulator = new RansomwareSimulator(testDir);
        simulator.ensureTestDataset();
        Thread.sleep(300);

        engine.startMonitoring(testDir);
        Thread.sleep(300);

        engine.getAlertManager().addListener(new com.ransomshield.alert.AlertListener() {
            @Override public void onThreatAssessed(com.ransomshield.model.ThreatAssessment assessment) {}
            @Override public void onIncidentRaised(com.ransomshield.model.Incident incident) {}
            @Override
            public void onEventProcessed(FileEvent event) {
                eventsReceived.add(event);
            }
        });
    }

    @AfterEach
    public void tearDown() {
        if (engine != null) {
            engine.shutdown();
        }
    }

    @Test
    public void traceMode1() throws Exception {
        System.out.println("=== TRACING MODE 1 ===");
        eventsReceived.clear();
        simulator.runSimulation(SimulationMode.NORMAL_ACTIVITY);
        Thread.sleep(2500);
        System.out.println("Mode 1 total events received: " + eventsReceived.size());
    }

    @Test
    public void traceMode2() throws Exception {
        System.out.println("=== TRACING MODE 2 ===");
        eventsReceived.clear();
        simulator.runSimulation(SimulationMode.HIGH_ENTROPY_SINGLE);
        Thread.sleep(2000);
        System.out.println("Mode 2 total events received: " + eventsReceived.size());
    }

    @Test
    public void traceMode4ThenModes1And2And4() throws Exception {
        System.out.println("=== TRACING MODE 4 THEN MODES 1, 2, 4 ===");
        simulator.runSimulation(SimulationMode.SUSPICIOUS_RENAME);
        Thread.sleep(1000);
        eventsReceived.clear();

        System.out.println("Running Mode 1 after Mode 4...");
        simulator.runSimulation(SimulationMode.NORMAL_ACTIVITY);
        Thread.sleep(2000);
        int m1Events = eventsReceived.size();
        System.out.println("Events received for Mode 1 after Mode 4: " + m1Events);

        eventsReceived.clear();
        System.out.println("Running Mode 2 after Mode 4...");
        simulator.runSimulation(SimulationMode.HIGH_ENTROPY_SINGLE);
        Thread.sleep(2000);
        int m2Events = eventsReceived.size();
        System.out.println("Events received for Mode 2 after Mode 4: " + m2Events);

        eventsReceived.clear();
        System.out.println("Running Mode 4 second time...");
        simulator.runSimulation(SimulationMode.SUSPICIOUS_RENAME);
        Thread.sleep(2000);
        int m4Events = eventsReceived.size();
        System.out.println("Events received for Mode 4 second time: " + m4Events);
    }

    @Test
    public void traceResetWhileMonitoring() throws Exception {
        System.out.println("=== TRACING RESET WHILE MONITORING ===");
        System.out.println("Registered paths before reset: " + engine.getFileMonitor().getRegisteredPaths());
        simulator.resetTestData();
        Thread.sleep(2000);
        System.out.println("Registered paths after reset: " + engine.getFileMonitor().getRegisteredPaths());
        System.out.println("FileMonitor running after reset: " + engine.isMonitoring());

        eventsReceived.clear();
        simulator.runSimulation(SimulationMode.NORMAL_ACTIVITY);
        Thread.sleep(2000);
        System.out.println("Events received for Mode 1 after reset: " + eventsReceived.size());
    }
}
