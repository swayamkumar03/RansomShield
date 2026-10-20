package com.ransomshield;

import com.ransomshield.alert.AlertManager;
import com.ransomshield.analysis.BehaviorDetector;
import com.ransomshield.analysis.EntropyCalculator;
import com.ransomshield.analysis.ThreatScoreEngine;
import com.ransomshield.database.DatabaseManager;
import com.ransomshield.database.FileEventRepository;
import com.ransomshield.database.IncidentRepository;
import com.ransomshield.model.FileEvent;
import com.ransomshield.model.MonitoringConfig;
import com.ransomshield.model.ThreatAssessment;
import com.ransomshield.monitor.EventQueueManager;
import com.ransomshield.monitor.FileMonitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Core orchestration engine uniting filesystem monitoring, the asynchronous event queue,
 * Shannon entropy computation, behavioral modeling, threat classification, and alerting.
 */
public class RansomShieldEngine {
    private static final Logger logger = LoggerFactory.getLogger(RansomShieldEngine.class);

    private final MonitoringConfig config;
    private final DatabaseManager databaseManager;
    private final IncidentRepository incidentRepository;
    private final FileEventRepository fileEventRepository;

    private final EventQueueManager eventQueue;
    private final FileMonitor fileMonitor;
    private final EntropyCalculator entropyCalculator;
    private final BehaviorDetector behaviorDetector;
    private final ThreatScoreEngine threatScoreEngine;
    private final AlertManager alertManager;
    private final com.ransomshield.defense.QuarantineService quarantineService;
    private final com.ransomshield.defense.ProcessContainmentService processContainmentService;
    private final com.ransomshield.defense.DefensePolicy defensePolicy;
    private final com.ransomshield.alert.NotificationService notificationService;
    private final com.ransomshield.defense.DefenseManager defenseManager;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private ExecutorService workerPool;
    private ScheduledExecutorService heartbeatScheduler;
    private Path activeMonitoredPath;
    private volatile ThreatAssessment latestAssessment = ThreatAssessment.createNormal();

    public RansomShieldEngine(MonitoringConfig config) {
        this.config = config != null ? config : new MonitoringConfig();
        this.databaseManager = new DatabaseManager(this.config.getDatabaseUrl());
        this.incidentRepository = new IncidentRepository(this.databaseManager);
        this.fileEventRepository = new FileEventRepository(this.databaseManager);

        this.eventQueue = new EventQueueManager(this.config.getQueueCapacity());
        this.fileMonitor = new FileMonitor(this.eventQueue, this.config.isRecursive());
        this.entropyCalculator = new EntropyCalculator(this.config.getMaxFileSizeMb() * 1024 * 1024L);
        this.behaviorDetector = new BehaviorDetector(this.config);
        this.threatScoreEngine = new ThreatScoreEngine(this.config);

        this.quarantineService = new com.ransomshield.defense.QuarantineService(this.databaseManager);
        this.processContainmentService = new com.ransomshield.defense.ProcessContainmentService();
        this.defensePolicy = new com.ransomshield.defense.DefensePolicy();
        this.notificationService = new com.ransomshield.alert.NotificationService();
        this.defenseManager = new com.ransomshield.defense.DefenseManager(
                this.incidentRepository,
                this.quarantineService,
                this.processContainmentService,
                this.defensePolicy,
                this.notificationService
        );

        this.alertManager = new AlertManager(this.incidentRepository, this.fileEventRepository, this.defenseManager);
    }

    /**
     * Starts monitoring the given root directory and initializes worker threads.
     */
    public synchronized void startMonitoring(Path directory) throws IOException {
        if (running.get()) {
            logger.warn("RansomShieldEngine is already running");
            return;
        }

        this.activeMonitoredPath = directory.toAbsolutePath().normalize();
        this.config.setMonitoredDirectory(activeMonitoredPath.toString());

        behaviorDetector.reset();
        eventQueue.clear();
        running.set(true);

        // Start FileMonitor
        fileMonitor.startMonitoring(activeMonitoredPath);

        // Initialize background analysis workers
        int workers = Math.max(2, config.getAnalysisWorkers());
        workerPool = Executors.newFixedThreadPool(workers, r -> {
            Thread t = new Thread(r, "RansomShield-AnalysisWorker");
            t.setDaemon(true);
            return t;
        });

        for (int i = 0; i < workers; i++) {
            workerPool.submit(this::processEventQueueLoop);
        }

        // Schedule periodic heartbeat for decaying window when no events arrive
        heartbeatScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "RansomShield-Heartbeat");
            t.setDaemon(true);
            return t;
        });
        heartbeatScheduler.scheduleAtFixedRate(this::evaluateHeartbeat, 1, 1, TimeUnit.SECONDS);

        logger.info("RansomShieldEngine started monitoring: {}", activeMonitoredPath);
    }

    /**
     * Stops monitoring and releases resources.
     */
    public synchronized void stopMonitoring() {
        if (!running.get()) return;

        running.set(false);
        fileMonitor.stopMonitoring();

        if (heartbeatScheduler != null) {
            heartbeatScheduler.shutdownNow();
        }

        if (workerPool != null) {
            workerPool.shutdownNow();
            try {
                workerPool.awaitTermination(1, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {}
        }

        logger.info("RansomShieldEngine stopped monitoring");
    }

    public boolean isMonitoring() {
        return running.get() && fileMonitor.isRunning();
    }

    /**
     * Analysis worker event consumption loop.
     */
    private void processEventQueueLoop() {
        while (running.get()) {
            try {
                FileEvent event = eventQueue.poll(500, TimeUnit.MILLISECONDS);
                if (event == null) continue;

                // Calculate Shannon entropy on created, modified, or renamed files
                if ("MODIFY".equalsIgnoreCase(event.getEventType()) 
                        || "CREATE".equalsIgnoreCase(event.getEventType())
                        || "RENAME".equalsIgnoreCase(event.getEventType())) {
                    double entropy = entropyCalculator.calculateEntropy(event.getPath());
                    event.setEntropy(entropy);
                }

                // Feed event into behavior detector
                behaviorDetector.recordEvent(event);

                // Run behavioral threat assessment
                BehaviorDetector.BehaviorSnapshot snapshot = behaviorDetector.getSnapshot();
                ThreatAssessment assessment = threatScoreEngine.assess(snapshot);
                this.latestAssessment = assessment;

                // Alert dispatch and persistence
                String rootDirStr = activeMonitoredPath != null ? activeMonitoredPath.toString() : "";
                alertManager.handleAssessment(assessment, rootDirStr);
                alertManager.notifyEventProcessed(event);

            } catch (InterruptedException e) {
                break;
            } catch (Exception e) {
                logger.error("Error processing event in worker loop: {}", e.getMessage(), e);
            }
        }
    }

    /**
     * Periodic heartbeat evaluation ensuring sliding window decay back to NORMAL.
     */
    private void evaluateHeartbeat() {
        if (!running.get()) return;

        try {
            BehaviorDetector.BehaviorSnapshot snapshot = behaviorDetector.getSnapshot();
            ThreatAssessment assessment = threatScoreEngine.assess(snapshot);
            this.latestAssessment = assessment;

            String rootDirStr = activeMonitoredPath != null ? activeMonitoredPath.toString() : "";
            alertManager.handleAssessment(assessment, rootDirStr);

        } catch (Exception e) {
            logger.warn("Error in heartbeat evaluation: {}", e.getMessage());
        }
    }

    public MonitoringConfig getConfig() {
        return config;
    }

    public DatabaseManager getDatabaseManager() {
        return databaseManager;
    }

    public IncidentRepository getIncidentRepository() {
        return incidentRepository;
    }

    public FileEventRepository getFileEventRepository() {
        return fileEventRepository;
    }

    public EventQueueManager getEventQueue() {
        return eventQueue;
    }

    public AlertManager getAlertManager() {
        return alertManager;
    }

    public ThreatAssessment getLatestAssessment() {
        return latestAssessment;
    }

    public BehaviorDetector getBehaviorDetector() {
        return behaviorDetector;
    }

    public FileMonitor getFileMonitor() {
        return fileMonitor;
    }

    public Path getActiveMonitoredPath() {
        return activeMonitoredPath;
    }

    public com.ransomshield.defense.DefenseManager getDefenseManager() {
        return defenseManager;
    }

    public com.ransomshield.defense.QuarantineService getQuarantineService() {
        return quarantineService;
    }

    public com.ransomshield.defense.ProcessContainmentService getProcessContainmentService() {
        return processContainmentService;
    }

    public com.ransomshield.alert.NotificationService getNotificationService() {
        return notificationService;
    }

    public void shutdown() {
        stopMonitoring();
        if (databaseManager != null) {
            databaseManager.close();
        }
    }
}
