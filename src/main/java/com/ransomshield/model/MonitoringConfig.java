package com.ransomshield.model;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Configuration holder for RansomShield filesystem monitoring, detection thresholds,
 * and engine parameters.
 */
public class MonitoringConfig {
    private static final Logger logger = LoggerFactory.getLogger(MonitoringConfig.class);

    private String monitoredDirectory = "./test-data";
    private String testDirectory = "./test-data";
    private boolean recursive = true;
    private int queueCapacity = 5000;
    private int analysisWorkers = 4;

    private double analysisWindowSeconds = 5.0;
    private long debounceMs = 150;
    private long maxFileSizeMb = 25;

    // Shannon Entropy Thresholds
    private double entropyLow = 6.0;
    private double entropyMedium = 7.0;
    private double entropyHigh = 7.5;

    // Modification Rate Thresholds (files/sec)
    private double rateLow = 2.0;
    private double rateMedium = 5.0;
    private double rateHigh = 15.0;

    // File Count Thresholds
    private int filesLow = 5;
    private int filesMedium = 20;
    private int filesHigh = 100;

    // Directory Thresholds
    private int directoriesMedium = 2;
    private int directoriesHigh = 3;
    private int directoriesCritical = 5;

    // Threat Score Level Thresholds
    private int scoreSuspicious = 30;
    private int scoreHigh = 60;
    private int scoreCritical = 80;

    // Suspicious extensions
    private final Set<String> suspiciousExtensions = new HashSet<>(Arrays.asList(
            ".encrypted", ".locked", ".crypto", ".crypted", ".ransom",
            ".wncry", ".locky", ".cerber", ".darkside", ".revil", ".blackcat"
    ));

    private String databaseUrl = "jdbc:sqlite:ransomshield.db";

    public MonitoringConfig() {
        loadProperties();
    }

    private void loadProperties() {
        try (InputStream in = getClass().getResourceAsStream("/config/application.properties")) {
            if (in != null) {
                Properties props = new Properties();
                props.load(in);

                monitoredDirectory = props.getProperty("monitoring.default-directory", monitoredDirectory);
                testDirectory = props.getProperty("monitoring.test-directory", testDirectory);
                recursive = Boolean.parseBoolean(props.getProperty("monitoring.recursive", String.valueOf(recursive)));
                queueCapacity = Integer.parseInt(props.getProperty("monitoring.queue-capacity", String.valueOf(queueCapacity)));
                analysisWorkers = Integer.parseInt(props.getProperty("monitoring.analysis-workers", String.valueOf(analysisWorkers)));

                analysisWindowSeconds = Double.parseDouble(props.getProperty("analysis.window.seconds", String.valueOf(analysisWindowSeconds)));
                debounceMs = Long.parseLong(props.getProperty("analysis.debounce.ms", String.valueOf(debounceMs)));
                maxFileSizeMb = Long.parseLong(props.getProperty("analysis.max-file-size-mb", String.valueOf(maxFileSizeMb)));

                entropyLow = Double.parseDouble(props.getProperty("threshold.entropy.low", String.valueOf(entropyLow)));
                entropyMedium = Double.parseDouble(props.getProperty("threshold.entropy.medium", String.valueOf(entropyMedium)));
                entropyHigh = Double.parseDouble(props.getProperty("threshold.entropy.high", String.valueOf(entropyHigh)));

                rateLow = Double.parseDouble(props.getProperty("threshold.rate.low", String.valueOf(rateLow)));
                rateMedium = Double.parseDouble(props.getProperty("threshold.rate.medium", String.valueOf(rateMedium)));
                rateHigh = Double.parseDouble(props.getProperty("threshold.rate.high", String.valueOf(rateHigh)));

                filesLow = Integer.parseInt(props.getProperty("threshold.files.low", String.valueOf(filesLow)));
                filesMedium = Integer.parseInt(props.getProperty("threshold.files.medium", String.valueOf(filesMedium)));
                filesHigh = Integer.parseInt(props.getProperty("threshold.files.high", String.valueOf(filesHigh)));

                directoriesMedium = Integer.parseInt(props.getProperty("threshold.directories.medium", String.valueOf(directoriesMedium)));
                directoriesHigh = Integer.parseInt(props.getProperty("threshold.directories.high", String.valueOf(directoriesHigh)));
                directoriesCritical = Integer.parseInt(props.getProperty("threshold.directories.critical", String.valueOf(directoriesCritical)));

                scoreSuspicious = Integer.parseInt(props.getProperty("threat.score.suspicious", String.valueOf(scoreSuspicious)));
                scoreHigh = Integer.parseInt(props.getProperty("threat.score.high", String.valueOf(scoreHigh)));
                scoreCritical = Integer.parseInt(props.getProperty("threat.score.critical", String.valueOf(scoreCritical)));

                String exts = props.getProperty("suspicious.extensions");
                if (exts != null && !exts.isBlank()) {
                    suspiciousExtensions.clear();
                    for (String ext : exts.split(",")) {
                        suspiciousExtensions.add(ext.trim().toLowerCase());
                    }
                }

                databaseUrl = props.getProperty("database.url", databaseUrl);
                logger.info("Loaded configuration successfully from application.properties");
            }
        } catch (Exception e) {
            logger.warn("Could not load application.properties, using defaults: {}", e.getMessage());
        }
    }

    public String getMonitoredDirectory() {
        return monitoredDirectory;
    }

    public void setMonitoredDirectory(String monitoredDirectory) {
        this.monitoredDirectory = monitoredDirectory;
    }

    public Path getMonitoredDirectoryPath() {
        return Paths.get(monitoredDirectory).toAbsolutePath().normalize();
    }

    public String getTestDirectory() {
        return testDirectory;
    }

    public void setTestDirectory(String testDirectory) {
        this.testDirectory = testDirectory;
    }

    public Path getTestDirectoryPath() {
        return Paths.get(testDirectory).toAbsolutePath().normalize();
    }

    public boolean isRecursive() {
        return recursive;
    }

    public void setRecursive(boolean recursive) {
        this.recursive = recursive;
    }

    public int getQueueCapacity() {
        return queueCapacity;
    }

    public void setQueueCapacity(int queueCapacity) {
        this.queueCapacity = queueCapacity;
    }

    public int getAnalysisWorkers() {
        return analysisWorkers;
    }

    public void setAnalysisWorkers(int analysisWorkers) {
        this.analysisWorkers = analysisWorkers;
    }

    public double getAnalysisWindowSeconds() {
        return analysisWindowSeconds;
    }

    public void setAnalysisWindowSeconds(double analysisWindowSeconds) {
        this.analysisWindowSeconds = analysisWindowSeconds;
    }

    public long getDebounceMs() {
        return debounceMs;
    }

    public void setDebounceMs(long debounceMs) {
        this.debounceMs = debounceMs;
    }

    public long getMaxFileSizeMb() {
        return maxFileSizeMb;
    }

    public void setMaxFileSizeMb(long maxFileSizeMb) {
        this.maxFileSizeMb = maxFileSizeMb;
    }

    public double getEntropyLow() {
        return entropyLow;
    }

    public void setEntropyLow(double entropyLow) {
        this.entropyLow = entropyLow;
    }

    public double getEntropyMedium() {
        return entropyMedium;
    }

    public void setEntropyMedium(double entropyMedium) {
        this.entropyMedium = entropyMedium;
    }

    public double getEntropyHigh() {
        return entropyHigh;
    }

    public void setEntropyHigh(double entropyHigh) {
        this.entropyHigh = entropyHigh;
    }

    public double getRateLow() {
        return rateLow;
    }

    public void setRateLow(double rateLow) {
        this.rateLow = rateLow;
    }

    public double getRateMedium() {
        return rateMedium;
    }

    public void setRateMedium(double rateMedium) {
        this.rateMedium = rateMedium;
    }

    public double getRateHigh() {
        return rateHigh;
    }

    public void setRateHigh(double rateHigh) {
        this.rateHigh = rateHigh;
    }

    public int getFilesLow() {
        return filesLow;
    }

    public void setFilesLow(int filesLow) {
        this.filesLow = filesLow;
    }

    public int getFilesMedium() {
        return filesMedium;
    }

    public void setFilesMedium(int filesMedium) {
        this.filesMedium = filesMedium;
    }

    public int getFilesHigh() {
        return filesHigh;
    }

    public void setFilesHigh(int filesHigh) {
        this.filesHigh = filesHigh;
    }

    public int getDirectoriesMedium() {
        return directoriesMedium;
    }

    public void setDirectoriesMedium(int directoriesMedium) {
        this.directoriesMedium = directoriesMedium;
    }

    public int getDirectoriesHigh() {
        return directoriesHigh;
    }

    public void setDirectoriesHigh(int directoriesHigh) {
        this.directoriesHigh = directoriesHigh;
    }

    public int getDirectoriesCritical() {
        return directoriesCritical;
    }

    public void setDirectoriesCritical(int directoriesCritical) {
        this.directoriesCritical = directoriesCritical;
    }

    public int getScoreSuspicious() {
        return scoreSuspicious;
    }

    public void setScoreSuspicious(int scoreSuspicious) {
        this.scoreSuspicious = scoreSuspicious;
    }

    public int getScoreHigh() {
        return scoreHigh;
    }

    public void setScoreHigh(int scoreHigh) {
        this.scoreHigh = scoreHigh;
    }

    public int getScoreCritical() {
        return scoreCritical;
    }

    public void setScoreCritical(int scoreCritical) {
        this.scoreCritical = scoreCritical;
    }

    public Set<String> getSuspiciousExtensions() {
        return Collections.unmodifiableSet(suspiciousExtensions);
    }

    public void addSuspiciousExtension(String ext) {
        if (ext != null && !ext.isBlank()) {
            this.suspiciousExtensions.add(ext.trim().toLowerCase());
        }
    }

    public boolean isSuspiciousExtension(String ext) {
        if (ext == null || ext.isBlank()) return false;
        String normalized = ext.startsWith(".") ? ext.toLowerCase() : "." + ext.toLowerCase();
        return suspiciousExtensions.contains(normalized);
    }

    public String getDatabaseUrl() {
        return databaseUrl;
    }

    public void setDatabaseUrl(String databaseUrl) {
        this.databaseUrl = databaseUrl;
    }
}
