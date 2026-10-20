package com.ransomshield.simulator;

import com.ransomshield.util.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.List;
import java.util.stream.Stream;

/**
 * Controlled, safe test simulator executing only inside a strictly guarded test directory.
 * Simulates filesystem behavioral signals (mass modifications, high entropy, directory traversal,
 * and extension renaming) WITHOUT real malware, shell calls, or actual encryption.
 */
public class RansomwareSimulator {
    private static final Logger logger = LoggerFactory.getLogger(RansomwareSimulator.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Path testDirectory;
    private final TestDataGenerator testDataGenerator;

    public RansomwareSimulator(Path testDirectory) {
        this.testDirectory = validateSafeTestDirectory(testDirectory);
        this.testDataGenerator = new TestDataGenerator(this.testDirectory);
    }

    /**
     * Enforces strict safety boundary validation.
     * Rejects user home, root directories, Windows system folders, etc.
     */
    public static Path validateSafeTestDirectory(Path path) {
        if (path == null) {
            throw new SecurityException("Simulator target directory cannot be null");
        }

        Path normalized = path.toAbsolutePath().normalize();

        // 1. Never operate on filesystem root
        if (normalized.equals(normalized.getRoot())) {
            throw new SecurityException("Simulator refused: target cannot be filesystem root: " + normalized);
        }

        // 2. Never operate directly on user home directory
        String userHome = System.getProperty("user.home");
        if (userHome != null) {
            Path homePath = Paths.get(userHome).toAbsolutePath().normalize();
            if (normalized.equals(homePath)) {
                throw new SecurityException("Simulator refused: target cannot be the user home directory: " + normalized);
            }
        }

        // 3. Never operate on critical system directories
        String[] prohibitedTokens = {"windows", "system32", "program files", "program files (x86)", "/etc", "/usr", "/bin", "/sbin"};
        String pathStr = normalized.toString().toLowerCase();
        for (String token : prohibitedTokens) {
            if (pathStr.contains(token)) {
                throw new SecurityException("Simulator refused: target directory cannot be in system path: " + normalized);
            }
        }

        return normalized;
    }

    /**
     * Prepares standard test files if the test directory is missing or empty.
     */
    public void ensureTestDataset() throws IOException {
        if (!Files.exists(testDirectory)) {
            Files.createDirectories(testDirectory);
        }

        Path docs = testDirectory.resolve("Documents");
        boolean needsInit = false;
        if (!Files.exists(docs)) {
            needsInit = true;
        } else {
            try (Stream<Path> stream = Files.list(docs)) {
                if (stream.noneMatch(p -> p.toString().endsWith(".txt"))) {
                    needsInit = true;
                }
            }
        }

        if (needsInit) {
            testDataGenerator.generateStandardDataset();
        }
    }

    /**
     * Clears all test files safely within the designated test root and regenerates the clean dataset
     * without deleting the monitored directory tree itself (which would invalidate WatchService keys).
     */
    public void resetTestData() throws IOException {
        validateSafeTestDirectory(testDirectory);
        logger.info("Clearing safe test directory contents: {}", testDirectory);

        if (Files.exists(testDirectory)) {
            try (Stream<Path> walk = Files.walk(testDirectory)) {
                walk.filter(Files::isRegularFile).forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (IOException e) {
                        logger.warn("Could not delete file during cleanup: {}", p, e);
                    }
                });
            }
        }

        Files.createDirectories(testDirectory);
        testDataGenerator.generateStandardDataset();
        logger.info("Successfully reset test dataset in {}", testDirectory);
    }

    /**
     * Executes the requested simulation mode safely.
     */
    public void runSimulation(SimulationMode mode) throws Exception {
        validateSafeTestDirectory(testDirectory);
        ensureTestDataset();

        logger.info("Starting safe simulation: {}", mode.getTitle());

        switch (mode) {
            case NORMAL_ACTIVITY -> runNormalActivity();
            case HIGH_ENTROPY_SINGLE -> runHighEntropySingle();
            case MASS_MODIFICATION -> runMassModification();
            case SUSPICIOUS_RENAME -> runSuspiciousRename();
            case MULTI_DIRECTORY_TRAVERSAL -> runMultiDirectoryTraversal();
            case COMBINED_RANSOMWARE_SIMULATION -> runCombinedSimulation();
        }

        logger.info("Finished safe simulation: {}", mode.getTitle());
    }

    // MODE 1: Normal Activity (2-3 files modified slowly with low-entropy text)
    private void runNormalActivity() throws Exception {
        Path docs = testDirectory.resolve("Documents");
        if (!Files.exists(docs)) {
            Files.createDirectories(docs);
        }

        for (int i = 1; i <= 3; i++) {
            Path file = docs.resolve(String.format("document_%02d.txt", i));
            if (!Files.exists(file)) {
                Path enc = docs.resolve(String.format("document_%02d.txt.encrypted", i));
                Files.deleteIfExists(enc);
                String initial = "RansomShield Document " + i + "\nThis is a standard text file with normal English entropy.\n"
                        + "Quarterly business notes, memos, project planning objectives, and general communications.\n".repeat(5);
                Files.writeString(file, initial, StandardCharsets.UTF_8);
                Thread.sleep(50);
            }
            String appendText = String.format("\n[Benign Update %d] Added notes at %s\n", i, java.time.Instant.now());
            Files.writeString(file, appendText, StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.APPEND);
            Thread.sleep(600); // intentional human-like slow modification
        }
    }

    // MODE 2: High Entropy Single File (Tests False-Positive Defense)
    private void runHighEntropySingle() throws Exception {
        Path docs = testDirectory.resolve("Documents");
        if (!Files.exists(docs)) {
            Files.createDirectories(docs);
        }

        Path file = docs.resolve("document_01.txt");
        if (!Files.exists(file)) {
            Path enc = docs.resolve("document_01.txt.encrypted");
            Files.deleteIfExists(enc);
            String initial = "RansomShield Document 1\nThis is a standard text file with normal English entropy.\n"
                    + "Quarterly business notes, memos, project planning objectives, and general communications.\n".repeat(5);
            Files.writeString(file, initial, StandardCharsets.UTF_8);
            Thread.sleep(50);
        }

        // Write 8 KB of uniform pseudorandom bytes (Shannon entropy ~ 7.9)
        byte[] highEntropyBytes = new byte[8192];
        RANDOM.nextBytes(highEntropyBytes);
        Files.write(file, highEntropyBytes);
    }

    // MODE 3: Mass File Modification (Rapidly modifies ~60 files without encryption)
    private void runMassModification() throws Exception {
        List<Path> files = getAllFiles();
        int count = Math.min(60, files.size());
        for (int i = 0; i < count; i++) {
            Path file = files.get(i);
            String content = "Rapid modification line update " + i + " timestamp: " + System.currentTimeMillis();
            Files.writeString(file, content, StandardCharsets.UTF_8);
            Thread.sleep(10); // burst speed ~100 files/sec
        }
    }

    // MODE 4: Suspicious Extension Rename (.txt -> .encrypted)
    private void runSuspiciousRename() throws Exception {
        Path docs = testDirectory.resolve("Documents");
        if (!Files.exists(docs)) {
            Files.createDirectories(docs);
        }

        List<Path> docFiles;
        try (Stream<Path> stream = Files.list(docs)) {
            docFiles = stream.filter(p -> p.toString().endsWith(".txt") && !p.toString().endsWith(".encrypted")).toList();
        }

        // If no .txt files exist to rename (e.g. already renamed in previous test), restore test text files first
        if (docFiles.isEmpty()) {
            logger.info("Restoring .txt test files in Documents for rename simulation...");
            for (int i = 1; i <= 30; i++) {
                Path file = docs.resolve(String.format("document_%02d.txt", i));
                Path enc = docs.resolve(String.format("document_%02d.txt.encrypted", i));
                Files.deleteIfExists(enc);
                String content = "RansomShield Document " + i + "\nThis is a standard text file with normal English entropy.\n"
                        + "Quarterly business notes, memos, project planning objectives, and general communications.\n".repeat(5);
                Files.writeString(file, content, StandardCharsets.UTF_8);
            }
            Thread.sleep(100);
            try (Stream<Path> stream = Files.list(docs)) {
                docFiles = stream.filter(p -> p.toString().endsWith(".txt") && !p.toString().endsWith(".encrypted")).toList();
            }
        }

        for (Path file : docFiles) {
            String originalName = file.getFileName().toString();
            Path target = docs.resolve(originalName + ".encrypted");
            Files.move(file, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            Thread.sleep(20);
        }
    }

    // MODE 5: Multi-Directory Traversal (Modifies across Documents, Images, Reports, Projects)
    private void runMultiDirectoryTraversal() throws Exception {
        String[] dirs = {"Documents", "Images", "Reports", "Projects"};
        for (String sub : dirs) {
            Path dirPath = testDirectory.resolve(sub);
            if (Files.exists(dirPath)) {
                try (Stream<Path> stream = Files.list(dirPath)) {
                    List<Path> subFiles = stream.limit(5).toList();
                    for (Path file : subFiles) {
                        String append = "\nDirectory traversal marker: " + System.currentTimeMillis();
                        Files.writeString(file, append, StandardCharsets.UTF_8, java.nio.file.StandardOpenOption.APPEND);
                        Thread.sleep(15);
                    }
                }
            }
        }
    }

    // MODE 6: Combined Ransomware-like Simulation (High entropy + mass burst + multi-dir + rename)
    private void runCombinedSimulation() throws Exception {
        List<Path> files = getAllFiles();
        int targetCount = Math.min(75, files.size());

        for (int i = 0; i < targetCount; i++) {
            Path file = files.get(i);
            if (!Files.exists(file) || Files.isDirectory(file)) continue;

            // 1. Replace with 4KB high entropy random bytes
            byte[] pseudoEncrypted = new byte[4096];
            RANDOM.nextBytes(pseudoEncrypted);
            Files.write(file, pseudoEncrypted);

            // 2. Rename to .encrypted if not already renamed
            if (!file.toString().endsWith(".encrypted")) {
                Path encryptedPath = Paths.get(file.toString() + ".encrypted");
                Files.move(file, encryptedPath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }

            Thread.sleep(15); // Rapid burst (~60 files/sec)
        }
    }

    private List<Path> getAllFiles() throws IOException {
        try (Stream<Path> walk = Files.walk(testDirectory)) {
            return walk.filter(Files::isRegularFile).toList();
        }
    }

    public Path getTestDirectory() {
        return testDirectory;
    }
}
